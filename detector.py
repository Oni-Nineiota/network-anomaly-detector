"""Network anomaly detector using only Python standard library."""

from collections import defaultdict
import math
import os
import json


# === THREAT INTELLIGENCE ===

_THREAT_INTEL_IPS = None


def _load_threat_intel():
    """Load known malicious IPs from threat_intel/known_bad_ips.txt."""
    global _THREAT_INTEL_IPS
    if _THREAT_INTEL_IPS is not None:
        return _THREAT_INTEL_IPS

    _THREAT_INTEL_IPS = set()
    intel_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intel", "known_bad_ips.txt")

    if not os.path.exists(intel_path):
        return _THREAT_INTEL_IPS

    with open(intel_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            _THREAT_INTEL_IPS.add(line)

    return _THREAT_INTEL_IPS


def check_threat_intel(ip):
    """Check if an IP is in the known malicious list. Returns True if malicious."""
    intel = _load_threat_intel()
    return ip in intel


def parse_log(filepath):
    """Read a Zeek conn.log file and return a list of parsed event dicts.

    Supports four formats:
    1. JSON (one JSON object per line) — auto-detected if line starts with '{'
    2. Real Zeek with #fields header — dynamic field mapping
    3. Synthetic format — 14 tab-separated fields, positional
    4. Headerless real Zeek — 22 tab-separated fields, positional
    """
    events = []
    field_positions = None  # Set if #fields header found
    detected_format = None  # "synthetic_14", "zeek_22", or "zeek_header"

    # Zeek field names we care about mapped to our internal keys
    zeek_field_map = {
        "ts": "timestamp",
        "uid": "conn_id",
        "id.orig_h": "src_ip",
        "id.orig_p": "src_port",
        "id.resp_h": "dest_ip",
        "id.resp_p": "dest_port",
        "proto": "protocol",
        "service": "service",
        "conn_state": "conn_state",
        "duration": "duration",
        "orig_bytes": "bytes_sent",
        "resp_bytes": "bytes_received",
    }

    def _safe_int(val):
        """Convert string to int, treating '-' and empty as 0."""
        if val == "-" or val == "" or val == "(empty)":
            return 0
        return int(val)

    def _safe_float(val):
        """Convert string to float, treating '-' and empty as 0.0."""
        if val == "-" or val == "" or val == "(empty)":
            return 0.0
        return float(val)

    def _safe_str(val):
        """Convert string, treating '-' and (empty) as empty string."""
        if val == "-" or val == "(empty)":
            return ""
        return val

    def _parse_with_header(fields):
        """Parse a line using dynamic field positions from #fields header."""
        event = {}

        ts_idx = field_positions.get("timestamp")
        if ts_idx is not None and ts_idx < len(fields):
            event["timestamp"] = _safe_float(fields[ts_idx])
        else:
            return None

        conn_idx = field_positions.get("conn_id")
        if conn_idx is not None and conn_idx < len(fields):
            event["conn_id"] = _safe_str(fields[conn_idx])
        else:
            event["conn_id"] = ""

        for str_field in ("src_ip", "dest_ip", "protocol", "service", "conn_state", "duration"):
            idx = field_positions.get(str_field)
            if idx is not None and idx < len(fields):
                event[str_field] = _safe_str(fields[idx])
            else:
                event[str_field] = ""

        for int_field in ("src_port", "dest_port", "bytes_sent", "bytes_received"):
            idx = field_positions.get(int_field)
            if idx is not None and idx < len(fields):
                event[int_field] = _safe_int(fields[idx])
            else:
                event[int_field] = 0

        return event

    def _parse_synthetic_14(fields):
        """Parse a line in our synthetic 14-field format."""
        return {
            "timestamp": _safe_float(fields[0]),
            "conn_id": _safe_str(fields[1]),
            "src_ip": _safe_str(fields[2]),
            "src_port": _safe_int(fields[3]),
            "dest_ip": _safe_str(fields[4]),
            "dest_port": _safe_int(fields[5]),
            "protocol": _safe_str(fields[6]),
            "service": _safe_str(fields[7]),
            "conn_state": _safe_str(fields[8]),
            "duration": _safe_str(fields[9]),
            "bytes_sent": _safe_int(fields[10]),
            "bytes_received": _safe_int(fields[11]),
        }

    def _parse_zeek_22(fields):
        """Parse a line in headerless real Zeek 22-field format."""
        return {
            "timestamp": _safe_float(fields[0]),
            "conn_id": _safe_str(fields[1]),
            "src_ip": _safe_str(fields[2]),
            "src_port": _safe_int(fields[3]),
            "dest_ip": _safe_str(fields[4]),
            "dest_port": _safe_int(fields[5]),
            "protocol": _safe_str(fields[6]),
            "service": _safe_str(fields[7]),
            "conn_state": _safe_str(fields[11]),
            "duration": _safe_str(fields[8]),
            "bytes_sent": _safe_int(fields[9]),
            "bytes_received": _safe_int(fields[10]),
        }

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # JSON format: detect if line starts with '{'
            if line.startswith("{"):
                if detected_format is None:
                    detected_format = "json"
                if detected_format == "json":
                    try:
                        obj = json.loads(line)
                        event = {
                            "timestamp": float(obj.get("ts", 0)),
                            "conn_id": str(obj.get("uid", "")),
                            "src_ip": str(obj.get("id.orig_h", obj.get("id_orig_h", ""))),
                            "src_port": int(obj.get("id.orig_p", obj.get("id_orig_p", 0))),
                            "dest_ip": str(obj.get("id.resp_h", obj.get("id_resp_h", ""))),
                            "dest_port": int(obj.get("id.resp_p", obj.get("id_resp_p", 0))),
                            "protocol": str(obj.get("proto", "")),
                            "service": str(obj.get("service", "")),
                            "conn_state": str(obj.get("conn_state", "")),
                            "duration": str(obj.get("duration", "")),
                            "bytes_sent": int(obj.get("orig_bytes", obj.get("orig_ip_bytes", 0)) or 0),
                            "bytes_received": int(obj.get("resp_bytes", obj.get("resp_ip_bytes", 0)) or 0),
                        }
                        if event["timestamp"] > 0:
                            events.append(event)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass
                    continue

            # Handle comment/header lines
            if line.startswith("#"):
                if line.startswith("#fields"):
                    # Parse field names from #fields header
                    parts = line.split("\t")
                    columns = parts[1:] if len(parts) > 1 else line.split()[1:]
                    field_positions = {}
                    for idx, col in enumerate(columns):
                        if col in zeek_field_map:
                            field_positions[zeek_field_map[col]] = idx
                    detected_format = "zeek_header"
                continue

            fields = line.split("\t")

            # Detect format from first data line if not already determined
            if detected_format is None:
                num_fields = len(fields)
                if num_fields == 14:
                    detected_format = "synthetic_14"
                elif num_fields >= 21:
                    detected_format = "zeek_22"
                else:
                    continue  # Unknown format, skip line

            try:
                if detected_format == "zeek_header" and field_positions:
                    event = _parse_with_header(fields)
                elif detected_format == "synthetic_14":
                    if len(fields) != 14:
                        continue
                    event = _parse_synthetic_14(fields)
                elif detected_format == "zeek_22":
                    if len(fields) < 21:
                        continue
                    event = _parse_zeek_22(fields)
                else:
                    continue

                if event:
                    events.append(event)
            except (ValueError, IndexError):
                continue

    return events


def detect_brute_force(events):
    """Detect brute force attempts on SSH/FTP/RDP ports using sliding window."""
    target_ports = {22, 21, 3389}
    results = []

    # Group by src_ip
    by_ip = defaultdict(list)
    for e in events:
        if e["dest_port"] in target_ports:
            by_ip[e["src_ip"]].append(e)

    for ip, conns in by_ip.items():
        # Sort by timestamp
        conns.sort(key=lambda x: x["timestamp"])

        # Group connections by dest_port for reporting
        port_groups = defaultdict(list)
        for c in conns:
            port_groups[c["dest_port"]].append(c)

        for port, port_conns in port_groups.items():
            if len(port_conns) < 10:
                continue

            # Sliding window: find max count within any 60-second window
            best_count = 0
            best_timespan = 0.0
            best_left = 0
            left = 0

            for right in range(len(port_conns)):
                # Shrink window from left if it exceeds 60 seconds
                while port_conns[right]["timestamp"] - port_conns[left]["timestamp"] > 60.0:
                    left += 1

                window_count = right - left + 1
                if window_count > best_count:
                    best_count = window_count
                    best_timespan = port_conns[right]["timestamp"] - port_conns[left]["timestamp"]
                    best_left = left

            if best_count >= 10:
                severity = "HIGH" if best_count >= 30 else "MEDIUM"
                results.append({
                    "type": "BRUTE_FORCE",
                    "mitre_id": "T1110",
                    "mitre_name": "Credential Access: Brute Force",
                    "src_ip": ip,
                    "count": best_count,
                    "timespan_seconds": round(best_timespan, 2),
                    "dest_port": port,
                    "severity": severity,
                    "window_start": port_conns[best_left]["timestamp"],
                })

    return results


def detect_port_scan(events):
    """Detect port scanning by finding IPs contacting many unique ports in a short window."""
    results = []

    # Group by src_ip
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["src_ip"]].append(e)

    for ip, conns in by_ip.items():
        # Sort by timestamp
        conns.sort(key=lambda x: x["timestamp"])

        if len(conns) < 10:
            continue

        # Sliding window approach: expand right, track unique ports
        best_unique = 0
        best_timespan = 0.0
        best_left = 0
        left = 0

        # For efficiency, use a counter for ports in the window
        port_count = defaultdict(int)
        unique_in_window = 0

        for right in range(len(conns)):
            # Add right element
            rport = conns[right]["dest_port"]
            if port_count[rport] == 0:
                unique_in_window += 1
            port_count[rport] += 1

            # Shrink from left if window exceeds 60 seconds
            while conns[right]["timestamp"] - conns[left]["timestamp"] > 60.0:
                lport = conns[left]["dest_port"]
                port_count[lport] -= 1
                if port_count[lport] == 0:
                    unique_in_window -= 1
                    del port_count[lport]
                left += 1

            if unique_in_window > best_unique:
                best_unique = unique_in_window
                best_timespan = conns[right]["timestamp"] - conns[left]["timestamp"]
                best_left = left

        if best_unique >= 10:
            severity = "HIGH" if best_unique >= 20 else "MEDIUM"
            results.append({
                "type": "PORT_SCAN",
                "mitre_id": "T1046",
                "mitre_name": "Discovery: Network Service Scanning",
                "src_ip": ip,
                "unique_ports": best_unique,
                "timespan_seconds": round(best_timespan, 2),
                "severity": severity,
                "window_start": conns[best_left]["timestamp"],
            })

    return results


def detect_traffic_spike(events):
    """Detect traffic spikes by comparing 10-second windows against the baseline average."""
    if not events:
        return []

    results = []

    # Determine time range
    timestamps = [e["timestamp"] for e in events]
    min_ts = min(timestamps)
    max_ts = max(timestamps)

    # Bucket events into 10-second windows
    bucket_size = 10.0
    num_buckets = max(1, math.ceil((max_ts - min_ts) / bucket_size))
    buckets = defaultdict(int)

    for ts in timestamps:
        bucket_idx = int((ts - min_ts) / bucket_size)
        buckets[bucket_idx] += 1

    # Calculate baseline: average connections per 10-second window
    # Use total buckets spanning the time range (including empty ones)
    total_buckets = num_buckets
    baseline = len(events) / total_buckets if total_buckets > 0 else 0

    if baseline == 0:
        return []

    # Find windows exceeding 3x baseline AND at least 8 connections
    threshold = 3 * baseline
    min_absolute_count = 8
    for bucket_idx, count in buckets.items():
        if count >= threshold and count >= min_absolute_count:
            multiplier = count / baseline
            severity = "HIGH" if multiplier >= 5 else "MEDIUM"
            window_start = min_ts + bucket_idx * bucket_size
            window_end = window_start + bucket_size
            results.append({
                "type": "TRAFFIC_SPIKE",
                "mitre_id": "T1498",
                "mitre_name": "Impact: Network Denial of Service",
                "window_start": round(window_start, 6),
                "window_end": round(window_end, 6),
                "connection_count": count,
                "baseline": round(baseline, 2),
                "multiplier": round(multiplier, 2),
                "severity": severity,
            })

    return results


def detect_slow_scan(events):
    """Detect slow/stealthy port scans using a wider 30-minute sliding window.

    Catches attackers who scan 1 port every 60+ seconds to evade short-window detection.
    Threshold: 15+ unique ports from one IP within a 1800-second (30 min) window.
    """
    results = []

    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["src_ip"]].append(e)

    for ip, conns in by_ip.items():
        conns.sort(key=lambda x: x["timestamp"])

        if len(conns) < 15:
            continue

        # Sliding window: 1800 seconds (30 minutes)
        best_unique = 0
        best_timespan = 0.0
        best_left = 0
        left = 0
        port_count = defaultdict(int)
        unique_in_window = 0

        for right in range(len(conns)):
            rport = conns[right]["dest_port"]
            if port_count[rport] == 0:
                unique_in_window += 1
            port_count[rport] += 1

            while conns[right]["timestamp"] - conns[left]["timestamp"] > 1800.0:
                lport = conns[left]["dest_port"]
                port_count[lport] -= 1
                if port_count[lport] == 0:
                    unique_in_window -= 1
                    del port_count[lport]
                left += 1

            if unique_in_window > best_unique:
                best_unique = unique_in_window
                best_timespan = conns[right]["timestamp"] - conns[left]["timestamp"]
                best_left = left

        # Only flag if 15+ unique ports AND timespan > 120s (to avoid overlap with fast scan detector)
        if best_unique >= 15 and best_timespan > 120.0:
            severity = "HIGH" if best_unique >= 25 else "MEDIUM"
            results.append({
                "type": "SLOW_SCAN",
                "mitre_id": "T1046",
                "mitre_name": "Discovery: Network Service Scanning (Stealth)",
                "src_ip": ip,
                "unique_ports": best_unique,
                "timespan_seconds": round(best_timespan, 2),
                "severity": severity,
                "window_start": conns[best_left]["timestamp"],
            })

    return results


def detect_data_exfiltration(events):
    """Detect data exfiltration by finding IPs with abnormally high outbound bytes.

    Flags an IP if it sends more than 100KB total to a single destination,
    AND the ratio of bytes_sent to bytes_received is > 10:1 (heavily asymmetric).
    """
    results = []

    # Group by (src_ip, dest_ip) pair
    pair_data = defaultdict(lambda: {"total_sent": 0, "total_recv": 0, "count": 0, "events": []})

    for e in events:
        key = (e["src_ip"], e["dest_ip"])
        pair_data[key]["total_sent"] += e["bytes_sent"]
        pair_data[key]["total_recv"] += e["bytes_received"]
        pair_data[key]["count"] += 1
        pair_data[key]["events"].append(e)

    for (src_ip, dest_ip), data in pair_data.items():
        total_sent = data["total_sent"]
        total_recv = data["total_recv"]
        count = data["count"]

        # Threshold: >100KB sent, ratio > 10:1, at least 5 connections
        if total_sent < 100000 or count < 5:
            continue

        ratio = total_sent / max(total_recv, 1)
        if ratio < 10:
            continue

        # Get time range
        timestamps = [e["timestamp"] for e in data["events"]]
        timespan = max(timestamps) - min(timestamps)

        severity = "HIGH" if total_sent > 500000 else "MEDIUM"
        results.append({
            "type": "DATA_EXFILTRATION",
            "mitre_id": "T1048",
            "mitre_name": "Exfiltration: Exfiltration Over Alternative Protocol",
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "bytes_sent": total_sent,
            "bytes_received": total_recv,
            "ratio": round(ratio, 1),
            "connection_count": count,
            "timespan_seconds": round(timespan, 2),
            "severity": severity,
            "window_start": min(timestamps),
        })

    return results


def calculate_threat_score(anomalies):
    """Calculate a nuanced threat score from 0-100 based on type, severity, and intensity."""
    # Base points per anomaly type and severity
    base_points = {
        ("BRUTE_FORCE", "HIGH"): 20,
        ("BRUTE_FORCE", "MEDIUM"): 10,
        ("PORT_SCAN", "HIGH"): 15,
        ("PORT_SCAN", "MEDIUM"): 8,
        ("SLOW_SCAN", "HIGH"): 12,
        ("SLOW_SCAN", "MEDIUM"): 7,
        ("TRAFFIC_SPIKE", "HIGH"): 12,
        ("TRAFFIC_SPIKE", "MEDIUM"): 6,
        ("DATA_EXFILTRATION", "HIGH"): 18,
        ("DATA_EXFILTRATION", "MEDIUM"): 10,
    }

    score = 0
    unique_ips = set()

    for a in anomalies:
        key = (a["type"], a["severity"])
        score += base_points.get(key, 0)

        # Bonus points based on intensity
        if a["type"] == "BRUTE_FORCE":
            count = a.get("count", 0)
            if count > 30:
                score += (count - 30) // 10

        elif a["type"] == "PORT_SCAN":
            ports = a.get("unique_ports", 0)
            if ports > 20:
                score += (ports - 20) // 5

        elif a["type"] == "TRAFFIC_SPIKE":
            multiplier = a.get("multiplier", 0)
            if multiplier > 8:
                score += 2

        # Track unique IPs
        if "src_ip" in a:
            unique_ips.add(a["src_ip"])

    # Coordinated attack penalty
    if len(unique_ips) > 2:
        score += 10

    return min(round(score), 100)


def get_flagged_ips(anomalies):
    """Return a dict mapping flagged IPs to lists of their anomaly descriptions."""
    flagged = defaultdict(list)
    for a in anomalies:
        ip = a.get("src_ip")
        if ip:
            desc = f"{a['type']} ({a['severity']})"
            if desc not in flagged[ip]:
                flagged[ip].append(desc)
    return dict(flagged)


def get_timeline_data(events):
    """Group events into 10-second buckets and return bucket counts."""
    if not events:
        return []

    timestamps = [e["timestamp"] for e in events]
    min_ts = min(timestamps)
    max_ts = max(timestamps)

    bucket_size = 10.0
    num_buckets = max(1, math.ceil((max_ts - min_ts) / bucket_size))
    buckets = defaultdict(int)

    for ts in timestamps:
        bucket_idx = int((ts - min_ts) / bucket_size)
        buckets[bucket_idx] += 1

    timeline = []
    for i in range(num_buckets):
        timeline.append({
            "bucket_start": round(min_ts + i * bucket_size, 6),
            "count": buckets.get(i, 0),
        })

    return timeline


def _get_ip_reputation(ip):
    """Determine IP reputation based on address range."""
    if ip.startswith("127."):
        return "LOOPBACK"
    if ip.startswith("10."):
        return "PRIVATE"
    if ip.startswith("192.168."):
        return "PRIVATE"
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second_octet = int(parts[1])
                if 16 <= second_octet <= 31:
                    return "PRIVATE"
            except ValueError:
                pass
    return "EXTERNAL"


def analyze_file(filepath):
    """Master function: parse, detect all anomalies, and return full analysis."""
    events = parse_log(filepath)

    # Run all detectors
    brute_force = detect_brute_force(events)
    port_scan = detect_port_scan(events)
    slow_scan = detect_slow_scan(events)
    traffic_spike = detect_traffic_spike(events)
    data_exfil = detect_data_exfiltration(events)

    anomalies = brute_force + port_scan + slow_scan + traffic_spike + data_exfil

    threat_score = calculate_threat_score(anomalies)
    flagged_ips = get_flagged_ips(anomalies)
    timeline_data = get_timeline_data(events)

    # Protocol breakdown
    protocol_counts = defaultdict(int)
    for e in events:
        protocol_counts[e["protocol"]] += 1
    protocol_breakdown = dict(protocol_counts)

    # Connection states
    state_counts = defaultdict(int)
    for e in events:
        state_counts[e["conn_state"]] += 1
    connection_states = dict(state_counts)

    # Top talkers — top 5 source IPs by connection count
    ip_counts = defaultdict(int)
    for e in events:
        ip_counts[e["src_ip"]] += 1
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_talkers = [
        {"ip": ip, "count": count, "reputation": _get_ip_reputation(ip)}
        for ip, count in sorted_ips
    ]

    # Get last 20 raw lines from file
    raw_lines = []
    with open(filepath, "r") as f:
        all_lines = f.readlines()
        raw_lines = [line.strip() for line in all_lines[-20:]]

    # Threat intelligence check — flag IPs on known blocklists
    threat_intel_hits = []
    checked_ips = set()
    for e in events:
        for ip in (e["src_ip"], e["dest_ip"]):
            if ip and ip not in checked_ips:
                checked_ips.add(ip)
                if check_threat_intel(ip):
                    threat_intel_hits.append(ip)

    return {
        "total_events": len(events),
        "anomalies": anomalies,
        "threat_score": threat_score,
        "flagged_ips": flagged_ips,
        "timeline_data": timeline_data,
        "raw_lines": raw_lines,
        "protocol_breakdown": protocol_breakdown,
        "connection_states": connection_states,
        "top_talkers": top_talkers,
        "threat_intel_hits": threat_intel_hits,
    }


if __name__ == "__main__":
    import json

    result = analyze_file("sample_logs/brute_force.log")
    print(f"Total events: {result['total_events']}")
    print(f"Anomalies found: {len(result['anomalies'])}")
    print(f"Threat score: {result['threat_score']}")
    print(f"Flagged IPs: {result['flagged_ips']}")
    print(f"Timeline buckets: {len(result['timeline_data'])}")

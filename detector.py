"""Network anomaly detector using only Python standard library."""

from collections import defaultdict
import math


def parse_log(filepath):
    """Read a Zeek conn.log file and return a list of parsed event dicts."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 14:
                continue
            try:
                event = {
                    "timestamp": float(fields[0]),
                    "conn_id": fields[1],
                    "src_ip": fields[2],
                    "src_port": int(fields[3]),
                    "dest_ip": fields[4],
                    "dest_port": int(fields[5]),
                    "protocol": fields[6],
                    "service": fields[7],
                    "conn_state": fields[8],
                    "duration": fields[9],
                    "bytes_sent": int(fields[10]),
                    "bytes_received": int(fields[11]),
                }
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
            left = 0

            for right in range(len(port_conns)):
                # Shrink window from left if it exceeds 60 seconds
                while port_conns[right]["timestamp"] - port_conns[left]["timestamp"] > 60.0:
                    left += 1

                window_count = right - left + 1
                if window_count > best_count:
                    best_count = window_count
                    best_timespan = port_conns[right]["timestamp"] - port_conns[left]["timestamp"]

            if best_count >= 10:
                severity = "HIGH" if best_count >= 30 else "MEDIUM"
                results.append({
                    "type": "BRUTE_FORCE",
                    "src_ip": ip,
                    "count": best_count,
                    "timespan_seconds": round(best_timespan, 2),
                    "dest_port": port,
                    "severity": severity,
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

        if best_unique >= 10:
            severity = "HIGH" if best_unique >= 20 else "MEDIUM"
            results.append({
                "type": "PORT_SCAN",
                "src_ip": ip,
                "unique_ports": best_unique,
                "timespan_seconds": round(best_timespan, 2),
                "severity": severity,
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
                "window_start": round(window_start, 6),
                "window_end": round(window_end, 6),
                "connection_count": count,
                "baseline": round(baseline, 2),
                "multiplier": round(multiplier, 2),
                "severity": severity,
            })

    return results


def calculate_threat_score(anomalies):
    """Calculate a threat score from 0-100 based on anomaly count and severity."""
    score = 0
    for a in anomalies:
        if a["severity"] == "HIGH":
            score += 25
        elif a["severity"] == "MEDIUM":
            score += 10
    return min(score, 100)


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


def analyze_file(filepath):
    """Master function: parse, detect all anomalies, and return full analysis."""
    events = parse_log(filepath)

    # Run all detectors
    brute_force = detect_brute_force(events)
    port_scan = detect_port_scan(events)
    traffic_spike = detect_traffic_spike(events)

    anomalies = brute_force + port_scan + traffic_spike

    threat_score = calculate_threat_score(anomalies)
    flagged_ips = get_flagged_ips(anomalies)
    timeline_data = get_timeline_data(events)

    # Get last 20 raw lines from file
    raw_lines = []
    with open(filepath, "r") as f:
        all_lines = f.readlines()
        raw_lines = [line.strip() for line in all_lines[-20:]]

    return {
        "total_events": len(events),
        "anomalies": anomalies,
        "threat_score": threat_score,
        "flagged_ips": flagged_ips,
        "timeline_data": timeline_data,
        "raw_lines": raw_lines,
    }


if __name__ == "__main__":
    import json

    result = analyze_file("sample_logs/brute_force.log")
    print(f"Total events: {result['total_events']}")
    print(f"Anomalies found: {len(result['anomalies'])}")
    print(f"Threat score: {result['threat_score']}")
    print(f"Flagged IPs: {result['flagged_ips']}")
    print(f"Timeline buckets: {len(result['timeline_data'])}")

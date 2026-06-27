"""Unit tests for the Network Anomaly Detector."""

import sys
import os
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import (
    parse_log,
    detect_brute_force,
    detect_port_scan,
    detect_slow_scan,
    detect_traffic_spike,
    detect_data_exfiltration,
    calculate_threat_score,
    check_threat_intel,
    get_flagged_ips,
    get_timeline_data,
    _get_ip_reputation,
    analyze_file,
)


def _make_event(ts=1000.0, src_ip="10.0.0.1", dest_ip="10.0.0.2",
                src_port=12345, dest_port=80, protocol="tcp",
                service="http", conn_state="SF", bytes_sent=500,
                bytes_received=1000):
    """Helper to create a single event dict."""
    return {
        "timestamp": ts,
        "conn_id": "Ctest123",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "service": service,
        "conn_state": conn_state,
        "duration": "1.0",
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
    }


def _write_temp_log(lines):
    """Write lines to a temp .log file and return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    f.write("\n".join(lines) + "\n")
    f.close()
    return f.name


# ===========================
# BRUTE FORCE TESTS
# ===========================

class TestBruteForceDetection:
    def test_detects_brute_force_ssh(self):
        """50 SSH connections from one IP in 30 seconds should be flagged."""
        events = []
        for i in range(50):
            events.append(_make_event(
                ts=1000.0 + i * 0.5,
                src_ip="192.168.1.100",
                dest_port=22,
                conn_state="S0"
            ))
        results = detect_brute_force(events)
        assert len(results) >= 1
        assert results[0]["type"] == "BRUTE_FORCE"
        assert results[0]["src_ip"] == "192.168.1.100"
        assert results[0]["severity"] == "HIGH"

    def test_no_brute_force_below_threshold(self):
        """5 SSH connections should NOT be flagged."""
        events = []
        for i in range(5):
            events.append(_make_event(
                ts=1000.0 + i * 2.0,
                src_ip="10.0.0.5",
                dest_port=22
            ))
        results = detect_brute_force(events)
        assert len(results) == 0

    def test_brute_force_rdp(self):
        """Brute force on RDP port 3389 should also be detected."""
        events = []
        for i in range(20):
            events.append(_make_event(
                ts=1000.0 + i * 2.0,
                src_ip="172.16.0.50",
                dest_port=3389,
                conn_state="S0"
            ))
        results = detect_brute_force(events)
        assert len(results) >= 1
        assert results[0]["dest_port"] == 3389

    def test_brute_force_has_mitre(self):
        """Brute force results should have MITRE ATT&CK mapping."""
        events = [_make_event(ts=1000.0 + i, src_ip="10.0.0.1", dest_port=22) for i in range(15)]
        results = detect_brute_force(events)
        assert len(results) >= 1
        assert results[0]["mitre_id"] == "T1110"
        assert "Brute Force" in results[0]["mitre_name"]


# ===========================
# PORT SCAN TESTS
# ===========================

class TestPortScanDetection:
    def test_detects_port_scan(self):
        """One IP hitting 25 unique ports in 40 seconds should be flagged."""
        events = []
        for i in range(25):
            events.append(_make_event(
                ts=1000.0 + i * 1.5,
                src_ip="10.0.0.23",
                dest_port=20 + i
            ))
        results = detect_port_scan(events)
        assert len(results) >= 1
        assert results[0]["type"] == "PORT_SCAN"
        assert results[0]["unique_ports"] >= 20

    def test_no_port_scan_few_ports(self):
        """3 unique ports should NOT be flagged."""
        events = []
        for i in range(3):
            events.append(_make_event(
                ts=1000.0 + i,
                src_ip="10.0.0.5",
                dest_port=80 + i
            ))
        results = detect_port_scan(events)
        assert len(results) == 0

    def test_port_scan_has_mitre(self):
        """Port scan results should have MITRE ATT&CK mapping."""
        events = [_make_event(ts=1000.0 + i, src_ip="10.0.0.1", dest_port=100 + i) for i in range(15)]
        results = detect_port_scan(events)
        assert len(results) >= 1
        assert results[0]["mitre_id"] == "T1046"


# ===========================
# SLOW SCAN TESTS
# ===========================

class TestSlowScanDetection:
    def test_detects_slow_scan(self):
        """30 ports spread over 30 minutes should be caught by slow scan detector."""
        events = []
        for i in range(30):
            events.append(_make_event(
                ts=1000.0 + i * 60.0,
                src_ip="172.16.5.10",
                dest_port=20 + i
            ))
        results = detect_slow_scan(events)
        assert len(results) >= 1
        assert results[0]["type"] == "SLOW_SCAN"
        assert results[0]["unique_ports"] >= 15

    def test_no_slow_scan_fast_scan(self):
        """Ports hit within 60 seconds should NOT trigger slow scan (handled by fast scan)."""
        events = []
        for i in range(20):
            events.append(_make_event(
                ts=1000.0 + i * 2.0,
                src_ip="10.0.0.1",
                dest_port=100 + i
            ))
        results = detect_slow_scan(events)
        assert len(results) == 0


# ===========================
# TRAFFIC SPIKE TESTS
# ===========================

class TestTrafficSpikeDetection:
    def test_detects_traffic_spike(self):
        """A burst of connections in one window should trigger spike detection."""
        events = []
        # Normal: 1 event per 10-second bucket over 100 seconds
        for i in range(10):
            events.append(_make_event(ts=1000.0 + i * 10.0))
        # Spike: 30 events in one 10-second window
        for i in range(30):
            events.append(_make_event(ts=1050.0 + i * 0.3))
        results = detect_traffic_spike(events)
        assert len(results) >= 1
        assert results[0]["type"] == "TRAFFIC_SPIKE"
        assert results[0]["multiplier"] >= 3

    def test_no_spike_uniform_traffic(self):
        """Evenly distributed traffic should not trigger spikes."""
        events = [_make_event(ts=1000.0 + i * 5.0) for i in range(100)]
        results = detect_traffic_spike(events)
        assert len(results) == 0


# ===========================
# DATA EXFILTRATION TESTS
# ===========================

class TestDataExfiltrationDetection:
    def test_detects_exfiltration(self):
        """Large outbound bytes with high ratio should be flagged."""
        events = []
        for i in range(10):
            events.append(_make_event(
                ts=1000.0 + i * 30.0,
                src_ip="192.168.10.55",
                dest_ip="203.0.113.42",
                dest_port=443,
                bytes_sent=100000,
                bytes_received=500
            ))
        results = detect_data_exfiltration(events)
        assert len(results) >= 1
        assert results[0]["type"] == "DATA_EXFILTRATION"
        assert results[0]["bytes_sent"] >= 500000
        assert results[0]["mitre_id"] == "T1048"

    def test_no_exfiltration_balanced_traffic(self):
        """Balanced send/receive should NOT be flagged."""
        events = []
        for i in range(10):
            events.append(_make_event(
                ts=1000.0 + i * 10.0,
                src_ip="10.0.0.1",
                dest_ip="10.0.0.2",
                bytes_sent=5000,
                bytes_received=4000
            ))
        results = detect_data_exfiltration(events)
        assert len(results) == 0


# ===========================
# THREAT SCORE TESTS
# ===========================

class TestThreatScore:
    def test_zero_score_no_anomalies(self):
        """No anomalies should give score 0."""
        assert calculate_threat_score([]) == 0

    def test_high_brute_force_scores_high(self):
        """A HIGH brute force should give at least 20 points."""
        anomalies = [{"type": "BRUTE_FORCE", "severity": "HIGH", "count": 50, "src_ip": "1.2.3.4"}]
        score = calculate_threat_score(anomalies)
        assert score >= 20

    def test_multiple_attackers_bonus(self):
        """3+ unique IPs should add coordinated attack penalty."""
        anomalies = [
            {"type": "PORT_SCAN", "severity": "MEDIUM", "unique_ports": 15, "src_ip": "1.1.1.1"},
            {"type": "PORT_SCAN", "severity": "MEDIUM", "unique_ports": 12, "src_ip": "2.2.2.2"},
            {"type": "BRUTE_FORCE", "severity": "MEDIUM", "count": 15, "src_ip": "3.3.3.3"},
        ]
        score = calculate_threat_score(anomalies)
        # 8 + 8 + 10 + 10 (coordinated) = 36
        assert score >= 30

    def test_score_capped_at_100(self):
        """Score should never exceed 100."""
        anomalies = [
            {"type": "BRUTE_FORCE", "severity": "HIGH", "count": 100, "src_ip": f"1.1.1.{i}"}
            for i in range(10)
        ]
        score = calculate_threat_score(anomalies)
        assert score == 100


# ===========================
# THREAT INTEL TESTS
# ===========================

class TestThreatIntel:
    def test_known_bad_ip_detected(self):
        """An IP in the blocklist should return True."""
        assert check_threat_intel("203.0.113.42") is True

    def test_private_ip_not_flagged(self):
        """A random private IP should not be in the blocklist."""
        assert check_threat_intel("192.168.1.1") is False

    def test_random_ip_not_flagged(self):
        """A made-up IP not in the list should return False."""
        assert check_threat_intel("99.99.99.99") is False


# ===========================
# IP REPUTATION TESTS
# ===========================

class TestIPReputation:
    def test_loopback(self):
        assert _get_ip_reputation("127.0.0.1") == "LOOPBACK"

    def test_private_10(self):
        assert _get_ip_reputation("10.0.0.5") == "PRIVATE"

    def test_private_192(self):
        assert _get_ip_reputation("192.168.1.1") == "PRIVATE"

    def test_private_172(self):
        assert _get_ip_reputation("172.16.0.1") == "PRIVATE"

    def test_external(self):
        assert _get_ip_reputation("8.8.8.8") == "EXTERNAL"


# ===========================
# PARSER TESTS
# ===========================

class TestParser:
    def test_parses_synthetic_14_field_format(self):
        """Parser should handle our 14-field synthetic format."""
        lines = [
            "1000.000000\tCtest1\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\thttp\tSF\t1.500000\t500\t1000\t5\t8"
        ]
        path = _write_temp_log(lines)
        try:
            events = parse_log(path)
            assert len(events) == 1
            assert events[0]["src_ip"] == "10.0.0.1"
            assert events[0]["dest_port"] == 80
            assert events[0]["bytes_sent"] == 500
        finally:
            os.unlink(path)

    def test_skips_corrupt_lines(self):
        """Parser should skip malformed lines without crashing."""
        lines = [
            "this is garbage",
            "",
            "also bad\ttoo few fields",
            "1000.000000\tCtest1\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\thttp\tSF\t1.500000\t500\t1000\t5\t8",
        ]
        path = _write_temp_log(lines)
        try:
            events = parse_log(path)
            assert len(events) == 1
        finally:
            os.unlink(path)

    def test_empty_file(self):
        """Parser should return empty list for empty file."""
        path = _write_temp_log([])
        try:
            events = parse_log(path)
            assert events == []
        finally:
            os.unlink(path)

    def test_handles_dash_values(self):
        """Parser should treat '-' as 0 for numeric fields."""
        lines = [
            "1000.000000\tCtest1\t10.0.0.1\t-\t10.0.0.2\t443\ttcp\t-\tSF\t-\t-\t-\t-\t-"
        ]
        path = _write_temp_log(lines)
        try:
            events = parse_log(path)
            assert len(events) == 1
            assert events[0]["src_port"] == 0
            assert events[0]["bytes_sent"] == 0
        finally:
            os.unlink(path)


# ===========================
# FULL PIPELINE TEST
# ===========================

class TestFullPipeline:
    def test_analyze_sample_file(self):
        """analyze_file on brute_force.log should return expected structure."""
        result = analyze_file("sample_logs/brute_force.log")
        assert "total_events" in result
        assert "anomalies" in result
        assert "threat_score" in result
        assert "flagged_ips" in result
        assert "timeline_data" in result
        assert "threat_intel_hits" in result
        assert result["total_events"] > 0
        assert result["threat_score"] >= 0

    def test_normal_traffic_no_anomalies(self):
        """Normal traffic should produce zero or minimal anomalies."""
        result = analyze_file("sample_logs/normal_traffic.log")
        assert result["threat_score"] == 0
        assert len(result["anomalies"]) == 0


    def test_parses_json_format(self):
        """Parser should handle JSON format (one object per line)."""
        lines = [
            '{"ts":1700000000.0,"uid":"C1","id.orig_h":"10.0.0.1","id.orig_p":12345,"id.resp_h":"10.0.0.2","id.resp_p":80,"proto":"tcp","service":"http","conn_state":"SF","duration":1.5,"orig_bytes":500,"resp_bytes":1000}'
        ]
        path = _write_temp_log(lines)
        try:
            events = parse_log(path)
            assert len(events) == 1
            assert events[0]["src_ip"] == "10.0.0.1"
            assert events[0]["dest_port"] == 80
            assert events[0]["bytes_sent"] == 500
            assert events[0]["protocol"] == "tcp"
        finally:
            os.unlink(path)

    def test_json_sample_file(self):
        """JSON brute force sample should be parseable and detectable."""
        result = analyze_file("sample_logs/brute_force_json.log")
        assert result["total_events"] == 18
        assert len(result["anomalies"]) >= 1
        brute = [a for a in result["anomalies"] if a["type"] == "BRUTE_FORCE"]
        assert len(brute) >= 1
        assert brute[0]["src_ip"] == "192.168.1.50"

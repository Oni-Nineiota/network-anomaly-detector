# Network Anomaly Detector

A real-time network log analysis tool that detects brute force attacks, port scans, DDoS floods, stealthy reconnaissance, and data exfiltration in Zeek conn.log files. Built with algorithmic detection (sliding windows, statistical baselines, traffic ratio analysis) — no machine learning dependencies.

## Features

- **5 Detection Engines** — Brute Force, Port Scan, Slow/Stealth Scan, Traffic Spike (DDoS), Data Exfiltration
- **MITRE ATT&CK Mapping** — Every detection tagged with framework IDs (T1110, T1046, T1498, T1048)
- **Local Threat Intelligence** — 200+ known malicious IPs checked against all traffic
- **Threat Scoring** — 0-100 composite score with severity weighting and coordinated attack detection
- **8 Sample Scenarios** — Brute force, port scan, DDoS flood, slow scan, data exfiltration, multi-attacker, combined attack, normal traffic
- **Multi-Format Parser** — Supports Zeek TSV (with/without headers), 14-field synthetic, 22-field real Zeek, and JSON format
- **Web Dashboard** — Terminal-themed UI with live charts, heatmaps, threat gauge, and staggered reveal animations
- **Export** — CSV and JSON report download for SIEM integration or incident documentation
- **33 Unit Tests** — Full test coverage on all detection algorithms

## Quick Start

### Option 1: Python (Direct)

```bash
git clone https://github.com/Oni-Nineiota/network-anomaly-detector.git
cd network-anomaly-detector
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python log_generator.py
python app.py
```

Open `http://localhost:5000` in your browser.

### Option 2: Docker

```bash
git clone https://github.com/Oni-Nineiota/network-anomaly-detector.git
cd network-anomaly-detector
docker build -t anomaly-detector .
docker run -p 5000:5000 anomaly-detector
```

Open `http://localhost:5000` in your browser.

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

All 33 tests should pass:

```
tests/test_detector.py::TestBruteForceDetection::test_detects_brute_force_ssh PASSED
tests/test_detector.py::TestPortScanDetection::test_detects_port_scan PASSED
tests/test_detector.py::TestSlowScanDetection::test_detects_slow_scan PASSED
tests/test_detector.py::TestTrafficSpikeDetection::test_detects_traffic_spike PASSED
tests/test_detector.py::TestDataExfiltrationDetection::test_detects_exfiltration PASSED
tests/test_detector.py::TestThreatIntel::test_known_bad_ip_detected PASSED
...
33 passed in 0.11s
```

## Detection Algorithms

| Detection | Technique | Threshold | MITRE |
|-----------|-----------|-----------|-------|
| Brute Force | Sliding window (60s) on SSH/FTP/RDP ports | ≥10 attempts in 60s | T1110 |
| Port Scan | Sliding window (60s), unique port counter | ≥10 unique ports in 60s | T1046 |
| Slow Scan | Wide sliding window (30 min) | ≥15 unique ports over >2 min | T1046 |
| Traffic Spike | 10s bucket comparison vs baseline average | ≥3x baseline AND ≥8 connections | T1498 |
| Data Exfiltration | Per-pair byte ratio analysis | >100KB sent, >10:1 send/receive ratio | T1048 |

## Sample Scenarios

| Scenario | What It Simulates | Expected Detection |
|----------|-------------------|-------------------|
| Brute Force | 45 SSH attempts from one IP in 90s | BRUTE_FORCE (HIGH) |
| Port Scan | 25 ports scanned in 45s | PORT_SCAN (HIGH) |
| DDoS Flood | 300+ connections from 15 IPs in 10s | TRAFFIC_SPIKE (HIGH) |
| Slow Scan | 30 ports over 30 minutes (stealthy) | SLOW_SCAN (HIGH) |
| Data Exfiltration | 2MB+ sent to single external IP | DATA_EXFILTRATION (HIGH) |
| Multi-Attacker | 3 simultaneous attackers | Score: 100/100 |
| Combined Attack | Brute force + port scan together | Multiple detections |
| Normal Traffic | Clean baseline traffic | No anomalies (score: 0) |

## Project Structure

```
├── app.py                  # Flask web application
├── detector.py             # Detection engine (5 algorithms + scoring)
├── log_generator.py        # Sample log file generator
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker containerization
├── threat_intel/
│   └── known_bad_ips.txt   # Local threat intelligence blocklist (200+ IPs)
├── sample_logs/            # 8 pre-generated attack scenarios
├── static/
│   └── style.css           # Terminal-themed UI styles
├── templates/
│   ├── index.html          # Main dashboard
│   └── report.html         # Incident report view
└── tests/
    └── test_detector.py    # 33 unit tests
```

## Tech Stack

- **Backend:** Python 3.11, Flask
- **Frontend:** Vanilla JavaScript, Chart.js, CSS3
- **Detection:** Pure algorithmic (sliding windows, statistical analysis)
- **Testing:** pytest
- **Deployment:** Docker

## Author

**Yadav Nishant Ajendrakumar**

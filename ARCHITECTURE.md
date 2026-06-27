# Architecture — Network Anomaly Detector

## System Overview

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌─────────────┐     ┌───────────┐
│  Log File   │────▶│   Parser    │────▶│  Detection Engine │────▶│   Scorer    │────▶│    UI     │
│ (TSV/JSON)  │     │ (auto-detect)│    │  (5 algorithms)   │     │ (0-100)     │     │ (Flask)   │
└─────────────┘     └─────────────┘     └──────────────────┘     └─────────────┘     └───────────┘
                                                │                        │
                                                ▼                        ▼
                                        ┌──────────────┐        ┌──────────────┐
                                        │ Threat Intel │        │   Export     │
                                        │ (blocklist)  │        │ (CSV/JSON)   │
                                        └──────────────┘        └──────────────┘
```

## Parser Design

The parser (`parse_log()`) auto-detects the log format from the first data line:

```
Line starts with '{' ?  ──▶  JSON mode (one object per line)
Line starts with '#fields' ?  ──▶  Header-based Zeek (dynamic field mapping)
Line has 14 tab fields ?  ──▶  Synthetic 14-field format
Line has 21+ tab fields ?  ──▶  Real Zeek 22-field format
Otherwise  ──▶  Skip line
```

Design choice: Auto-detection rather than requiring the user to specify format.
This handles real-world scenarios where analysts don't always know which Zeek
output mode was used.

### JSON Field Mapping

```
Zeek JSON Key    →   Internal Key
─────────────────────────────────
ts               →   timestamp
uid              →   conn_id
id.orig_h        →   src_ip
id.orig_p        →   src_port
id.resp_h        →   dest_ip
id.resp_p        →   dest_port
proto            →   protocol
service          →   service
conn_state       →   conn_state
duration         →   duration
orig_bytes       →   bytes_sent
resp_bytes       →   bytes_received
```

## Detection Algorithms

### 1. Brute Force Detection

**Technique:** Sliding window on authentication ports (22/SSH, 21/FTP, 3389/RDP)

**How it works:**
- Group all connections by source IP
- Filter to target ports only
- Slide a 60-second window across each IP's connections
- Find the window with the maximum connection count

**Thresholds:**
- ≥10 connections in 60s → MEDIUM severity
- ≥30 connections in 60s → HIGH severity

**Why 60 seconds:** Real brute force tools (Hydra, Medusa) typically attempt 10-50
logins per minute. A 60s window catches both fast and moderately-paced attacks.

**Why 10 minimum:** Reduces false positives from legitimate users who retry
passwords a few times.

### 2. Port Scan Detection (Fast)

**Technique:** Sliding window tracking unique destination ports per source IP

**How it works:**
- Group connections by source IP
- Slide a 60-second window
- Track unique port count using a frequency counter (O(1) add/remove)
- Find window with maximum unique ports

**Thresholds:**
- ≥10 unique ports in 60s → MEDIUM
- ≥20 unique ports in 60s → HIGH

**Why unique ports matter:** A scanner hitting 25 different ports is suspicious.
A web server receiving 25 connections on port 443 is not.

### 3. Slow Scan Detection

**Technique:** Same algorithm as fast scan but with a 30-minute window

**How it works:**
- Identical sliding window approach
- Window size: 1800 seconds (30 minutes) instead of 60
- Only flags if timespan > 120s (avoids double-flagging fast scans)

**Thresholds:**
- ≥15 unique ports over >2 minutes → MEDIUM
- ≥25 unique ports over >2 minutes → HIGH

**Why this exists:** Sophisticated attackers (APTs) scan one port every 60-90
seconds to evade short-window IDS rules. This detector catches them.

### 4. Traffic Spike Detection (DDoS)

**Technique:** Time-bucketed comparison against statistical baseline

**How it works:**
- Divide the entire log timespan into 10-second buckets
- Count connections per bucket
- Calculate baseline: total_events / total_buckets (includes empty buckets)
- Flag any bucket exceeding 3x baseline AND ≥8 absolute connections

**Thresholds:**
- ≥3x baseline AND ≥8 connections → MEDIUM
- ≥5x baseline → HIGH

**Why 10-second buckets:** DDoS floods are bursty. 10 seconds is granular enough
to catch a flood without fragmenting legitimate traffic bursts.

**Why 3x multiplier:** Eliminates noise from slight variations in normal traffic
patterns while catching genuine volumetric anomalies.

### 5. Data Exfiltration Detection

**Technique:** Per-(source, destination) pair byte ratio analysis

**How it works:**
- Group all connections by (src_ip, dest_ip) pair
- Sum bytes_sent and bytes_received for each pair
- Calculate ratio: total_sent / total_received
- Flag if ratio > 10:1 AND total_sent > 100KB AND ≥5 connections

**Thresholds:**
- >100KB sent with >10:1 ratio → MEDIUM
- >500KB sent with >10:1 ratio → HIGH

**Why ratio-based:** Normal browsing has roughly balanced traffic (you send a
request, get a larger response). Exfiltration inverts this — you send massive
data OUT and get tiny acknowledgments back.

## Threat Scoring

The threat score (0-100) combines multiple signals:

```
Score = Σ(base_points) + Σ(intensity_bonuses) + coordinated_penalty

Base Points:
  BRUTE_FORCE HIGH    = 20
  BRUTE_FORCE MEDIUM  = 10
  PORT_SCAN HIGH      = 15
  PORT_SCAN MEDIUM    = 8
  SLOW_SCAN HIGH      = 12
  SLOW_SCAN MEDIUM    = 7
  TRAFFIC_SPIKE HIGH  = 12
  TRAFFIC_SPIKE MEDIUM = 6
  DATA_EXFIL HIGH     = 18
  DATA_EXFIL MEDIUM   = 10

Intensity Bonuses:
  Brute force >30 attempts: +(count-30)/10
  Port scan >20 ports: +(ports-20)/5
  Spike multiplier >8x: +2

Coordinated Attack Penalty:
  3+ unique attacker IPs: +10

Final score capped at 100.
```

**Why weighted scoring:** Not all attacks are equal. Data exfiltration (actual data
theft) scores higher than a port scan (just reconnaissance). Multiple attackers
suggest coordination, which is more dangerous than a lone scanner.

## Threat Intelligence

**Approach:** Local file-based blocklist (no external API calls)

**File:** `threat_intel/known_bad_ips.txt` — ~200 IPs from public sources

**Lookup:** IPs loaded into a Python `set` on first use. Each IP check is O(1).

**Why local, not API:**
- No API key required (evaluators can clone and run immediately)
- No rate limiting or network dependency
- Deterministic results (same input always produces same output)
- Demonstrates the concept without infrastructure requirements

**Categories in blocklist:**
- Command & Control servers
- Known scanners / brute forcers
- Tor exit nodes (commonly abused)
- Malware distribution infrastructure
- DDoS botnet nodes
- Spam / phishing sources
- Cryptojacking infrastructure
- APT / nation-state associated

## Design Decisions

### Why Algorithmic Detection Over Machine Learning?

1. **Deterministic** — Same input always produces same output. No model drift.
2. **Explainable** — Every detection has a clear reason ("45 SSH attempts in 56s")
3. **No training data** — Works out of the box, no dataset collection needed
4. **Lightweight** — Runs in <100ms on 500+ event logs. No GPU, no numpy.
5. **Auditable** — Security teams can verify the logic. ML models are black boxes.

### Why Flask?

- Single file, minimal boilerplate
- Serves both the API (JSON) and the UI (templates)
- No database needed — analysis is stateless per request
- Easy to containerize

### Why No Database?

- The tool analyzes one file at a time and returns results immediately
- No persistent storage needed — results live in memory for the session
- Keeps deployment simple (no Postgres/Redis setup)
- Evaluators can `git clone` + `python app.py` and it works

### Why Standard Library for Detection?

The detector uses only `collections.defaultdict` and `math` — no pandas, numpy,
or sklearn. This proves the algorithms are understood at a fundamental level,
not just "imported from a library."

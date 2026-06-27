import random
import os
import time


def _random_ip():
    """Generate a random private IP address."""
    return f"{random.choice([10, 172, 192])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_conn_id():
    """Generate a random Zeek-style connection ID."""
    return f"C{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))}"


def _format_line(ts, conn_id, src_ip, src_port, dst_ip, dst_port, proto, service, conn_state, duration, bytes_sent, bytes_recv, pkts_sent, pkts_recv):
    """Format a single Zeek conn.log line."""
    return f"{ts:.6f}\t{conn_id}\t{src_ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{proto}\t{service}\t{conn_state}\t{duration:.6f}\t{bytes_sent}\t{bytes_recv}\t{pkts_sent}\t{pkts_recv}"


def _normal_traffic_lines(num_lines, base_time, duration_seconds, source_ips):
    """Generate normal traffic lines spread over a duration."""
    lines = []
    ports_services = [
        (80, "http"),
        (443, "ssl"),
        (53, "dns"),
        (25, "smtp"),
    ]

    for _ in range(num_lines):
        ts = base_time + random.uniform(0, duration_seconds)
        src_ip = random.choice(source_ips)
        src_port = random.randint(1024, 65535)
        dst_ip = _random_ip()
        dst_port, service = random.choice(ports_services)
        proto = "udp" if dst_port == 53 else "tcp"
        conn_state = "SF"
        dur = random.uniform(0.01, 5.0)
        bytes_sent = random.randint(100, 15000)
        bytes_recv = random.randint(200, 50000)
        pkts_sent = random.randint(3, 30)
        pkts_recv = random.randint(3, 50)
        conn_id = _random_conn_id()

        lines.append(_format_line(ts, conn_id, src_ip, src_port, dst_ip, dst_port, proto, service, conn_state, dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    return lines


def generate_brute_force():
    """Generate brute force attack log with 500+ lines.

    Plants 45 failed SSH attempts from 192.168.1.45 (port 22, conn_state S0)
    spread over 90 seconds at a random point in the log.
    Rest is normal traffic from 8 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    # Generate 8 random source IPs for normal traffic
    normal_ips = [_random_ip() for _ in range(8)]

    # Normal traffic (fill to get 500+ total with 45 attack lines)
    normal_count = random.randint(460, 480)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # Brute force attack: 45 failed SSH attempts from 192.168.1.45
    attack_start = base_time + random.uniform(300, one_hour - 300)
    attacker_ip = "192.168.1.45"

    for i in range(45):
        ts = attack_start + random.uniform(0, 90.0)
        src_port = random.randint(1024, 65535)
        dst_ip = _random_ip()
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.5)
        bytes_sent = random.randint(0, 100)
        bytes_recv = 0
        pkts_sent = random.randint(1, 3)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, attacker_ip, src_port, dst_ip, 22, "tcp", "ssh", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Sort by timestamp
    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/brute_force.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/brute_force.log ({len(lines)} lines)")


def generate_port_scan():
    """Generate port scan attack log with 500+ lines.

    Plants IP 10.0.0.23 hitting 25 well-known ports within 45 seconds (conn_state S0).
    Rest is normal traffic from 8 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    # Generate 8 random source IPs for normal traffic
    normal_ips = [_random_ip() for _ in range(8)]

    # Normal traffic
    normal_count = random.randint(480, 500)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # Port scan attack: 10.0.0.23 hitting 25 different well-known ports
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 6379, 8080, 8443, 9200, 27017, 5432, 110, 143, 993, 995, 1433]
    attack_start = base_time + random.uniform(300, one_hour - 300)
    scanner_ip = "10.0.0.23"
    dst_ip = _random_ip()  # Single target for the scan

    for port in scan_ports:
        ts = attack_start + random.uniform(0, 45.0)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.3)
        bytes_sent = random.randint(0, 80)
        bytes_recv = 0
        pkts_sent = random.randint(1, 2)
        pkts_recv = 0
        service = "-"

        lines.append(_format_line(ts, conn_id, scanner_ip, src_port, dst_ip, port, "tcp", service, "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Sort by timestamp
    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/port_scan.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/port_scan.log ({len(lines)} lines)")


def generate_normal_traffic():
    """Generate completely clean normal traffic log with 500+ lines.

    10 different IPs, ports 80/443/53/25/123, conn_state SF,
    random realistic byte counts, spread over 1 hour. No anomalies.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    # Generate 10 random source IPs
    source_ips = [_random_ip() for _ in range(10)]

    lines = []
    ports_services = [
        (80, "http"),
        (443, "ssl"),
        (53, "dns"),
        (25, "smtp"),
        (123, "ntp"),
    ]

    num_lines = random.randint(510, 550)

    for _ in range(num_lines):
        ts = base_time + random.uniform(0, one_hour)
        src_ip = random.choice(source_ips)
        src_port = random.randint(1024, 65535)
        dst_ip = _random_ip()
        dst_port, service = random.choice(ports_services)
        proto = "udp" if dst_port in (53, 123) else "tcp"
        conn_state = "SF"
        dur = random.uniform(0.01, 5.0)
        bytes_sent = random.randint(100, 15000)
        bytes_recv = random.randint(200, 50000)
        pkts_sent = random.randint(3, 30)
        pkts_recv = random.randint(3, 50)
        conn_id = _random_conn_id()

        lines.append(_format_line(ts, conn_id, src_ip, src_port, dst_ip, dst_port, proto, service, conn_state, dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Sort by timestamp
    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/normal_traffic.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/normal_traffic.log ({len(lines)} lines)")


def generate_combined_attack():
    """Generate a combined attack log with 500+ lines.

    Plants two simultaneous attacks:
    - 192.168.1.45 brute forcing SSH (40 attempts over 90s starting at 10 min mark)
    - 10.0.0.23 port scanning 22 ports within 45s starting at 12 min mark
    Rest is normal background traffic from 8 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    # Generate 8 random source IPs for normal traffic
    normal_ips = [_random_ip() for _ in range(8)]

    # Normal background traffic
    normal_count = random.randint(450, 470)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # Attack 1: Brute force from 192.168.1.45 starting at 10 minute mark
    brute_start = base_time + 600.0  # 10 minutes in
    attacker_ip = "192.168.1.45"

    for _ in range(40):
        ts = brute_start + random.uniform(0, 90.0)
        src_port = random.randint(1024, 65535)
        dst_ip = _random_ip()
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.5)
        bytes_sent = random.randint(0, 100)
        bytes_recv = 0
        pkts_sent = random.randint(1, 3)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, attacker_ip, src_port, dst_ip, 22, "tcp", "ssh", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Attack 2: Port scan from 10.0.0.23 starting at 12 minute mark
    scan_start = base_time + 720.0  # 12 minutes in
    scanner_ip = "10.0.0.23"
    scan_target = _random_ip()
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 6379, 8080, 8443, 9200, 27017, 5432, 143, 993]

    for port in scan_ports:
        ts = scan_start + random.uniform(0, 45.0)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.3)
        bytes_sent = random.randint(0, 80)
        bytes_recv = 0
        pkts_sent = random.randint(1, 2)
        pkts_recv = 0
        service = "-"

        lines.append(_format_line(ts, conn_id, scanner_ip, src_port, scan_target, port, "tcp", service, "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Sort by timestamp
    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/combined_attack.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/combined_attack.log ({len(lines)} lines)")


def generate_ddos_flood():
    """Generate a DDoS flood log with 600+ lines.

    Plants 300+ connections from 15 different attacker IPs all targeting
    a single destination IP on port 80 within a 10-second burst.
    Background: normal traffic from 6 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    normal_ips = [_random_ip() for _ in range(6)]
    normal_count = random.randint(300, 320)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # DDoS: 15 attacker IPs flooding one target
    attack_start = base_time + random.uniform(600, 2400)
    target_ip = "10.50.1.100"
    attacker_ips = [_random_ip() for _ in range(15)]

    for _ in range(320):
        ts = attack_start + random.uniform(0, 10.0)
        src_ip = random.choice(attacker_ips)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.1)
        bytes_sent = random.randint(40, 200)
        bytes_recv = 0
        pkts_sent = random.randint(1, 3)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, src_ip, src_port, target_ip, 80, "tcp", "http", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/ddos_flood.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/ddos_flood.log ({len(lines)} lines)")


def generate_slow_scan():
    """Generate a slow/stealthy port scan log with 500+ lines.

    Plants IP 172.16.5.10 scanning 30 unique ports over 30 minutes
    (~1 port every 60 seconds). This is designed to evade detection
    windows that only look at 60-second intervals.
    Background: normal traffic from 8 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    normal_ips = [_random_ip() for _ in range(8)]
    normal_count = random.randint(480, 510)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # Slow scan: 30 ports over 30 minutes
    scan_start = base_time + 300.0
    scanner_ip = "172.16.5.10"
    target_ip = _random_ip()
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                  993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
                  8080, 8443, 9090, 9200, 11211, 27017, 28017, 50000, 61616]

    for i, port in enumerate(scan_ports):
        # Spread over 30 minutes with some jitter
        ts = scan_start + (i * 60.0) + random.uniform(-5, 5)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.2)
        bytes_sent = random.randint(0, 60)
        bytes_recv = 0
        pkts_sent = random.randint(1, 2)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, scanner_ip, src_port, target_ip, port, "tcp", "-", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/slow_scan.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/slow_scan.log ({len(lines)} lines)")


def generate_data_exfiltration():
    """Generate a data exfiltration log with 500+ lines.

    Plants IP 192.168.10.55 making 20 connections to a single external IP,
    each transferring 50-200KB outbound (total ~2MB exfiltrated).
    Uses port 443 (SSL) to look like normal HTTPS traffic.
    Background: normal traffic from 8 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    normal_ips = [_random_ip() for _ in range(8)]
    normal_count = random.randint(480, 510)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # Data exfiltration: large outbound transfers
    exfil_start = base_time + random.uniform(600, 2400)
    insider_ip = "192.168.10.55"
    exfil_target = "203.0.113.42"  # "External" IP from documentation range

    for i in range(20):
        ts = exfil_start + (i * random.uniform(30, 90))
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(2.0, 15.0)
        # Massive outbound bytes (50KB-200KB per connection)
        bytes_sent = random.randint(50000, 200000)
        bytes_recv = random.randint(500, 3000)  # Small response
        pkts_sent = random.randint(50, 200)
        pkts_recv = random.randint(10, 30)

        lines.append(_format_line(ts, conn_id, insider_ip, src_port, exfil_target, 443, "tcp", "ssl", "SF", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/data_exfiltration.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/data_exfiltration.log ({len(lines)} lines)")


def generate_multi_attacker():
    """Generate a multi-attacker coordinated assault log with 700+ lines.

    Plants 3 simultaneous attackers:
    - 192.168.1.99 brute forcing RDP (port 3389, 50 attempts over 60s)
    - 10.0.0.77 scanning 25 ports within 40 seconds
    - 172.16.3.200 + 4 other IPs DDoS flooding port 443 (100 connections in 8s)
    Background: normal traffic from 8 IPs over 1 hour.
    """
    base_time = time.time() - 3600
    one_hour = 3600.0

    normal_ips = [_random_ip() for _ in range(8)]
    normal_count = random.randint(450, 480)
    lines = _normal_traffic_lines(normal_count, base_time, one_hour, normal_ips)

    # Attack 1: RDP brute force at 15 minute mark
    brute_start = base_time + 900.0
    brute_ip = "192.168.1.99"
    rdp_target = _random_ip()

    for _ in range(50):
        ts = brute_start + random.uniform(0, 60.0)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.3)
        bytes_sent = random.randint(0, 80)
        bytes_recv = 0
        pkts_sent = random.randint(1, 3)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, brute_ip, src_port, rdp_target, 3389, "tcp", "-", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Attack 2: Port scan at 16 minute mark
    scan_start = base_time + 960.0
    scanner_ip = "10.0.0.77"
    scan_target = _random_ip()
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
                  3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
                  27017, 1433, 143, 993, 995, 11211]

    for port in scan_ports:
        ts = scan_start + random.uniform(0, 40.0)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.2)
        bytes_sent = random.randint(0, 60)
        bytes_recv = 0
        pkts_sent = random.randint(1, 2)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, scanner_ip, src_port, scan_target, port, "tcp", "-", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    # Attack 3: Mini DDoS at 17 minute mark
    ddos_start = base_time + 1020.0
    ddos_ips = ["172.16.3.200"] + [_random_ip() for _ in range(4)]
    ddos_target = _random_ip()

    for _ in range(100):
        ts = ddos_start + random.uniform(0, 8.0)
        src_ip = random.choice(ddos_ips)
        src_port = random.randint(1024, 65535)
        conn_id = _random_conn_id()
        dur = random.uniform(0.0, 0.05)
        bytes_sent = random.randint(40, 150)
        bytes_recv = 0
        pkts_sent = random.randint(1, 2)
        pkts_recv = 0

        lines.append(_format_line(ts, conn_id, src_ip, src_port, ddos_target, 443, "tcp", "ssl", "S0", dur, bytes_sent, bytes_recv, pkts_sent, pkts_recv))

    lines.sort(key=lambda l: float(l.split('\t')[0]))

    os.makedirs("sample_logs", exist_ok=True)
    with open("sample_logs/multi_attacker.log", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Written sample_logs/multi_attacker.log ({len(lines)} lines)")


if __name__ == "__main__":
    generate_brute_force()
    generate_port_scan()
    generate_normal_traffic()
    generate_combined_attack()
    generate_ddos_flood()
    generate_slow_scan()
    generate_data_exfiltration()
    generate_multi_attacker()
    print("\nAll log files generated successfully.")

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


if __name__ == "__main__":
    generate_brute_force()
    generate_port_scan()
    generate_normal_traffic()
    print("\nAll log files generated successfully.")

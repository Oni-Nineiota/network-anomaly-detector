import random
from datetime import datetime, timedelta

def generate_brute_force():
    lines = []
    attack_ip = "192.168.1.45"
    normal_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "172.16.0.5"]
    start_time = datetime(2024, 1, 15, 10, 23, 0)
    
    # 60 failed SSH attempts from one IP in 90 seconds
    for i in range(60):
        ts = start_time + timedelta(seconds=i * 1.5)
        unix_ts = ts.timestamp()
        line = f"{unix_ts:.6f}\tConn{i:04d}\t{attack_ip}\t{random.randint(49152,65535)}\t10.0.0.1\t22\ttcp\tssh\tS0\t-\t0\t0\t1\t52"
        lines.append((unix_ts, line))
    
    # Normal traffic mixed in
    for i in range(30):
        ts = start_time + timedelta(seconds=random.randint(0, 90))
        unix_ts = ts.timestamp()
        ip = random.choice(normal_ips)
        line = f"{unix_ts:.6f}\tConn{i+100:04d}\t{ip}\t{random.randint(49152,65535)}\t10.0.0.1\t80\ttcp\thttp\tSF\t0.5\t500\t1200\t5\t6"
        lines.append((unix_ts, line))
    
    lines.sort()
    return "\n".join(l for _, l in lines)

def generate_port_scan():
    lines = []
    attacker_ip = "10.0.0.23"
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 6379, 8080, 8443, 9200, 27017, 5432]
    start_time = datetime(2024, 1, 15, 14, 10, 0)
    
    # Hit 20 different ports in 45 seconds
    for i, port in enumerate(ports):
        ts = start_time + timedelta(seconds=i * 2.2)
        unix_ts = ts.timestamp()
        line = f"{unix_ts:.6f}\tConn{i:04d}\t{attacker_ip}\t{random.randint(49152,65535)}\t192.168.1.100\t{port}\ttcp\t-\tS0\t-\t0\t0\t1\t40"
        lines.append((unix_ts, line))
    
    # Normal traffic mixed in
    normal_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    for i in range(20):
        ts = start_time + timedelta(seconds=random.randint(0, 45))
        unix_ts = ts.timestamp()
        ip = random.choice(normal_ips)
        line = f"{unix_ts:.6f}\tConn{i+100:04d}\t{ip}\t{random.randint(49152,65535)}\t192.168.1.100\t80\ttcp\thttp\tSF\t0.3\t300\t900\t4\t5"
        lines.append((unix_ts, line))
    
    lines.sort()
    return "\n".join(l for _, l in lines)

def generate_normal_traffic():
    lines = []
    ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]
    services = [("80", "http"), ("443", "https"), ("53", "dns"), ("25", "smtp")]
    start_time = datetime(2024, 1, 15, 9, 0, 0)
    
    for i in range(100):
        ts = start_time + timedelta(seconds=random.randint(0, 3600))
        unix_ts = ts.timestamp()
        ip = random.choice(ips)
        port, service = random.choice(services)
        line = f"{unix_ts:.6f}\tConn{i:04d}\t{ip}\t{random.randint(49152,65535)}\t8.8.8.8\t{port}\ttcp\t{service}\tSF\t{random.uniform(0.1,2.0):.1f}\t{random.randint(100,1000)}\t{random.randint(200,2000)}\t{random.randint(3,10)}\t{random.randint(3,10)}"
        lines.append((unix_ts, line))
    
    lines.sort()
    return "\n".join(l for _, l in lines)

if __name__ == "__main__":
    with open("sample_logs/brute_force.log", "w") as f:
        f.write(generate_brute_force())
    print("Generated brute_force.log")
    
    with open("sample_logs/port_scan.log", "w") as f:
        f.write(generate_port_scan())
    print("Generated port_scan.log")
    
    with open("sample_logs/normal_traffic.log", "w") as f:
        f.write(generate_normal_traffic())
    print("Generated normal_traffic.log")
    
    print("All sample logs generated.")
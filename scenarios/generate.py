import json
import random
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def write_syslog(path, host, tz_offset, clock_skew, entries, malformed=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for dt, proc, msg in entries:
        local_dt = dt + timedelta(seconds=tz_offset + clock_skew)
        ts = local_dt.strftime("%b %e %H:%M:%S").replace(" 0", "  ")
        lines.append(f"{ts} {host} {proc}: {msg}\n")
    if malformed:
        for m in malformed:
            lines.insert(random.randint(0, len(lines)), m + "\n")
    with open(path, 'w') as f:
        f.writelines(lines)

def write_nginx(path, clock_skew, tz_str, entries, malformed=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for dt, ip, method, req_path, status, ua in entries:
        local_dt = dt + timedelta(seconds=clock_skew)
        ts = local_dt.strftime("%d/%b/%Y:%H:%M:%S")
        lines.append(f"{ip} - - [{ts} {tz_str}] \"{method} {req_path} HTTP/1.1\" {status} 512 \"-\" \"{ua}\"\n")
    if malformed:
        for m in malformed:
            lines.insert(random.randint(0, len(lines)), m + "\n")
    with open(path, 'w') as f:
        f.writelines(lines)

def get_utc(dt_str):
    return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

def generate_s1():
    base = Path("scenarios/s1_ssh_bruteforce")
    base.mkdir(parents=True, exist_ok=True)
    
    entries = []
    start_time = get_utc("2026-10-03T02:14:07Z")
    
    # Noise
    for i in range(100):
        dt = start_time - timedelta(minutes=random.randint(10, 60))
        entries.append((dt, "sshd[100]", "Accepted publickey for alice from 198.51.100.10 port 50000 ssh2"))
    
    # Attack steps
    for i in range(150):
        dt = start_time + timedelta(seconds=i*2)
        user = random.choice(["root", "admin", "test", "oracle"])
        msg = f"Failed password for invalid user {user} from 203.0.113.50 port 51122 ssh2"
        entries.append((dt, "sshd[1234]", msg))
        
    entries.append((get_utc("2026-10-03T02:19:51Z"), "sshd[1234]", "Accepted password for deploy from 203.0.113.50 port 51122 ssh2"))
    entries.append((get_utc("2026-10-03T02:20:30Z"), "sshd[1234]", "pam_unix(sshd:session): session opened for user deploy"))
    entries.append((get_utc("2026-10-03T02:22:12Z"), "sudo", "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"))
    entries.append((get_utc("2026-10-03T02:24:40Z"), "useradd", "new user: name=support"))
    entries.append((get_utc("2026-10-03T02:31:05Z"), "sshd[1234]", "pam_unix(sshd:session): session closed for user deploy"))
    
    entries.sort(key=lambda x: x[0])
    
    malformed = [
        "Oct  3 02:15:00 web01 sshd[1]: Truncated line",
        "\x00\x01\x02garbled binary",
        "Feb 30 02:15:00 web01 sshd[1]: Bad date",
        "Just some random text not matching syslog"
    ]
    
    write_syslog(base / "auth.log", "web01", 0, 0, entries, malformed)
    
    sources = {
        "case_id": "s1_ssh_bruteforce",
        "year_hint": 2026,
        "reference_host": "web01",
        "sources": [{"path": "auth.log", "host": "web01", "source_type": "auth_log", "declared_tz": "UTC"}]
    }
    write_json(base / "sources.json", sources)
    
    gt = {
        "case_id": "s1_ssh_bruteforce",
        "attacker_ips": ["203.0.113.50"],
        "steps": [
            {"id": "S1-01", "ts_utc": "2026-10-03T02:14:07Z", "host": "web01", "event_type": "ssh_failed_login", "match": {"src_ip": "203.0.113.50"}, "description": "First brute-force attempt"},
            {"id": "S1-02", "ts_utc": "2026-10-03T02:19:51Z", "host": "web01", "event_type": "ssh_accepted_login", "match": {"src_ip": "203.0.113.50", "username": "deploy"}, "description": "First successful login (the answer to 'when did they get in?')"}
        ],
        "triage_questions": [
            {"q": "When did the attacker first successfully log in (UTC)?", "answer": "2026-10-03T02:19:51Z"},
            {"q": "Which source IP?", "answer": "203.0.113.50"},
            {"q": "What was the first privileged command run?", "answer": "sudo /bin/bash"}
        ],
        "expected_parse_gaps": 4,
        "expected_skew": {}
    }
    write_json(base / "ground_truth.json", gt)

def generate_s2():
    base = Path("scenarios/s2_web_attack")
    base.mkdir(parents=True, exist_ok=True)
    
    entries = []
    start_time = get_utc("2026-10-05T14:02:10Z")
    
    # Noise
    for i in range(100):
        dt = start_time - timedelta(minutes=random.randint(10, 60))
        entries.append((dt, "198.51.100.20", "GET", "/index.html", "200", "Mozilla/5.0"))
        
    # Attack
    entries.append((get_utc("2026-10-05T14:02:10Z"), "203.0.113.77", "GET", "/wp-login.php", "404", "Nikto"))
    entries.append((get_utc("2026-10-05T14:09:33Z"), "203.0.113.77", "GET", "/products.php?id=1%27%20UNION%20SELECT", "200", "Nikto"))
    entries.append((get_utc("2026-10-05T14:14:02Z"), "203.0.113.77", "GET", "/download?file=../../etc/passwd", "200", "Nikto"))
    entries.append((get_utc("2026-10-05T14:18:47Z"), "203.0.113.77", "POST", "/upload.php", "200", "Nikto"))
    entries.append((get_utc("2026-10-05T14:20:15Z"), "203.0.113.77", "GET", "/uploads/shell.php?cmd=id", "200", "Nikto"))
    entries.append((get_utc("2026-10-05T14:27:40Z"), "203.0.113.77", "GET", "/admin", "404", "Nikto"))
    
    entries.sort(key=lambda x: x[0])
    
    malformed = [
        "203.0.113.77 - - [05/Oct/2026:14:00:00 +0000] \"GET / HTTP/1.1",
        "203.0.113.77 - - [BadDate] \"GET / HTTP/1.1\" 200 512 \"-\" \"-\"",
        "203.0.113.77 - - [05/Oct/2026:14:00:00 +0000] GET / HTTP/1.1 200 512 - -",
        "Oct  5 14:00:00 web01 wrong format",
        ""
    ]
    
    write_nginx(base / "access.log", 0, "+0000", entries, malformed)
    
    sources = {
        "case_id": "s2_web_attack",
        "year_hint": 2026,
        "reference_host": "web01",
        "sources": [{"path": "access.log", "host": "web01", "source_type": "nginx", "declared_tz": "UTC"}]
    }
    write_json(base / "sources.json", sources)
    
    gt = {
        "case_id": "s2_web_attack",
        "attacker_ips": ["203.0.113.77"],
        "steps": [
            {"id": "S2-01", "ts_utc": "2026-10-05T14:02:10Z", "host": "web01", "event_type": "web_scan", "match": {"src_ip": "203.0.113.77"}, "description": "Scanner probe"}
        ],
        "triage_questions": [
            {"q": "When did the attacker first successfully log in (UTC)?", "answer": "N/A"},
            {"q": "Which source IP?", "answer": "203.0.113.77"},
            {"q": "What was the first privileged command run?", "answer": "N/A"}
        ],
        "expected_parse_gaps": 5,
        "expected_skew": {}
    }
    write_json(base / "ground_truth.json", gt)

def generate_s3():
    base = Path("scenarios/s3_clock_skew")
    base.mkdir(parents=True, exist_ok=True)
    
    web_nginx, web_auth = [], []
    db_nginx, db_auth = [], []
    
    # S3 Anchors
    start_time = get_utc("2026-10-08T09:00:00Z")
    paths = ["/admin", "/backup.sql", "/server-status", "/info.php", "/test", "/config", "/db", "/logs", "/metrics", "/api"]
    for i, p in enumerate(paths):
        dt = start_time + timedelta(seconds=i*2)
        web_nginx.append((dt, "203.0.113.90", "GET", p, "404", "Scanner"))
        db_nginx.append((dt + timedelta(seconds=random.randint(0, 2)), "203.0.113.90", "GET", p, "404", "Scanner"))
        
    web_nginx.append((get_utc("2026-10-08T09:05:30Z"), "203.0.113.90", "GET", "/search.php?q='UNION", "200", "Scanner"))
    web_nginx.append((get_utc("2026-10-08T09:08:12Z"), "203.0.113.90", "GET", "/shell.php", "200", "Scanner"))
    
    db_auth.append((get_utc("2026-10-08T09:12:45Z"), "sshd[1234]", "Accepted password for dbadmin from 192.0.2.10 port 51122 ssh2"))
    db_auth.append((get_utc("2026-10-08T09:14:03Z"), "sudo", "dbadmin : TTY=pts/0 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/bin/bash"))
    db_nginx.append((get_utc("2026-10-08T09:15:30Z"), "203.0.113.90", "GET", "/export.php", "200", "Scanner"))
    
    write_nginx(base / "web01" / "access.log", 0, "+0000", web_nginx)
    write_syslog(base / "web01" / "auth.log", "web01", 0, 0, web_auth)
    
    # db01 runs 7 min fast (420s)
    # Asia/Kolkata is UTC+5:30 (19800s)
    write_nginx(base / "db01" / "access.log", 420, "+0000", db_nginx)
    write_syslog(base / "db01" / "auth.log", "db01", 19800, 420, db_auth)
    
    sources = {
        "case_id": "s3_clock_skew",
        "year_hint": 2026,
        "reference_host": "web01",
        "sources": [
            {"path": "web01/auth.log", "host": "web01", "source_type": "auth_log", "declared_tz": "UTC"},
            {"path": "web01/access.log", "host": "web01", "source_type": "nginx", "declared_tz": "UTC"},
            {"path": "db01/auth.log", "host": "db01", "source_type": "auth_log", "declared_tz": "Asia/Kolkata"},
            {"path": "db01/access.log", "host": "db01", "source_type": "nginx", "declared_tz": "UTC"}
        ]
    }
    write_json(base / "sources.json", sources)
    
    gt = {
        "case_id": "s3_clock_skew",
        "attacker_ips": ["203.0.113.90"],
        "steps": [
            {"id": "S3-04", "ts_utc": "2026-10-08T09:12:45Z", "host": "db01", "event_type": "ssh_accepted_login", "match": {"src_ip": "192.0.2.10", "username": "dbadmin"}, "description": "Pivot to DB"}
        ],
        "triage_questions": [
            {"q": "When did the attacker first successfully log in (UTC)?", "answer": "2026-10-08T09:12:45Z"},
            {"q": "Which source IP?", "answer": "203.0.113.90"},
            {"q": "Which happened first: web01 webshell or db01 login?", "answer": "web01 webshell"}
        ],
        "expected_parse_gaps": 0,
        "expected_skew": {"db01": -420}
    }
    write_json(base / "ground_truth.json", gt)

if __name__ == "__main__":
    generate_s1()
    generate_s2()
    generate_s3()
    print("Scenarios generated successfully.")

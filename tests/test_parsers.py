import pytest
from forensic.parsers.auth_log import AuthLogParser
from forensic.parsers.nginx import NginxParser
from forensic.models import ParseContext, Event, ParseGap

def test_auth_log_ssh_failed():
    parser = AuthLogParser()
    ctx = ParseContext("web01", "auth_log", "UTC", 2026)
    line = "Oct  3 02:14:07 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 51122 ssh2"
    
    res = parser.parse_line(line, 1, 0, ctx)
    assert isinstance(res, Event)
    assert res.event_type == "ssh_invalid_user"
    assert res.username == "admin"
    assert res.src_ip == "203.0.113.50"
    
def test_auth_log_sudo():
    parser = AuthLogParser()
    ctx = ParseContext("web01", "auth_log", "UTC", 2026)
    line = "Oct  3 02:15:00 web01 sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    
    res = parser.parse_line(line, 1, 0, ctx)
    assert isinstance(res, Event)
    assert res.event_type == "sudo_command"
    assert res.username == "deploy"
    assert res.severity == "high"
    
def test_nginx_sqli():
    parser = NginxParser()
    ctx = ParseContext("web01", "nginx", "UTC", 2026)
    line = '203.0.113.50 - - [03/Oct/2026:02:30:11 +0000] "GET /index.php?id=1%27%20UNION%20SELECT%201,2 HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
    
    res = parser.parse_line(line, 1, 0, ctx)
    assert isinstance(res, Event)
    assert res.event_type == "web_sqli_attempt"
    assert res.severity == "high"
    assert res.src_ip == "203.0.113.50"

def test_nginx_truncated():
    parser = NginxParser()
    ctx = ParseContext("web01", "nginx", "UTC", 2026)
    line = '203.0.113.50 - - [03/Oct/2026:02:30:11 +0000] "GET /index.php'
    
    res = parser.parse_line(line, 1, 0, ctx)
    assert isinstance(res, ParseGap)
    assert res.reason == "truncated"

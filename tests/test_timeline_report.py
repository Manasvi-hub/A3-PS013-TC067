import pytest
import sqlite3
import json
import csv
from pathlib import Path
from forensic.timeline import Filters, query_events, summary_stats, gap_summary
from forensic.report import generate_report

def test_timeline_filters(tmp_path):
    db_path = tmp_path / "case.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, host TEXT, event_type TEXT, severity TEXT, src_ip TEXT, username TEXT, ts_utc_corrected TEXT, ts_utc TEXT, ts_original TEXT, message TEXT, evidence_id INTEGER, line_no INTEGER, byte_offset INTEGER)")
    conn.execute("CREATE VIRTUAL TABLE events_fts USING fts5(message, content='events', content_rowid='id')")
    
    conn.execute("INSERT INTO events (host, event_type, severity, src_ip, ts_utc_corrected, message) VALUES ('web01', 'web_request', 'low', '10.0.0.1', '2026-10-01T12:00:00Z', 'normal request')")
    conn.execute("INSERT INTO events_fts (rowid, message) VALUES (last_insert_rowid(), 'normal request')")
    
    conn.execute("INSERT INTO events (host, event_type, severity, src_ip, ts_utc_corrected, message) VALUES ('db01', 'ssh_failed_login', 'high', '10.0.0.2', '2026-10-01T12:05:00Z', 'attack '' quote')")
    conn.execute("INSERT INTO events_fts (rowid, message) VALUES (last_insert_rowid(), 'attack '' quote')")
    conn.commit()
    
    events = query_events(conn, Filters(hosts=["web01"]))
    assert len(events) == 1
    
    # FTS with quotes should not raise
    events = query_events(conn, Filters(text="attack ' quote"))
    assert len(events) == 1
    
    events = query_events(conn, Filters(text='attack " quote'))
    assert len(events) == 0

def test_report_generation(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    db_path = case_dir / "case.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, host TEXT, event_type TEXT, severity TEXT, src_ip TEXT, username TEXT, ts_utc_corrected TEXT, ts_utc TEXT, ts_original TEXT, message TEXT, evidence_id INTEGER, line_no INTEGER, byte_offset INTEGER)")
    conn.execute("CREATE VIRTUAL TABLE events_fts USING fts5(message, content='events', content_rowid='id')")
    conn.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, filename TEXT, host TEXT, source_type TEXT, line_count INTEGER, sha256 TEXT)")
    conn.execute("CREATE TABLE parse_gaps (id INTEGER PRIMARY KEY, evidence_id INTEGER, reason TEXT, raw_line TEXT, line_no INTEGER)")
    conn.execute("CREATE TABLE skew_corrections (host TEXT, offset_s INTEGER)")
    conn.commit()
    conn.close()
    
    out_html = tmp_path / "report.html"
    out_json = tmp_path / "report.json"
    out_csv = tmp_path / "report.csv"
    
    generate_report(case_dir, out_html, out_json, out_csv)
    
    assert out_html.exists()
    html = out_html.read_text()
    assert "1. Case Summary" in html
    assert "Limitations & scope:" in html
    
    assert out_json.exists()
    j = json.loads(out_json.read_text())
    assert "summary" in j
    assert "limitations" in j
    
    assert out_csv.exists()
    with open(out_csv, newline='') as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header[0] == "ts_utc_corrected"

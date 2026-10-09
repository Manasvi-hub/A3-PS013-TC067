import sqlite3
from dataclasses import dataclass
from typing import Optional, List, Dict
from datetime import datetime, timedelta

@dataclass
class Filters:
    hosts: Optional[List[str]] = None
    source_types: Optional[List[str]] = None
    event_types: Optional[List[str]] = None
    severities: Optional[List[str]] = None
    src_ip: Optional[str] = None
    username: Optional[str] = None
    ts_from: Optional[str] = None
    ts_to: Optional[str] = None
    text: Optional[str] = None
    use_corrected: bool = True

def query_events(conn: sqlite3.Connection, f: Filters, limit: int = 5000, offset: int = 0) -> List[dict]:
    query = "SELECT events.* FROM events "
    params = []
    
    if f.text:
        query += " JOIN events_fts ON events.id = events_fts.rowid "
        
    conditions = []
    
    if f.text:
        safe_text = f.text.replace('"', '""')
        conditions.append("events_fts MATCH ?")
        params.append(f'"{safe_text}"')
        
    if f.hosts:
        conditions.append(f"events.host IN ({','.join(['?']*len(f.hosts))})")
        params.extend(f.hosts)
        
    if f.source_types:
        conditions.append(f"events.source_type IN ({','.join(['?']*len(f.source_types))})")
        params.extend(f.source_types)

    if f.event_types:
        conditions.append(f"events.event_type IN ({','.join(['?']*len(f.event_types))})")
        params.extend(f.event_types)
        
    if f.severities:
        conditions.append(f"events.severity IN ({','.join(['?']*len(f.severities))})")
        params.extend(f.severities)
        
    if f.src_ip:
        conditions.append("events.src_ip = ?")
        params.append(f.src_ip)
        
    if f.username:
        conditions.append("events.username = ?")
        params.append(f.username)
        
    ts_col = "events.ts_utc_corrected" if f.use_corrected else "events.ts_utc"
    if f.ts_from:
        conditions.append(f"{ts_col} >= ?")
        params.append(f.ts_from)
    if f.ts_to:
        conditions.append(f"{ts_col} <= ?")
        params.append(f.ts_to)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += f" ORDER BY {ts_col} ASC, events.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]

def summary_stats(conn: sqlite3.Connection) -> dict:
    events = conn.execute("SELECT host, event_type, severity, src_ip FROM events").fetchall()
    if not events:
        return {}
    
    by_type = {}
    by_sev = {}
    by_host = {}
    ips = {}
    for r in events:
        by_type[r["event_type"]] = by_type.get(r["event_type"], 0) + 1
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        by_host[r["host"]] = by_host.get(r["host"], 0) + 1
        if r["src_ip"]:
            ips[r["src_ip"]] = ips.get(r["src_ip"], 0) + 1
            
    top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
    
    first = conn.execute("SELECT ts_utc_corrected FROM events ORDER BY ts_utc_corrected ASC LIMIT 1").fetchone()
    last = conn.execute("SELECT ts_utc_corrected FROM events ORDER BY ts_utc_corrected DESC LIMIT 1").fetchone()
    
    ev_files = conn.execute("SELECT COUNT(*) as c FROM evidence").fetchone()["c"]
    gaps = conn.execute("SELECT COUNT(*) as c FROM parse_gaps").fetchone()["c"]
    
    return {
        "total_events": len(events),
        "hosts": list(by_host.keys()),
        "first_event": first["ts_utc_corrected"] if first else None,
        "last_event": last["ts_utc_corrected"] if last else None,
        "by_type": by_type,
        "by_severity": by_sev,
        "by_host": by_host,
        "top_src_ips": top_ips,
        "evidence_files": ev_files,
        "total_gaps": gaps
    }

def gap_summary(conn: sqlite3.Connection) -> List[dict]:
    res = []
    evs = conn.execute("SELECT id, filename, host, line_count FROM evidence").fetchall()
    for ev in evs:
        eid = ev["id"]
        parsed = conn.execute("SELECT COUNT(*) as c FROM events WHERE evidence_id = ?", (eid,)).fetchone()["c"]
        gaps = conn.execute("SELECT reason, COUNT(*) as c FROM parse_gaps WHERE evidence_id = ? GROUP BY reason", (eid,)).fetchall()
        
        reasons = {g["reason"]: g["c"] for g in gaps}
        blank_lines = reasons.get("empty_line", 0)
        total = ev["line_count"] or 0
        
        pct = 0
        if total - blank_lines > 0:
            pct = parsed / (total - blank_lines) * 100
            
        res.append({
            "evidence_id": eid,
            "filename": ev["filename"],
            "host": ev["host"],
            "total_lines": total,
            "blank_lines": blank_lines,
            "parsed": parsed,
            "gaps": sum(reasons.values()),
            "parsed_pct": pct,
            "reasons": reasons
        })
    return res

def key_events(conn: sqlite3.Connection) -> List[dict]:
    high_med = conn.execute("SELECT * FROM events WHERE severity IN ('high', 'medium')").fetchall()
    
    others = []
    ips = conn.execute("SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL").fetchall()
    for ip_row in ips:
        ip = ip_row["src_ip"]
        ssh = conn.execute("SELECT * FROM events WHERE src_ip = ? AND event_type = 'ssh_accepted_login' ORDER BY ts_utc_corrected ASC LIMIT 1", (ip,)).fetchone()
        if ssh: others.append(ssh)
        
        web = conn.execute("SELECT * FROM events WHERE src_ip = ? AND event_type LIKE 'web_%' AND event_type != 'web_request' ORDER BY ts_utc_corrected ASC LIMIT 1", (ip,)).fetchone()
        if web: others.append(web)
        
    combined = {r["id"]: dict(r) for r in high_med + others}
    return sorted(combined.values(), key=lambda x: x["ts_utc_corrected"])

def skew_summary(conn: sqlite3.Connection) -> List[dict]:
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM skew_corrections").fetchall()]
    except sqlite3.OperationalError:
        return []

def evidence_manifest(conn: sqlite3.Connection) -> List[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM evidence").fetchall()]

def context_window(conn: sqlite3.Connection, event_id: int, seconds: int = 60) -> List[dict]:
    row = conn.execute("SELECT ts_utc_corrected FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return []
        
    ts_str = row["ts_utc_corrected"].replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(ts_str)
    except ValueError:
        return []
        
    start = (ts - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end = (ts + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    rows = conn.execute("SELECT * FROM events WHERE ts_utc_corrected >= ? AND ts_utc_corrected <= ? ORDER BY ts_utc_corrected ASC", (start, end)).fetchall()
    return [dict(r) for r in rows]

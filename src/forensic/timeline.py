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
    ts_from: Optional[str] = None      # ISO UTC
    ts_to: Optional[str] = None
    text: Optional[str] = None         # FTS query
    use_corrected: bool = True

def query_events(conn: sqlite3.Connection, f: Filters, limit=5000, offset=0) -> List[sqlite3.Row]:
    query = "SELECT events.* FROM events "
    params = []
    
    if f.text:
        query += " JOIN events_fts ON events.id = events_fts.rowid "
    
    conditions = []
    
    if f.text:
        sanitized = f.text.replace('"', '""')
        conditions.append(f"events_fts MATCH '\"{sanitized}\"'")
        
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
    
    return conn.execute(query, params).fetchall()

def context_window(conn: sqlite3.Connection, event_id: int, seconds=60) -> List[sqlite3.Row]:
    row = conn.execute("SELECT ts_utc_corrected FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row: return []
    
    ts_str = row["ts_utc_corrected"].replace("Z", "+00:00")
    ts = datetime.fromisoformat(ts_str)
    start = (ts - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = (ts + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.999Z")
    
    return conn.execute("SELECT * FROM events WHERE ts_utc_corrected >= ? AND ts_utc_corrected <= ? ORDER BY ts_utc_corrected", (start, end)).fetchall()

def get_evidence(conn: sqlite3.Connection, evidence_id: int) -> sqlite3.Row:
    return conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()

def summary_stats(conn: sqlite3.Connection) -> dict:
    return {}

def key_events(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM events WHERE severity IN ('high', 'medium') ORDER BY ts_utc_corrected").fetchall()

def gap_summary(conn: sqlite3.Connection) -> List[dict]:
    return []

def skew_summary(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    try:
        return conn.execute("SELECT * FROM skew_corrections").fetchall()
    except sqlite3.OperationalError:
        return []

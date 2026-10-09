import statistics
from datetime import datetime
from pathlib import Path
from . import db

def parse_utc(ts_str: str) -> datetime:
    # ISO-8601 UTC string like "2026-10-08T09:12:44.000Z"
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def skew(case_dir: Path, reference_host: str = None, manual_offset_str: str = None) -> None:
    conn = db.connect(case_dir)
    
    hosts = [row["host"] for row in conn.execute("SELECT DISTINCT host FROM events").fetchall()]
    if not hosts:
        print("No hosts found in events.")
        return
        
    if not reference_host:
        # Pick the first one as reference if not provided
        reference_host = hosts[0]
        
    if reference_host not in hosts:
        print(f"Reference host '{reference_host}' not found in events.")
        return
        
    manual_offsets = {}
    if manual_offset_str:
        # e.g., "db01=-420"
        try:
            parts = manual_offset_str.split("=")
            manual_offsets[parts[0]] = float(parts[1])
        except Exception:
            print("Invalid format for --offset. Use host=seconds, e.g. db01=-420")
            return

    conn.execute("DELETE FROM skew_corrections")
    
    for host in hosts:
        if host == reference_host:
            continue
            
        if host in manual_offsets:
            offset = manual_offsets[host]
            conn.execute(
                "INSERT INTO skew_corrections (host, reference_host, offset_s, method, anchor_count, confidence_note) VALUES (?, ?, ?, ?, ?, ?)",
                (host, reference_host, offset, "manual", 0, "operator supplied")
            )
            apply_offset(conn, host, offset)
            continue
            
        # Anchor-based estimation
        # Eligible keys: (src_ip, event_type, detail_key)
        # For web, detail is path; for ssh, detail might be None but username is there
        # Let's extract anchor eligible events
        # We need events that share src_ip, event_type, and (username or detail)
        # Actually, simpler: join on src_ip AND event_type AND (detail OR username)
        
        # Load host events
        h_events = conn.execute("""
            SELECT id, ts_utc, src_ip, event_type, detail, username 
            FROM events 
            WHERE host = ? AND src_ip IS NOT NULL
        """, (host,)).fetchall()
        
        # Load ref events
        r_events = conn.execute("""
            SELECT id, ts_utc, src_ip, event_type, detail, username 
            FROM events 
            WHERE host = ? AND src_ip IS NOT NULL
        """, (reference_host,)).fetchall()
        
        # Group ref events by key
        r_by_key = {}
        for r in r_events:
            key = (r["src_ip"], r["event_type"], r["detail"], r["username"])
            if key not in r_by_key:
                r_by_key[key] = []
            r_by_key[key].append(r)
            
        anchors = []
        window = 1800 # 30 mins
        max_true_gap = 5
        
        for h in h_events:
            key = (h["src_ip"], h["event_type"], h["detail"], h["username"])
            if key in r_by_key:
                h_ts = parse_utc(h["ts_utc"])
                best_diff = None
                best_r = None
                
                for r in r_by_key[key]:
                    r_ts = parse_utc(r["ts_utc"])
                    diff_s = (r_ts - h_ts).total_seconds()
                    
                    if abs(diff_s) <= window:
                        if best_diff is None or abs(diff_s) < abs(best_diff):
                            best_diff = diff_s
                            best_r = r
                            
                if best_diff is not None:
                    anchors.append(best_diff)
                    
        n = len(anchors)
        if n >= 3:
            offset = statistics.median(anchors)
            stdev = statistics.pstdev(anchors) if n > 1 else 0.0
            
            if stdev < 2 and n >= 5:
                confidence = "high"
            elif stdev < 10:
                confidence = "medium"
            else:
                confidence = "low"
                
            note = f"{n} anchors, median {offset:.1f}s, stdev {stdev:.1f}s ({confidence}). Assumes paired events < {max_true_gap}s apart."
            method = "anchor_median"
            
            conn.execute(
                "INSERT INTO skew_corrections (host, reference_host, offset_s, method, anchor_count, stdev_s, confidence_note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host, reference_host, offset, method, n, stdev, note)
            )
            apply_offset(conn, host, offset)
        else:
            conn.execute(
                "INSERT INTO skew_corrections (host, reference_host, offset_s, method, anchor_count, confidence_note) VALUES (?, ?, ?, ?, ?, ?)",
                (host, reference_host, 0.0, "none", n, "insufficient anchors; no correction applied. Use --offset to set manually.")
            )
            apply_offset(conn, host, 0.0)
            
    conn.commit()
    print("Skew estimation complete.")

def apply_offset(conn, host: str, offset_s: float):
    # Update ts_utc_corrected and skew_offset_s
    # ts_utc is ISO8601. We parse, add offset, and format back.
    # We can do this in Python or SQLite. Doing in Python for simplicity.
    rows = conn.execute("SELECT id, ts_utc FROM events WHERE host = ?", (host,)).fetchall()
    
    updates = []
    for r in rows:
        ts = parse_utc(r["ts_utc"])
        ts_corrected = ts.timestamp() + offset_s
        ts_corrected_dt = datetime.fromtimestamp(ts_corrected, timezone.utc)
        ts_corrected_str = ts_corrected_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        updates.append((offset_s, ts_corrected_str, r["id"]))
        
    conn.executemany("UPDATE events SET skew_offset_s = ?, ts_utc_corrected = ? WHERE id = ?", updates)

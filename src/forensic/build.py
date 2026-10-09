import os
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from . import db
from .models import ParseContext, Event, ParseGap
from .parsers import REGISTRY

def iterate_with_offsets(file_path: Path):
    """Yield (line_no, byte_offset, line_str)"""
    with open(file_path, "rb") as f:
        line_no = 1
        byte_offset = 0
        for line_bytes in f:
            try:
                line_str = line_bytes.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
            
            yield line_no, byte_offset, line_str
            
            line_no += 1
            byte_offset += len(line_bytes)

def build(case_dir: Path) -> None:
    conn = db.connect(case_dir)
    
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM parse_gaps")
    conn.execute("DELETE FROM skew_corrections")
    conn.commit()
    
    meta_row = conn.execute("SELECT value FROM case_meta WHERE key = 'year_hint'").fetchone()
    year_hint = int(meta_row["value"]) if meta_row else None
    
    evidence_rows = conn.execute("SELECT id, filename, stored_path, host, source_type, declared_tz FROM evidence").fetchall()
    
    print(f"{'Evidence ID':<15} | {'Parsed':<10} | {'Gaps':<10} | {'% Parsed':<10}")
    print("-" * 55)
    
    for ev in evidence_rows:
        evidence_id = ev["id"]
        source_type = ev["source_type"]
        stored_path = case_dir / ev["stored_path"]
        
        parser_cls = REGISTRY.get(source_type)
        if not parser_cls:
            print(f"Unknown parser for source_type: {source_type}")
            continue
            
        parser = parser_cls()
        mtime_stamp = stored_path.stat().st_mtime
        mtime_utc = datetime.fromtimestamp(mtime_stamp, timezone.utc)
        
        ctx = ParseContext(
            host=ev["host"],
            source_type=source_type,
            declared_tz=ev["declared_tz"],
            year_hint=year_hint,
            file_mtime_utc=mtime_utc
        )
        
        events = []
        gaps = []
        gap_reasons = defaultdict(int)
        
        for line_no, byte_offset, line in iterate_with_offsets(stored_path):
            if "\ufffd" in line: # from errors="replace"
                gaps.append(ParseGap(line_no, "encoding_error", line))
                gap_reasons["encoding_error"] += 1
                continue
                
            result = parser.parse_line(line, line_no, byte_offset, ctx)
            if isinstance(result, Event):
                events.append(result)
            elif isinstance(result, ParseGap):
                gaps.append(result)
                gap_reasons[result.reason] += 1
                
        db.insert_events(conn, evidence_id, events)
        db.insert_gaps(conn, evidence_id, gaps)
        
        total = len(events) + len(gaps)
        parsed_pct = (len(events) / total * 100) if total > 0 else 0.0
        
        print(f"{evidence_id:<15} | {len(events):<10} | {len(gaps):<10} | {parsed_pct:.1f}%")
        if gaps:
            print(f"  Gap reasons: {dict(gap_reasons)}")
            
    # Rebuild FTS
    conn.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
    conn.commit()
    print("FTS index rebuilt.")
    print("Build complete.")

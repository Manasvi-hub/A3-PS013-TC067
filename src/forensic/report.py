from jinja2 import Environment, FileSystemLoader
import sqlite3
from pathlib import Path
import json
from forensic.timeline import Filters, query_events, key_events, summary_stats

def generate_report(case_dir: Path, out_html: Path, out_json: Path = None, out_csv: Path = None):
    db_path = case_dir / "case.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    events = query_events(conn, Filters())
    key_evs = key_events(conn)
    stats = summary_stats(conn)
    
    # Check if templates exists
    templates_dir = Path("templates")
    if templates_dir.exists():
        env = Environment(loader=FileSystemLoader(str(templates_dir)))
        try:
            template = env.get_template("report.html")
            html_content = template.render(
                case_id=case_dir.name,
                events=events,
                key_events=key_evs,
                stats=stats
            )
        except Exception:
            html_content = f"<html><body><h1>Report for {case_dir.name}</h1></body></html>"
    else:
        html_content = f"<html><body><h1>Report for {case_dir.name}</h1></body></html>"
        
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html_content)
    
    if out_json:
        data = {
            "case_id": case_dir.name,
            "stats": stats,
            "key_events": [dict(r) for r in key_evs]
        }
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(data, indent=2))
        
    if out_csv:
        import csv
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with open(out_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["ts_utc", "host", "event_type", "severity", "src_ip", "username", "message"])
            for e in events:
                writer.writerow([e["ts_utc_corrected"], e["host"], e["event_type"], e["severity"], e["src_ip"], e["username"], e["message"]])

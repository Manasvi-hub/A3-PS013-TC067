import sqlite3
import pandas as pd
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent / "src"))
try:
    from forensic.timeline import gap_summary
except ImportError:
    # If not run from the correct environment
    pass

def generate_gap_report():
    cases_dir = Path(__file__).parent.parent / "cases"
    out_md = Path(__file__).parent / "parsing_gap_analysis.md"
    
    with open(out_md, "w") as f:
        f.write("# Parsing Gap Analysis\n\n")
        
        for case_db in cases_dir.glob("*/case.db"):
            f.write(f"## Case: {case_db.parent.name}\n")
            conn = sqlite3.connect(case_db)
            conn.row_factory = sqlite3.Row
            try:
                gaps = gap_summary(conn)
                if not gaps:
                    f.write("No gaps.\n\n")
                    continue
                    
                df = pd.DataFrame(gaps)
                f.write(df.to_markdown(index=False) + "\n\n")
                
                f.write("### Reasons Breakdown\n")
                for g in gaps:
                    f.write(f"**{g['filename']}**\n")
                    for r, c in g.get("reasons", {}).items():
                        f.write(f"- {r}: {c}\n")
                f.write("\n")
            except Exception as e:
                f.write(f"Error analyzing case: {e}\n\n")
            finally:
                conn.close()
                
        f.write("## Discussion\n")
        f.write("What the tool does not parse: custom application logs, multiline stack traces that break syslog format, non-standard dates.\n")

if __name__ == "__main__":
    generate_gap_report()

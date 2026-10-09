import streamlit as st
import pandas as pd
import sqlite3
import argparse
import sys
from pathlib import Path

# Add src to pythonpath if run directly
sys.path.append(str(Path(__file__).parent.parent / "src"))
from forensic.timeline import query_events, Filters, get_evidence

st.set_page_config(page_title="Forensic Viewer", layout="wide")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default="cases/s1_fake")
    try:
        return parser.parse_args(sys.argv[1:])
    except SystemExit:
        return parser.parse_args([])
        
args = parse_args()
case_dir = Path(args.case)
db_path = case_dir / "case.db"

if not db_path.exists():
    st.error(f"Case database not found: {db_path}")
    st.stop()
    
def get_conn():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

conn = get_conn()

st.title(f"Case Viewer: {case_dir.name}")

st.sidebar.header("Filters")
f_text = st.sidebar.text_input("Search (FTS)")
use_corrected = st.sidebar.checkbox("Use Skew-Corrected Time", value=True)

f = Filters(text=f_text if f_text else None, use_corrected=use_corrected)
events = query_events(conn, f)

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Timeline", "Event Detail", "Evidence", "Parsing Gaps", "Clock Skew"])

with tab1:
    st.subheader("Event Timeline")
    if not events:
        st.write("No events match the filters.")
    else:
        df = pd.DataFrame([dict(r) for r in events])
        st.dataframe(df[["ts_utc_corrected", "host", "event_type", "severity", "src_ip", "message"]])

with tab2:
    st.subheader("Event Detail")
    if events:
        selected_idx = st.selectbox("Select Event ID", [r["id"] for r in events])
        if selected_idx:
            ev = next((r for r in events if r["id"] == selected_idx), None)
            if ev:
                st.json(dict(ev))
                evidence = get_evidence(conn, ev["evidence_id"])
                if evidence:
                    st.write(f"**Evidence Hash**: {evidence['sha256']}")
    
with tab3:
    st.subheader("Evidence Manifest")
    evs = conn.execute("SELECT * FROM evidence").fetchall()
    st.dataframe(pd.DataFrame([dict(r) for r in evs]))
    
with tab4:
    st.subheader("Parsing Gaps")
    try:
        gaps = conn.execute("SELECT * FROM parse_gaps").fetchall()
        st.dataframe(pd.DataFrame([dict(r) for r in gaps]))
    except sqlite3.OperationalError:
        st.write("No parse_gaps table.")
        
with tab5:
    st.subheader("Clock Skew")
    try:
        skews = conn.execute("SELECT * FROM skew_corrections").fetchall()
        st.dataframe(pd.DataFrame([dict(r) for r in skews]))
    except sqlite3.OperationalError:
        st.write("No skew_corrections table.")

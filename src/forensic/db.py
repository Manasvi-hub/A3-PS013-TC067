import sqlite3
from pathlib import Path

from forensic.models import Event, ParseGap


def connect(case_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(case_dir / "case.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_schema(conn: sqlite3.Connection) -> None:
    pass

def insert_evidence(conn: sqlite3.Connection, **fields) -> int:
    pass

def insert_events(conn: sqlite3.Connection, evidence_id: int, events: list[Event]) -> None:
    pass

def insert_gaps(conn: sqlite3.Connection, evidence_id: int, gaps: list[ParseGap]) -> None:
    pass

def rebuild_fts(conn: sqlite3.Connection) -> None:
    pass

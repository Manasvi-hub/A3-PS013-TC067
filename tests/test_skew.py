import pytest
from forensic.skew import parse_utc
from datetime import datetime, timezone

def test_parse_utc():
    ts = "2026-10-08T09:12:44.000Z"
    dt = parse_utc(ts)
    assert dt == datetime(2026, 10, 8, 9, 12, 44, tzinfo=timezone.utc)
    
# Advanced skew tests would require a seeded database with events

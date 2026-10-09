import pytest
from datetime import datetime, timezone
from forensic.models import ParseContext
from forensic.normalize import syslog_to_utc

def test_syslog_to_utc_with_year_hint():
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    
    # Oct 3 02:14:07
    dt, new_year = syslog_to_utc("Oct  3 02:14:07", ctx, None, None)
    assert dt == datetime(2026, 10, 3, 2, 14, 7, tzinfo=timezone.utc)
    assert new_year == 2026

def test_syslog_to_utc_rollover():
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    
    dt1, year1 = syslog_to_utc("Dec 31 23:59:59", ctx, None, None)
    assert dt1.year == 2026
    
    dt2, year2 = syslog_to_utc("Jan  1 00:00:01", ctx, datetime(1900, 12, 31), year1)
    assert dt2.year == 2027
    assert year2 == 2027

def test_syslog_to_utc_invalid():
    ctx = ParseContext(host="test", source_type="auth_log", declared_tz="UTC", year_hint=2026)
    with pytest.raises(ValueError):
        syslog_to_utc("Feb 30 12:00:00", ctx, None, None)

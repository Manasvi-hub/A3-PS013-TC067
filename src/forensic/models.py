from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ParseContext:
    host: str
    source_type: str          # 'auth_log' | 'nginx'
    declared_tz: str          # IANA tz, e.g. "Asia/Kolkata"
    year_hint: int            # used for syslog lines that have no year
    file_mtime_utc: datetime | None = None   # fallback for year inference

@dataclass
class Event:
    line_no: int
    byte_offset: int
    ts_original: str
    ts_utc: datetime          # tz-aware UTC
    host: str
    source_type: str
    event_type: str
    severity: str = "info"
    src_ip: str | None = None
    username: str | None = None
    detail: str | None = None
    message: str = ""
    raw_line: str = ""

@dataclass
class ParseGap:
    line_no: int
    reason: str               # see parse_gaps.reason vocabulary
    raw_line: str

# Every parser implements:
class LineParser:
    def parse_line(self, line: str, line_no: int, byte_offset: int,
                   ctx: ParseContext) -> "Event | ParseGap": ...

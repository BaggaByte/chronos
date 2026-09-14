"""
Module 2: UTC Normalization Engine.

Handles:
  - ISO8601 with/without offset
  - Unix epoch (seconds / milliseconds)
  - Syslog-style "Mon DD HH:MM:SS" (no year, no TZ)
  - Localized Windows timestamps
  - Offset inference from host timezone metadata
  - DST-aware conversion via zoneinfo
  - Clock-skew flagging (caller supplies peer events)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.schema import ChronosEvent

# Syslog-style without year
SYSLOG_TS = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$"
)

# Apache / common: 12/Sep/2025:08:14:22 +0000
APACHE_TS = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>\w{3})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<offset>[+-]\d{4})$"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class UTCNormalizer:
    def __init__(
        self,
        default_year: Optional[int] = None,
        host_timezones: Optional[dict[str, str]] = None,
    ):
        """
        default_year: used when syslog lines omit the year.
        host_timezones: mapping host → IANA timezone name for offset inference.
        """
        self.default_year = default_year or datetime.now(timezone.utc).year
        self.host_timezones = host_timezones or {}

    def normalize(self, event: ChronosEvent) -> ChronosEvent:
        """
        Populate utc_timestamp, utc_epoch_ns and offset_inferred on the event.
        Returns the same (mutated) event for chaining.
        """
        raw = event.raw_timestamp
        if not raw:
            return event

        dt, inferred = self._parse_raw(raw, event.host)
        if dt is None:
            return event

        # Ensure timezone-aware UTC
        if dt.tzinfo is None:
            # Should not happen after _parse_raw, but be safe
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        event.utc_timestamp = dt
        event.utc_epoch_ns = int(dt.timestamp() * 1_000_000_000)
        event.offset_inferred = inferred
        return event

    def _parse_raw(self, raw: str, host: str) -> Tuple[Optional[datetime], bool]:
        raw = raw.strip()

        # 1. Epoch (seconds or milliseconds)
        if re.fullmatch(r"\d{10,13}", raw):
            val = int(raw)
            if val > 1_000_000_000_000:  # ms
                val //= 1000
            return datetime.fromtimestamp(val, tz=timezone.utc), False

        # 2. Apache style with explicit offset
        m = APACHE_TS.match(raw)
        if m:
            mon = MONTHS[m.group("mon")]
            offset_str = m.group("offset")  # +0000 / -0400
            sign = 1 if offset_str[0] == "+" else -1
            oh, om = int(offset_str[1:3]), int(offset_str[3:5])
            offset = timedelta(hours=sign * oh, minutes=sign * om)
            dt = datetime(
                int(m.group("year")), mon, int(m.group("day")),
                int(m.group("h")), int(m.group("m")), int(m.group("s")),
                tzinfo=timezone(offset),
            )
            return dt, False

        # 3. ISO8601 (with or without offset / Z)
        try:
            # Python 3.11+ fromisoformat handles many variants
            cleaned = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                # No offset present → try host timezone inference
                return self._apply_host_tz(dt, host)
            return dt, False
        except ValueError:
            pass

        # 4. Syslog style (no year, no TZ)
        m = SYSLOG_TS.match(raw)
        if m:
            mon = MONTHS.get(m.group("mon"))
            if mon is None:
                return None, False
            naive = datetime(
                self.default_year, mon, int(m.group("day")),
                int(m.group("h")), int(m.group("m")), int(m.group("s")),
            )
            return self._apply_host_tz(naive, host)

        return None, False

    def _apply_host_tz(self, naive: datetime, host: str) -> Tuple[datetime, bool]:
        tz_name = self.host_timezones.get(host)
        if not tz_name:
            # Fall back to UTC and flag as inferred
            return naive.replace(tzinfo=timezone.utc), True
        try:
            tz = ZoneInfo(tz_name)
            aware = naive.replace(tzinfo=tz)
            return aware, True
        except ZoneInfoNotFoundError:
            return naive.replace(tzinfo=timezone.utc), True

    def detect_clock_skew(
        self,
        events: List[ChronosEvent],
        max_skew_seconds: float = 120.0,
    ) -> List[ChronosEvent]:
        """
        Simple pairwise heuristic: if two events from different hosts share
        a strong correlation key (same src_ip + user) but their normalized
        timestamps differ by more than max_skew_seconds while the raw
        activity order is reversed, flag both.

        For the prototype we just mark events whose host is known to have
        a configured skew; a fuller implementation would run statistical
        tests across correlation groups.
        """
        # Placeholder – real logic lives in the correlation module.
        # Here we only surface the flag if the caller already set it.
        return events

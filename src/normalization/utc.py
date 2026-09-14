"""
Module 2: UTC Normalization Engine.

Two-phase design:

  Phase A (this module) — parse each raw timestamp string. If it carries
  an explicit offset, `Z`, or is an epoch value, resolve it to true UTC
  immediately with confidence="explicit". If it's naive (no offset — the
  common case for syslog and many EVTX exports), park it as a pending
  (event, naive_datetime) pair instead of guessing.

  Phase B (src/normalization/tz_infer.py) — resolves every pending event
  via cross-host network-flow correlation, falling back to an analyst-
  supplied prior only when correlation finds nothing. See that module for
  why a single-pass "guess the offset" approach isn't good enough.

Handles:
  - ISO8601 with/without offset, `Z`
  - Unix epoch (seconds / milliseconds)
  - Apache/Nginx combined-log style with explicit numeric offset
  - Syslog-style "Mon DD HH:MM:SS" (no year, no TZ) — naive
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, List

from src.schema import ChronosEvent
from src.normalization.tz_infer import infer_offsets, HostOffsetResult

# Syslog-style without year
SYSLOG_TS = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$"
)

# Apache / common: 12/Sep/2025:08:14:22 +0000
APACHE_TS = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>\w{3})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<offset>[+-]\d{4})$"
)

# ISO8601 without offset (naive) — e.g. Windows Event Viewer local-time export
ISO_NAIVE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class UTCNormalizer:
    def __init__(
        self,
        default_year: Optional[int] = None,
        host_timezones: Optional[Dict[str, str]] = None,
    ):
        """
        default_year: used when syslog lines omit the year.
        host_timezones: optional fallback priors if provided directly to normalizer.
        """
        self.default_year = default_year or datetime.now(timezone.utc).year
        self.host_timezones = host_timezones or {}

    def normalize(self, event: ChronosEvent) -> ChronosEvent:
        """
        Single-event helper for convenience and backwards compatibility.
        Populates utc_timestamp, utc_epoch_ns and offset_inferred.
        """
        raw = event.raw_timestamp
        if not raw:
            return event
        outcome = self._parse_raw(raw.strip())
        if outcome is None:
            return event
        dt, is_naive = outcome
        if is_naive:
            tz_name = self.host_timezones.get(event.host)
            if tz_name:
                from zoneinfo import ZoneInfo
                try:
                    dt = dt.replace(tzinfo=ZoneInfo(tz_name)).astimezone(timezone.utc)
                except Exception:
                    dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.replace(tzinfo=timezone.utc)
            event.utc_timestamp = dt
            event.utc_epoch_ns = int(dt.timestamp() * 1_000_000_000)
            event.offset_inferred = True
            event.offset_confidence = "prior" if tz_name else "defaulted_utc"
        else:
            dt = dt.astimezone(timezone.utc)
            event.utc_timestamp = dt
            event.utc_epoch_ns = int(dt.timestamp() * 1_000_000_000)
            event.offset_inferred = False
            event.offset_confidence = "explicit"
            event.inferred_utc_offset_minutes = 0
        return event

    def normalize_batch(
        self,
        events: List[ChronosEvent],
        prior_map: Optional[Dict[str, str]] = None,
        asset_ip_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, HostOffsetResult]:
        """
        Resolve every event's utc_timestamp. Explicit-offset events are
        resolved directly (Phase A). Naive events are resolved via
        cross-host correlation with an asset-inventory fallback (Phase B).

        Returns a per-host summary of how each ambiguous host's offset
        was determined (for reporting) — never used as input to itself.
        """
        pending: Dict[str, Tuple[ChronosEvent, datetime]] = {}
        resolved: List[ChronosEvent] = []

        for e in events:
            raw = e.raw_timestamp
            if not raw:
                continue
            outcome = self._parse_raw(raw.strip())
            if outcome is None:
                continue
            dt, is_naive = outcome
            if is_naive:
                pending[e.event_id] = (e, dt)
                e.offset_inferred = True
            else:
                dt = dt.astimezone(timezone.utc)
                e.utc_timestamp = dt
                e.utc_epoch_ns = int(dt.timestamp() * 1_000_000_000)
                e.offset_inferred = False
                e.offset_confidence = "explicit"
                e.inferred_utc_offset_minutes = 0
                resolved.append(e)

        effective_priors = dict(self.host_timezones)
        if prior_map:
            effective_priors.update(prior_map)

        host_results = infer_offsets(
            pending, resolved, prior_map=effective_priors, asset_ip_map=asset_ip_map
        )

        for e, _ in pending.values():
            r = host_results.get(e.host)
            if r is None:
                continue
            e.offset_confidence = r.confidence
            if r.skew_flag and r.residual_seconds:
                e.clock_skew_flag = True
                e.estimated_skew_seconds = r.residual_seconds

        return host_results

    def _parse_raw(self, raw: str) -> Optional[Tuple[datetime, bool]]:
        """Returns (datetime, is_naive). is_naive=True means the datetime
        has no real offset attached yet and still needs Phase B."""

        # 1. Epoch (seconds or milliseconds) — always explicit
        if re.fullmatch(r"\d{10,13}", raw):
            val = int(raw)
            if val > 1_000_000_000_000:  # ms
                val //= 1000
            return datetime.fromtimestamp(val, tz=timezone.utc), False

        # 2. Apache style with explicit offset — always explicit
        m = APACHE_TS.match(raw)
        if m:
            mon = MONTHS[m.group("mon")]
            offset_str = m.group("offset")
            sign = 1 if offset_str[0] == "+" else -1
            oh, om = int(offset_str[1:3]), int(offset_str[3:5])
            offset = timedelta(hours=sign * oh, minutes=sign * om)
            dt = datetime(
                int(m.group("year")), mon, int(m.group("day")),
                int(m.group("h")), int(m.group("m")), int(m.group("s")),
                tzinfo=timezone(offset),
            )
            return dt, False

        # 3. ISO8601 with offset or Z — explicit
        if not ISO_NAIVE.match(raw):
            try:
                cleaned = raw.replace("Z", "+00:00")
                dt = datetime.fromisoformat(cleaned)
                if dt.tzinfo is not None:
                    return dt, False
            except ValueError:
                pass

        # 4. ISO8601 without offset — naive
        if ISO_NAIVE.match(raw):
            try:
                return datetime.fromisoformat(raw), True
            except ValueError:
                pass

        # 5. Syslog style (no year, no TZ) — naive
        m = SYSLOG_TS.match(raw)
        if m:
            mon = MONTHS.get(m.group("mon"))
            if mon is None:
                return None
            naive = datetime(
                self.default_year, mon, int(m.group("day")),
                int(m.group("h")), int(m.group("m")), int(m.group("s")),
            )
            return naive, True

        return None

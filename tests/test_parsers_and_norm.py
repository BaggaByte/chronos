#!/usr/bin/env python3
"""Basic unit tests for parsers and UTC normalization."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.parsers.auth_log import AuthLogParser
from src.parsers.apache import ApacheParser
from src.parsers.cloudtrail import CloudTrailParser
from src.parsers.evtx_parser import EvtxParser
from src.normalization.utc import UTCNormalizer
from src.schema import ChronosEvent, SourceType


DATA = ROOT / "data" / "synthetic"


def test_auth_log_parser():
    parser = AuthLogParser()
    events = list(parser.parse(DATA / "auth.log"))
    assert len(events) >= 3
    ssh = [e for e in events if e.action and "ssh_accepted" in e.action]
    assert ssh, "expected at least one SSH accepted event"
    assert any(e.src_ip == "203.0.113.77" for e in ssh)
    assert any(e.user == "j.mitchell" for e in ssh)
    print("  [PASS] auth.log parser")


def test_apache_parser():
    parser = ApacheParser()
    events = list(parser.parse(DATA / "access.log"))
    assert len(events) >= 2
    login = [e for e in events if e.extra.get("path") == "/login"]
    assert login
    print("  [PASS] apache parser")


def test_evtx_json_parser():
    parser = EvtxParser()
    events = list(parser.parse(DATA / "windows_events.json"))
    assert len(events) == 3
    dump = [e for e in events if "credential dump" in (e.action or "").lower()]
    assert dump
    print("  [PASS] evtx JSON parser")


def test_cloudtrail_parser():
    parser = CloudTrailParser()
    events = list(parser.parse(DATA / "cloudtrail.jsonl"))
    assert len(events) == 2
    put = [e for e in events if e.action == "PutObject"]
    assert put
    assert put[0].src_ip == "203.0.113.77"
    print("  [PASS] cloudtrail parser")


def test_utc_normalization_syslog():
    norm = UTCNormalizer(default_year=2025, host_timezones={"lin-db-03": "UTC"})
    e = ChronosEvent(
        event_id="t1",
        source_type=SourceType.AUTH_LOG,
        host="lin-db-03",
        raw_timestamp="Sep 12 10:19:22",
    )
    norm.normalize(e)
    assert e.utc_timestamp is not None
    assert e.utc_timestamp.year == 2025
    assert e.utc_timestamp.month == 9
    assert e.utc_timestamp.day == 12
    assert e.offset_inferred is True
    print("  [PASS] syslog → UTC (inferred)")


def test_utc_normalization_apache_explicit():
    norm = UTCNormalizer(default_year=2025)
    e = ChronosEvent(
        event_id="t2",
        source_type=SourceType.APACHE,
        host="web-portal-01",
        raw_timestamp="12/Sep/2025:08:14:22 +0000",
    )
    norm.normalize(e)
    assert e.utc_timestamp is not None
    assert e.offset_inferred is False
    assert e.utc_timestamp.hour == 8
    print("  [PASS] apache explicit offset → UTC")


def test_utc_iso_with_z():
    norm = UTCNormalizer()
    e = ChronosEvent(
        event_id="t3",
        source_type=SourceType.AWS_CLOUDTRAIL,
        host="s3.amazonaws.com",
        raw_timestamp="2025-09-12T12:12:22Z",
    )
    norm.normalize(e)
    assert e.utc_timestamp is not None
    assert e.offset_inferred is False
    print("  [PASS] ISO8601 Z → UTC")


if __name__ == "__main__":
    print("Running Chronos unit tests…")
    test_auth_log_parser()
    test_apache_parser()
    test_evtx_json_parser()
    test_cloudtrail_parser()
    test_utc_normalization_syslog()
    test_utc_normalization_apache_explicit()
    test_utc_iso_with_z()
    print("\nAll tests passed.")

#!/usr/bin/env python3
"""Correlation accuracy test against synthetic ground truth."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.parsers.auth_log import AuthLogParser
from src.parsers.apache import ApacheParser
from src.parsers.cisco import CiscoSyslogParser
from src.parsers.cloudtrail import CloudTrailParser
from src.parsers.evtx_parser import EvtxParser
from src.normalization.utc import UTCNormalizer
from src.correlation.engine import CorrelationEngine
from src.anomaly.tagger import AttackTagger
from src.schema import SourceType

DATA = ROOT / "data" / "synthetic"


def _load_all_events():
    gt = json.loads((DATA / "ground_truth.json").read_text())
    host_tz = gt.get("host_timezones", {})
    parsers = [
        (DATA / "auth.log", AuthLogParser()),
        (DATA / "access.log", ApacheParser()),
        (DATA / "cisco.log", CiscoSyslogParser()),
        (DATA / "windows_events.json", EvtxParser()),
        (DATA / "cloudtrail.jsonl", CloudTrailParser()),
    ]
    events = []
    for path, parser in parsers:
        if not path.exists():
            continue
        for e in parser.parse(path):
            if path.name == "access.log":
                e.host = "web-portal-01"
            events.append(e)
    norm = UTCNormalizer(default_year=2025, host_timezones=host_tz)
    for e in events:
        norm.normalize(e)
    AttackTagger().tag(events)
    return events, gt


def test_single_attacker_group():
    events, gt = _load_all_events()
    groups = list(CorrelationEngine(time_window_seconds=3600 * 8).correlate(
        [e for e in events if e.utc_timestamp]
    ))
    assert len(groups) >= 1, "expected at least one correlation group"
    primary = max(groups, key=lambda g: len(g.event_ids))
    assert gt["attacker_ip"] in (primary.keys.get("src_ip") or ""), \
        f"primary group should be keyed on attacker IP, got {primary.keys}"
    # Most attacker events should be in the primary group
    attacker_events = [
        e for e in events
        if e.src_ip == gt["attacker_ip"] or e.user == gt["compromised_user"]
    ]
    covered = sum(1 for e in attacker_events if e.event_id in set(primary.event_ids))
    recall = covered / max(len(attacker_events), 1)
    assert recall >= 0.7, f"correlation recall too low: {recall:.2f}"
    print(f"  [PASS] correlation recall={recall:.2f}  group_size={len(primary.event_ids)}")


def test_benign_excluded():
    events, gt = _load_all_events()
    groups = CorrelationEngine(time_window_seconds=3600 * 8).correlate(
        [e for e in events if e.utc_timestamp]
    )
    primary = max(groups, key=lambda g: len(g.event_ids))
    primary_ids = set(primary.event_ids)
    # Admin user noise should largely stay out of the attacker group
    admin_in_group = [
        e for e in events
        if e.user == "svc_backup" and e.event_id in primary_ids
    ]
    # Allow a small amount of incidental overlap
    assert len(admin_in_group) <= 2, f"too many benign admin events pulled in: {len(admin_in_group)}"
    print(f"  [PASS] benign exclusion (admin in attacker group: {len(admin_in_group)})")


def test_no_false_merge_on_process_only():
    """Two benign events sharing only a common process name must NOT merge."""
    from datetime import datetime, timezone, timedelta
    from src.schema import ChronosEvent, SourceType
    from src.correlation.engine import CorrelationEngine

    t0 = datetime(2025, 9, 12, 10, 0, 0, tzinfo=timezone.utc)
    e1 = ChronosEvent(
        event_id="benign-1", source_type=SourceType.AUTH_LOG, host="host-a",
        raw_timestamp="", utc_timestamp=t0, user="alice", src_ip="10.0.0.1",
        process="sshd[100]", action="ssh_accepted_publickey",
    )
    e2 = ChronosEvent(
        event_id="benign-2", source_type=SourceType.AUTH_LOG, host="host-b",
        raw_timestamp="", utc_timestamp=t0 + timedelta(minutes=1),
        user="bob", src_ip="10.0.0.2", process="sshd[100]", action="ssh_accepted_publickey",
    )
    groups = CorrelationEngine().correlate([e1, e2])
    merged = any(
        "benign-1" in g.event_ids and "benign-2" in g.event_ids for g in groups
    )
    assert not merged, "process-only share must not create a correlation group"
    print("  [PASS] no false-merge on process-only")


def test_sliding_time_window_split():
    """Events from the same actor separated by more than time_window must split into separate groups."""
    from datetime import datetime, timezone, timedelta
    from src.schema import ChronosEvent, SourceType
    from src.correlation.engine import CorrelationEngine

    t0 = datetime(2025, 9, 12, 10, 0, 0, tzinfo=timezone.utc)
    # Campaign 1
    e1 = ChronosEvent(
        event_id="camp1-1", source_type=SourceType.APACHE, host="web-01",
        raw_timestamp="", utc_timestamp=t0, user="target_user", src_ip="203.0.113.88",
        action="GET /login",
    )
    e2 = ChronosEvent(
        event_id="camp1-2", source_type=SourceType.APACHE, host="web-01",
        raw_timestamp="", utc_timestamp=t0 + timedelta(minutes=15), user="target_user", src_ip="203.0.113.88",
        action="POST /login",
    )
    # Campaign 2: 7 days later (exceeds 6-hour window)
    t_later = t0 + timedelta(days=7)
    e3 = ChronosEvent(
        event_id="camp2-1", source_type=SourceType.APACHE, host="web-01",
        raw_timestamp="", utc_timestamp=t_later, user="target_user", src_ip="203.0.113.88",
        action="GET /admin",
    )
    e4 = ChronosEvent(
        event_id="camp2-2", source_type=SourceType.APACHE, host="web-01",
        raw_timestamp="", utc_timestamp=t_later + timedelta(minutes=10), user="target_user", src_ip="203.0.113.88",
        action="POST /admin",
    )

    engine = CorrelationEngine(time_window_seconds=3600 * 6)
    groups = list(engine.correlate([e1, e2, e3, e4]))
    assert len(groups) == 2, f"Expected 2 separate time-window groups, got {len(groups)}"
    g1_ids = set(groups[0].event_ids)
    g2_ids = set(groups[1].event_ids)
    assert g1_ids.isdisjoint(g2_ids), "Event groups must be disjoint"
    print("  [PASS] sliding time window partition verified")


if __name__ == "__main__":
    print("Running correlation tests…")
    test_single_attacker_group()
    test_benign_excluded()
    test_no_false_merge_on_process_only()
    test_sliding_time_window_split()
    print("All correlation tests passed.")

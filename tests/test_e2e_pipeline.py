#!/usr/bin/env python3
"""
End-to-end validation against synthetic ground truth.
Confirms stage ordering, technique coverage, and gap signals.
"""

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
from src.anomaly.detector import AnomalyDetector

DATA = ROOT / "data" / "synthetic"


def run_pipeline_in_memory():
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
    events = [e for e in events if e.utc_timestamp]
    events.sort(key=lambda x: x.utc_timestamp)
    AttackTagger().tag(events)
    groups = list(CorrelationEngine(time_window_seconds=3600 * 8).correlate(events))
    spikes = AnomalyDetector(z_threshold=2.0).detect_spikes(events)
    gaps = AnomalyDetector().detect_gaps(events, groups)
    return events, groups, spikes, gaps, gt


def test_techniques_cover_stages():
    events, groups, spikes, gaps, gt = run_pipeline_in_memory()
    observed = set()
    for e in events:
        observed.update(e.attack_techniques)
    expected = set()
    for stage in gt.get("stages", []):
        expected.update(stage.get("techniques", []))
    missing = expected - observed
    assert not missing, f"missing techniques for known stages: {missing}"
    print(f"  [PASS] all ground-truth techniques observed: {sorted(expected)}")


def test_narrative_stage_order():
    events, groups, spikes, gaps, gt = run_pipeline_in_memory()
    assert groups, "no correlation groups"
    primary = max(groups, key=lambda g: len(g.event_ids))
    # Extract ordered actions from narrative
    lines = [ln for ln in primary.narrative.splitlines() if ln.strip()]
    assert len(lines) >= 4, "narrative too short for 4-stage incident"
    # Rough order check: login before credential dump before ssh before PutObject
    text = primary.narrative.lower()
    pos_login = text.find("login")
    pos_dump = text.find("credential dump")
    pos_ssh = text.find("ssh_accepted")
    pos_put = text.find("putobject")
    assert pos_login >= 0 and pos_dump > pos_login, "login should precede credential dump"
    assert pos_ssh > pos_dump, "ssh lateral should follow credential dump"
    assert pos_put > pos_ssh, "exfil should follow lateral movement"
    print("  [PASS] narrative stage order correct")


def test_gaps_present():
    events, groups, spikes, gaps, gt = run_pipeline_in_memory()
    # 4-stage attack should produce at least a couple of inter-stage gaps
    assert len(gaps) >= 2, f"expected multiple gaps, got {len(gaps)}"
    print(f"  [PASS] gap count={len(gaps)}")


def test_offset_inferred_flagged():
    events, groups, spikes, gaps, gt = run_pipeline_in_memory()
    inferred = sum(1 for e in events if e.offset_inferred)
    # Synthetic set deliberately includes syslog-style lines
    assert inferred >= 1, "expected some offset-inferred flags"
    print(f"  [PASS] offset_inferred count={inferred}")


if __name__ == "__main__":
    print("Running e2e pipeline tests…")
    test_techniques_cover_stages()
    test_narrative_stage_order()
    test_gaps_present()
    test_offset_inferred_flagged()
    print("All e2e tests passed.")

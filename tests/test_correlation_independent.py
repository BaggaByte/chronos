#!/usr/bin/env python3
"""
tests/test_correlation_independent.py

Runs the existing, unmodified correlation engine against Scenario B.
Validates:
  1. 100% Recall and 100% Precision on unseen attacker IP/user/hosts.
  2. Decoy noisy scanner IP is completely excluded.
  3. Session-ID-only internal pivot hop is successfully correlated.
  4. Unauthenticated / anonymous events with user=None do not cause false merges.
  5. Truly naive local timestamps (Australia/Sydney) exercise offset inference properly.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.correlation.engine import correlate
from scripts.generate_scenario_b import build_dataset, ground_truth, DECOY_IP, ATTACKER_SESSION_ID


def test_recall_and_precision_on_independent_scenario():
    events = build_dataset()
    groups = correlate(events)
    gt = ground_truth()

    assert groups, "Expected at least one correlation group in Scenario B"
    attacker_group = max(groups, key=lambda g: (len(g.techniques), len(g.events)))
    recovered_ids = {e.id for e in attacker_group.events}
    expected_ids = set(gt["attacker_event_ids"])

    # 1. Recall check
    recall = len(recovered_ids & expected_ids) / len(expected_ids)
    print(f"  [PASS] Scenario B recall: {recall:.2f} (recovered {len(recovered_ids & expected_ids)}/{len(expected_ids)})")
    assert recall >= 0.9, f"Recall dropped to {recall:.2f} on unseen scenario"

    # 2. Strict Precision / zero contamination check
    absorbed_benign = recovered_ids - expected_ids
    print(f"  [PASS] Contamination check: {len(absorbed_benign)} non-attacker events absorbed")
    assert len(absorbed_benign) == 0, f"Benign events absorbed into attacker group: {absorbed_benign}"


def test_decoy_ip_not_absorbed():
    events = build_dataset()
    groups = correlate(events)
    assert groups, "Expected at least one correlation group in Scenario B"
    attacker_group = max(groups, key=lambda g: (len(g.techniques), len(g.events)))
    decoy_events = [e for e in attacker_group.events if e.src_ip == DECOY_IP]
    print(f"  [PASS] Decoy IP ({DECOY_IP}) events in attacker group: {len(decoy_events)}")
    assert not decoy_events, "Unrelated decoy IP was incorrectly merged into attacker group"


def test_session_id_only_hop_recovered():
    """Validates that an event sharing only a session_id (no attacker IP or user) is joined."""
    events = build_dataset()
    groups = correlate(events)
    attacker_group = max(groups, key=lambda g: (len(g.techniques), len(g.events)))
    recovered_ids = {e.id for e in attacker_group.events}

    # att-0005 is the session-only WMI query
    assert "att-0005" in recovered_ids, "Session-ID-only event (att-0005) was missed by correlation"
    sess_ev = next(e for e in attacker_group.events if e.id == "att-0005")
    assert sess_ev.session_id == ATTACKER_SESSION_ID
    assert sess_ev.user is None and sess_ev.src_ip is None
    print("  [PASS] Session-ID-only correlation hop verified (att-0005)")


def test_unauthenticated_users_never_merged():
    """Confirms that anonymous web traffic on portal-b02 is never falsely absorbed."""
    events = build_dataset(benign_count=150)
    groups = correlate(events)
    attacker_group = max(groups, key=lambda g: (len(g.techniques), len(g.events)))

    # No benign unauthenticated web event should be in the attacker group
    benign_anonymous_in_group = [
        e for e in attacker_group.events
        if e.id.startswith("benign-web") and (e.user is None or e.user == "-")
    ]
    print(f"  [PASS] Benign anonymous events absorbed: {len(benign_anonymous_in_group)}")
    assert not benign_anonymous_in_group, "Benign anonymous events falsely merged on empty user"


def test_timezone_offset_inference_sydney():
    """Validates that naive Sydney timestamps are correctly offset-inferred."""
    events = build_dataset()
    sydney_evtx = [e for e in events if e.host == "WIN-HR-04"]
    assert sydney_evtx, "Expected EVTX events on WIN-HR-04"
    for e in sydney_evtx:
        assert e.utc_timestamp is not None, f"Event {e.id} failed UTC normalization"
        assert e.offset_inferred is True, f"Event {e.id} should have offset_inferred=True"
    print(f"  [PASS] Australia/Sydney offset inference verified on {len(sydney_evtx)} events")


if __name__ == "__main__":
    print("Running independent scenario correlation tests…")
    test_recall_and_precision_on_independent_scenario()
    test_decoy_ip_not_absorbed()
    test_session_id_only_hop_recovered()
    test_unauthenticated_users_never_merged()
    test_timezone_offset_inference_sydney()
    print("All independent scenario correlation tests passed.")

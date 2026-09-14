"""
Tests for Module 2b: Cross-Source Timezone Offset Inference.
"""

from datetime import datetime, timezone, timedelta
from src.schema import ChronosEvent, SourceType
from src.normalization.offset_inference import infer_offsets, HostOffsetResult, _try_correlate_host


def test_offset_inference_from_flow_correlation():
    """Anchor on host A correlates with naive host B sharing an IP key."""
    t_anchor = datetime(2025, 9, 12, 12, 0, 0, tzinfo=timezone.utc)
    anchor_event = ChronosEvent(
        event_id="anchor-1",
        source_type=SourceType.APACHE,
        host="web-01",
        raw_timestamp="12/Sep/2025:12:00:00 +0000",
        utc_timestamp=t_anchor,
        utc_epoch_ns=int(t_anchor.timestamp() * 1e9),
        src_ip="203.0.113.50",
        dst_ip="10.0.1.10",
        action="web_request",
    )

    # Host B recorded event at 08:00:00 local time (UTC-4 -> -240 minutes)
    naive_dt = datetime(2025, 9, 12, 8, 0, 0)
    naive_event = ChronosEvent(
        event_id="naive-1",
        source_type=SourceType.AUTH_LOG,
        host="db-01",
        raw_timestamp="Sep 12 08:00:00",
        src_ip="203.0.113.50",
        action="ssh_login",
    )

    pending = {"naive-1": (naive_event, naive_dt)}
    results = infer_offsets(pending, [anchor_event])

    assert "db-01" in results
    res = results["db-01"]
    assert res.confidence == "correlated"
    assert res.offset_minutes == -240  # UTC-4 correctly recovered!
    assert res.residual_seconds == 0.0
    assert not res.skew_flag
    assert naive_event.utc_timestamp == t_anchor


def test_clock_skew_flagging():
    """Host has -240 offset but also 47s hardware clock drift."""
    t_anchor = datetime(2025, 9, 12, 12, 0, 0, tzinfo=timezone.utc)
    anchor = ChronosEvent(
        event_id="a1",
        source_type=SourceType.APACHE,
        host="web-01",
        raw_timestamp="12/Sep/2025:12:00:00 +0000",
        utc_timestamp=t_anchor,
        src_ip="203.0.113.50",
    )

    # Local clock is at 08:00:47 (drift = 47s)
    naive_dt = datetime(2025, 9, 12, 8, 0, 47)
    naive = ChronosEvent(
        event_id="n1",
        source_type=SourceType.AUTH_LOG,
        host="db-01",
        raw_timestamp="Sep 12 08:00:47",
        src_ip="203.0.113.50",
    )

    results = infer_offsets({"n1": (naive, naive_dt)}, [anchor])
    res = results["db-01"]
    assert res.confidence == "correlated"
    assert res.offset_minutes == -240
    assert res.skew_flag is True
    assert res.residual_seconds == 47.0


def test_fallback_to_prior_when_uncorrelated():
    """When no shared IP key exists, falls back to analyst prior inventory."""
    naive_dt = datetime(2025, 9, 12, 10, 0, 0)
    naive = ChronosEvent(
        event_id="n1",
        source_type=SourceType.AUTH_LOG,
        host="isolated-host",
        raw_timestamp="Sep 12 10:00:00",
        src_ip="192.168.1.100",
    )

    prior_map = {"isolated-host": "Asia/Kolkata"}  # UTC+05:30 -> +330 min
    results = infer_offsets({"n1": (naive, naive_dt)}, [], prior_map=prior_map)

    res = results["isolated-host"]
    assert res.confidence == "prior"
    assert res.offset_minutes == 330
    assert naive.utc_timestamp == datetime(2025, 9, 12, 4, 30, 0, tzinfo=timezone.utc)


def test_default_utc_when_no_prior_and_no_correlation():
    """Uncorrelated host with no prior defaults to UTC with low confidence flag."""
    naive_dt = datetime(2025, 9, 12, 10, 0, 0)
    naive = ChronosEvent(
        event_id="n1",
        source_type=SourceType.AUTH_LOG,
        host="ghost-host",
        raw_timestamp="Sep 12 10:00:00",
    )

    results = infer_offsets({"n1": (naive, naive_dt)}, [])
    res = results["ghost-host"]
    assert res.confidence == "defaulted_utc"
    assert res.offset_minutes == 0

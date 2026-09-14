"""
Module 2b: Cross-Source Timezone Offset Inference.

This is the real answer to "how do we resolve a naive local timestamp on a
host we don't have an explicit offset for" — the part the brief calls out
as the hardest problem, and the part earlier revisions of this project
faked by reading the answer key out of the synthetic-data generator.

Algorithm (mirrors real DFIR practice):

  1. Explicit-offset / epoch sources (Apache with a numeric offset,
     CloudTrail's `Z`-suffixed ISO8601, raw epoch) are already true UTC.
     These seed the "resolved anchor" pool with zero assumptions.

  2. For every host with only naive (no-offset) timestamps, search a
     bounded grid of real-world UTC offsets (every 15 minutes from -12:00
     to +14:00 — every IANA zone in use today is a multiple of 15
     minutes) and look for a **network-flow correlation**: another
     already-resolved event, sharing a source/destination IP with this
     host's event (including the host's own IP if known from asset
     inventory), whose time — once this candidate offset is applied —
     lines up far more tightly than any other candidate. Two systems
     observing the same TCP connection (firewall + server, client + web
     tier, etc.) should agree to within seconds; a wrong offset is off
     by (multiples of) tens of minutes to hours, so the correct offset
     stands out clearly by a margin test, not an absolute threshold.

  3. Once a host is resolved this way, its events themselves become new
     anchors, so resolution *propagates* across hosts (e.g. resolving the
     firewall from a web-tier anchor, then resolving a database host from
     the now-resolved firewall) — this is iterative, not one-shot.

  4. Any host that still can't be resolved this way falls back to an
     analyst-supplied asset-inventory prior (config/asset_inventory.yaml)
     — realistic (a team knows its own infrastructure) but explicitly
     lower-confidence than a correlation-confirmed result, and never
     used for infrastructure Chronos has no record of.

  5. Once an offset is fixed, the *residual* left over at the best-fit
     candidate — if small but non-zero and consistent — is reported as
     clock skew (drift), not silently absorbed into the offset.

Nothing here reads ground_truth.json. Ground truth is used only by the
test suite / pipeline's post-hoc scoring printout, never as an input.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from src.schema import ChronosEvent

# Every real-world UTC offset in use is a multiple of 15 minutes
# (whole hours, half hours like India, and quarter hours like Nepal/Chatham).
CANDIDATE_OFFSETS_MIN: List[int] = list(range(-12 * 60, 14 * 60 + 1, 15))

# A candidate pairing is only usable evidence within this window — beyond
# it we're almost certainly linking unrelated activity, not the same
# network flow or tightly-coupled action.
MAX_PAIR_WINDOW_SECONDS = 6 * 3600

# How much better the best candidate must be than the runner-up before we
# trust it (guards against a coincidental near-match at the wrong offset).
MIN_SEPARATION_RATIO = 4.0

# A best-fit residual below this is "clean" (no meaningful drift).
SKEW_NOISE_FLOOR_SECONDS = 5.0


@dataclass
class HostOffsetResult:
    host: str
    offset_minutes: int
    confidence: str            # correlated | prior | prior_confirmed | defaulted_utc
    basis: str                 # human-readable explanation
    pairs_used: int = 0
    residual_seconds: Optional[float] = None
    skew_flag: bool = False


def _event_ip_keys(e: ChronosEvent, asset_ip_map: Dict[str, str]) -> set:
    keys = set()
    if e.src_ip:
        keys.add(e.src_ip)
    if e.dst_ip:
        keys.add(e.dst_ip)
    own_ip = asset_ip_map.get(e.host)
    if own_ip:
        keys.add(own_ip)
    return keys


def _try_correlate_host(
    host: str,
    naive_events: List[Tuple[ChronosEvent, datetime]],
    resolved_pool: List[ChronosEvent],
    asset_ip_map: Dict[str, str],
) -> Optional[HostOffsetResult]:
    """Search the offset grid for the candidate that best aligns this
    host's naive events with already-resolved anchor events sharing an
    IP-based key, via a margin test rather than an absolute threshold.
    """
    # Pre-index resolved anchors by every IP key they carry, for speed.
    anchors_by_key: Dict[str, List[ChronosEvent]] = defaultdict(list)
    for a in resolved_pool:
        for k in _event_ip_keys(a, asset_ip_map):
            anchors_by_key[k].append(a)

    # IMPORTANT: score by each event's SINGLE best-matching anchor, then
    # take the host's best-explained event — not an average over every
    # key-sharing pair. A shared external/attacker IP recurs across many
    # unrelated log lines; averaging in all of them would drown out the
    # one genuine same-network-flow coincidence that actually pins the
    # offset. A real correlation needs only one tight match.
    scored: List[Tuple[float, int, int]] = []  # (best_event_residual, offset, tight_pairs)
    for offset in CANDIDATE_OFFSETS_MIN:
        per_event_best: List[float] = []
        for e, naive_dt in naive_events:
            cand_utc = (naive_dt - timedelta(minutes=offset)).replace(tzinfo=timezone.utc)
            best_for_event: Optional[float] = None
            for k in _event_ip_keys(e, asset_ip_map):
                for a in anchors_by_key.get(k, []):
                    if a.utc_timestamp is None:
                        continue
                    delta = abs((a.utc_timestamp - cand_utc).total_seconds())
                    if delta <= MAX_PAIR_WINDOW_SECONDS:
                        if best_for_event is None or delta < best_for_event:
                            best_for_event = delta
            if best_for_event is not None:
                per_event_best.append(best_for_event)
        if per_event_best:
            tight_pairs = sum(1 for d in per_event_best if d <= 30)
            scored.append((min(per_event_best), offset, max(tight_pairs, 1)))

    if not scored:
        return None

    scored.sort(key=lambda x: x[0])
    best_score, best_offset, best_pairs = scored[0]

    if len(scored) > 1:
        second_score = scored[1][0]
        # Require the best candidate to be clearly better than the
        # runner-up (guarding against exact ties or coincidental near-matches).
        if second_score <= best_score or (second_score < max(best_score, 1.0) * MIN_SEPARATION_RATIO and second_score < 3600):
            return None  # ambiguous — don't force a confident answer

    if best_score > 3600:
        return None  # even the best candidate isn't believable

    skew = best_score if best_score > SKEW_NOISE_FLOOR_SECONDS else 0.0
    return HostOffsetResult(
        host=host,
        offset_minutes=best_offset,
        confidence="correlated",
        basis=f"network-flow correlation ({best_pairs} shared-IP pair(s) within tolerance)",
        pairs_used=best_pairs,
        residual_seconds=round(best_score, 1),
        skew_flag=skew > 0,
    )


def infer_offsets(
    pending: Dict[str, Tuple[ChronosEvent, datetime]],
    resolved_events: List[ChronosEvent],
    prior_map: Optional[Dict[str, str]] = None,
    asset_ip_map: Optional[Dict[str, str]] = None,
    max_passes: int = 4,
) -> Dict[str, HostOffsetResult]:
    """
    pending: event_id -> (event, naive_local_datetime) for events whose raw
             timestamp carried no explicit offset.
    resolved_events: events already known to be true UTC (explicit offset,
             epoch, or Z-suffixed ISO8601).
    prior_map: optional host -> IANA timezone name, analyst-supplied
             fallback (e.g. asset inventory). NOT the answer key.
    asset_ip_map: optional host -> internal IP, also analyst-supplied,
             used only to widen the correlation search (see module docstring).
    """
    prior_map = prior_map or {}
    asset_ip_map = asset_ip_map or {}

    by_host: Dict[str, List[Tuple[ChronosEvent, datetime]]] = defaultdict(list)
    for e, naive_dt in pending.values():
        by_host[e.host].append((e, naive_dt))

    resolved_pool: List[ChronosEvent] = list(resolved_events)
    remaining = set(by_host.keys())
    results: Dict[str, HostOffsetResult] = {}

    for _ in range(max_passes):
        progressed = False
        for host in list(remaining):
            result = _try_correlate_host(host, by_host[host], resolved_pool, asset_ip_map)
            if result is None:
                continue
            _apply_offset(by_host[host], result.offset_minutes, confidence=result.confidence, skew_flag=result.skew_flag)
            results[host] = result
            resolved_pool.extend(e for e, _ in by_host[host])
            remaining.discard(host)
            progressed = True
        if not progressed:
            break

    for host in list(remaining):
        tz_name = prior_map.get(host)
        if tz_name:
            offset_min = _tz_offset_minutes(tz_name, by_host[host][0][1])
            _apply_offset(by_host[host], offset_min, confidence="prior", skew_flag=False)
            results[host] = HostOffsetResult(
                host=host,
                offset_minutes=offset_min,
                confidence="prior",
                basis=f"asset-inventory prior ({tz_name}); no cross-host correlation evidence available",
            )
        else:
            _apply_offset(by_host[host], 0, confidence="defaulted_utc", skew_flag=False)
            results[host] = HostOffsetResult(
                host=host,
                offset_minutes=0,
                confidence="defaulted_utc",
                basis="no correlation evidence and no asset-inventory record — assumed UTC (low confidence)",
            )
        remaining.discard(host)

    return results


def _apply_offset(
    events: List[Tuple[ChronosEvent, datetime]],
    offset_minutes: int,
    confidence: str = "correlated",
    skew_flag: bool = False,
) -> None:
    for e, naive_dt in events:
        utc_dt = (naive_dt - timedelta(minutes=offset_minutes)).replace(tzinfo=timezone.utc)
        e.utc_timestamp = utc_dt
        e.utc_epoch_ns = int(utc_dt.timestamp() * 1_000_000_000)
        e.offset_inferred = True
        e.offset_confidence = confidence
        e.clock_skew_flag = skew_flag
        e.inferred_utc_offset_minutes = offset_minutes


def _tz_offset_minutes(tz_name: str, at_naive: datetime) -> int:
    """UTC offset (minutes) of an IANA zone at roughly the given naive
    instant — used only for the prior fallback path."""
    from zoneinfo import ZoneInfo
    try:
        aware = at_naive.replace(tzinfo=ZoneInfo(tz_name))
        return int(aware.utcoffset().total_seconds() // 60)
    except Exception:
        return 0

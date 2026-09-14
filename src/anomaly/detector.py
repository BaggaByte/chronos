"""
Module 4 (part): Spike detector (rolling z-score / IQR) and
time-gap analyzer (adaptive threshold).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import statistics

from src.schema import ChronosEvent


class AnomalyDetector:
    def __init__(
        self,
        spike_window_minutes: int = 30,
        z_threshold: float = 2.5,
        gap_multiplier: float = 3.0,
        min_gap_seconds: int = 300,
    ):
        self.window = timedelta(minutes=spike_window_minutes)
        self.z_threshold = z_threshold
        self.gap_multiplier = gap_multiplier
        self.min_gap_seconds = min_gap_seconds

    def detect_spikes(self, events: List[ChronosEvent]) -> List[Dict]:
        """
        Per-host, per-action-category rolling count → z-score outlier.
        Returns list of spike descriptions.
        """
        # Bucket counts per (host, 5-min bin)
        bins: Dict[Tuple[str, int], int] = defaultdict(int)
        for e in events:
            if not e.utc_timestamp:
                continue
            # 5-minute epoch bins
            bin_id = int(e.utc_timestamp.timestamp() // 300)
            bins[(e.host, bin_id)] += 1

        # Group by host
        by_host: Dict[str, List[int]] = defaultdict(list)
        for (host, _), cnt in bins.items():
            by_host[host].append(cnt)

        spikes = []
        for host, counts in by_host.items():
            if len(counts) < 3:
                continue
            try:
                mean = statistics.mean(counts)
                stdev = statistics.stdev(counts) if len(counts) > 1 else 0.0
            except statistics.StatisticsError:
                continue
            if stdev == 0:
                continue
            for (h, bin_id), cnt in bins.items():
                if h != host:
                    continue
                z = (cnt - mean) / stdev
                if z >= self.z_threshold:
                    spikes.append({
                        "type": "execution_spike",
                        "host": host,
                        "bin_start_utc": datetime.fromtimestamp(bin_id * 300, tz=timezone.utc).isoformat(),
                        "count": cnt,
                        "z_score": round(z, 2),
                        "mean": round(mean, 2),
                        "severity": "medium" if z < 4 else "high",
                    })
        return spikes

    def detect_gaps(
        self,
        events: List[ChronosEvent],
        correlation_groups: Optional[List] = None,
    ) -> List[Dict]:
        """
        Within each correlation group (or globally if none supplied),
        look for inter-event gaps larger than adaptive threshold.
        """
        gaps = []
        groups_to_check = []

        if correlation_groups:
            id_to_event = {e.event_id: e for e in events}
            for g in correlation_groups:
                members = [id_to_event[eid] for eid in g.event_ids if eid in id_to_event]
                groups_to_check.append((g.group_id, members))
        else:
            groups_to_check.append(("global", events))

        for gid, members in groups_to_check:
            timed = sorted(
                [e for e in members if e.utc_timestamp],
                key=lambda e: e.utc_timestamp,  # type: ignore
            )
            if len(timed) < 2:
                continue
            deltas = []
            for a, b in zip(timed, timed[1:]):
                delta = (b.utc_timestamp - a.utc_timestamp).total_seconds()  # type: ignore
                deltas.append(delta)

            if not deltas:
                continue
            try:
                median_gap = statistics.median(deltas)
            except statistics.StatisticsError:
                median_gap = 60.0
            threshold = max(self.min_gap_seconds, median_gap * self.gap_multiplier)

            for a, b, delta in zip(timed, timed[1:], deltas):
                if delta >= threshold:
                    gaps.append({
                        "type": "time_gap",
                        "group_id": gid,
                        "from_event": a.event_id,
                        "to_event": b.event_id,
                        "from_ts": a.utc_timestamp.isoformat() if a.utc_timestamp else None,
                        "to_ts": b.utc_timestamp.isoformat() if b.utc_timestamp else None,
                        "gap_seconds": int(delta),
                        "threshold_seconds": int(threshold),
                        "hosts": list({a.host, b.host}),
                        "severity": "low" if delta < threshold * 2 else "medium",
                    })
        return gaps

"""
Module 3: Cross-Host Correlation Engine.

Joins events on shared identifiers within a configurable sliding time window:
  - source / destination IP (primary seed – prefers external)
  - username (strong expander – excludes generic/placeholder usernames)
  - session ID (expands all events in that session)
  - process ID (weak expander – guarded by user/IP intersection)
  - hostname (informational)

Events are partitioned by time window: activity gaps exceeding time_window_seconds
are split into separate correlation clusters. Claimed events are strictly assigned
to one group to prevent double-counting.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Set, Tuple, Iterable, Iterator

from src.schema import ChronosEvent, CorrelationGroup

# Usernames representing unauthenticated placeholders or high-volume generic scan targets
GENERIC_NOISE_USERS = {
    "-", "", "none", "n/a", "null", "unknown", "anonymous", "anonymous logon",
    "admin", "administrator", "root", "test", "guest", "user", "default",
    "scanbot", "scanner", "testuser",
}


def _is_external(ip: str) -> bool:
    if not ip:
        return False
    # RFC 1918 and loopback check
    if ip == "127.0.0.1" or ip == "::1" or ip.startswith("10.") or ip.startswith("192.168."):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            second = int(parts[1])
            if 16 <= second <= 31:
                return False
    return True


def _is_valid_user(user: Optional[str]) -> bool:
    if not user:
        return False
    u = user.strip().lower()
    if u in GENERIC_NOISE_USERS:
        return False
    return True


class CorrelationEngine:
    def __init__(self, time_window_seconds: int = 3600 * 6):
        self.window = timedelta(seconds=time_window_seconds)

    def correlate(self, events_stream: Iterable[ChronosEvent]) -> Iterator[CorrelationGroup]:
        # Always sort events chronologically before sliding-window processing
        # to ensure cross-source events from different log parsers form coherent chains.
        sorted_stream = sorted(
            [e for e in events_stream if e.utc_timestamp],
            key=lambda e: e.utc_timestamp,
        )
        buffer: List[ChronosEvent] = []
        claimed: Set[str] = set()
        
        for e in sorted_stream:
                
            buffer.append(e)
            
            # Keep buffer bounded: process when it spans > 2x window
            if buffer[-1].utc_timestamp - buffer[0].utc_timestamp > self.window * 2:
                boundary = buffer[-1].utc_timestamp - self.window
                
                # Extract mature groups
                tentative_groups = self._correlate_batch(buffer, claimed)
                for g in tentative_groups:
                    if g.end_utc and g.end_utc < boundary:
                        yield g
                        claimed.update(g.event_ids)
                        
                # Purge events older than boundary (they can never link to future events 
                # because the time gap exceeds self.window).
                buffer = [x for x in buffer if x.utc_timestamp >= boundary]
                
        # Flush remaining events at end of stream
        if buffer:
            tentative_groups = self._correlate_batch(buffer, claimed)
            for g in tentative_groups:
                yield g
                claimed.update(g.event_ids)

    def _correlate_batch(self, events: List[ChronosEvent], global_claimed: Set[str]) -> List[CorrelationGroup]:
        by_ip: Dict[str, List[ChronosEvent]] = defaultdict(list)
        by_user: Dict[str, List[ChronosEvent]] = defaultdict(list)
        by_session: Dict[str, List[ChronosEvent]] = defaultdict(list)
        by_process: Dict[str, List[ChronosEvent]] = defaultdict(list)

        for e in events:
            if e.event_id in global_claimed:
                continue
            if e.src_ip: by_ip[e.src_ip].append(e)
            if e.dst_ip: by_ip[e.dst_ip].append(e)
            if _is_valid_user(e.user): by_user[e.user].append(e)
            if e.session_id: by_session[e.session_id].append(e)
            if e.process: by_process[e.process].append(e)

        external_ips = [ip for ip in by_ip if _is_external(ip)]

        def _seed_priority(ip_addr: str) -> Tuple[int, int, int]:
            ev_list = by_ip[ip_addr]
            valid_users = len({ev.user for ev in ev_list if _is_valid_user(ev.user)})
            hosts = len({ev.host for ev in ev_list if ev.host})
            has_tech = sum(1 for ev in ev_list if ev.attack_techniques)
            return (valid_users > 0, hosts, has_tech)

        seed_ips = sorted(external_ips or list(by_ip.keys()), key=_seed_priority, reverse=True)

        groups: List[CorrelationGroup] = []
        local_claimed: Set[str] = set()

        for ip in seed_ips:
            members = list(by_ip[ip])
            seed_ids = {e.event_id for e in members}

            users = {e.user for e in members if _is_valid_user(e.user)}
            for u in users:
                for e in by_user.get(u, []):
                    if e.event_id not in seed_ids:
                        members.append(e)
                        seed_ids.add(e.event_id)

            sessions = {e.session_id for e in members if e.session_id}
            for s in sessions:
                for e in by_session.get(s, []):
                    if e.event_id not in seed_ids:
                        members.append(e)
                        seed_ids.add(e.event_id)

            group_users = {e.user for e in members if _is_valid_user(e.user)}
            group_ips = {e.src_ip for e in members if e.src_ip} | {e.dst_ip for e in members if e.dst_ip}

            processes = {e.process for e in members if e.process}
            for p in processes:
                for e in by_process.get(p, []):
                    if e.event_id in seed_ids:
                        continue
                    if (e.user and e.user in group_users) or (e.src_ip and e.src_ip in group_ips):
                        members.append(e)
                        seed_ids.add(e.event_id)

            time_clusters = self._cluster_by_time_window(members)

            for cluster in time_clusters:
                unclaimed_members = [e for e in cluster if e.event_id not in local_claimed]
                if len(unclaimed_members) < 2:
                    continue

                group_id = f"cg-{uuid.uuid4().hex[:10]}"
                for e in unclaimed_members:
                    e.correlation_group_id = group_id
                    local_claimed.add(e.event_id)

                times = [e.utc_timestamp for e in unclaimed_members if e.utc_timestamp]
                techniques: Set[str] = set()
                for e in unclaimed_members:
                    techniques.update(e.attack_techniques)

                cluster_users = {e.user for e in unclaimed_members if _is_valid_user(e.user)}
                cluster_sessions = {e.session_id for e in unclaimed_members if e.session_id}
                host_set = {e.host for e in unclaimed_members if e.host}

                groups.append(CorrelationGroup(
                    group_id=group_id,
                    keys={
                        "src_ip": ip,
                        "users": ",".join(sorted(cluster_users)) if cluster_users else "",
                        "hosts": ",".join(sorted(host_set)),
                        "sessions": ",".join(sorted(cluster_sessions)) if cluster_sessions else "",
                    },
                    event_ids=[e.event_id for e in unclaimed_members],
                    events=unclaimed_members,
                    start_utc=min(times) if times else None,
                    end_utc=max(times) if times else None,
                    techniques=sorted(techniques),
                    narrative=self._build_narrative(unclaimed_members),
                ))

        groups.sort(
            key=lambda g: (len(g.techniques), len(g.keys.get("hosts", "").split(",")), len(g.event_ids)),
            reverse=True,
        )
        return groups

    def _cluster_by_time_window(self, events: List[ChronosEvent]) -> List[List[ChronosEvent]]:
        """
        Deduplicates events and partitions them into contiguous clusters where
        the gap between consecutive events does not exceed self.window.
        """
        by_id = {e.event_id: e for e in events}
        sorted_events = [e for e in by_id.values() if e.utc_timestamp is not None]
        if not sorted_events:
            return []
        sorted_events.sort(key=lambda e: e.utc_timestamp)  # type: ignore

        clusters: List[List[ChronosEvent]] = []
        current_cluster: List[ChronosEvent] = [sorted_events[0]]

        for ev in sorted_events[1:]:
            prev_ev = current_cluster[-1]
            delta = ev.utc_timestamp - prev_ev.utc_timestamp  # type: ignore
            if delta <= self.window:
                current_cluster.append(ev)
            else:
                clusters.append(current_cluster)
                current_cluster = [ev]
        if current_cluster:
            clusters.append(current_cluster)

        return clusters

    def _build_narrative(self, events: List[ChronosEvent]) -> str:
        events = sorted(
            [e for e in events if e.utc_timestamp],
            key=lambda e: e.utc_timestamp,  # type: ignore
        )
        lines = []
        for e in events:
            ts = e.utc_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if e.utc_timestamp else "?"
            tech = f" [{','.join(e.attack_techniques)}]" if e.attack_techniques else ""
            lines.append(
                f"{ts} | {e.host} | {e.user or '-'} | {e.src_ip or '-'} | {e.action}{tech}"
            )
        return "\n".join(lines)


def correlate(events: Iterable[ChronosEvent], time_window_seconds: int = 3600 * 6) -> List[CorrelationGroup]:
    """Convenience functional interface for CorrelationEngine."""
    return list(CorrelationEngine(time_window_seconds=time_window_seconds).correlate(events))

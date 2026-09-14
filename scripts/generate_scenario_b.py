#!/usr/bin/env python3
"""
scripts/generate_scenario_b.py

Independent validation scenario (Scenario B).
Its purpose is to check that correlation and normalization logic generalizes across:
  - Unseen attacker IP (198.51.100.23) and user (r.chen)
  - Second unrelated external decoy IP (192.0.2.44) performing noisy failed scans
  - 5-stage attack path (Access -> Discovery -> Credential Dumping -> Lateral Movement -> Exfiltration)
  - Different hostnames and host count (4 hosts)
  - Truly naive non-UTC timezones (Asia/Kolkata, Australia/Sydney) exercising offset inference
  - Session-ID-only correlation hop (exercises session_id join key)
  - Harder signal-to-noise ratio (~150 benign events to 10 attacker events)
  - Deterministic event IDs for 100% reproducible testing
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.schema import ChronosEvent, SourceType
from src.normalization.utc import UTCNormalizer
from src.anomaly.tagger import AttackTagger

OUTPUT_DIR = ROOT / "data" / "scenario_b"

# ---------------------------------------------------------------------------
# Scenario B Constants
# ---------------------------------------------------------------------------
ATTACKER_IP = "198.51.100.23"
ATTACKER_USER = "r.chen"
DECOY_IP = "192.0.2.44"
ATTACKER_SESSION_ID = "0x3e7-r.chen-hr"

WEB_HOST = "portal-b02"
WINDOWS_HOST = "WIN-HR-04"
LINUX_HOST = "lin-app-09"
CLOUD_HOST = "s3.amazonaws.com"
HOSTS = [WEB_HOST, WINDOWS_HOST, LINUX_HOST, CLOUD_HOST]

HOST_TZ = {
    WEB_HOST: "Asia/Kolkata",
    WINDOWS_HOST: "Australia/Sydney",
    LINUX_HOST: "UTC",
}

CLOCK_SKEW_SECONDS = {
    WINDOWS_HOST: 33,
}

T0 = datetime(2025, 10, 5, 4, 30, 0, tzinfo=timezone.utc)

STAGES = [
    "initial_access",    # T1190 - public exploit
    "discovery",         # T1082 - whoami / systeminfo / session token reuse
    "credential_access", # T1003 - procdump / special privileges
    "lateral_movement",  # T1021 - SSH to lin-app-09
    "exfiltration",      # T1560 / T1041 - tar + S3 PutObject
]

_CACHED_GROUND_TRUTH: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Event Generation Helpers
# ---------------------------------------------------------------------------
def _format_naive_sydney(utc_dt: datetime) -> str:
    """Format UTC datetime as a naive local ISO8601 string in Sydney time (no offset suffix)."""
    local = utc_dt.astimezone(ZoneInfo("Australia/Sydney"))
    return local.strftime("%Y-%m-%dT%H:%M:%S")


def _format_naive_kolkata_syslog(utc_dt: datetime) -> str:
    """Format UTC datetime as a naive syslog-style string in Kolkata time."""
    local = utc_dt.astimezone(ZoneInfo("Asia/Kolkata"))
    return local.strftime("%b %d %H:%M:%S")


def build_attacker_thread() -> Tuple[List[ChronosEvent], List[str]]:
    """
    Builds the 10 attacker events across 5 distinct stages, including
    a session-ID-only pivot and timezone-naive timestamps.
    Returns (events, attacker_event_ids).
    """
    events: List[ChronosEvent] = []
    ids: List[str] = []

    # 1. Initial Access (portal-b02, Apache in Asia/Kolkata) - T1190
    t1 = T0
    eid1 = "att-0001"
    e1 = ChronosEvent(
        event_id=eid1,
        source_type=SourceType.APACHE,
        host=WEB_HOST,
        user=None,  # anonymous probe
        src_ip=ATTACKER_IP,
        action="GET /api/v1/auth",
        raw_timestamp=t1.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        raw_ref=f"access.log:{eid1}",
        extra={"method": "GET", "path": "/api/v1/auth", "status": 200},
    )
    events.append(e1)
    ids.append(eid1)

    t2 = t1 + timedelta(minutes=2, seconds=45)
    eid2 = "att-0002"
    e2 = ChronosEvent(
        event_id=eid2,
        source_type=SourceType.APACHE,
        host=WEB_HOST,
        user=ATTACKER_USER,
        src_ip=ATTACKER_IP,
        action="POST /api/v1/auth",
        raw_timestamp=t2.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        raw_ref=f"access.log:{eid2}",
        extra={"method": "POST", "path": "/api/v1/auth", "status": 200},
    )
    events.append(e2)
    ids.append(eid2)

    # 2. Discovery (WIN-HR-04, EVTX in Australia/Sydney) - T1082
    # Note: timestamps are naive local Sydney time without offset suffix to test offset inference!
    t3 = t1 + timedelta(minutes=28)
    t3_skewed = t3 + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    eid3 = "att-0003"
    e3 = ChronosEvent(
        event_id=eid3,
        source_type=SourceType.EVTX,
        host=WINDOWS_HOST,
        user=ATTACKER_USER,
        src_ip=ATTACKER_IP,
        session_id=ATTACKER_SESSION_ID,
        action="Successful logon",
        raw_timestamp=_format_naive_sydney(t3_skewed),
        raw_ref=f"windows_events.json:{eid3}",
        extra={"EventID": 4624, "LogonType": 10, "SubjectUserName": ATTACKER_USER},
    )
    events.append(e3)
    ids.append(eid3)

    t4 = t3 + timedelta(minutes=1, seconds=15)
    t4_skewed = t4 + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    eid4 = "att-0004"
    e4 = ChronosEvent(
        event_id=eid4,
        source_type=SourceType.EVTX,
        host=WINDOWS_HOST,
        user=ATTACKER_USER,
        session_id=ATTACKER_SESSION_ID,
        action="Process creation (system info discovery)",
        process="C:\\Windows\\System32\\whoami.exe",
        raw_timestamp=_format_naive_sydney(t4_skewed),
        raw_ref=f"windows_events.json:{eid4}",
        extra={"EventID": 4688, "CommandLine": "whoami.exe /all", "SubjectUserName": ATTACKER_USER},
    )
    events.append(e4)
    ids.append(eid4)

    # 2b. Session-ID ONLY Correlation Hop (Internal WMI query running under local service token)
    # Has NO matching external IP and NO matching attacker user, but carries ATTACKER_SESSION_ID!
    t4b = t3 + timedelta(minutes=5)
    t4b_skewed = t4b + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    eid4b = "att-0005"
    e4b = ChronosEvent(
        event_id=eid4b,
        source_type=SourceType.EVTX,
        host=WINDOWS_HOST,
        user=None,  # No user specified on internal background query
        src_ip=None,  # No external IP
        session_id=ATTACKER_SESSION_ID,  # Joins purely on session token!
        action="Process creation (wmic query)",
        process="C:\\Windows\\System32\\wbem\\WMIC.exe",
        raw_timestamp=_format_naive_sydney(t4b_skewed),
        raw_ref=f"windows_events.json:{eid4b}",
        extra={"EventID": 4688, "CommandLine": "wmic.exe useraccount get name,sid"},
    )
    events.append(e4b)
    ids.append(eid4b)

    # 3. Credential Access (WIN-HR-04, EVTX in Australia/Sydney) - T1003
    t5 = t3 + timedelta(minutes=14)
    t5_skewed = t5 + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    eid5 = "att-0006"
    e5 = ChronosEvent(
        event_id=eid5,
        source_type=SourceType.EVTX,
        host=WINDOWS_HOST,
        user=ATTACKER_USER,
        session_id=ATTACKER_SESSION_ID,
        action="Special privileges assigned",
        raw_timestamp=_format_naive_sydney(t5_skewed),
        raw_ref=f"windows_events.json:{eid5}",
        extra={"EventID": 4672, "SubjectUserName": ATTACKER_USER, "PrivilegeList": "SeDebugPrivilege"},
    )
    events.append(e5)
    ids.append(eid5)

    t6 = t5 + timedelta(minutes=2, seconds=10)
    t6_skewed = t6 + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    eid6 = "att-0007"
    e6 = ChronosEvent(
        event_id=eid6,
        source_type=SourceType.EVTX,
        host=WINDOWS_HOST,
        user=ATTACKER_USER,
        session_id=ATTACKER_SESSION_ID,
        action="Process creation (credential dump)",
        process="C:\\Tools\\procdump.exe",
        raw_timestamp=_format_naive_sydney(t6_skewed),
        raw_ref=f"windows_events.json:{eid6}",
        extra={"EventID": 4688, "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp", "SubjectUserName": ATTACKER_USER},
    )
    events.append(e6)
    ids.append(eid6)

    # 4. Lateral Movement (lin-app-09, auth.log in UTC) - T1021 / T1078
    t7 = t1 + timedelta(hours=1, minutes=45)
    eid7 = "att-0008"
    e7 = ChronosEvent(
        event_id=eid7,
        source_type=SourceType.AUTH_LOG,
        host=LINUX_HOST,
        user=ATTACKER_USER,
        src_ip=ATTACKER_IP,
        action="ssh_accepted_publickey",
        process="sshd[24102]",
        raw_timestamp=t7.strftime("%b %d %H:%M:%S"),
        raw_ref=f"auth.log:{eid7}",
    )
    events.append(e7)
    ids.append(eid7)

    # 5. Staging and Exfiltration (lin-app-09 & S3) - T1560 / T1041
    t8 = t7 + timedelta(minutes=50)
    eid8 = "att-0009"
    e8 = ChronosEvent(
        event_id=eid8,
        source_type=SourceType.AUTH_LOG,
        host=LINUX_HOST,
        user=ATTACKER_USER,
        action="sudo",
        process="sudo",
        raw_timestamp=t8.strftime("%b %d %H:%M:%S"),
        raw_ref=f"auth.log:{eid8}",
        extra={"command": "/bin/tar czf /tmp/hr_records.tgz /data/hr"},
    )
    events.append(e8)
    ids.append(eid8)

    t9 = t8 + timedelta(minutes=15)
    eid9 = "att-0010"
    e9 = ChronosEvent(
        event_id=eid9,
        source_type=SourceType.AWS_CLOUDTRAIL,
        host=CLOUD_HOST,
        user=ATTACKER_USER,
        src_ip=ATTACKER_IP,
        action="PutObject",
        raw_timestamp=t9.isoformat().replace("+00:00", "Z"),
        raw_ref=f"cloudtrail.jsonl:{eid9}",
        extra={"bucketName": "hr-records-archive", "key": "exfil/hr_records.tgz"},
    )
    events.append(e9)
    ids.append(eid9)

    return events, ids


def build_decoy_noise(n: int = 12) -> List[ChronosEvent]:
    """
    DECOY_IP hammers login/admin endpoints on portal-b02 with failed requests.
    Unrelated to ATTACKER_USER; must NOT get pulled into attacker's group.
    """
    rng = random.Random(1337)
    decoy_events: List[ChronosEvent] = []
    paths = ["/wp-login.php", "/admin", "/login", "/.env", "/xmlrpc.php", "/api/v1/auth"]
    users = [None, "-", "admin", "root", "test", "administrator"]

    for i in range(n):
        t = T0 + timedelta(minutes=rng.randint(1, 240))
        eid = f"decoy-{i+1:04d}"
        u = rng.choice(users)
        p = rng.choice(paths)
        e = ChronosEvent(
            event_id=eid,
            source_type=SourceType.APACHE,
            host=WEB_HOST,
            user=None if u == "-" else u,
            src_ip=DECOY_IP,
            action=f"POST {p}",
            raw_timestamp=t.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            raw_ref=f"access.log:{eid}",
            extra={"method": "POST", "path": p, "status": rng.choice([401, 403, 404])},
        )
        decoy_events.append(e)

    return decoy_events


def build_benign_background(n: int = 150) -> List[ChronosEvent]:
    """
    ~150 unrelated background events across portal-b02, WIN-HR-04, lin-app-09, CloudTrail.
    Deterministic event IDs and diverse benign users.
    """
    rng = random.Random(7331)
    benign: List[ChronosEvent] = []

    benign_users = ["svc_backup", "svc_monitor", "corp_alice", "corp_bob", "deploy_bot"]
    internal_ips = [f"10.20.1.{i}" for i in range(10, 50)] + [f"10.20.2.{i}" for i in range(10, 50)]

    for i in range(n):
        t = T0 + timedelta(minutes=rng.randint(0, 360))
        target_type = i % 4

        if target_type == 0:
            # Web portal normal traffic (some unauthenticated with user=None or user="-")
            eid = f"benign-web-{i+1:04d}"
            e = ChronosEvent(
                event_id=eid,
                source_type=SourceType.APACHE,
                host=WEB_HOST,
                user=None if (i % 2 == 0) else rng.choice(["corp_alice", "corp_bob"]),
                src_ip=rng.choice(internal_ips),
                action="GET /dashboard",
                raw_timestamp=t.strftime("%d/%b/%Y:%H:%M:%S +0000"),
                raw_ref=f"access.log:{eid}",
                extra={"method": "GET", "path": "/dashboard", "status": 200},
            )
        elif target_type == 1:
            # Linux auth routine cron / admin logins
            u = rng.choice(benign_users)
            eid = f"benign-lin-{i+1:04d}"
            e = ChronosEvent(
                event_id=eid,
                source_type=SourceType.AUTH_LOG,
                host=LINUX_HOST,
                user=u,
                src_ip=rng.choice(internal_ips),
                action="ssh_accepted_publickey",
                process=f"sshd[{15000 + i}]",
                raw_timestamp=t.strftime("%b %d %H:%M:%S"),
                raw_ref=f"auth.log:{eid}",
            )
        elif target_type == 2:
            # Windows HR workstation normal background events (naive Sydney timestamp)
            u = rng.choice(["svc_inventory", "local_admin", "corp_alice"])
            t_win = t + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
            eid = f"benign-win-{i+1:04d}"
            e = ChronosEvent(
                event_id=eid,
                source_type=SourceType.EVTX,
                host=WINDOWS_HOST,
                user=u,
                src_ip=rng.choice(internal_ips),
                action="Successful logon",
                raw_timestamp=_format_naive_sydney(t_win),
                raw_ref=f"windows_events.json:{eid}",
                extra={"EventID": 4624, "LogonType": 3, "SubjectUserName": u},
            )
        else:
            # AWS CloudTrail routine queries
            u = rng.choice(["svc_cloudwatch", "dev_read_only"])
            eid = f"benign-ct-{i+1:04d}"
            e = ChronosEvent(
                event_id=eid,
                source_type=SourceType.AWS_CLOUDTRAIL,
                host=CLOUD_HOST,
                user=u,
                src_ip="10.20.1.5",
                action="DescribeInstances",
                raw_timestamp=t.isoformat().replace("+00:00", "Z"),
                raw_ref=f"cloudtrail.jsonl:{eid}",
            )
        benign.append(e)

    return benign


def build_dataset(benign_count: int = 150) -> List[ChronosEvent]:
    """
    Constructs and returns the normalized, tagged Scenario B event list in memory.
    """
    global _CACHED_GROUND_TRUTH

    attacker_events, attacker_ids = build_attacker_thread()
    decoy_events = build_decoy_noise(n=12)
    benign_events = build_benign_background(n=benign_count)

    all_events = attacker_events + decoy_events + benign_events

    normalizer = UTCNormalizer(default_year=2025, host_timezones=HOST_TZ)
    for e in all_events:
        normalizer.normalize(e)

    AttackTagger().tag(all_events)

    _CACHED_GROUND_TRUTH = {
        "incident_id": "SCENARIO-B-VALIDATION",
        "attacker_ip": ATTACKER_IP,
        "compromised_user": ATTACKER_USER,
        "decoy_ip": DECOY_IP,
        "attacker_session_id": ATTACKER_SESSION_ID,
        "attacker_event_ids": attacker_ids,
        "total_attacker_events": len(attacker_ids),
        "total_decoy_events": len(decoy_events),
        "total_benign_events": len(benign_events),
        "stages": STAGES,
        "host_timezones": HOST_TZ,
        "clock_skew_seconds": CLOCK_SKEW_SECONDS,
    }

    return all_events


def ground_truth() -> Dict[str, Any]:
    """Returns the ground truth dictionary for Scenario B."""
    global _CACHED_GROUND_TRUTH
    if not _CACHED_GROUND_TRUTH:
        build_dataset()
    return _CACHED_GROUND_TRUTH


if __name__ == "__main__":
    events = build_dataset()
    gt = ground_truth()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "ground_truth.json", "w") as f:
        json.dump(gt, f, indent=2)
    print(f"[+] Scenario B generated with {len(events)} total events.")
    print(f"    Attacker events: {gt['total_attacker_events']}")
    print(f"    Decoy events:    {gt['total_decoy_events']}")
    print(f"    Benign events:   {gt['total_benign_events']}")
    print(f"    Ground truth saved to {OUTPUT_DIR / 'ground_truth.json'}")

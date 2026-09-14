#!/usr/bin/env python3
"""
Module 7: Synthetic Dataset Generator for Chronos.

Fabricates a coherent multi-stage aerospace-breach incident:
  spear-phishing → credential dump → lateral movement → data staging → exfiltration

Outputs correlated events simultaneously in all five target formats, with
deliberately mixed timezones/offsets and one clock-skewed host.
"""

from __future__ import annotations

import json
import os
import sys
import random
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple
from zoneinfo import ZoneInfo
import argparse

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Scenario constants
# ---------------------------------------------------------------------------

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
ATTACKER_IP = "203.0.113.77"          # external attacker (TEST-NET-3)
COMPROMISED_USER = "j.mitchell"
ADMIN_USER = "svc_backup"
WINDOWS_HOST = "WIN-ENG-07"
LINUX_HOST = "lin-db-03"
WEB_HOST = "web-portal-01"
FIREWALL = "fw-edge-01"

# Internal IPs — real ASA logs always show dotted IPs, never hostnames, in
# interface descriptors. Also doubles as a legitimate "asset inventory"
# IP<->host mapping (something a real security team genuinely knows about
# its own infrastructure, unlike an attacker's clock).
WINDOWS_HOST_IP = "10.10.6.40"
LINUX_HOST_IP = "10.10.8.33"
AWS_ACCOUNT = "123456789012"
S3_BUCKET = "aero-design-archives"

# Host timezone metadata (used by normalization later)
HOST_TZ = {
    WINDOWS_HOST: "America/New_York",   # EDT/EST
    LINUX_HOST: "UTC",
    WEB_HOST: "Europe/London",          # BST/GMT
    FIREWALL: "America/Los_Angeles",    # PDT/PST
}

# Deliberate clock skew on the Windows host: +47 seconds
CLOCK_SKEW_SECONDS = {
    WINDOWS_HOST: 47,
}

# Incident timeline anchors (true UTC)
T0 = datetime(2025, 9, 12, 8, 14, 22, tzinfo=timezone.utc)  # phishing email opened


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Genuine local-time helpers
#
# NOTE (fix): earlier revisions of this generator wrote every "local"
# timestamp field via `t.astimezone(ZoneInfo("UTC"))` — a no-op — so despite
# HOST_TZ claiming non-UTC zones for three of the four hosts, nothing in the
# actual log files ever required real offset inference. These helpers
# perform a genuine conversion into each host's IANA zone so the emitted
# strings reflect real local wall-clock time (including DST), and only
# `ground_truth.json` retains the true UTC value for after-the-fact grading.
# ---------------------------------------------------------------------------

def local_naive_str(t_utc: datetime, tz_name: str, fmt: str) -> str:
    """Genuine conversion to a host's local wall-clock time, offset stripped.

    Mirrors two real-world sources of timestamp ambiguity:
      - default syslog/rsyslog output (no NTP/timezone directive configured)
      - Windows Event Viewer / wevtutil exports displayed in local time
        instead of UTC (a well-known DFIR pitfall — EVTX SystemTime is
        stored in UTC internally, but tooling frequently renders it local).
    """
    local_dt = t_utc.astimezone(ZoneInfo(tz_name))
    return local_dt.strftime(fmt)


def apache_local_ts(t_utc: datetime, tz_name: str) -> str:
    """Genuine Apache/Nginx combined-log timestamp: real local time WITH the
    correct seasonal numeric offset (e.g. Europe/London is +0100 under BST
    in September, not +0000) — this is what a real webserver in that zone
    would actually write.
    """
    local_dt = t_utc.astimezone(ZoneInfo(tz_name))
    return local_dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(entries: List[Dict[str, Any]], path: Path) -> None:
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)


# ---------------------------------------------------------------------------
# Format writers
# ---------------------------------------------------------------------------

def write_auth_log(events: List[Dict], path: Path) -> None:
    """Linux auth.log style (syslog format, no year, no explicit TZ)."""
    lines = []
    for e in events:
        # syslog style: "Sep 12 08:14:22 hostname sshd[1234]: message"
        ts = e["local_ts"]  # already formatted without year
        lines.append(f"{ts} {e['host']} {e['process']}: {e['msg']}")
    path.write_text("\n".join(lines) + "\n")


def write_apache_access(events: List[Dict], path: Path) -> None:
    """Combined log format."""
    lines = []
    for e in events:
        # 203.0.113.77 - j.mitchell [12/Sep/2025:08:14:22 +0000] "GET /login HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
        lines.append(
            f'{e["src_ip"]} - {e.get("user", "-")} [{e["ts_apache"]}] '
            f'"{e["method"]} {e["path"]} HTTP/1.1" {e["status"]} {e["size"]} '
            f'"-" "{e["ua"]}"'
        )
    path.write_text("\n".join(lines) + "\n")


def write_cisco_syslog(events: List[Dict], path: Path) -> None:
    """RFC 3164-ish Cisco style."""
    lines = []
    for e in events:
        # <severity>Sep 12 08:14:22 fw-edge-01 %ASA-6-302013: Built outbound TCP connection ...
        lines.append(
            f'<{e["pri"]}>{e["ts_syslog"]} {e["host"]} {e["msg"]}'
        )
    path.write_text("\n".join(lines) + "\n")


def write_cloudtrail(events: List[Dict], path: Path) -> None:
    """AWS CloudTrail JSON records (one JSON object per line for simplicity)."""
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def write_evtx_json(events: List[Dict], path: Path) -> None:
    """
    We emit a JSON representation of Windows events because generating a real
    binary EVTX inside a pure-Python demo is heavy. The parser will accept
    this JSON fallback as well as real EVTX via python-evtx.
    """
    with open(path, "w") as f:
        json.dump({"Events": events}, f, indent=2)


# ---------------------------------------------------------------------------
# Scenario stages
# ---------------------------------------------------------------------------

def stage_initial_access() -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Phishing → web portal login (T1566 / T1190)."""
    auth, apache, cisco = [], [], []

    # Attacker hits the login page
    t = T0
    apache.append({
        "src_ip": ATTACKER_IP,
        "user": "-",
        "ts_apache": apache_local_ts(t, HOST_TZ[WEB_HOST]),
        "method": "GET",
        "path": "/login",
        "status": 200,
        "size": 4521,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "utc": t,
        "host": WEB_HOST,
    })

    # Successful credential stuffing / phishing credential use
    t = T0 + timedelta(minutes=3, seconds=12)
    apache.append({
        "src_ip": ATTACKER_IP,
        "user": COMPROMISED_USER,
        "ts_apache": apache_local_ts(t, HOST_TZ[WEB_HOST]),
        "method": "POST",
        "path": "/login",
        "status": 302,
        "size": 0,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "utc": t,
        "host": WEB_HOST,
    })

    # Firewall allows the inbound connection (default syslog: local device
    # time, no offset marker — genuinely ambiguous, like a real ASA box)
    cisco.append({
        "pri": "166",
        "ts_syslog": local_naive_str(t, HOST_TZ[FIREWALL], "%b %d %H:%M:%S"),
        "host": FIREWALL,
        "msg": f"%ASA-6-302013: Built inbound TCP connection 88421 for outside:{ATTACKER_IP}/44345 "
               f"({ATTACKER_IP}/44345) to inside:10.10.5.20/443 (10.10.5.20/443)",
        "utc": t,
        "src_ip": ATTACKER_IP,
        "dst_ip": "10.10.5.20",
    })

    return auth, apache, cisco


def stage_credential_dump() -> Tuple[List[Dict], List[Dict]]:
    """Credential dumping on the Windows engineering workstation (T1003)."""
    # Windows events (JSON stand-in for EVTX)
    evtx = []
    # Linux auth events that show the same user later

    # Logon type 10 (RemoteInteractive) – attacker lands on WIN-ENG-07
    #
    # NOTE: real EVTX stores SystemTime in UTC internally, but this JSON
    # stand-in simulates the *export/display* path (Get-WinEvent / Event
    # Viewer default view), which very commonly renders local machine time
    # with no offset marker — a well-known DFIR pitfall. We also bake in
    # the deliberate +47s clock-skew here, so the naive local string alone
    # is not enough to recover true UTC even after the zone is inferred.
    t = T0 + timedelta(hours=1, minutes=22)
    skewed = t + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])

    # The firewall observes the inbound RDP connection at the *true*,
    # unskewed instant (its own clock is accurate) — this is the network-
    # flow anchor that lets Chronos independently detect the Windows host's
    # clock drift, rather than reading it from an answer key.
    rdp_cisco_entries: List[Dict] = [{
        "pri": "166",
        "ts_syslog": local_naive_str(t, HOST_TZ[FIREWALL], "%b %d %H:%M:%S"),
        "host": FIREWALL,
        "msg": f"%ASA-6-302013: Built inbound TCP connection 88500 for outside:{ATTACKER_IP}/51900 "
               f"({ATTACKER_IP}/51900) to inside:{WINDOWS_HOST_IP}/3389 ({WINDOWS_HOST_IP}/3389)",
        "utc": t,
        "src_ip": ATTACKER_IP,
        "dst_ip": WINDOWS_HOST_IP,
    }]

    evtx.append({
        "EventID": 4624,
        "TimeCreated": local_naive_str(skewed, HOST_TZ[WINDOWS_HOST], "%Y-%m-%dT%H:%M:%S"),
        "Computer": WINDOWS_HOST,
        "SubjectUserName": COMPROMISED_USER,
        "IpAddress": ATTACKER_IP,
        "LogonType": 10,
        "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "utc_true": t.isoformat(),
        "action": "Successful logon",
    })

    # Special privileges assigned (4672)
    t2 = t + timedelta(seconds=4)
    skewed2 = t2 + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    evtx.append({
        "EventID": 4672,
        "TimeCreated": local_naive_str(skewed2, HOST_TZ[WINDOWS_HOST], "%Y-%m-%dT%H:%M:%S"),
        "Computer": WINDOWS_HOST,
        "SubjectUserName": COMPROMISED_USER,
        "PrivilegeList": "SeDebugPrivilege SeImpersonatePrivilege",
        "utc_true": t2.isoformat(),
        "action": "Special privileges assigned",
    })

    # Process creation – mimikatz-like (4688)
    t3 = t + timedelta(minutes=2, seconds=11)
    skewed3 = t3 + timedelta(seconds=CLOCK_SKEW_SECONDS[WINDOWS_HOST])
    evtx.append({
        "EventID": 4688,
        "TimeCreated": local_naive_str(skewed3, HOST_TZ[WINDOWS_HOST], "%Y-%m-%dT%H:%M:%S"),
        "Computer": WINDOWS_HOST,
        "SubjectUserName": COMPROMISED_USER,
        "NewProcessName": "C:\\Users\\j.mitchell\\AppData\\Local\\Temp\\mimi.exe",
        "CommandLine": "mimi.exe privilege::debug sekurlsa::logonpasswords",
        "utc_true": t3.isoformat(),
        "action": "Process creation (credential dump)",
    })

    return evtx, rdp_cisco_entries


def stage_lateral_movement() -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """SSH lateral movement to the Linux DB host (T1021)."""
    auth, cisco, evtx = [], [], []

    t = T0 + timedelta(hours=2, minutes=5)
    # SSH success on lin-db-03 (auth.log – no year, no TZ marker).
    # lin-db-03's real HOST_TZ *is* UTC, so this one is legitimately a
    # trivial case — not every source in a real investigation is ambiguous.
    local = t.astimezone(ZoneInfo(HOST_TZ[LINUX_HOST]))
    auth.append({
        "local_ts": local.strftime("%b %d %H:%M:%S"),
        "host": LINUX_HOST,
        "process": "sshd[18442]",
        "msg": f"Accepted publickey for {COMPROMISED_USER} from {ATTACKER_IP} port 51234 ssh2",
        "utc": t,
        "user": COMPROMISED_USER,
        "src_ip": ATTACKER_IP,
    })
    auth.append({
        "local_ts": local.strftime("%b %d %H:%M:%S"),
        "host": LINUX_HOST,
        "process": "sshd[18442]",
        "msg": f"pam_unix(sshd:session): session opened for user {COMPROMISED_USER} by (uid=0)",
        "utc": t,
        "user": COMPROMISED_USER,
        "src_ip": ATTACKER_IP,
    })

    # Firewall sees the outbound from Windows then inbound to Linux
    # (genuine Los_Angeles local time, no offset marker)
    cisco.append({
        "pri": "166",
        "ts_syslog": local_naive_str(t, HOST_TZ[FIREWALL], "%b %d %H:%M:%S"),
        "host": FIREWALL,
        "msg": f"%ASA-6-302013: Built outbound TCP connection 89102 for inside:10.10.7.15/49821 "
               f"(10.10.7.15/49821) to outside:{LINUX_HOST_IP}/22 ({LINUX_HOST_IP}/22)",
        "utc": t,
        "src_ip": "10.10.7.15",
        "dst_ip": "10.10.8.33",
    })

    return auth, cisco, evtx


def stage_staging_and_exfil() -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Archive collection + S3 exfiltration (T1560 / T1041)."""
    auth, cloudtrail, apache = [], [], []

    # tar on the Linux host (lin-db-03 is genuinely UTC)
    t = T0 + timedelta(hours=3, minutes=40)
    local = t.astimezone(ZoneInfo(HOST_TZ[LINUX_HOST]))
    auth.append({
        "local_ts": local.strftime("%b %d %H:%M:%S"),
        "host": LINUX_HOST,
        "process": "sudo",
        "msg": f"{COMPROMISED_USER} : TTY=pts/0 ; PWD=/home/{COMPROMISED_USER} ; "
               f"USER=root ; COMMAND=/bin/tar czf /tmp/designs.tgz /opt/aero/designs",
        "utc": t,
        "user": COMPROMISED_USER,
        "src_ip": None,
    })

    # AWS CloudTrail – PutObject to S3
    t2 = t + timedelta(minutes=18)
    cloudtrail.append({
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": f"arn:aws:iam::{AWS_ACCOUNT}:user/{COMPROMISED_USER}",
            "accountId": AWS_ACCOUNT,
            "userName": COMPROMISED_USER,
        },
        "eventTime": t2.isoformat().replace("+00:00", "Z"),
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "bucketName": S3_BUCKET,
            "key": "exfil/designs.tgz",
        },
        "responseElements": None,
        "requestID": "EXAMPLEREQUESTID",
        "eventID": "example-event-id-001",
        "eventType": "AwsApiCall",
        "recipientAccountId": AWS_ACCOUNT,
    })

    # Another CloudTrail event – GetCallerIdentity (recon)
    t3 = t2 - timedelta(minutes=2)
    cloudtrail.append({
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": f"arn:aws:iam::{AWS_ACCOUNT}:user/{COMPROMISED_USER}",
            "accountId": AWS_ACCOUNT,
            "userName": COMPROMISED_USER,
        },
        "eventTime": t3.isoformat().replace("+00:00", "Z"),
        "eventSource": "sts.amazonaws.com",
        "eventName": "GetCallerIdentity",
        "awsRegion": "us-east-1",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": None,
        "responseElements": {
            "account": AWS_ACCOUNT,
            "userId": "AIDAEXAMPLE",
            "arn": f"arn:aws:iam::{AWS_ACCOUNT}:user/{COMPROMISED_USER}",
        },
        "requestID": "EXAMPLEREQUESTID2",
        "eventID": "example-event-id-002",
        "eventType": "AwsApiCall",
        "recipientAccountId": AWS_ACCOUNT,
    })

    return auth, cloudtrail, apache


def add_benign_noise(scale: int = 1) -> Tuple[List, List, List, List, List]:
    """
    Ordinary background traffic + an intentional execution spike.

    scale=1  → ~30 benign events (demo)
    scale=50 → thousands of events for a lightweight scale timing run
    """
    auth, apache, cisco, evtx, ct = [], [], [], [], []
    rng = random.Random(42)

    # --- steady background ---
    for i in range(8 * scale):
        t = T0 + timedelta(minutes=rng.randint(5, 400))
        local = t.astimezone(ZoneInfo(HOST_TZ[LINUX_HOST]))
        auth.append({
            "local_ts": local.strftime("%b %d %H:%M:%S"),
            "host": LINUX_HOST,
            "process": f"sshd[{19000 + i}]",
            "msg": f"Accepted publickey for {ADMIN_USER} from 10.10.1.{50 + (i % 20)} port {40000 + i} ssh2",
            "utc": t,
            "user": ADMIN_USER,
            "src_ip": f"10.10.1.{50 + (i % 20)}",
        })

    for i in range(20 * scale):
        t = T0 + timedelta(minutes=rng.randint(0, 420))
        apache.append({
            "src_ip": f"10.10.2.{20 + (i % 30)}",
            "user": "-",
            "ts_apache": apache_local_ts(t, HOST_TZ[WEB_HOST]),
            "method": "GET",
            "path": "/static/logo.png" if i % 3 else "/health",
            "status": 200,
            "size": 8192,
            "ua": "Mozilla/5.0",
            "utc": t,
            "host": WEB_HOST,
        })

    # --- intentional spike: burst of failed SSH then success (auth storm) ---
    # Concentrated in a 3-minute window so rolling z-score / IQR will flag it.
    # Deterministic auth storm: 40*scale events in a single 5-minute bin
    # so rolling z-score is reliably high (reproducible with seed 42).
    spike_start = T0 + timedelta(hours=5, minutes=10)
    for i in range(40 * scale):
        t = spike_start + timedelta(seconds=i % 60)  # all within first minute of the bin
        local = t.astimezone(ZoneInfo(HOST_TZ[LINUX_HOST]))
        auth.append({
            "local_ts": local.strftime("%b %d %H:%M:%S"),
            "host": LINUX_HOST,
            "process": f"sshd[{30000 + i}]",
            "msg": f"Failed password for invalid user scanbot from 198.51.100.{(i % 50) + 1} port {50000 + i} ssh2",
            "utc": t,
            "user": "scanbot",
            "src_ip": f"198.51.100.{(i % 50) + 1}",
        })

    return auth, apache, cisco, evtx, ct


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Chronos synthetic dataset")
    parser.add_argument("--scale", type=int, default=1, help="Noise/spike multiplier (1=demo, 50=scale run)")
    args = parser.parse_args()
    ensure_dir(OUTPUT_DIR)
    print(f"[*] Generating synthetic aerospace-breach dataset (scale={args.scale}) → {OUTPUT_DIR}")

    all_auth: List[Dict] = []
    all_apache: List[Dict] = []
    all_cisco: List[Dict] = []
    all_evtx: List[Dict] = []
    all_ct: List[Dict] = []

    # Stage 1
    a, ap, c = stage_initial_access()
    all_auth.extend(a)
    all_apache.extend(ap)
    all_cisco.extend(c)

    # Stage 2
    e, c = stage_credential_dump()
    all_evtx.extend(e)
    all_cisco.extend(c)

    # Stage 3
    a, c, e = stage_lateral_movement()
    all_auth.extend(a)
    all_cisco.extend(c)
    all_evtx.extend(e)

    # Stage 4
    a, ct, ap = stage_staging_and_exfil()
    all_auth.extend(a)
    all_ct.extend(ct)
    all_apache.extend(ap)

    # Noise
    a, ap, c, e, ct = add_benign_noise(scale=args.scale)
    all_auth.extend(a)
    all_apache.extend(ap)
    all_cisco.extend(c)
    all_evtx.extend(e)
    all_ct.extend(ct)

    # Sort each list by true UTC for realism
    all_auth.sort(key=lambda x: x["utc"])
    all_apache.sort(key=lambda x: x["utc"])
    all_cisco.sort(key=lambda x: x["utc"])
    all_evtx.sort(key=lambda x: x.get("utc_true", x.get("TimeCreated", "")))
    all_ct.sort(key=lambda x: x["eventTime"])

    # Write files
    paths = {
        "auth.log": OUTPUT_DIR / "auth.log",
        "access.log": OUTPUT_DIR / "access.log",
        "cisco.log": OUTPUT_DIR / "cisco.log",
        "windows_events.json": OUTPUT_DIR / "windows_events.json",
        "cloudtrail.jsonl": OUTPUT_DIR / "cloudtrail.jsonl",
    }

    write_auth_log(all_auth, paths["auth.log"])
    write_apache_access(all_apache, paths["access.log"])
    write_cisco_syslog(all_cisco, paths["cisco.log"])
    write_evtx_json(all_evtx, paths["windows_events.json"])
    write_cloudtrail(all_ct, paths["cloudtrail.jsonl"])

    # Ground-truth metadata (for validation)
    ground_truth = {
        "incident_id": "AERO-2025-0912-EXFIL",
        "attacker_ip": ATTACKER_IP,
        "compromised_user": COMPROMISED_USER,
        "hosts": {
            "windows": WINDOWS_HOST,
            "linux": LINUX_HOST,
            "web": WEB_HOST,
            "firewall": FIREWALL,
        },
        "host_timezones": HOST_TZ,
        "clock_skew_seconds": CLOCK_SKEW_SECONDS,
        "stages": [
            {"name": "Initial Access", "techniques": ["T1566", "T1190"], "start_utc": T0.isoformat()},
            {"name": "Credential Dumping", "techniques": ["T1003"], "start_utc": (T0 + timedelta(hours=1, minutes=22)).isoformat()},
            {"name": "Lateral Movement", "techniques": ["T1021"], "start_utc": (T0 + timedelta(hours=2, minutes=5)).isoformat()},
            {"name": "Data Staging & Exfiltration", "techniques": ["T1560", "T1041"], "start_utc": (T0 + timedelta(hours=3, minutes=40)).isoformat()},
        ],
        "expected_correlation_keys": {
            "src_ip": ATTACKER_IP,
            "user": COMPROMISED_USER,
        },
        "file_counts": {
            "auth.log": len(all_auth),
            "access.log": len(all_apache),
            "cisco.log": len(all_cisco),
            "windows_events.json": len(all_evtx),
            "cloudtrail.jsonl": len(all_ct),
        },
    }
    gt_path = OUTPUT_DIR / "ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    # Ingest manifest skeleton (hashes will be filled by the real ingestion engine)
    manifest = []
    for name, p in paths.items():
        manifest.append({
            "source_path": str(p.name),
            "sha256": sha256_file(p),
            "source_type": {
                "auth.log": "auth.log",
                "access.log": "apache",
                "cisco.log": "cisco_syslog",
                "windows_events.json": "evtx",
                "cloudtrail.jsonl": "aws_cloudtrail",
            }[name],
            "size_bytes": p.stat().st_size,
            "event_count_approx": ground_truth["file_counts"][name],
        })
    write_manifest(manifest, OUTPUT_DIR / "manifest.json")

    print("[+] Files written:")
    for name, p in paths.items():
        print(f"    {p.name:30s}  {p.stat().st_size:6d} bytes  ~{ground_truth['file_counts'][name]} events")
    print(f"    ground_truth.json + manifest.json")
    print("[*] Done. Use this dataset to exercise parsers, UTC normalization, and correlation.")


if __name__ == "__main__":
    main()

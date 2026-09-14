#!/usr/bin/env python3
"""
windows_openssh_collector.py - Real-Time Windows OpenSSH Security Event Collector.

Monitors Windows OpenSSH events from the Windows Event Log channel (OpenSSH/Operational)
or C:\ProgramData\ssh\logs\sshd.log and live-streams normalized authentication telemetry
to the Chronos Ingestion Hub.

Usage:
  python scripts/windows_openssh_collector.py --server http://127.0.0.1:8000
  python scripts/windows_openssh_collector.py --server http://127.0.0.1:8000 --poll-interval 1.0
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chronos.windows_collector")

HOSTNAME = socket.gethostname()

# Regexes for Windows OpenSSH event messages
SSH_FAILED_RE = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
SSH_SESSION_RE = re.compile(
    r"session\s+opened\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)


def get_winevent_powershell(last_timestamp_utc: str) -> List[Dict[str, Any]]:
    """
    Queries OpenSSH/Operational events from Windows Event Log via PowerShell.
    Returns list of dicts with TimeCreated, Id, Message.
    """
    ps_cmd = (
        f"$filter = @{{LogName='OpenSSH/Operational'; StartTime=[datetime]::Parse('{last_timestamp_utc}')}}; "
        "Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | "
        "Select-Object -Property RecordId, TimeCreated, Id, Message | "
        "ConvertTo-Json -Compress"
    )
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        if not out:
            return []
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
    except Exception as e:
        logger.debug(f"PowerShell query returned nothing or error: {e}")
    return []


def ship_live_record(server_url: str, raw_line: str, source_type: str = "windows_openssh") -> bool:
    payload = json.dumps({
        "source_type": source_type,
        "raw_line": raw_line,
        "host": HOSTNAME,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{server_url.rstrip('/')}/api/ingest/live",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "ChronosWindowsCollector/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status == 200
    except Exception as e:
        logger.error(f"Failed to ship event to Chronos: {e}")
        return False


def run_collector(server_url: str, poll_interval: float = 1.0):
    logger.info("=" * 65)
    logger.info("  CHRONOS WINDOWS OPENSSH LIVE COLLECTOR")
    logger.info(f"  Target Server: {server_url}")
    logger.info(f"  Monitored Channel: OpenSSH/Operational on host '{HOSTNAME}'")
    logger.info("=" * 65)

    seen_record_ids = set()
    # Start tracking from current UTC time
    last_query_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Also check if file log exists
    file_log = Path("C:/ProgramData/ssh/logs/sshd.log")
    file_handle = None
    if file_log.exists():
        try:
            file_handle = open(file_log, "r", encoding="utf-8", errors="replace")
            file_handle.seek(0, os.SEEK_END)
            logger.info(f"Also tailing file log: {file_log}")
        except Exception as e:
            logger.warning(f"Could not open {file_log}: {e}")

    while True:
        try:
            # 1. Query Windows Event Log
            events = get_winevent_powershell(last_query_time)
            for ev in events:
                rec_id = ev.get("RecordId")
                if rec_id and rec_id in seen_record_ids:
                    continue
                if rec_id:
                    seen_record_ids.add(rec_id)
                    if len(seen_record_ids) > 10000:
                        seen_record_ids.clear()

                raw_msg = ev.get("Message", "").strip()
                time_created = ev.get("TimeCreated", "")
                if raw_msg:
                    # Format standard syslog-like string for universal parser
                    now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
                    formatted_line = f"{now_str} {HOSTNAME} sshd[{ev.get('Id', 0)}]: {raw_msg}"
                    success = ship_live_record(server_url, formatted_line, "windows_openssh")
                    if success:
                        logger.info(f"[Windows EventLog] Forwarded: {raw_msg[:75]}...")

            # 2. Tail sshd.log if active
            if file_handle:
                while True:
                    fline = file_handle.readline()
                    if not fline:
                        break
                    fline = fline.strip()
                    if fline:
                        now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
                        formatted_line = f"{now_str} {HOSTNAME} sshd: {fline}"
                        ship_live_record(server_url, formatted_line, "windows_openssh")
                        logger.info(f"[sshd.log] Forwarded: {fline[:75]}...")

            time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Stopping Windows OpenSSH collector...")
            break
        except Exception as e:
            logger.warning(f"Collector loop iteration warning: {e}")
            time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="Windows OpenSSH Live Collector for Chronos")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Chronos live server URL")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Poll interval in seconds")
    args = parser.parse_args()

    run_collector(server_url=args.server, poll_interval=args.poll_interval)


if __name__ == "__main__":
    main()

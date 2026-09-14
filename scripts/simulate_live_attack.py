#!/usr/bin/env python3
"""
simulate_live_attack.py - Real-time Kali Linux vs Ubuntu Attack Simulator.

Simulates an adversary on Kali Linux (192.168.1.50) performing:
  1. Reconnaissance (Nmap port scan) -> Suricata SCAN alert
  2. Credential Access (Hydra password spray) -> Suricata brute-force alert + auth.log failed passwords (T1110)
  3. Initial Access (Compromise of 'deploy' account) -> auth.log accepted password (T1078)
  4. Privilege Escalation (Sudo to read /etc/shadow) -> auth.log sudo event (T1003)

Streams events directly to Chronos Live Ingestion Hub or outputs to terminal.

Usage:
  python scripts/simulate_live_attack.py --server http://127.0.0.1:8000
  python scripts/simulate_live_attack.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

KALI_IP = "192.168.1.50"
UBUNTU_IP = "192.168.1.100"
UBUNTU_HOST = "ubuntu-server"


def generate_auth_failed(user: str, port: int) -> str:
    now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return f"{now} {UBUNTU_HOST} sshd[{random.randint(10000, 30000)}]: Failed password for invalid user {user} from {KALI_IP} port {port} ssh2"


def generate_auth_accepted(user: str, port: int) -> str:
    now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return f"{now} {UBUNTU_HOST} sshd[{random.randint(10000, 30000)}]: Accepted password for {user} from {KALI_IP} port {port} ssh2"


def generate_auth_session(user: str) -> str:
    now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return f"{now} {UBUNTU_HOST} sshd[{random.randint(10000, 30000)}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"


def generate_auth_sudo(user: str, cmd: str) -> str:
    now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return f"{now} {UBUNTU_HOST} sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"


def generate_suricata_alert(sig: str, category: str, sev: int, src_p: int, dst_p: int = 22) -> str:
    now_iso = datetime.now(timezone.utc).isoformat()
    doc = {
        "timestamp": now_iso,
        "event_type": "alert",
        "src_ip": KALI_IP,
        "src_port": src_p,
        "dest_ip": UBUNTU_IP,
        "dest_port": dst_p,
        "proto": "TCP",
        "host": UBUNTU_HOST,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": sig,
            "category": category,
            "severity": sev,
        },
    }
    return json.dumps(doc)


def generate_suricata_ssh_flow(client_version: str, src_p: int) -> str:
    now_iso = datetime.now(timezone.utc).isoformat()
    doc = {
        "timestamp": now_iso,
        "event_type": "ssh",
        "src_ip": KALI_IP,
        "src_port": src_p,
        "dest_ip": UBUNTU_IP,
        "dest_port": 22,
        "proto": "TCP",
        "host": UBUNTU_HOST,
        "ssh": {
            "client": {"proto_version": "2.0", "software_version": client_version},
            "server": {"proto_version": "2.0", "software_version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
            "event_type": "session",
        },
    }
    return json.dumps(doc)


def ship_event(server_url: str, source_type: str, line: str, dry_run: bool = False):
    if dry_run:
        print(f"[{source_type.upper():<8}] {line}")
        return

    payload = json.dumps({"source_type": source_type, "raw_line": line, "host": UBUNTU_HOST}).encode("utf-8")
    req = urllib.request.Request(
        f"{server_url.rstrip('/')}/api/ingest/live",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            pass
    except Exception as e:
        print(f"Error shipping to {server_url}: {e}")


def run_simulation(server_url: str, delay: float = 0.4, dry_run: bool = False):
    print("=" * 70)
    print("  CHRONOS LIVE ATTACK SIMULATION: Kali Linux -> Ubuntu Server")
    print(f"  Target: {server_url if not dry_run else 'DRY RUN'}")
    print("=" * 70)

    # 1. Reconnaissance: Port Scan
    print("\n[Phase 1] Kali Reconnaissance: Nmap SYN Scan on Port 22...")
    sport = random.randint(40000, 60000)
    ship_event(server_url, "suricata", generate_suricata_alert("ET SCAN Potential SSH Scan", "Attempted Information Leak", 3, sport), dry_run)
    time.sleep(delay)

    # 2. Credential Access: Hydra Password Spray
    print("[Phase 2] Kali Credential Access: Hydra SSH Brute-Force...")
    bad_users = ["root", "admin", "test", "postgres", "guest", "ubuntu", "support"]
    for u in bad_users:
        sp = random.randint(40000, 60000)
        # Suricata SSH flow + Suricata brute force alert
        ship_event(server_url, "suricata", generate_suricata_ssh_flow("libssh-0.9.6 / Hydra", sp), dry_run)
        ship_event(server_url, "auth.log", generate_auth_failed(u, sp), dry_run)
        time.sleep(delay)

    # Suricata flags brute force spike
    ship_event(
        server_url,
        "suricata",
        generate_suricata_alert("ET POLICY SSH Brute Force Inbound Login Failed", "Attempted Administrator Privilege Gain", 1, sport),
        dry_run,
    )
    time.sleep(delay)

    # 3. Initial Access: Successful compromise on 'deploy' account
    print("[Phase 3] Initial Access: Successful Authentication for 'deploy'...")
    comp_port = random.randint(40000, 60000)
    ship_event(server_url, "auth.log", generate_auth_accepted("deploy", comp_port), dry_run)
    ship_event(server_url, "auth.log", generate_auth_session("deploy"), dry_run)
    time.sleep(delay)

    # 4. Privilege Escalation: Sudo execution
    print("[Phase 4] Privilege Escalation: Sudo execution on /etc/shadow...")
    ship_event(server_url, "auth.log", generate_auth_sudo("deploy", "/bin/cat /etc/shadow"), dry_run)

    print("\nSimulation complete! All stages emitted and correlated.")


def main():
    parser = argparse.ArgumentParser(description="Simulate Kali -> Ubuntu live attack into Chronos")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Chronos live server URL")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between events in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print generated lines instead of POSTing")

    args = parser.parse_args()
    run_simulation(args.server, delay=args.delay, dry_run=args.dry_run)


if __name__ == "__main__":
    main()

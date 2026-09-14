"""
Unit and integration tests for Suricata parser and Live Ingestion Hub.
"""

import json
from pathlib import Path
from src.parsers.auth_log import AuthLogParser
from src.parsers.suricata import SuricataParser
from src.schema import SourceType, ATTACKTechnique
from src.ingestion.live_server import LiveIngestionHub


def test_suricata_alert_parsing():
    parser = SuricataParser()
    raw_alert = json.dumps({
        "timestamp": "2025-09-12T08:14:22.500000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "src_port": 45123,
        "dest_ip": "192.168.1.100",
        "dest_port": 22,
        "proto": "TCP",
        "host": "ubuntu-server",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2010935,
            "rev": 3,
            "signature": "ET POLICY SSH Brute Force Inbound Login Failed",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        }
    })

    event = parser.parse_line(raw_alert)
    assert event is not None
    assert event.source_type == SourceType.SURICATA
    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "192.168.1.100"
    assert event.host == "ubuntu-server"
    assert event.severity == "high"
    assert "T1110" in event.attack_techniques
    assert "SSH Brute Force" in event.action
    assert event.extra["signature_id"] == 2010935


def test_suricata_scan_and_ssh_event():
    parser = SuricataParser()
    scan_raw = json.dumps({
        "timestamp": "2025-09-12T08:14:20.000000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "dest_ip": "192.168.1.100",
        "alert": {
            "signature": "ET SCAN Potential SSH Scan",
            "category": "Attempted Information Leak",
            "severity": 3,
        }
    })
    event = parser.parse_line(scan_raw)
    assert event is not None
    assert "T1595" in event.attack_techniques
    assert event.severity == "low"

    ssh_raw = json.dumps({
        "timestamp": "2025-09-12T08:14:21.000000Z",
        "event_type": "ssh",
        "src_ip": "192.168.1.50",
        "dest_ip": "192.168.1.100",
        "ssh": {
            "client": {"proto_version": "2.0", "software_version": "Hydra-v9.5"},
            "server": {"proto_version": "2.0", "software_version": "OpenSSH_8.9p1"},
            "event_type": "session"
        }
    })
    ssh_event = parser.parse_line(ssh_raw)
    assert ssh_event is not None
    assert ssh_event.extra["client_software"] == "Hydra-v9.5"
    assert "T1021" in ssh_event.attack_techniques


def test_auth_log_failed_password():
    parser = AuthLogParser()
    line = "Sep 12 08:14:22 lin-db-03 sshd[18442]: Failed password for invalid user admin from 192.168.1.50 port 51234 ssh2"
    event = parser.parse_line(line, 10)
    assert event is not None
    assert event.source_type == SourceType.AUTH_LOG
    assert event.user == "admin"
    assert event.src_ip == "192.168.1.50"
    assert event.action == "ssh_failed_password"
    assert event.extra["port"] == "51234"
    assert "T1110" in event.attack_techniques


def test_live_ingestion_hub_stream():
    hub = LiveIngestionHub()
    q = hub.subscribe()

    # 1. Ingest Failed Password
    ev1 = hub.ingest_record("auth.log", "Sep 12 08:14:22 ubuntu-srv sshd[123]: Failed password for root from 192.168.1.50 port 4444 ssh2")
    assert ev1 is not None
    assert ev1.utc_timestamp is not None
    assert "T1110" in ev1.attack_techniques

    # 2. Ingest Suricata Alert
    suri_line = json.dumps({
        "timestamp": "2025-09-12T08:14:23.000000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "dest_ip": "192.168.1.100",
        "alert": {"signature": "ET POLICY SSH Brute Force Inbound Login Failed", "severity": 1}
    })
    ev2 = hub.ingest_record("suricata", suri_line)
    assert ev2 is not None
    assert ev2.utc_timestamp is not None

    stats = hub.get_stats()
    assert stats["total_ingested"] == 2
    assert stats["auth_events"] == 1
    assert stats["suricata_events"] == 1
    assert "192.168.1.50" in stats["active_src_ips"]

    # Check subscriber queue received both
    item1 = q.get_nowait()
    assert item1["action"] == "ssh_failed_password"
    item2 = q.get_nowait()
    assert "ET POLICY SSH Brute Force" in item2["action"]

    # 3. Ingest Windows OpenSSH event
    win_line = "Sep 14 22:00:01 WIN-SRV-01 sshd[4]: Failed password for invalid user hacker from 127.0.0.1 port 59123 ssh2"
    ev3 = hub.ingest_record("windows_openssh", win_line)
    assert ev3 is not None
    assert ev3.source_type == SourceType.EVTX
    assert ev3.user == "hacker"
    assert "T1110" in ev3.attack_techniques

    hub.unsubscribe(q)

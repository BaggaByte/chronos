"""
Suricata EVE JSON parser for Chronos.
Parses Suricata NIDS alerts, SSH handshakes, and network flow telemetry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from src.parsers.base import BaseParser
from src.schema import ChronosEvent, SourceType, ATTACKTechnique


class SuricataParser(BaseParser):
    source_type = SourceType.SURICATA

    def parse(self, path: Path) -> Iterator[ChronosEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                event = self.parse_line(line, lineno)
                if event:
                    yield event

    def parse_line(self, line: str, lineno: int = 0) -> Optional[ChronosEvent]:
        line = line.rstrip("\n").strip()
        if not line:
            return None

        try:
            data: Dict[str, Any] = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None

        event_type = str(data.get("event_type", "unknown")).lower()
        raw_ts = str(data.get("timestamp") or "")
        src_ip = data.get("src_ip")
        dst_ip = data.get("dest_ip")
        src_port = data.get("src_port")
        dst_port = data.get("dest_port")
        proto = data.get("proto")
        host = data.get("host") or data.get("sensor") or "suricata-nids"

        action = f"suricata_{event_type}"
        severity = "info"
        techniques: List[str] = []
        extra: Dict[str, Any] = {
            "event_type": event_type,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
        }

        if event_type == "alert":
            alert = data.get("alert", {})
            sig = alert.get("signature", "Unknown Alert")
            category = alert.get("category", "Generic Alert")
            raw_sev = alert.get("severity", 3)
            sig_id = alert.get("signature_id")

            action = f"alert: {sig}"
            extra["signature"] = sig
            extra["signature_id"] = sig_id
            extra["category"] = category
            extra["alert_severity"] = raw_sev

            # Severity mapping (Suricata: 1=High, 2=Medium, 3=Low/Info)
            if raw_sev == 1:
                severity = "high"
            elif raw_sev == 2:
                severity = "medium"
            else:
                severity = "low"

            sig_lower = sig.lower()
            cat_lower = category.lower()

            # ATT&CK Mapping
            if any(k in sig_lower or k in cat_lower for k in ["brute", "hydra", "password", "login failed", "credential"]):
                techniques.append(ATTACKTechnique.T1110.value)
                severity = "high" if raw_sev <= 2 else severity
            elif any(k in sig_lower or k in cat_lower for k in ["scan", "sweep", "probing", "nmap"]):
                techniques.append(ATTACKTechnique.T1595.value)
            elif "ssh" in sig_lower:
                techniques.append(ATTACKTechnique.T1021.value)
            elif "exploit" in sig_lower or "cve" in sig_lower:
                techniques.append(ATTACKTechnique.T1190.value)
                severity = "high"

        elif event_type == "ssh":
            ssh_info = data.get("ssh", {})
            action = f"ssh_{ssh_info.get('event_type', 'session')}"
            extra["client_proto"] = ssh_info.get("client", {}).get("proto_version")
            extra["client_software"] = ssh_info.get("client", {}).get("software_version")
            extra["server_proto"] = ssh_info.get("server", {}).get("proto_version")
            extra["server_software"] = ssh_info.get("server", {}).get("software_version")
            techniques.append(ATTACKTechnique.T1021.value)

        elif event_type == "flow":
            flow = data.get("flow", {})
            action = f"flow_{flow.get('state', 'unknown')}"
            extra["bytes_toserver"] = flow.get("bytes_toserver")
            extra["bytes_toclient"] = flow.get("bytes_toclient")
            extra["pkts_toserver"] = flow.get("pkts_toserver")
            extra["pkts_toclient"] = flow.get("pkts_toclient")

        elif event_type == "dns":
            dns = data.get("dns", {})
            action = f"dns_{dns.get('type', 'query')}"
            extra["rrname"] = dns.get("rrname")
            extra["rrtype"] = dns.get("rrtype")
            extra["rdata"] = dns.get("rdata")

        return ChronosEvent(
            event_id=ChronosEvent.generate_id("suricata", line),
            source_type=self.source_type,
            host=host,
            raw_timestamp=raw_ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            action=action,
            severity=severity,
            attack_techniques=sorted(set(techniques)),
            raw_ref=f"line:{lineno}",
            extra=extra,
        )

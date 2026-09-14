"""
Cisco ASA / syslog (RFC 3164 / 5424 style) parser.
Focuses on connection build / teardown and deny messages.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Optional

from src.parsers.base import BaseParser
from src.schema import ChronosEvent, SourceType


# <166>Sep 12 08:17:34 fw-edge-01 %ASA-6-302013: Built inbound TCP connection ...
CISCO_LINE = re.compile(
    r'^<?(?P<pri>\d+)?>?(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<msg>%ASA-\d+-\d+:\s+.+)$'
)

# Extract IPs and ports from common ASA messages
CONN_RE = re.compile(
    r"(?P<dir>inbound|outbound)\s+TCP\s+connection\s+\d+\s+for\s+"
    r"(?P<from_if>\w+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+).*?"
    r"to\s+(?P<to_if>\w+):(?P<dst_target>[^/\s]+)/(?P<dst_port>\d+)(?:\s+\((?P<dst_ip_paren>[\d.]+)/\d+\))?",
    re.IGNORECASE,
)


class CiscoSyslogParser(BaseParser):
    source_type = SourceType.CISCO_SYSLOG

    def parse(self, path: Path) -> Iterator[ChronosEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                event = self._parse_line(line, lineno)
                if event:
                    yield event

    def _parse_line(self, line: str, lineno: int) -> Optional[ChronosEvent]:
        m = CISCO_LINE.match(line)
        if not m:
            return None
        msg = m.group("msg")
        src_ip = dst_ip = None
        action = "cisco_event"
        cm = CONN_RE.search(msg)
        if cm:
            src_ip = cm.group("src_ip")
            paren_ip = cm.group("dst_ip_paren")
            target = cm.group("dst_target")
            dst_ip = paren_ip if paren_ip else (target if re.match(r"^[\d.]+$", target) else None)
            action = f"built_{cm.group('dir')}_tcp"
        return ChronosEvent(
            event_id=ChronosEvent.generate_id("cisco", line),
            source_type=self.source_type,
            host=m.group("host"),
            raw_timestamp=m.group("ts"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            action=action,
            raw_ref=f"line:{lineno}",
            extra={"raw_msg": msg, "pri": m.group("pri")},
        )

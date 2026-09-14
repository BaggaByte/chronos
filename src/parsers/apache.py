"""
Apache / Nginx combined & common log format parser.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Optional

from src.parsers.base import BaseParser
from src.schema import ChronosEvent, SourceType


# Combined log format
# 203.0.113.77 - j.mitchell [12/Sep/2025:08:17:34 +0000] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0 ..."
COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


class ApacheParser(BaseParser):
    source_type = SourceType.APACHE

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
        m = COMBINED.match(line)
        if not m:
            return None
        user = m.group("user")
        if user == "-":
            user = None
        return ChronosEvent(
            event_id=ChronosEvent.generate_id("apache", line),
            source_type=self.source_type,
            host="web-portal-01",  # can be overridden by caller if known
            raw_timestamp=m.group("ts"),
            user=user,
            src_ip=m.group("ip"),
            action=f"{m.group('method')} {m.group('path')}",
            raw_ref=f"line:{lineno}",
            extra={
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "size": m.group("size"),
                "user_agent": m.group("ua"),
            },
        )

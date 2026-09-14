"""
Linux auth.log / syslog-style authentication log parser.
Handles SSH auth, sudo, session open/close.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from src.parsers.base import BaseParser
from src.schema import ChronosEvent, SourceType


# Example lines:
# Sep 12 08:14:22 lin-db-03 sshd[18442]: Accepted publickey for j.mitchell from 203.0.113.77 port 51234 ssh2
# Sep 12 08:14:22 lin-db-03 sshd[18442]: pam_unix(sshd:session): session opened for user j.mitchell by (uid=0)
# Sep 12 11:54:22 lin-db-03 sudo: j.mitchell : TTY=pts/0 ; PWD=/home/j.mitchell ; USER=root ; COMMAND=/bin/tar ...

SSH_ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>sshd\[\d+\]):\s+"
    r"Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

SESSION_OPEN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+):\s+"
    r"pam_unix\(sshd:session\):\s+session opened for user\s+(?P<user>\S+)",
    re.IGNORECASE,
)

SUDO = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sudo:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)

GENERIC = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^:]+):\s+(?P<msg>.+)$",
)


class AuthLogParser(BaseParser):
    source_type = SourceType.AUTH_LOG

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
        m = SSH_ACCEPTED.match(line)
        if m:
            return ChronosEvent(
                event_id=ChronosEvent.generate_id("auth.log", line),
                source_type=self.source_type,
                host=m.group("host"),
                raw_timestamp=m.group("ts"),
                user=m.group("user"),
                src_ip=m.group("ip"),
                action=f"ssh_accepted_{m.group('method')}",
                process=m.group("proc"),
                raw_ref=f"line:{lineno}",
                extra={"port": m.group("port"), "method": m.group("method")},
            )

        m = SESSION_OPEN.match(line)
        if m:
            return ChronosEvent(
                event_id=ChronosEvent.generate_id("auth.log", line),
                source_type=self.source_type,
                host=m.group("host"),
                raw_timestamp=m.group("ts"),
                user=m.group("user"),
                action="session_opened",
                process=m.group("proc"),
                raw_ref=f"line:{lineno}",
            )

        m = SUDO.match(line)
        if m:
            return ChronosEvent(
                event_id=ChronosEvent.generate_id("auth.log", line),
                source_type=self.source_type,
                host=m.group("host"),
                raw_timestamp=m.group("ts"),
                user=m.group("user"),
                action="sudo",
                process="sudo",
                raw_ref=f"line:{lineno}",
                extra={"command": m.group("cmd").strip()},
            )

        m = GENERIC.match(line)
        if m:
            return ChronosEvent(
                event_id=ChronosEvent.generate_id("auth.log", line),
                source_type=self.source_type,
                host=m.group("host"),
                raw_timestamp=m.group("ts"),
                action="other",
                process=m.group("proc"),
                raw_ref=f"line:{lineno}",
                extra={"msg": m.group("msg")},
            )
        return None

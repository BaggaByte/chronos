"""
AWS CloudTrail JSON / JSONL parser.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Optional

from src.parsers.base import BaseParser
from src.schema import ChronosEvent, SourceType


class CloudTrailParser(BaseParser):
    source_type = SourceType.AWS_CLOUDTRAIL

    def parse(self, path: Path) -> Iterator[ChronosEvent]:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = self._record_to_event(rec, lineno)
                if ev:
                    yield ev

    def _record_to_event(self, rec: dict, ref: int) -> Optional[ChronosEvent]:
        user_identity = rec.get("userIdentity") or {}
        user = user_identity.get("userName") or user_identity.get("principalId")
        src_ip = rec.get("sourceIPAddress")
        event_name = rec.get("eventName", "Unknown")
        event_time = rec.get("eventTime", "")
        return ChronosEvent(
            event_id=ChronosEvent.generate_id("cloudtrail", rec.get("eventID", str(ref))),
            source_type=self.source_type,
            host=rec.get("eventSource", "aws"),
            raw_timestamp=event_time,
            user=user,
            src_ip=src_ip,
            action=event_name,
            raw_ref=f"record:{ref}",
            extra={
                "aws_region": rec.get("awsRegion"),
                "event_source": rec.get("eventSource"),
                "request_parameters": rec.get("requestParameters"),
                "user_agent": rec.get("userAgent"),
            },
        )

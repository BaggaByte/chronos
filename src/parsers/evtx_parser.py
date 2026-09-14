"""
Windows EVTX parser.

Primary path: JSON stand-in produced by the synthetic generator
(or any exported JSON). Optional path: real binary EVTX via python-evtx
when the library is installed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Optional

from src.parsers.base import BaseParser
from src.schema import ChronosEvent, SourceType


class EvtxParser(BaseParser):
    source_type = SourceType.EVTX

    def parse(self, path: Path) -> Iterator[ChronosEvent]:
        # Prefer JSON fallback (used by our synthetic dataset)
        if path.suffix.lower() in {".json", ".jsonl"}:
            yield from self._parse_json(path)
            return

        # Attempt real EVTX
        try:
            yield from self._parse_binary_evtx(path)
        except ImportError:
            raise RuntimeError(
                "python-evtx is required to parse binary .evtx files. "
                "Install it or supply a JSON export."
            )

    def _parse_json(self, path: Path) -> Iterator[ChronosEvent]:
        # Minimal brace-counting stream parser for {"Events": [ {...}, {...} ]}
        with open(path, "r", encoding="utf-8") as f:
            in_events = False
            in_obj = False
            brace_count = 0
            buf = []
            idx = 0
            
            for line in f:
                if not in_events:
                    if '"Events"' in line and '[' in line:
                        in_events = True
                    continue
                
                s = line.strip()
                if not in_obj:
                    if s.startswith("{"):
                        in_obj = True
                        brace_count = 0
                    elif s.startswith("]"):
                        break
                
                if in_obj:
                    buf.append(line)
                    brace_count += line.count("{") - line.count("}")
                    if brace_count == 0:
                        # object ended. Strip any trailing comma.
                        obj_str = "".join(buf).strip().rstrip(",")
                        try:
                            rec = json.loads(obj_str)
                            ev = self._record_to_event(rec, idx)
                            if ev:
                                yield ev
                            idx += 1
                        except json.JSONDecodeError:
                            pass
                        buf = []
                        in_obj = False

    def _parse_binary_evtx(self, path: Path) -> Iterator[ChronosEvent]:
        from Evtx.Evtx import Evtx  # type: ignore

        with Evtx(str(path)) as log:
            for idx, record in enumerate(log.records()):
                try:
                    xml = record.xml()
                    # Extremely lightweight extraction – production code would
                    # use a proper XML walker or python-evtx helpers.
                    # For the prototype we rely on the JSON path.
                    yield ChronosEvent(
                        event_id=ChronosEvent.generate_id("evtx", str(idx)),
                        source_type=self.source_type,
                        host="unknown",
                        raw_timestamp="",
                        action="raw_evtx",
                        raw_ref=f"record:{idx}",
                        extra={"xml_snippet": xml[:200]},
                    )
                except Exception:
                    continue

    def _record_to_event(self, rec: dict, ref: int) -> Optional[ChronosEvent]:
        event_id = rec.get("EventID")
        computer = rec.get("Computer", "unknown")
        time_created = rec.get("TimeCreated", "")
        user = rec.get("SubjectUserName") or rec.get("TargetUserName")
        src_ip = rec.get("IpAddress")
        action = rec.get("action") or f"EventID_{event_id}"
        process = rec.get("NewProcessName") or rec.get("ProcessName")

        extra = {k: v for k, v in rec.items() if k not in {
            "EventID", "Computer", "TimeCreated", "SubjectUserName",
            "IpAddress", "action", "NewProcessName", "ProcessName", "utc_true"
        }}
        if "utc_true" in rec:
            extra["utc_true"] = rec["utc_true"]  # ground-truth helper

        return ChronosEvent(
            event_id=ChronosEvent.generate_id("evtx", f"{event_id}:{time_created}:{ref}"),
            source_type=self.source_type,
            host=computer,
            raw_timestamp=time_created,
            user=user,
            src_ip=src_ip if src_ip and src_ip != "-" else None,
            action=action,
            process=process,
            raw_ref=f"record:{ref}",
            extra=extra,
        )

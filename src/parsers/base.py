"""
Base parser utilities and common ChronosEvent emission helpers.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional

from src.schema import ChronosEvent, SourceType, IngestManifestEntry, PARSER_VERSION


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class BaseParser(ABC):
    source_type: SourceType
    parser_version: str = PARSER_VERSION

    def __init__(self, host_timezone: Optional[str] = None):
        """
        host_timezone: IANA name used when the log format lacks an explicit offset.
        """
        self.host_timezone = host_timezone

    @abstractmethod
    def parse(self, path: Path) -> Iterator[ChronosEvent]:
        """Yield ChronosEvent objects from the given file."""
        ...

    def ingest(self, path: Path) -> tuple[List[ChronosEvent], IngestManifestEntry]:
        """
        Full ingest path: hash → parse → return events + manifest entry.
        Original file is never modified.
        """
        digest = sha256_of_file(path)
        events = list(self.parse(path))
        entry = IngestManifestEntry(
            source_path=str(path),
            sha256=digest,
            source_type=self.source_type,
            ingest_time_utc=datetime.utcnow().isoformat() + "Z",
            parser_version=self.parser_version,
            event_count=len(events),
        )
        return events, entry

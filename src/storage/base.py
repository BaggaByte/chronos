"""
Abstract storage interface so SQLite and Elasticsearch are interchangeable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.schema import ChronosEvent


class StorageBackend(ABC):
    """Minimal contract required by the pipeline and UI."""

    @abstractmethod
    def write_events(self, events: List[ChronosEvent]) -> int:
        """Bulk-insert / upsert events. Returns number written."""
        ...

    @abstractmethod
    def query_range(
        self,
        start_ns: Optional[int] = None,
        end_ns: Optional[int] = None,
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        user: Optional[str] = None,
        technique: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Time-range + filter query used by timeline and anomaly stages."""
        ...

    @abstractmethod
    def aggregate_counts(
        self,
        group_by: str = "host",
        start_ns: Optional[int] = None,
        end_ns: Optional[int] = None,
    ) -> Dict[str, int]:
        """Simple aggregation for spike detection / dashboard stats."""
        ...

    def close(self) -> None:
        """Optional cleanup."""
        pass

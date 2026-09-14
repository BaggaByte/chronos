"""
Module 5: SQLite fallback storage with time-indexed events.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from src.schema import ChronosEvent
from src.storage.base import StorageBackend


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    source_type     TEXT NOT NULL,
    host            TEXT,
    user            TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    action          TEXT,
    process         TEXT,
    session_id      TEXT,
    raw_timestamp   TEXT,
    utc_timestamp   TEXT,
    utc_epoch_ns    INTEGER,
    offset_inferred INTEGER DEFAULT 0,
    clock_skew_flag INTEGER DEFAULT 0,
    attack_techniques TEXT,          -- JSON array
    correlation_group_id TEXT,
    severity        TEXT DEFAULT 'info',
    raw_ref         TEXT,
    extra           TEXT             -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_events_utc ON events(utc_epoch_ns);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_group ON events(correlation_group_id);
"""


class SQLiteStore(StorageBackend):
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def write_events(self, events: List[ChronosEvent]) -> int:
        return self.bulk_insert(events)

    def bulk_insert(self, events: List[ChronosEvent], chunk_size: int = 2000) -> int:
        """Batched insert: single transaction, chunked executemany."""
        if not events:
            return 0
        sql = """
            INSERT OR REPLACE INTO events (
                event_id, source_type, host, user, src_ip, dst_ip, action,
                process, session_id, raw_timestamp, utc_timestamp, utc_epoch_ns,
                offset_inferred, clock_skew_flag, attack_techniques,
                correlation_group_id, severity, raw_ref, extra
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        self.conn.execute("BEGIN")
        total = 0
        chunk: list = []
        for e in events:
            chunk.append((
                e.event_id,
                e.source_type.value if hasattr(e.source_type, "value") else e.source_type,
                e.host,
                e.user,
                e.src_ip,
                e.dst_ip,
                e.action,
                e.process,
                e.session_id,
                e.raw_timestamp,
                e.utc_timestamp.isoformat() if e.utc_timestamp else None,
                e.utc_epoch_ns,
                1 if e.offset_inferred else 0,
                1 if e.clock_skew_flag else 0,
                json.dumps(e.attack_techniques),
                e.correlation_group_id,
                e.severity,
                e.raw_ref,
                json.dumps(e.extra),
            ))
            if len(chunk) >= chunk_size:
                self.conn.executemany(sql, chunk)
                total += len(chunk)
                chunk = []
        if chunk:
            self.conn.executemany(sql, chunk)
            total += len(chunk)
        self.conn.commit()
        return total

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
        clauses = []
        params: List[Any] = []
        if start_ns is not None:
            clauses.append("utc_epoch_ns >= ?")
            params.append(start_ns)
        if end_ns is not None:
            clauses.append("utc_epoch_ns <= ?")
            params.append(end_ns)
        if host:
            clauses.append("host = ?")
            params.append(host)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if user:
            clauses.append("user = ?")
            params.append(user)
        if technique:
            clauses.append("attack_techniques LIKE ?")
            params.append(f"%{technique}%")

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY utc_epoch_ns ASC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def aggregate_counts(
        self,
        group_by: str = "host",
        start_ns: Optional[int] = None,
        end_ns: Optional[int] = None,
    ) -> Dict[str, int]:
        allowed = {"host", "src_ip", "user", "source_type", "severity"}
        if group_by not in allowed:
            group_by = "host"
        clauses = []
        params: List[Any] = []
        if start_ns is not None:
            clauses.append("utc_epoch_ns >= ?")
            params.append(start_ns)
        if end_ns is not None:
            clauses.append("utc_epoch_ns <= ?")
            params.append(end_ns)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT {group_by} AS k, COUNT(*) AS c FROM events {where} GROUP BY {group_by}"
        cur = self.conn.execute(sql, params)
        return {row["k"] or "(null)": row["c"] for row in cur.fetchall()}

    def close(self) -> None:
        self.conn.close()

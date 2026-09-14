"""
ChronosEvent schema and related data models.
Common event representation emitted by all parsers.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import hashlib
import uuid


class SourceType(str, Enum):
    AUTH_LOG = "auth.log"
    EVTX = "evtx"
    APACHE = "apache"
    NGINX = "nginx"
    CISCO_SYSLOG = "cisco_syslog"
    AWS_CLOUDTRAIL = "aws_cloudtrail"


class ATTACKTechnique(str, Enum):
    """MITRE ATT&CK technique-level tags used by Chronos."""
    T1566 = "T1566"  # Phishing
    T1190 = "T1190"  # Exploit Public-Facing Application
    T1003 = "T1003"  # OS Credential Dumping
    T1021 = "T1021"  # Remote Services
    T1560 = "T1560"  # Archive Collected Data
    T1041 = "T1041"  # Exfiltration Over C2 Channel
    T1078 = "T1078"  # Valid Accounts
    T1059 = "T1059"  # Command and Scripting Interpreter
    T1082 = "T1082"  # System Information Discovery
    T1105 = "T1105"  # Ingress Tool Transfer
    UNKNOWN = "UNKNOWN"


@dataclass
class ChronosEvent:
    """
    Canonical event schema produced by every parser.
    All timestamps are stored as both nanosecond-precision UTC epoch
    and ISO8601-UTC string after normalization.
    """
    event_id: str
    source_type: SourceType
    host: str
    raw_timestamp: str
    utc_timestamp: Optional[datetime] = None          # timezone-aware UTC
    utc_epoch_ns: Optional[int] = None                # nanoseconds since epoch
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    action: Optional[str] = None
    process: Optional[str] = None
    session_id: Optional[str] = None
    raw_ref: Optional[str] = None                     # pointer back to original line/record
    offset_inferred: bool = False                     # True if timezone offset was not explicit in the raw string
    offset_confidence: str = "explicit"                # explicit | correlated | prior | defaulted_utc
    inferred_utc_offset_minutes: Optional[int] = None  # offset actually applied, once known
    clock_skew_flag: bool = False
    estimated_skew_seconds: Optional[float] = None     # residual drift detected after offset correction
    attack_techniques: List[str] = field(default_factory=list)
    correlation_group_id: Optional[str] = None
    severity: str = "info"                            # info | low | medium | high | critical
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.utc_timestamp is not None:
            d["utc_timestamp"] = self.utc_timestamp.isoformat()
        d["source_type"] = self.source_type.value if isinstance(self.source_type, SourceType) else self.source_type
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @property
    def id(self) -> str:
        return self.event_id

    @staticmethod
    def generate_id(source: str, raw: str) -> str:
        """Deterministic-ish ID from source + raw content hash + uuid for uniqueness."""
        h = hashlib.sha256(f"{source}:{raw}".encode()).hexdigest()[:12]
        return f"{h}-{uuid.uuid4().hex[:8]}"


@dataclass
class IngestManifestEntry:
    """Chain-of-custody record for a single ingested file."""
    source_path: str
    sha256: str
    source_type: SourceType
    ingest_time_utc: str
    parser_version: str
    event_count: int = 0
    notes: str = ""


@dataclass
class CorrelationGroup:
    """A set of events joined by shared identifiers within a time window."""
    group_id: str
    keys: Dict[str, str]          # e.g. {"src_ip": "10.0.0.5", "user": "jdoe"}
    event_ids: List[str]
    start_utc: Optional[datetime] = None
    end_utc: Optional[datetime] = None
    techniques: List[str] = field(default_factory=list)
    narrative: str = ""
    events: List[ChronosEvent] = field(default_factory=list)


PARSER_VERSION = "0.1.0"

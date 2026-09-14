"""
Module 1 (explicit): Ingestion & Integrity Engine – chain-of-custody.

Computes SHA-256 of every raw source *before* any parsing, records an
ingest manifest, and never mutates the original files.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.schema import SourceType, IngestManifestEntry, PARSER_VERSION


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of a file. Original is never modified."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest_entry(
    path: Path,
    source_type: SourceType,
    event_count: int = 0,
    notes: str = "",
    parser_version: str = PARSER_VERSION,
) -> IngestManifestEntry:
    """Create a single chain-of-custody record for one ingested file."""
    return IngestManifestEntry(
        source_path=str(path.resolve()),
        sha256=sha256_file(path),
        source_type=source_type,
        ingest_time_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        parser_version=parser_version,
        event_count=event_count,
        notes=notes,
    )


def write_manifest(
    entries: List[IngestManifestEntry],
    output_path: Path,
) -> Path:
    """
    Persist the ingest manifest as JSON.
    This is the minimum viable chain-of-custody artifact.
    """
    payload = []
    for e in entries:
        payload.append({
            "source_path": e.source_path,
            "sha256": e.sha256,
            "source_type": e.source_type.value if hasattr(e.source_type, "value") else e.source_type,
            "ingest_time_utc": e.ingest_time_utc,
            "parser_version": e.parser_version,
            "event_count": e.event_count,
            "notes": e.notes,
        })
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return output_path


def verify_manifest(manifest_path: Path, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Re-hash every source listed in a manifest and report matches/mismatches.
    Useful for demonstrating integrity preservation to a judge.
    """
    with open(manifest_path, encoding="utf-8") as f:
        entries = json.load(f)

    results = {"ok": True, "checked": 0, "mismatches": []}
    for entry in entries:
        rel = Path(entry["source_path"])
        candidate = (base_dir / rel.name) if base_dir else rel
        if not candidate.exists():
            # try just the basename next to the manifest
            candidate = manifest_path.parent / rel.name
        if not candidate.exists():
            results["ok"] = False
            results["mismatches"].append({
                "path": entry["source_path"],
                "error": "file not found",
            })
            continue
        current = sha256_file(candidate)
        results["checked"] += 1
        if current != entry["sha256"]:
            results["ok"] = False
            results["mismatches"].append({
                "path": str(candidate),
                "expected": entry["sha256"],
                "actual": current,
            })
    return results

#!/usr/bin/env python3
"""
End-to-end Chronos pipeline runner.

Ingests the synthetic dataset, normalizes timestamps, tags ATT&CK techniques,
correlates across hosts, detects anomalies, stores results, exports
forensic summary (CSV/JSON/PDF|TXT), and prints the attacker narrative.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.parsers.auth_log import AuthLogParser
from src.parsers.apache import ApacheParser
from src.parsers.cisco import CiscoSyslogParser
from src.parsers.cloudtrail import CloudTrailParser
from src.parsers.evtx_parser import EvtxParser
from src.ingestion.manifest import build_manifest_entry, write_manifest, verify_manifest
from src.normalization.utc import UTCNormalizer
from src.correlation.engine import CorrelationEngine
from src.anomaly.tagger import AttackTagger
from src.anomaly.detector import AnomalyDetector
from src.storage.sqlite_store import SQLiteStore
from src.reporting.export import export_all, export_ui_data
from src.schema import ChronosEvent, SourceType


DATA_DIR = ROOT / "data" / "synthetic"
DB_PATH = ROOT / "data" / "chronos_events.db"
REPORT_PATH = ROOT / "data" / "forensic_report.json"
MANIFEST_PATH = ROOT / "data" / "ingest_manifest.json"
EXPORT_DIR = ROOT / "data" / "exports"


def load_ground_truth():
    gt_path = DATA_DIR / "ground_truth.json"
    if gt_path.exists():
        with open(gt_path) as f:
            return json.load(f)
    return {}


def main() -> None:
    t0 = time.perf_counter()
    print("=" * 70)
    print("  CHRONOS Forensics Engine – Pipeline Run")
    print("=" * 70)

    gt = load_ground_truth()
    host_tz = gt.get("host_timezones", {
        "WIN-ENG-07": "America/New_York",
        "lin-db-03": "UTC",
        "web-portal-01": "Europe/London",
        "fw-edge-01": "America/Los_Angeles",
    })
    default_year = 2025

    # ------------------------------------------------------------------
    # 1. Ingestion & Integrity (explicit manifest module)
    # ------------------------------------------------------------------
    print("\n[1] Ingestion & Integrity")
    parser_map = {
        DATA_DIR / "auth.log": (AuthLogParser(host_timezone=host_tz.get("lin-db-03")), SourceType.AUTH_LOG),
        DATA_DIR / "access.log": (ApacheParser(host_timezone=host_tz.get("web-portal-01")), SourceType.APACHE),
        DATA_DIR / "cisco.log": (CiscoSyslogParser(host_timezone=host_tz.get("fw-edge-01")), SourceType.CISCO_SYSLOG),
        DATA_DIR / "windows_events.json": (EvtxParser(host_timezone=host_tz.get("WIN-ENG-07")), SourceType.EVTX),
        DATA_DIR / "cloudtrail.jsonl": (CloudTrailParser(), SourceType.AWS_CLOUDTRAIL),
    }

    all_events: list[ChronosEvent] = []
    manifest_entries = []
    manifest_for_report = []

    for path, (parser, stype) in parser_map.items():
        if not path.exists():
            print(f"  ! Missing {path.name}, skipping")
            continue
        entry = build_manifest_entry(path, stype)
        events = list(parser.parse(path))
        entry.event_count = len(events)
        if path.name == "access.log":
            for e in events:
                e.host = "web-portal-01"
        all_events.extend(events)
        manifest_entries.append(entry)
        manifest_for_report.append({
            "source": path.name,
            "sha256": entry.sha256,
            "events": entry.event_count,
            "parser": entry.parser_version,
        })
        print(f"  OK {path.name:25s}  SHA-256={entry.sha256[:16]}...  events={entry.event_count}")

    write_manifest(manifest_entries, MANIFEST_PATH)
    print(f"  Manifest written -> {MANIFEST_PATH.name}")
    print(f"  Total raw events: {len(all_events)}")

    # ------------------------------------------------------------------
    # 2. UTC Normalization
    # ------------------------------------------------------------------
    print("\n[2] UTC Normalization")
    normalizer = UTCNormalizer(default_year=default_year, host_timezones=host_tz)
    for e in all_events:
        normalizer.normalize(e)

    normalized = [e for e in all_events if e.utc_timestamp is not None]
    inferred = sum(1 for e in normalized if e.offset_inferred)
    print(f"  Normalized: {len(normalized)} / {len(all_events)}")
    print(f"  Offset-inferred (flagged): {inferred}")

    for e in sorted(normalized, key=lambda x: x.utc_timestamp)[:3]:  # type: ignore
        flag = " [INFERRED]" if e.offset_inferred else ""
        print(f"    {e.utc_timestamp.isoformat()}  {e.host:15s}  {e.action}{flag}")

    # ------------------------------------------------------------------
    # 3. ATT&CK Tagging (data-driven rules)
    # ------------------------------------------------------------------
    print("\n[3] ATT&CK Technique Tagging")
    tagger = AttackTagger()
    tagger.tag(normalized)
    tagged = [e for e in normalized if e.attack_techniques]
    print(f"  Events with technique tags: {len(tagged)}")
    tech_counts: dict[str, int] = {}
    for e in tagged:
        for t in e.attack_techniques:
            tech_counts[t] = tech_counts.get(t, 0) + 1
    for t, c in sorted(tech_counts.items()):
        print(f"    {t}: {c}")

    # ------------------------------------------------------------------
    # 4. Cross-host Correlation
    # ------------------------------------------------------------------
    print("\n[4] Cross-Host Correlation")
    correlator = CorrelationEngine(time_window_seconds=3600 * 8)
    groups = list(correlator.correlate(normalized))
    print(f"  Correlation groups: {len(groups)}")
    for g in groups:
        print(f"    {g.group_id}  keys={g.keys}  events={len(g.event_ids)}  techniques={g.techniques}")

    # ------------------------------------------------------------------
    # 5. Anomaly Detection
    # ------------------------------------------------------------------
    print("\n[5] Anomaly & Gap Detection")
    detector = AnomalyDetector(spike_window_minutes=5, z_threshold=2.0)
    spikes = detector.detect_spikes(normalized)
    gaps = detector.detect_gaps(normalized, groups)
    print(f"  Spikes: {len(spikes)}")
    for s in spikes[:5]:
        print(f"    host={s.get('host')}  count={s.get('count')}  z={s.get('z_score')}  sev={s.get('severity')}")
    print(f"  Gaps:   {len(gaps)}")
    for g in gaps[:5]:
        print(f"    gap={g['gap_seconds']}s  hosts={g['hosts']}  severity={g['severity']}")

    # ------------------------------------------------------------------
    # 6. Storage
    # ------------------------------------------------------------------
    print("\n[6] Storage (SQLite via StorageBackend)")
    if DB_PATH.exists():
        DB_PATH.unlink()
    store = SQLiteStore(DB_PATH)
    n = store.write_events(normalized)
    print(f"  Inserted {n} events -> {DB_PATH.name}")

    # ------------------------------------------------------------------
    # 7. Forensic Narrative
    # ------------------------------------------------------------------
    print("\n[7] Attacker Narrative (primary correlation group)")
    print("-" * 70)
    if groups:
        primary = max(groups, key=lambda g: len(g.event_ids))
        print(primary.narrative)
        print("-" * 70)
        print(f"  Group span: {primary.start_utc} -> {primary.end_utc}")
        print(f"  Techniques: {primary.techniques}")
        benign = len(normalized) - len(primary.event_ids)
        print(f"  Attacker-thread events: {len(primary.event_ids)}  |  Benign excluded: {benign}")
    else:
        print("  (no groups formed)")

    # ------------------------------------------------------------------
    # 8. Export + Report
    # ------------------------------------------------------------------
    report = {
        "manifest": manifest_for_report,
        "total_events": len(normalized),
        "offset_inferred_count": inferred,
        "technique_counts": tech_counts,
        "correlation_groups": [
            {
                "group_id": g.group_id,
                "keys": g.keys,
                "event_count": len(g.event_ids),
                "techniques": g.techniques,
                "start": g.start_utc.isoformat() if g.start_utc else None,
                "end": g.end_utc.isoformat() if g.end_utc else None,
                "narrative": g.narrative,
            }
            for g in groups
        ],
        "spikes": spikes,
        "gaps": gaps,
        "ground_truth_match": {
            "attacker_ip_seen": any(e.src_ip == gt.get("attacker_ip") for e in normalized),
            "compromised_user_seen": any(e.user == gt.get("compromised_user") for e in normalized),
        },
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)

    event_dicts = [e.to_dict() for e in normalized]
    export_paths = export_all(report, event_dicts, EXPORT_DIR)
    
    ui_data_dir = ROOT / "ui" / "src" / "data"
    ui_paths = export_ui_data(report, event_dicts, ui_data_dir)
    
    print(f"\n[8] Exports -> {EXPORT_DIR}")
    for k, p in export_paths.items():
        print(f"    {k}: {p.name}")
    print(f"\n    UI Data -> {ui_data_dir}")
    for k, p in ui_paths.items():
        print(f"    {k}: {p.name}")

    v = verify_manifest(MANIFEST_PATH, base_dir=DATA_DIR)
    print(f"\n[9] Manifest verification: ok={v['ok']}  checked={v['checked']}  mismatches={len(v['mismatches'])}")

    store.close()
    elapsed = time.perf_counter() - t0
    print(f"\nDone in {elapsed:.2f}s.")
    print(f"UI Integration: Data populated at {ui_data_dir}")
    print(f"To run the Enhanced UI:\n  cd {ROOT / 'ui'}\n  npm install\n  npm run dev")


if __name__ == "__main__":
    main()

# Chronos Forensics Engine

**Track:** PS-10 — Forensics & Incident Response  
**Problem:** Automated Incident Timeline Reconstruction

Chronos ingests heterogeneous forensic logs (Linux `auth.log`, Windows EVTX/JSON, Apache/Nginx, Cisco syslog, AWS CloudTrail), preserves evidentiary integrity (SHA-256 + ingest manifest), normalizes every timestamp to UTC (including missing-offset and DST cases), correlates events across hosts into an attacker-centric narrative, tags MITRE ATT&CK techniques, detects spikes and dwell-time gaps, and produces an interactive timeline plus a forensic summary report.

---

## Quick Start

```bash
# 1. Generate the synthetic aerospace-breach dataset
python3 scripts/generate_synthetic_dataset.py

# 2. Run the full pipeline (ingest → normalize → tag → correlate → anomalies → store)
python3 scripts/run_pipeline.py
```

Outputs:
- `data/synthetic/` — multi-format log files + `ground_truth.json` + `manifest.json`
- `data/chronos.db` — SQLite time-indexed event store
- `data/forensic_report.json` — correlation groups, narrative, spikes, gaps

---

## Project Layout

```
chronos/
├── scripts/
│   ├── generate_synthetic_dataset.py   # Module 7 – coherent multi-stage incident
│   └── run_pipeline.py                 # End-to-end runner
├── src/
│   ├── schema.py                       # ChronosEvent, CorrelationGroup, manifest
│   ├── parsers/                        # Per-format parsers + integrity hashing
│   ├── normalization/utc.py            # Offset inference, DST, clock-skew flags
│   ├── correlation/engine.py           # Cross-host IP/user/session join
│   ├── anomaly/
│   │   ├── tagger.py                   # Technique-level ATT&CK rules
│   │   └── detector.py                 # Rolling z-score spikes + adaptive gaps
│   ├── storage/sqlite_store.py         # Offline fallback (ES-ready design)
│   └── ui/timeline.html                # Lightweight timeline viewer
├── data/
│   ├── synthetic/                      # Generated logs + ground truth
│   ├── chronos.db
│   └── forensic_report.json
├── tests/
├── requirements.txt
└── README.md
```

---

## Architecture (summary)

1. **Ingestion & Integrity** — read-only intake, SHA-256 of every source, ingest manifest.
2. **Parsing & UTC Normalization** — format detectors, host-timezone offset inference, DST via `zoneinfo`, clock-skew flags.
3. **Storage** — SQLite with `utc_epoch_ns` index (Elasticsearch drop-in later).
4. **Correlation / ATT&CK / Anomalies** — IP+user joins → correlation groups; rule-based technique tags; z-score spikes + adaptive inter-event gaps.
5. **Visualization & Reporting** — narrative view, JSON/CSV/PDF-ready export, HTML timeline shell.

---

## Synthetic Scenario (ground truth)

| Stage                    | Techniques     | Key signals                                      |
|--------------------------|----------------|--------------------------------------------------|
| Initial Access           | T1566, T1190   | External IP → web portal `/login`                |
| Credential Dumping       | T1003          | WIN-ENG-07 Event 4688 (mimikatz-like) + 4672     |
| Lateral Movement         | T1021, T1078   | SSH to `lin-db-03` as `j.mitchell`               |
| Staging & Exfiltration   | T1560, T1041   | `tar` via sudo → S3 `PutObject`                  |

Deliberate challenges baked into the dataset:
- Mixed timezones (America/New_York, Europe/London, America/Los_Angeles, UTC)
- Syslog lines without year or offset
- One host with +47 s clock skew
- Correlated identifiers across all five formats

---

## Extending the Prototype

| Next step                         | How                                                                 |
|-----------------------------------|---------------------------------------------------------------------|
| Real binary EVTX                  | `pip install python-evtx` and point `EvtxParser` at `.evtx` files  |
| Elasticsearch                     | Swap `SQLiteStore` for an ES bulk indexer (schema already time-centric) |
| FastAPI query layer               | Expose `/events?start=&end=&host=&technique=` for the HTML UI      |
| PDF executive summary             | Feed `forensic_report.json` narrative into ReportLab / fpdf2       |
| Larger scale                      | Stream parsers + chunked bulk inserts; the design is already streaming-friendly |

---

## Verification Checklist (from the plan)

- [x] Per-format parsers emit a common `ChronosEvent` schema  
- [x] SHA-256 + ingest manifest recorded  
- [x] UTC normalization with offset-inferred flags  
- [x] Cross-host correlation recovers the single attacker group  
- [x] Technique-level ATT&CK tags applied  
- [x] Gap detection surfaces dwell times between stages  
- [x] SQLite store + JSON forensic report  
- [ ] Interactive Vis.js/D3 timeline (HTML shell present; wire to API)  
- [ ] Unit tests for each parser & normalization edge case  

---

## License / Notes

Prototype built for a time-boxed forensics / IR challenge.  
Not production-hardened; treat all inferred timestamps and correlation groups as analyst-reviewable hypotheses.

---

## Recent hardening (post-review)

* **Explicit ingestion module** – `src/ingestion/manifest.py` owns SHA-256 + chain-of-custody writes; pipeline no longer buries this logic.
* **Export module** – `src/reporting/export.py` produces CSV event log, executive JSON, and PDF/TXT forensic summary.
* **StorageBackend ABC** – `src/storage/base.py` defines `write_events` / `query_range` / `aggregate_counts`; SQLite implements it (ES-ready).
* **Data-driven ATT&CK rules** – `config/attack_mappings.yaml` + fallback embedded rules.
* **Correlation keys expanded** – IP, user, session/process ID, hostname.
* **Spike-capable synthetic data** – generator injects a concentrated auth-storm so z-score detection fires (3 spikes in demo run).
* **Tests** – `test_correlation.py` (recall + benign exclusion) and `test_e2e_pipeline.py` (technique coverage, stage order, gaps, offset flags).
* **Demo talking points**
  - Chronos isolated the attacker’s **11-event thread** from **69 benign** background events.
  - **53/80** timestamps flagged offset-inferred (intentional timezone ambiguity).
  - Spike detector flags the injected auth storm on `lin-db-03` (z≈3.06).
  - Manifest verification returns `ok=True` after re-hashing all sources.

### How to run (updated)

```bash
python3 scripts/generate_synthetic_dataset.py
python3 scripts/run_pipeline.py
python3 tests/test_parsers_and_norm.py
python3 tests/test_correlation.py
python3 tests/test_e2e_pipeline.py

# UI
python3 -m http.server 8000 --directory .
# then open http://localhost:8000/src/ui/timeline.html
```

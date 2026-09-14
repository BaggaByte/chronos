# Implementation Plan: Chronos Forensics Engine

**Track:** PS-10 — Forensics & Incident Response
**Problem:** Automated Incident Timeline Reconstruction

---

## 1. Project Overview & Scope

### 1.1 Executive Summary
Chronos is an automated multi-source forensic timeline parser and visual reconstruction platform for incident response. Following a data exfiltration breach at an aerospace organization, investigators must reconcile hundreds of gigabytes of heterogeneous logs — Linux `auth.log`, Windows `EVTX`, Apache/Nginx access logs, Cisco firewall syslogs, and AWS CloudTrail — into one trustworthy, chronologically correct narrative.

Manual workflows (spreadsheets, `grep`, ad-hoc scripts) fail at this scale for three reasons: timestamp/timezone misalignment across sources, no systematic way to correlate the same actor across five different log formats, and no defensible chain of custody over the evidence. Chronos addresses all three: it ingests logs with integrity preservation, normalizes every timestamp to UTC, correlates events across hosts into attacker stages, flags anomalies and suspicious gaps, and renders an interactive, exportable timeline.

### 1.2 Core Objectives & Requirements
* **Multi-format ingestion** — EVTX, Linux auth.log, Apache/Nginx, Cisco syslog, AWS CloudTrail.
* **Evidentiary integrity** — hash raw sources on ingestion; never mutate originals; log every transform.
* **UTC normalization** — resolve ISO8601, epoch, syslog-style, and localized Windows timestamps, including missing-offset and DST edge cases.
* **Cross-host correlation** — join events across sources on shared identifiers (IP, username, session/process ID, hostname) into one attacker-centric narrative.
* **ATT&CK-tagged categorization** — technique-level tagging, not just tactic-level labels.
* **Anomaly & gap detection** — named, explainable statistical methods.
* **Interactive timeline + export** — zoomable/searchable UI, PDF/CSV forensic summary.

---

## 2. Architecture & Data Flow

```
+-------------------------------------------------------------------------------+
| 1. INGESTION & INTEGRITY LAYER                                                |
|  Read-only log intake | SHA-256 hash of raw sources | Ingest manifest/audit log|
|  auth.log | EVTX | Apache/Nginx | Cisco Syslog | AWS CloudTrail               |
+-------------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------------+
| 2. PARSING & UTC NORMALIZATION CORE                                           |
|  Format Detectors | Per-format Parsers | Timezone Resolver (offset inference, |
|  DST handling) | Clock-skew flagging across hosts                            |
+-------------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------------+
| 3. STORAGE & QUERY LAYER                                                      |
|  Elasticsearch index (time-series events) — fallback: SQLite w/ time index    |
+-------------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------------+
| 4. CORRELATION, CATEGORIZATION & ANOMALY PIPELINE                             |
|  Cross-host Correlator (IP/user/session/host) | ATT&CK Technique Tagger |     |
|  Spike Detector (rolling z-score/IQR) | Time-Gap Analyzer (adaptive threshold)|
+-------------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------------+
| 5. VISUALIZATION & REPORTING UI                                               |
|  Zoomable Timeline (Vis.js/D3) | Attacker Narrative View | PDF/CSV Export     |
+-------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Specifications

### Module 1: Ingestion & Integrity Engine
* Read-only intake of all five log types; original files are never modified in place.
* SHA-256 hash computed and recorded for every ingested file before parsing, plus an ingest manifest (source, hash, ingest time, parser version) — the minimum viable chain-of-custody record.
* Parsers:
  * **EVTX** — `python-evtx`, extracting Event IDs (4624 logon, 4672 special privileges, 4688 process creation, etc.).
  * **Linux auth.log** — regex-based parsing for SSH auth, `sudo` elevation, session open/close.
  * **Apache/Nginx** — combined/common log format parser (`apache-log-parser` or custom regex) for path, status, UA, IP.
  * **Cisco syslog** — RFC 3164/5424-style parser for connection/deny events, ports, direction.
  * **AWS CloudTrail** — JSON records for `eventName`, `sourceIPAddress`, `userIdentity`, S3/IAM actions.
* All parsers emit a common `ChronosEvent` schema: `{event_id, source_type, host, user, src_ip, dst_ip, raw_timestamp, utc_timestamp, action, raw_ref}`.

### Module 2: UTC Normalization Engine
* Input formats: ISO8601, epoch (s/ms), syslog-style (`Oct 11 14:32:01`, no year/tz), localized Windows timestamps.
* **Offset inference**: where a source has no explicit UTC offset (syslog, some EVTX exports), resolve using declared/assumed host timezone metadata rather than defaulting silently to UTC — flag any event whose offset was inferred rather than explicit.
* **DST handling**: use `pytz`/`zoneinfo` transition tables, not fixed offsets, so spring-forward/fall-back does not silently shift or duplicate an hour of events.
* **Clock-skew flag**: when overlapping activity from two hosts implies an inconsistent order once normalized, flag the pair for analyst review rather than trusting host clocks blindly.
* Output: nanosecond-precision UTC epoch + ISO8601-UTC string.

### Module 3: Cross-Host Correlation Engine
* Correlation keys, applied within a configurable time window: source/destination IP, username, session or process ID (where available), and hostname.
* Produces correlation groups ("this IP + this user across these 3 hosts") that Module 4 uses to build the unified attacker narrative — this is what turns five separate log streams into one story.

### Module 4: ATT&CK Tagging & Anomaly Detection
* **Technique-level tagging** (not just tactic labels):
  * Initial Access → T1566 (Phishing) / T1190 (External Web Exploitation)
  * Credential Dumping → T1003 (OS Credential Dumping)
  * Lateral Movement → T1021 (Remote Services — RDP/SSH)
  * Data Staging/Exfiltration → T1560 (Archive Collected Data), T1041 (Exfiltration Over C2 Channel)
* **Execution spike detection**: rolling-window z-score or IQR outlier detection on per-host, per-category event counts.
* **Time-gap analysis**: adaptive threshold on inter-event time deltas within a correlation group, flagging dwell time between stages (e.g., credential dump → lateral movement) as suspicious inactivity.
* Both methods are intentionally simple/statistical rather than ML-based — explainable within a short judging window and buildable inside the timeline.

### Module 5: Storage & Query Layer
* **Primary**: Elasticsearch index per engagement — native time-range queries and aggregations power both the anomaly detection and the zoomable timeline without custom indexing code.
* **Offline/fallback**: SQLite with an indexed `utc_timestamp` column, for demo environments without an ES instance.

### Module 6: Interactive Timeline & Forensic Summary Interface
* Zoomable/searchable timeline (Vis.js Timeline or D3), filterable by host, IP, user, ATT&CK technique, severity.
* Correlated attacker narrative view showing the joined multi-host sequence from Module 3.
* PDF/CSV export: executive summary (stage-by-stage narrative + key IOCs) and full detailed event log.

### Module 7: Synthetic Dataset Generator (new)
* Since real breach logs aren't available, a generator script fabricates a coherent multi-stage incident — spear-phishing → credential dump → lateral movement → exfiltration — with **correlated identifiers and timestamps** written out simultaneously in all five target formats (including deliberately mixed timezones/offsets to exercise Module 2, and one deliberately clock-skewed host to exercise the skew flag).
* This dataset is both the test fixture for Module 1–4 and the demo dataset for the video/deck.

---

## 4. Prototype Implementation Roadmap

### Phase 1: Ingestion, Integrity & UTC Normalization
* Define the `ChronosEvent` schema.
* Build the synthetic dataset generator (Module 7) — needed before anything else can be tested.
* Implement per-format parsers with SHA-256 ingest hashing and manifest logging.
* Implement UTC normalization with offset inference, DST handling, and clock-skew flagging.

### Phase 2: Storage, Correlation & Anomaly Pipeline
* Stand up the Elasticsearch index (or SQLite fallback) and bulk-load normalized events.
* Build the cross-host correlator (IP/user/session/host join logic).
* Build the ATT&CK technique tagger.
* Implement rolling z-score/IQR spike detection and adaptive-threshold gap analysis.

### Phase 3: Visual Timeline Frontend & Narrative Engine
* Zoomable timeline UI (Vis.js/D3) backed by the storage layer's time-range queries.
* Attacker narrative view rendering correlation groups in sequence.
* Search/filter by host, IP, user, ATT&CK technique, severity.

### Phase 4: Forensic Reporting & Validation
* PDF/CSV forensic summary exporter.
* Run full pipeline against the synthetic aerospace-breach dataset; confirm correct UTC ordering, correct correlation grouping, and correct anomaly/gap flags against the dataset's known ground truth.
* Unit tests per parser (one fixture file per format, asserting field extraction) and per normalization edge case (missing offset, DST boundary, epoch ms vs s).

### Phase 5: Packaging & Deliverables
* Presentation deck (.pptx/.pdf): architecture, normalization approach, correlation logic, live-timeline screenshots.
* 3–5 minute demo video: ingest the synthetic dataset live, show timeline reconstruction, anomaly flags, and exported report.
* Source code ZIP: parsers, correlation engine, dashboard, synthetic dataset generator, README with setup instructions.

### Illustrative time-boxed schedule (adjust to actual hackathon duration/team size)
| Block | Focus |
|---|---|
| Day 1 AM | Schema + synthetic dataset generator |
| Day 1 PM | Parsers + ingest hashing |
| Day 2 AM | UTC normalization + correlation engine |
| Day 2 PM | Storage layer + ATT&CK tagging + anomaly detection |
| Day 3 AM | Timeline UI + export |
| Day 3 PM | End-to-end validation + deck + demo video + packaging |

---

## 5. Tech Stack (recommended)

* **Core language**: Python — parsers, normalization, correlation, anomaly detection.
* **Backend/API**: FastAPI, serving query endpoints to the frontend.
* **Storage**: Elasticsearch (primary — native time aggregations for both timeline and spike detection); SQLite as an offline fallback.
* **Frontend**: Vis.js Timeline or D3 for the zoomable view; lightweight HTML/JS over a full SPA framework, given the time budget.
* **Key libraries**: `python-evtx`, `python-dateutil`/`zoneinfo`, `apache-log-parser`, `boto3` (CloudTrail JSON handling), `pandas`/`numpy` for the statistical anomaly checks.

---

## 6. Verification & Testing Strategy

1. **Per-parser unit tests**: one fixture file per format, asserting correct field extraction and count.
2. **Timestamp normalization tests**: explicit-offset, missing-offset, epoch (s/ms), and DST-boundary cases, each asserting exact UTC alignment.
3. **Correlation accuracy test**: given the synthetic dataset's known actor identifiers, confirm all five log sources are joined into a single correlation group.
4. **End-to-end aerospace breach simulation**: run the full pipeline on the synthetic multi-gigabyte-scale dataset; confirm unified narrative generation, correct stage ordering, and correct anomaly/gap flags against ground truth.
5. **Success metrics**: parser field-extraction accuracy (%), UTC normalization accuracy on edge cases (%), correlation recall against known ground-truth groups, and end-to-end reconstruction time vs. a manual `grep`/spreadsheet baseline on the same dataset.

---

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| EVTX parsing library gaps on obscure Event IDs | Scope to the Event IDs actually used in the synthetic dataset; document as a known limitation |
| Performance at "hundreds of GB" scale within a prototype timeframe | Demonstrate on a representative multi-GB synthetic slice; design ingestion as streaming/chunked so the approach scales even if the demo doesn't run the full volume live |
| Clock-skew/missing-offset heuristics being wrong on real-world edge cases | Flag inferred/uncertain timestamps in the UI rather than silently trusting them |
| Time pressure cutting into Phase 5 (deliverables) | Schedule packaging explicitly as its own phase, not squeezed in after Phase 4 |

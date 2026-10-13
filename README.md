# AIORI PS-013 Incident Timeline & Evidence Collection

A lightweight, zero-infrastructure forensic tool designed for incident responders. It ingests Linux `auth.log` and Nginx `access.log` files, preserves them untouched in a read-only evidence store with SHA-256 integrity manifests, parses them into normalized SQLite databases with UTC timestamps and full-text search (FTS5), records parsing gaps without dropping unparsed lines, and automatically estimates and corrects inter-host clock skew.

---

## Installation

```bash
python -m venv .venv

# Activate virtual environment:
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Unix / macOS:
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

---

## CLI Usage & Commands

The package installs the `forensic` command-line interface with 8 dedicated sub-commands:

### 1. Ingest Evidence
Copies source log files untouched into `cases/<case_id>/evidence/`, computes SHA-256 hashes on the fly, marks copies read-only (`0o444`), initializes the SQLite database, and creates `manifest.json` and `manifest.sha256`:
```bash
forensic ingest --case cases/s1_ssh_bruteforce --sources scenarios/s1_ssh_bruteforce/sources.json --collector analyst
```

### 2. Verify Evidence Integrity
Re-computes SHA-256 hashes of all stored evidence files and compares them against `manifest.json`, `manifest.sha256`, and the SQLite `evidence` table. Returns exit code `0` (`OK`) or `1` (`TAMPERED` / `MISSING`):
```bash
forensic verify --case cases/s1_ssh_bruteforce
```

### 3. Build Database & Full-Text Search
Parses stored evidence lines, converts timestamps to normalized UTC ISO-8601, extracts structured attributes (`event_type`, `severity`, `src_ip`, `username`, `detail`), records unparsed lines into `parse_gaps`, and rebuilds the SQLite FTS5 search index:
```bash
forensic build --case cases/s1_ssh_bruteforce
```

### 4. Estimate & Correct Clock Skew
Identifies multi-host anchor pairs (identical source IP, action type, and target within an observation window) to calculate median clock offset and standard deviation confidence notes:
```bash
# Automated anchor-based estimation:
forensic skew --case cases/s3_clock_skew --reference web01

# Manual operator override:
forensic skew --case cases/s3_clock_skew --offset db01=-420
```

### 5. Search Timeline (CLI)
Search normalized events with full-text search and filters (`--host`, `--ip`, `--type`, `--from`, `--to`):
```bash
forensic search --case cases/s2_web_attack "UNION"
forensic search --case cases/s1_ssh_bruteforce --type ssh_accepted_login
```

### 6. Generate Incident Report
Exports a self-contained incident report in HTML (styled for PDF printing), JSON, and CSV:
```bash
forensic report --case cases/s3_clock_skew --out reports/s3_clock_skew.html --json reports/s3_clock_skew.json --csv reports/s3_clock_skew.csv
```

### 7. Interactive Timeline Viewer (Streamlit)
Launches the interactive 5-tab forensic dashboard (Timeline histogram & table, Event Details with cryptographic hashes & context window, Evidence Manifest with live tamper verification, Parsing Gaps, and Clock Skew before/after comparison):
```bash
forensic ui --case cases/s3_clock_skew
```

### 8. Batch Run All Scenarios
Convenience command to ingest, build, estimate skew, and generate reports across all scenarios in `scenarios/`:
```bash
forensic run-all
```

---

## Scenarios & Expected Metrics

Tested against 3 synthetic incidents with ground truth:

| Scenario | Incident Type | Expected Parse Gaps | Expected Clock Skew |
|---|---|---|---|
| **S1** `s1_ssh_bruteforce` | SSH brute-force & privilege escalation | 4 gaps (97.6% parsed) | None (single host) |
| **S2** `s2_web_attack` | SQLi probe, webshell upload & access | 5 gaps (96.4% parsed) | None (single host) |
| **S3** `s3_clock_skew` | Multi-host pivot with ~7 min clock drift | 0 gaps (100% parsed) | `db01` ≈ -420s (estimated: -421.5s, 10 anchors) |

---

## Results & Evaluation

- **Ground Truth Validation**: 18 of 18 attack progression steps matched within 1.5 seconds across all 3 scenarios (`tests/test_ground_truth.py`).
- **Clock Skew Resolution**: In S3, `db01` offset was estimated at -421.5 s (true offset: -420 s) with 10 anchor pairs and standard deviation 0.9 s (high confidence), restoring true causal ordering between `web01` webshell upload and `db01` pivot.
- **Parsing Gap Transparency**: Zero silent drops. Identified 4 gaps in S1, 5 in S2, and 0 in S3; documented in [evaluation/parsing_gap_analysis.md](evaluation/parsing_gap_analysis.md).
- **Triage Performance vs Manual Baseline**: In our small sample (6 timed sessions, testers who know the tool), the tool gave a 3.1x overall speedup (median 11.2 s vs 34.8 s) versus raw `grep`/`less`/`sort`, and the manual S3 session gave a wrong first-login time under the 7-minute clock skew while all tool answers were correct. These are indicative results only; see [evaluation/triage_summary.md](evaluation/triage_summary.md) for the data and limitations.
- **Cryptographic Evidence Integrity**: SHA-256 manifest and read-only preservation; tampering of even a single byte in stored evidence is immediately detected and flagged.

---

## SQLite Database Architecture

- `case_meta`: Key-value storage for case configuration (`case_id`, `created_at_utc`, `tool_version`).
- `evidence`: Registry of collected files and their metadata (SHA-256 hash, size, line count, collector, timezone).
- `events`: Normalized events with `ts_utc`, `ts_utc_corrected`, `skew_offset_s`, `event_type`, `severity`, and raw line traceability.
- `events_fts`: SQLite FTS5 full-text index across `message`, `raw_line`, `username`, `src_ip`, and `detail`.
- `parse_gaps`: Structured log of unparsed lines with reason (`no_regex_match`, `bad_timestamp`, `truncated`, `empty_line`, `encoding_error`).
- `skew_corrections`: Record of calculated offsets, reference hosts, anchor counts, standard deviation, and confidence notes.

---



## Known Limitations & Out of Scope

- **Syslog Timestamp Ambiguity**: Syslog formats omit the year and timezone; these are declared by the operator (via `sources.json`) or inferred from file mtime.
- **Anchor Pairing Assumption**: Clock skew anchor matching assumes corresponding actions on different hosts occur within 5 seconds of each other.
- **DST Fold**: Daylight Saving Time fold ambiguity is treated with `fold=0`.
- **Supported Formats**: Prototype supports Linux syslog (`auth.log`) and Nginx combined `access.log`.
- **Out of Scope**: Not forensically certified; does not perform live endpoint takeover or malware removal.

---

## Deliverables

- [x] [docs/pseudocode.md](docs/pseudocode.md): Core algorithm pseudocode snippet
- [x] [docs/demo_script.md](docs/demo_script.md): Rehearsed 5-minute demo script
- [x] [A3-PS013-TC067.pdf](A3-PS013-TC067.pdf): Final presentation slide deck
- [x] [evaluation/triage_summary.md](evaluation/triage_summary.md): Human triage timing comparison summary
- [x] [evaluation/parsing_gap_analysis.md](evaluation/parsing_gap_analysis.md): Parsing coverage and gap report

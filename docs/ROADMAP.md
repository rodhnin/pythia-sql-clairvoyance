# Pythia SQL Clairvoyance - Development Roadmap

---

## v0.1.0 — Initial Release ✅ RELEASED (November 2025)

**Status:** Production Ready

### Features Included

#### Core SQL Injection Detection

- ✅ **Error-Based Detection**: Multi-DBMS error signature recognition (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- ✅ **Boolean Blind Detection**: Logic-based inference with true/false response comparison
- ✅ **Time-Based Blind Detection**: Timing attacks with baseline measurement
- ✅ **UNION-Based Detection**: Column counting, injectable column identification, data extraction
- ✅ **Multi-Method Detection**: GET parameters, POST data, headers, cookies
- ✅ **Intelligent Crawling**: Form discovery, link extraction, parameter enumeration (depth 2, 100 pages)

#### Performance & Control

- ✅ **Rate Limiting**: Safe 2.0 req/s / Aggressive 5.0 req/s, thread-safe implementation
- ✅ **Thread Pool Management**: Concurrent testing with 1-20 worker threads
- ✅ **Graceful Degradation**: Continues testing even if endpoints fail

#### Infrastructure

- ✅ **Consent Token System**: HTTP `.well-known` or DNS TXT verification, 48-hour expiry
- ✅ **SQLite Database**: Scan history and findings (shared with Argus/Hephaestus at `~/.argos/argos.db`)
- ✅ **Dual Reporting**: JSON (machine-readable) and HTML (human-readable)
- ✅ **AI-Powered Remediation**: OpenAI, Anthropic, Ollama via LangChain 1.0.0
- ✅ **Docker Support**: Vulnerable labs (PHP & Flask) for safe testing
- ✅ **DBMS Fingerprinting**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite

---

## v0.2.0 — Full Parity & Enterprise Features ✅ RELEASED (May 2026)

**Status:** Released

This version achieves complete 4/4 technique parity across all difficulty levels (DVWA low/medium/high), adds two new detection vectors, and introduces deep toolchain integration.

### What Was Delivered

#### New Detection Vectors

- ✅ **Second-Order SQLi** (`PYTHIA-SQL-040`): Store→retrieve injection pattern detection. Maps POST routes (register, comment, profile) to retrieval routes (dashboard, profile, admin).
- ✅ **ORDER BY / GROUP BY Injection** (`PYTHIA-SQL-050`): Numeric sort parameter injection via behavioral comparison.

#### Session-Variable Chain (DVWA High Parity)

- ✅ POST→GET chain detection for all 4 techniques
- ✅ Race condition prevention (sequential session-var processing)
- ✅ JS-aware popup URL extraction (`--js` flag) with front-of-queue BFS priority

#### DBMS-Specific Finding Codes

- ✅ Error-based split into 5 codes: MySQL (001), PostgreSQL (002), MSSQL (003), Oracle (004), SQLite (005)
- ✅ Time-based split into 3 codes: MySQL SLEEP (020), MSSQL WAITFOR (021), PostgreSQL pg_sleep (022)
- ✅ UNION-based split into 2 codes: parameter (030), cookie (031)

#### WAF Bypass Payloads

- ✅ 60 error-based, 30 boolean-blind, 35 time-based, 45 UNION-based bypass variants
- ✅ Techniques: hex encoding, URL double-encoding, inline comments (`/*!*/`), case variation, whitespace variants
- ✅ Active ONLY in `--aggressive` mode

#### Report Enrichment

- ✅ OWASP A03 mapping for all `PYTHIA-SQL-*` codes (`pyth/core/owasp.py`)
- ✅ CWE-89 classification for all findings
- ✅ CVSS base score 9.8 in every finding
- ✅ Contextual risk scoring (`contextual_score` field): HTTP vs HTTPS, PII detection, root DB user
- ✅ CVE enrichment via NVD API (`--ai-agent` mode, no API key required)

#### CI/CD Integration

- ✅ `--fail-on <severity>`: Exit 10 if findings found at threshold or above; Exit 0 for clean scans
- ✅ `--sarif`: SARIF 2.1.0 output for GitHub Security, GitLab SAST, Azure DevOps (logs to stderr)

#### Diff Reports

- ✅ `--diff last`: Compare vs most recent completed scan for same target
- ✅ `--diff <scan_id>`: Compare vs specific scan by ID
- ✅ New/fixed/persisting finding classification
- ✅ Mode mismatch warning (informational)

#### Auth Headers

- ✅ `--auth-header`: Custom HTTP headers (Bearer tokens, API keys, cookies). Pass multiple times.
- ✅ `--auto-csrf`: Automatic CSRF token extraction and inclusion

#### Enhanced Crawler

- ✅ `--no-crawl`: Skip BFS, test target URL only
- ✅ `--js`: JS-aware popup/onclick URL extraction (regex-based, no Playwright dependency)
- ✅ `--max-depth` (default 2) and `--max-pages` (default 100) configurable

#### AI Enhancements

- ✅ `--ai-provider` and `--ai-model` CLI flags (no YAML editing required)
- ✅ `--ai-stream`: Streaming output token by token
- ✅ `--ai-compare "openai,anthropic"`: Multi-provider comparison in parallel
- ✅ `--ai-agent`: NVD CVE lookup agent
- ✅ `--ai-budget`: Cost cap per scan
- ✅ `AICostTracker`: Tracks tokens and cost, saves to `~/.argos/costs.json`
- ✅ Default model: `gpt-4o-mini-2024-07-18`
- ✅ Graceful degradation without API key (exit 0, scan completes)

#### HTML Report Enhancements

- ✅ Filter bar (severity, OWASP, detection method, DBMS)
- ✅ OWASP/CWE/CVE badges per finding
- ✅ CVSS and contextual score display
- ✅ Payload visualization with syntax highlighting
- ✅ Expandable evidence sections
- ✅ AI tabs (standard / agent / compare)
- ✅ Diff section in report

#### Database

- ✅ `ai_costs` table added (schema v1.1)
- ✅ `save_ai_cost()`, `list_scans()`, `get_findings()` Python API
- ✅ Costs saved to `~/.argos/costs.json` (shared Argos Suite)

#### False Positive Hardening

- ✅ Boolean-blind: `SequenceMatcher` similarity scoring (< 0.95 threshold)
- ✅ Boolean-blind: `min_consistent_results=2` — requires 2 confirming payloads
- ✅ Time-based: triple confirmation (baseline → payload → re-confirm)
- ✅ Dedup key: `(base_url, method, vulnerable_param, detection_method)` — no pagination duplicates

### v0.2.0 QA Results

| Target         | Mode                              | Findings | Notes                                 |
| -------------- | --------------------------------- | -------- | ------------------------------------- |
| PHP lab 8081   | aggressive                        | 26       | All techniques                        |
| Flask lab 8082 | `--js --aggressive`               | 18       | Session-var + second-order + ORDER BY |
| DVWA low       | `--no-crawl --aggressive`         | 4        | 4/4 techniques                        |
| DVWA medium    | `--no-crawl --aggressive`         | 4        | 4/4 techniques                        |
| DVWA high      | `--js --max-pages 2 --aggressive` | 4        | Session-var chain                     |
| Static URL     | `--aggressive`                    | 0        | No false positives                    |

---

## v0.3.0 — Pytest Suite & Developer Tooling (Q3 2026)

**Status:** Planned

**Focus:** Test coverage, developer experience, interactive tooling

### Planned Features

#### Test Suite (0 → 40+ tests)

- Pytest suite covering all 14 finding codes
- Unit tests for each detector (error-based, boolean-blind, time-based, union-based, second-order, ORDER BY)
- Integration tests against Docker labs
- Schema validation tests
- False positive regression tests
- CI/CD pipeline tests (--fail-on exit codes)

#### Interactive Config Management

- CLI-based configuration without YAML editing
- Profile management (`--save-profile`, `--load-profile`)
- `python -m pyth config set ai.provider anthropic`

#### Database CLI (IMPROV-011)

- `python -m pyth db scans list`
- `python -m pyth db findings search --code PYTHIA-SQL-001`
- `python -m pyth db findings critical --limit 20`
- `python -m pyth db costs summary`

#### Session Expiry Detection

- Detect when authenticated scans lose their session mid-scan
- Automatic re-authentication attempt with provided credentials
- Clear warning when session expires and results may be incomplete

#### Multi-Site Batch Scanning

- `python -m pyth --targets targets.txt` — scan multiple sites from file
- Per-target report generation
- Summary report across all targets

---

## v0.4.0 — Intelligence & Automation (Q1 2027)

**Focus:** ML, automation, advanced capabilities

### Planned Features

- **ML-Based Detection**: Anomaly detection to reduce false positives further
- **Automated Exploitation (Read-Only)**: Controlled data extraction to prove impact without damage
- **REST API Server**: FastAPI-based interface for programmatic scanning
- **AI Chat Interface**: Conversational analysis of scan results
- **Advanced WAF Bypass**: ML-driven payload mutation based on target WAF fingerprint

---

## Positioning

Pythia does not compete with SQLMap on raw exploitation depth. Pythia competes by being the **most ethical, professional, AI-integrated, and CI/CD-ready** open-source SQL injection scanner:

| Capability                           | SQLMap    | Pythia                    |
| ------------------------------------ | --------- | ------------------------- |
| Raw exploitation depth               | Excellent | Not the goal              |
| Ethical consent system               | No        | Yes                       |
| AI-powered remediation               | No        | Yes (3 providers + agent) |
| OWASP/CWE/CVSS metadata              | No        | Yes                       |
| CI/CD integration (SARIF, --fail-on) | Limited   | Yes                       |
| Second-order detection               | Basic     | Yes                       |
| Professional HTML reports            | No        | Yes                       |
| Shared ecosystem DB                  | No        | Yes (Argos Suite)         |
| Cost tracking                        | No        | Yes                       |

---

_Pythia v0.2.0 — May 2026_
_Author: Rodney Dhavid Jimenez Chacin (rodhnin)_

# Changelog

All notable changes to Pythia SQL Clairvoyance will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-04

**v0.2.0 — Full SQLi Parity, AI Integration & Enhanced Detection**

This release achieves complete 4/4 technique parity with industry tools across all difficulty levels (DVWA low/medium/high), adds two new detection vectors, and introduces deep report enrichment with OWASP/CVE/CVSS metadata.

---

### Added

#### New Detection Vectors

- **Second-Order SQLi** (`PYTHIA-SQL-040`): Detects store→retrieve injection patterns (e.g. POST `/register` → GET `/profile/<username>`). Maps automatic store routes (register, comment, profile, settings) to retrieval routes (dashboard, profile, admin).
- **ORDER BY / GROUP BY Injection** (`PYTHIA-SQL-050`): Detects numeric sort parameter injection via behavioral comparison (`/products?sort=price` → error/content change analysis).

#### Session-Variable POST→GET Chain (DVWA High Parity)

- All 4 detectors (error-based, boolean-blind, time-based, union-based) now implement the POST→GET chain for session-variable forms.
- Detection flow: POST payload to action URL → GET parent URL → analyze response. Equivalent to DVWA `security=high` where `session-input.php` stores the value and `sqli/` executes the SQL.
- Scanner isolates session-var forms and runs them sequentially to avoid race conditions on shared session state.

#### WAF Bypass Payloads (`pyth/checks/waf_bypass.py`)

- 60 error-based, 30 boolean-blind, 35 time-based, 45 UNION-based payloads
- WAF bypass variants: hex encoding, URL double-encoding, inline comments (`/*!*/`), case variation, whitespace variants
- Active ONLY in `--aggressive` mode

#### OWASP / CWE / CVE Enrichment

- `pyth/core/owasp.py`: All `PYTHIA-SQL-*` codes → A03 Injection / CWE-89
- `pyth/core/cve_lookup.py`: NVD API lookup (no API key required) by DBMS version + `cweId=CWE-89`
- Each finding enriched with `owasp`, `cwe`, `vulnerabilities[]` (CVE id, CVSS, description, NVD link)

#### Contextual Risk Scoring (`pyth/core/risk_scoring.py`)

- Base CVSS 9.8 (CWE-89) with automatic modifiers: root DB privileges, PII in responses, HTTP vs HTTPS, WAF presence
- `contextual_score` field in every finding

#### AI Cost Tracking & Budget Control

- `PRICING_TABLE` for all major models (GPT-4o, Claude 3.5, Gemini, etc.)
- `AICostTracker` class: tracks tokens + cost per scan, saves to `~/.argos/costs.json` (shared Argos Suite)
- `--ai-budget` flag to cap spend per scan
- `--ai-stream` flag for streaming output token by token

#### AI Agent Mode (`--ai-agent`)

- LangChain agent with NVD CVE lookup tool
- Searches CVEs by detected DBMS version + CWE-89
- Iterative refinement for deeper analysis

#### HTML Report Enhancements (`templates/report.html.j2`)

- Filter bar: filter findings by severity, OWASP category, detection method, DBMS
- OWASP / CWE / CVE badges per finding
- CVSS score display with color coding
- Payload visualization with syntax highlighting
- Expandable evidence sections (request/response diff)
- AI tabs: standard analysis / agent mode / compare mode
- Diff section showing new vs resolved findings vs baseline

#### Enhanced JS-Aware Crawler (`--js` flag)

- `_js_extract_popup_urls()`: extracts `window.open()`, `popUp()`, `open()` URLs from onclick attributes — supports both extensioned (`.php`) and extensionless (Flask/Django routes) URLs
- Popup URLs get front-of-queue priority (`appendleft`) in BFS — ensures session-var pages visited before nav links exhaust `max_pages` budget
- `--js` + `--max-pages 2` sufficient for DVWA high (sqli/ + session-input.php)

#### New CLI Flags

- `--no-crawl`: skip BFS crawl, test only the target URL directly
- `--js`: enable JS-aware popup/onclick URL extraction
- `--auth-header`: pass custom HTTP headers for authenticated scans (Bearer tokens, API keys); can be passed multiple times
- `--auto-csrf`: automatically detect and include CSRF tokens in forms
- `--fail-on <severity>`: exit 10 if findings at or above severity found (CI/CD integration)
- `--sarif`: output SARIF 2.1.0 format for GitHub Security / GitLab SAST (logs redirect to stderr)
- `--diff last` / `--diff <scan_id>`: compare against previous scan
- `--ai-budget`, `--ai-stream`, `--ai-agent`, `--ai-compare`, `--ai-provider`, `--ai-model`

#### Database (`~/.argos/argos.db`)

- `list_scans()`, `get_findings()`, `save_ai_cost()`, `get_ai_costs()` — shared with Argus Suite
- New `ai_costs` table: tool, provider, model, input_tokens, output_tokens, cost_usd, scan_id, created_at
- `tool='pythia'` in all scan records

#### Diff Reports (`pyth/core/diff.py`)

- `compute_diff()`: compare current scan vs last/specific scan
- `_get_last_completed_scan()`: automatic baseline selection for `--diff last`
- New/fixed/persisting finding classification
- Mode mismatch warning (informational only; scan continues)

#### Structured Logging (`pyth/core/logging.py`)

- Secret redaction for cookies, tokens, auth headers in all log output

---

### Fixed

- **`--version` output hardcoded to 0.1.0** → fixed to read from `pyth/__init__.py` (now correctly shows 0.2.0)
- **`cvss=None` in all findings** → fixed: base score 9.8 (CWE-89) set during normalization step
- **`payload=None` in boolean-blind/union-based findings** → fixed: payload promoted from `evidence.variants` list during normalization
- **SARIF stdout mixed with scan logs** → fixed: all log handlers redirected to stderr when `--sarif` is active
- **Flask session-var not detected** → fixed: global nav `onclick` caused wrong `parent_url` assignment; `window.open()` onclick moved to `/user-lookup` page only in Flask lab app
- **Boolean-blind false positives**: `SequenceMatcher` similarity scoring replaces length comparison; `min_consistent_results=2` requires confirmation with second payload before reporting
- **`is_significant_diff` threshold**: Added 3rd condition (`relative_diff >= 1.0% AND diff >= 20 bytes`) to catch small but real differences (DVWA = 71 bytes = 1.56%)
- **Error-based session-var finding URL**: `params_for_url[param_name] = original_value` — finding URL stores original value not payload
- **Dedup key**: changed to `(base_url, method, vulnerable_param, detection_method)` — excludes query params to prevent duplicate findings across paginated URLs
- **Time-based `_create_finding` signature**: corrected `test_times=test_times` kwarg
- **DVWA login CSRF token**: `user_token` extracted from login.php GET response before POST; same for security.php level change
- **`urlparse` shadowing bug**: removed local import inside `scan()` that shadowed module-level import, causing `UnboundLocalError`
- **Crawler onclick regex**: pattern now matches extensionless routes (`/user-input`) in addition to file extensions (`.php`, `.html`)
- **Race condition on session-var forms**: session-var forms run sequentially (error-based then boolean-blind) after parallel phase completes

---

### Changed

- Finding codes expanded to DBMS-specific: `PYTHIA-SQL-001` (MySQL/MariaDB), `002` (PostgreSQL), `003` (MSSQL), `004` (Oracle), `005` (SQLite)
- Post-scan normalization step: promotes `evidence.parameter` → top-level `parameter`, `evidence.method` → `vector`, resolves `Unknown` DBMS via cross-finding URL matching
- `pyth/__init__.py`: version bumped to `0.2.0`
- Default AI model changed from `gpt-4-turbo-preview` to `gpt-4o-mini-2024-07-18`
- Rate limits clarified: safe mode default 2.0 req/s, aggressive mode default 5.0 req/s
- Docker lab `flask-app/app.py`: `window.open('/user-input',...)` onclick moved from global nav to `/user-lookup` page only — ensures crawler assigns correct `parent_url` for session-var detection
- `--fail-on` exit code: exit **10** (not exit 1) when findings found at or above threshold; exit 0 means clean scan

---

### QA Results (2026-03-17/18, aggressive mode)

| Target                                                | Findings    | Notes                                            |
| ----------------------------------------------------- | ----------- | ------------------------------------------------ |
| DVWA low (`?id=1`) `--no-crawl --aggressive`          | 4 findings  | PYTHIA-SQL-001/010/020/030 all 4 techniques      |
| DVWA medium (`sqli/`) `--no-crawl --aggressive`       | 4 findings  | POST form, all techniques                        |
| DVWA high (`sqli/`) `--js --max-pages 2 --aggressive` | 4 findings  | Session-var POST→GET chain                       |
| Flask lab (8082) `--js --aggressive`                  | 18 findings | Session-var /user-lookup, second-order, ORDER BY |
| PHP lab (8081) `--aggressive`                         | 26 findings | All techniques, second-order, ORDER BY           |
| Static URL (false positive test) `--aggressive`       | 0 findings  | No false positives                               |

---

## [0.1.0] - 2025-11-04

**Initial Production Release**

Pythia v0.1.0 is a comprehensive SQL injection scanner with ethical testing practices, AI-powered analysis, and professional reporting. This release includes 4 detection methods, multi-DBMS support, and robust error handling.

---

### Added

#### Core SQL Injection Scanner

**Detection Methods**

- **Error-Based Detection**: Multi-DBMS error signature recognition (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Boolean Blind Detection**: Logic-based inference with true/false response comparison
- **Time-Based Blind Detection**: Timing attacks with baseline measurement and statistical validation
- **UNION-Based Detection**: Column counting, injectable column identification, data extraction attempts

**Testing Vectors**

- GET parameters
- POST data (form fields)
- HTTP headers (User-Agent, Referer, X-\* custom headers)
- Cookies
- JSON payloads
- XML data

**Web Crawler**

- Form discovery and parameter extraction
- Link extraction and navigation
- Maximum depth configuration (default: 2 levels)
- Maximum pages limit (default: 100 pages)
- robots.txt respect
- Intelligent deduplication

**Multi-DBMS Support**

- MySQL/MariaDB detection and payloads
- PostgreSQL detection and payloads
- Microsoft SQL Server detection and payloads
- Oracle detection and payloads
- SQLite detection and payloads

---

#### AI-Powered Analysis

**Multi-Provider Support**

- **OpenAI GPT-4 Turbo**: Premium quality analysis, ~35 seconds, $0.25/scan
- **Anthropic Claude**: Privacy-focused with strong code remediation, ~45 seconds, $0.30/scan
- **Ollama (Local Models)**: 100% offline, no data leaves your machine, free

**Analysis Modes**

- **Technical Tone**: Code remediation with prepared statement examples (PHP, Python, Node.js, Java)
- **Non-Technical Tone**: Executive summaries with business impact and compliance implications
- **Both Modes**: Combined analysis for complete team coverage

**Security & Privacy**

- Automatic sanitization removes sensitive data (credentials, tokens, SQL queries)
- No database credentials or query results sent to AI providers
- Configurable via environment variables and YAML

---

#### Infrastructure & Reporting

**Ethical Testing Framework**

- **Consent Token System**: Verify domain ownership before aggressive testing
    - HTTP verification (`.well-known/verify-{token}.txt`)
    - DNS TXT record verification
    - 48-hour token expiration
    - Shared database with Argus/Hephaestus ecosystem

**Dual Report Formats**

- **JSON Reports**: Machine-readable with schema validation
- **HTML Reports**: Professional, self-contained with severity breakdown

**Database Persistence**

- SQLite database shared with Argus and Hephaestus (`~/.argos/argos.db`)
- Tracks all SQL injection findings across scans
- Consent token management (cross-tool compatibility)

**Advanced Logging**

- Automatic secret redaction (passwords, tokens, database credentials)
- Multiple verbosity levels (`-v`, `-vv`, `-vvv`)
- JSON and text format support

---

#### Performance & Control

**Rate Limiting**

- Configurable request throttling
- Default: 2.0 req/s (safe) / 5.0 req/s (aggressive)

**Concurrent Testing**

- Thread pool management (1-20 workers)
- Parallel injection testing for faster scans
- Intelligent retry logic
- Graceful degradation on failures

**Scan Modes**

- **Safe Mode** (default): Error-based + Boolean-blind, no consent required
- **Aggressive Mode**: All 4 techniques, requires verified ownership

---

#### Error Handling & Resilience

- Handles timeouts, DNS failures, connection errors gracefully
- Automatic database corruption detection and recovery
- Ctrl+C handling with proper scan status updates (status set to "aborted")
- Continues testing despite individual endpoint failures

**Standardized Exit Codes**

- `0`: Scan completed successfully (or no findings at `--fail-on` threshold)
- `1`: Technical error (connection, timeout, database)
- `10`: Findings found at or above `--fail-on` severity threshold
- `130`: User cancelled (Ctrl+C)

---

### Performance

**Scan Speed**

- Safe mode: 8-60 seconds (depending on target)
- Aggressive mode: 30-180 seconds (with deep testing)
- With AI analysis: +30-50 seconds

---

### Known Limitations (v0.1.0 — resolved in v0.2.0)

- Generic payloads used for all DBMS types (resolved: DBMS-specific codes in v0.2.0)
- Limited JavaScript link extraction (resolved: `--js` flag in v0.2.0)
- Provider switching required manual YAML editing (resolved: `--ai-provider` flag in v0.2.0)
- No cost tracking or budget limits (resolved: `AICostTracker` in v0.2.0)
- No streaming responses (resolved: `--ai-stream` in v0.2.0)

---

## Installation

### Requirements

- Python 3.11+
- pip (Python package manager)

### Quick Start

**1. Clone the repository**

```bash
git clone https://github.com/rodhnin/pythia-sql-clairvoyance.git
cd pythia-sql-clairvoyance
```

**2. Create and activate virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**3. Install dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**4. (Optional) Configure AI providers**

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

**5. Run first scan**

```bash
python -m pyth --target http://localhost:8081
python -m pyth --target http://localhost:8081 --use-ai --html
```

---

## Acknowledgments

- OWASP community for SQL injection research
- LangChain team for AI framework
- OpenAI, Anthropic, and Ollama for AI models
- SQLMap project for inspiration
- Argos ecosystem (Argus, Hephaestus) for shared infrastructure
- All contributors and testers

---

[0.2.0]: https://github.com/rodhnin/pythia-sql-clairvoyance/releases/tag/v0.2.0
[0.1.0]: https://github.com/rodhnin/pythia-sql-clairvoyance/releases/tag/v0.1.0

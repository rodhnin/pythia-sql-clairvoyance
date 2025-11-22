# Changelog

All notable changes to Pythia SQL Clairvoyance will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2025-11-04

**Initial Production Release** 🎉

Pythia v0.1.0 is a comprehensive SQL injection scanner with ethical testing practices, AI-powered analysis, and professional reporting. This release includes 4 detection methods, multi-DBMS support, and robust error handling.

---

### Added

#### Core SQL Injection Scanner

**Detection Methods**

-   **Error-Based Detection**: Multi-DBMS error signature recognition (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
-   **Boolean Blind Detection**: Logic-based inference with true/false response comparison
-   **Time-Based Blind Detection**: Timing attacks with baseline measurement and statistical validation
-   **UNION-Based Detection**: Column counting, injectable column identification, data extraction attempts

**Testing Vectors**

-   GET parameters
-   POST data (form fields)
-   HTTP headers (User-Agent, Referer, X-\* custom headers)
-   Cookies
-   JSON payloads
-   XML data

**Web Crawler**

-   Form discovery and parameter extraction
-   Link extraction and navigation
-   Maximum depth configuration (default: 3 levels)
-   Maximum pages limit (default: 100 pages)
-   robots.txt respect
-   Intelligent deduplication

**Multi-DBMS Support**

-   MySQL/MariaDB detection and payloads
-   PostgreSQL detection and payloads
-   Microsoft SQL Server detection and payloads
-   Oracle detection and payloads
-   SQLite detection and payloads

---

#### AI-Powered Analysis

**Multi-Provider Support**

-   **OpenAI GPT-4 Turbo**: Premium quality analysis, ~35 seconds, $0.25/scan
-   **Anthropic Claude**: Privacy-focused with strong code remediation, ~45 seconds, $0.30/scan
-   **Ollama (Local Models)**: 100% offline, no data leaves your machine, free

**Analysis Modes**

-   **Technical Tone**: Code remediation with prepared statement examples (PHP, Python, Node.js, Java)
-   **Non-Technical Tone**: Executive summaries with business impact and compliance implications
-   **Both Modes**: Combined analysis for complete team coverage

**Security & Privacy**

-   Automatic sanitization removes sensitive data (credentials, tokens, SQL queries)
-   No database credentials or query results sent to AI providers
-   Configurable via environment variables and YAML

**Standalone Testing**

```bash
python -m pyth.core.ai openai
python -m pyth.core.ai anthropic
python -m pyth.core.ai ollama
```

---

#### Infrastructure & Reporting

**Ethical Testing Framework**

-   **Consent Token System**: Verify domain ownership before aggressive testing
    -   HTTP verification (`.well-known/verify-{token}.txt`)
    -   DNS TXT record verification
    -   48-hour token expiration
    -   Shared database with Argus/Hephaestus ecosystem

**Dual Report Formats**

-   **JSON Reports**: Machine-readable with schema validation
    -   Complete scan metadata
    -   Structured findings with evidence (payloads, responses, timing data)
    -   AI analysis (when enabled)
-   **HTML Reports**: Professional, self-contained
    -   Responsive design
    -   Severity-color-coded findings
    -   Payload visualization
    -   AI analysis beautifully formatted

**Database Persistence**

-   SQLite database shared with Argus and Hephaestus (`~/.argos/argos.db`)
-   Tracks all SQL injection findings across scans
-   Consent token management (cross-tool compatibility)
-   SQL views for common queries
-   Automatic corruption recovery

**Advanced Logging**

-   Automatic secret redaction (passwords, tokens, database credentials)
-   Multiple verbosity levels (`-v`, `-vv`)
-   JSON and text format support
-   Timestamped with severity levels

---

#### Performance & Control

**Rate Limiting**

-   Configurable request throttling (2-40 req/s)
-   Thread-safe implementation
-   Default: 2 req/s (safe) / 40 req/s (aggressive)

**Concurrent Testing**

-   Thread pool management (1-20 workers)
-   Parallel injection testing for faster scans
-   Intelligent retry logic
-   Graceful degradation on failures

**Scan Modes**

-   **Safe Mode** (default): Passive detection, no consent required
-   **Aggressive Mode**: Deep testing with time-based and advanced payloads, requires verified ownership

---

#### Error Handling & Resilience

**Connection Error Management**

-   Handles timeouts gracefully
-   DNS resolution failure recovery
-   Connection refused detection
-   Network error handling

**Database Resilience**

-   Automatic corruption detection and recovery
-   Read-only mode support
-   Graceful degradation when DB unavailable
-   Shared database integrity with Argus ecosystem

**Partial Scan Support**

-   Continues testing despite individual endpoint failures
-   Preserves partial results if target goes offline
-   Handles target restarts mid-scan

**Graceful Interruption**

-   Ctrl+C handling with proper scan status updates
-   Status set to "aborted" with error message
-   Timestamp recorded for interrupted scans

**Standardized Exit Codes**

-   `0`: Scan completed successfully
-   `1`: Technical error (connection, timeout, database)
-   `130`: User cancelled (Ctrl+C)

---

#### Developer Experience

**Rich CLI Interface**

-   25+ command-line flags
-   Colored output with progress indicators
-   ASCII art branding
-   Comprehensive `--help` documentation

**Configuration Management**

-   YAML configuration file (`config/default.yaml`)
-   Environment variable overrides
-   CLI flag priority system

---

### Performance

**Scan Speed**

-   Safe mode: 8-60 seconds (depending on target)
-   Aggressive mode: 30-180 seconds (with deep testing)
-   With AI analysis: +30-50 seconds
-   Average requests per scan: 50-200

**AI Analysis Performance**

| Provider         | Duration | Quality    | Cost per Scan |
| ---------------- | -------- | ---------- | ------------- |
| OpenAI GPT-4     | ~35s     | ⭐⭐⭐⭐⭐ | $0.25         |
| Anthropic Claude | ~45s     | ⭐⭐⭐⭐⭐ | $0.30         |
| Ollama (CPU)     | ~28min   | ⭐⭐⭐     | Free          |
| Ollama (GPU)     | ~75s\*   | ⭐⭐⭐     | Free          |

\*GPU time is estimated

**Resource Usage**

-   Memory: <400MB peak
-   Database: 4.0 MB for 638 scans with 5,000+ findings
-   Report size: JSON ~15-40KB, HTML ~50-150KB
-   Detection rate: 90%+ for common SQL injection vulnerabilities

---

### Security

**Safe by Default**

-   Non-intrusive checks unless explicitly authorized
-   Consent enforcement for aggressive mode
-   Automatic secret redaction in all outputs
-   AI data sanitization (removes credentials, queries, database schema details)

**Privacy Options**

-   Ollama support for 100% offline operation
-   No telemetry or tracking
-   Local database storage only
-   Shared ecosystem database with Argus/Hephaestus

**Best Practices**

-   Schema validation for all reports
-   Foreign key constraints enforced
-   No information leakage in error messages
-   Secure credential handling
-   Localhost consent bypass for testing

---

### Fixed

**Core Scanner Improvements**

-   Implemented accurate SQL injection detection across 4 methods
-   Enhanced crawler with form discovery and parameter extraction
-   Corrected port preservation in consent verification
-   Added intelligent payload selection based on context
-   Implemented baseline timing measurement for accurate time-based detection

**AI Integration**

-   Updated to LangChain v1.0.0 (modern LCEL chains)
-   Fixed prompt template processing for SQL injection context
-   Preserved code formatting in technical remediation guides
-   Resolved Python 3.12+ datetime warnings

**Error Handling**

-   Improved connection error classification
-   Added database corruption auto-recovery
-   Implemented read-only mode graceful degradation
-   Fixed Ctrl+C handling to properly mark scans as "aborted"

**Rate Limiting**

-   Implemented thread-safe HTTP client
-   Added proper rate limit enforcement
-   Fixed request throttling accuracy

---

### Known Limitations

These limitations are documented and tracked for future versions:

**Detection Accuracy**

-   Generic payloads used for all DBMS types
-   No automatic DBMS fingerprinting
-   Planned improvement: **IMPROV-003** in v0.2.0 (DBMS-specific payloads)

**Crawler Capabilities**

-   Limited JavaScript link extraction
-   No API endpoint discovery
-   Basic form parsing only
-   Planned improvement: **IMPROV-009** in v0.2.0 (enhanced crawler)

**Scan Modes**

-   Aggressive mode differs mainly in rate limiting
-   Limited payload diversity
-   Planned improvement: **IMPROV-004** in v0.2.0 (deeper testing, advanced techniques)

**AI Features**

-   Provider switching requires manual YAML editing
-   No cost tracking or budget limits
-   No streaming responses
-   Planned improvements: **IMPROV-005, IMPROV-006, IMPROV-009** in v0.2.0-v0.3.0

**Database Management**

-   Requires SQL knowledge for advanced queries
-   Planned improvement: **IMPROV-011** in v0.3.0 (interactive CLI)

---

## Installation

### Requirements

-   Python 3.11+
-   pip (Python package manager)

### Quick Start

**1. Clone the repository**

```bash
git clone https://github.com/rodhnin/pythia-sql-clairvoyance.git
cd pythia-sql-clairvoyance
```

**2. Create and activate virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate  # Windows
```

**3. Install dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**4. (Optional) Configure AI providers**

```bash
# For OpenAI
export OPENAI_API_KEY="sk-..."

# For Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# For Ollama (no API key needed)
ollama serve
ollama pull llama3.2
```

**5. Run first scan**

```bash
# Basic scan (no AI)
python -m pyth --target http://localhost:8081

# With AI analysis
python -m pyth --target http://localhost:8081 --use-ai --html
```

---

## Usage Examples

### Basic Scanning

```bash
# Safe mode scan (default)
python -m pyth --target http://example.com

# Generate HTML report
python -m pyth --target http://example.com --html

# Verbose output
python -m pyth --target http://example.com -v
```

### AI-Powered Analysis

```bash
# Technical analysis with code examples
python -m pyth --target http://example.com \
  --use-ai \
  --ai-tone technical \
  --html

# Executive summary for stakeholders
python -m pyth --target http://example.com \
  --use-ai \
  --ai-tone non_technical \
  --html

# Both analyses
python -m pyth --target http://example.com \
  --use-ai \
  --ai-tone both \
  --html
```

### Aggressive Mode (Requires Consent)

```bash
# 1. Generate consent token
python -m pyth --gen-consent example.com

# 2. Place token on server
# HTTP: Create file at https://example.com/.well-known/verify-{token}.txt
# OR DNS: Add TXT record "pythia-verify={token}"

# 3. Verify consent
python -m pyth --verify-consent http --domain example.com --token verify-{token}

# 4. Run aggressive scan
python -m pyth --target http://example.com --aggressive --use-ai --html
```

### Crawler Configuration

```bash
# Deep crawling with custom limits
python -m pyth --target http://example.com \
  --max-depth 5 \
  --max-pages 200 \
  --aggressive

# Fast scan with minimal crawling
python -m pyth --target http://example.com \
  --max-depth 1 \
  --max-pages 10
```

---

## Configuration

### AI Provider Selection

Edit `config/default.yaml`:

```yaml
ai:
    provider: "openai" # Options: openai, anthropic, ollama
    model: "gpt-4-turbo-preview"
    temperature: 0.3
    max_completion_tokens: 2000
```

**Note:** Dynamic provider switching will be available in v0.3.0 (**IMPROV-009**)

### Rate Limiting

```bash
# Slow scan (2 req/s, safe mode)
python -m pyth --target example.com --rate 2

# Fast scan (40 req/s, requires consent)
python -m pyth --target example.com --rate 40 --aggressive
```

### Thread Control

```bash
# Single-threaded
python -m pyth --target example.com --threads 1

# Multi-threaded (10 workers)
python -m pyth --target example.com --threads 10
```

---

## Database Management

Pythia shares the database with Argus, Asterion and Hephaestus at `~/.argos/argos.db`.

### Query Examples

**View recent Pythia scans:**

```sql
sqlite3 ~/.argos/argos.db "SELECT * FROM v_recent_scans WHERE tool = 'pythia' LIMIT 10;"
```

**Find critical SQL injection findings:**

```sql
sqlite3 ~/.argos/argos.db "
SELECT domain, finding_code, title, severity
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia' AND f.severity = 'critical';
"
```

**Check verified domains:**

```sql
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains;"
```

For complete database reference, see `docs/DATABASE_GUIDE.md`

**Note:** Interactive database CLI will be available in v0.3.0 (**IMPROV-011**)

---

## Migration Notes

### Upgrading from Pre-Release

This is the first production release. No migration required.

### Database Compatibility

Pythia uses the shared Argos ecosystem database. Consent tokens verified for Pythia work across Argus and Hephaestus.

### Future Upgrades

**v0.2.0** (Q2 2026):

-   Backward compatible
-   New features: DBMS fingerprinting, enhanced crawler, AI cost tracking
-   No database migration required

**v0.3.0** (Q3 2026):

-   Database schema v2 (automatic migration provided)
-   Breaking change: Configuration file format (migration tool included)
-   New features: Interactive config, database CLI, AI chat

---

## Roadmap

**v0.2.0** (Q2 2026) - Enhanced Detection & AI

-   DBMS fingerprinting and adaptive payloads
-   Enhanced crawler (JavaScript, APIs, sitemap parsing)
-   Aggressive mode enhancement (50+ payloads per type)
-   AI cost tracking & budget limits

**v0.3.0** (Q3 2026) - Enterprise Features

-   Interactive config management
-   Database CLI interface
-   Multi-site scanning
-   AI chat for SQL injection queries

**v0.4.0** (Q1 2027) - Intelligence & Automation

-   ML-based detection
-   Automated code remediation suggestions
-   WAF bypass automation

See `ROADMAP.md` for complete feature list.

---

## Support & Contributing

**Found a bug?**  
Open an issue: https://github.com/rodhnin/pythia-sql-clairvoyance/issues

**Feature request?**  
Start a discussion: https://github.com/rodhnin/pythia-sql-clairvoyance/discussions

**Want to contribute?**  
See `CONTRIBUTING.md` for guidelines

**Need help?**  
Check documentation in `docs/` or ask in Discussions

---

## License

See `LICENSE` file for details.

---

## Acknowledgments

-   OWASP community for SQL injection research
-   LangChain team for AI framework
-   OpenAI, Anthropic, and Ollama for AI models
-   SQLMap project for inspiration
-   Argos ecosystem (Argus, Hephaestus) for shared infrastructure
-   All contributors and testers

---

**Generated:** November 2025  
**Version:** 0.1.0  
**Status:** Production Release

[0.1.0]: https://github.com/rodhnin/pythia-sql-clairvoyance/releases/tag/v0.1.0

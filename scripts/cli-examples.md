# Pythia CLI Examples — v0.2.0

Comprehensive command-line usage examples for Pythia SQL injection scanner.

---

## Quick Reference — All 40 Flags

```
TARGET & MODE
  --target URL          Target URL to scan (required)
  --safe                Safe mode only: error-based + boolean-blind
  --aggressive          All 6 methods + WAF bypass payloads (requires consent)
  --no-crawl            Skip BFS crawl, test target URL only

CRAWL CONTROL
  --max-depth N         Crawl depth (default: 2)
  --max-pages N         Max pages to crawl (default: 100)
  --js                  Enable JS/onclick URL extraction (popup forms, SPAs)
  --no-robots           Ignore robots.txt restrictions

AUTH & HEADERS
  --cookie "k=v"        Session cookie for authenticated scanning
  --auth-header "K: V"  Custom HTTP header (can pass multiple times)
  --user-agent "..."    Custom User-Agent string
  --auto-csrf           Auto-extract and include CSRF tokens from forms

HTTP
  --rate N              Requests per second (default: 2.0 safe / 5.0 aggressive)
  --threads N           Worker threads (default: 5, max 20)
  --timeout N           Request timeout in seconds (default: 30)
  --no-verify-ssl       Skip TLS certificate verification
  --domain DOMAIN       Restrict crawl to specific domain

CONSENT
  --gen-consent DOMAIN  Generate consent token for a domain
  --verify-consent METHOD  Verify token (http or dns)
  --token TOKEN         Pass consent token directly

AI
  --use-ai              Enable AI-powered analysis
  --ai-tone TONE        technical / non_technical / both
  --ai-provider NAME    openai / anthropic / ollama
  --ai-model MODEL      Specific model (e.g. gpt-4o, claude-3-5-sonnet)
  --ai-stream           Stream AI output token by token
  --ai-compare "a,b"    Multi-provider comparison in parallel
  --ai-agent            Agent mode: autonomous NVD CVE lookup
  --ai-budget N         Max spend per scan in USD
  --api-key-env VAR     Environment variable name for API key

OUTPUT
  --html                Generate HTML report (in addition to JSON)
  --report-dir PATH     Custom directory for reports
  --sarif               Output SARIF 2.1.0 to stdout (logs go to stderr)
  --log-file PATH       Write logs to file
  --log-json            Structured JSON log format
  --no-color            Disable ANSI colors
  -v / -vv / -vvv       Verbosity levels

CI/CD
  --fail-on SEVERITY    Exit 10 if findings at threshold+ (critical/high/medium/low)
  --diff last           Compare vs most recent scan for same target
  --diff SCAN_ID        Compare vs specific scan by ID

DATABASE
  --db PATH             Custom SQLite database path (default: ~/.argos/argos.db)
```

---

## Basic Scanning

### Quick Scan (Safe Mode)

```bash
# Default: error-based + boolean-blind only — no consent required
python -m pyth --target http://example.com/products?id=1

# Explicit safe mode
python -m pyth --target http://example.com/search?q=test --safe

# With HTML report
python -m pyth --target http://example.com/search?q=test --html
```

### Custom Output Directory

```bash
python -m pyth --target http://example.com/users?id=5 \
  --report-dir ./client-reports \
  --html
```

### Skip Crawl — Test Single Endpoint

```bash
# Only tests the exact URL, no link following
python -m pyth --target "http://example.com/products?id=1" \
  --no-crawl \
  --html
```

---

## Verbosity & Logging

### Increase Verbosity

```bash
# INFO level (-v)
python -m pyth --target http://example.com/api/posts?id=1 -v

# DEBUG level (-vv)
python -m pyth --target http://example.com/products?category=books -vv

# Maximum verbosity (HTTP details)
python -m pyth --target http://example.com/search?q=test -vvv
```

### Logging to File

```bash
# Log to custom file
python -m pyth --target http://example.com/items?id=1 \
  --log-file ./logs/sqli-scan.log -vv

# JSON formatted logs (for SIEM)
python -m pyth --target http://example.com/api/users?id=1 \
  --log-json \
  --log-file ./logs/sqli-scan.json
```

### Quiet Mode

```bash
# Suppress console output (only warnings+)
python -m pyth --target http://example.com/products?id=1 --quiet

# Disable colors (for log files)
python -m pyth --target http://example.com/search?q=test --no-color
```

---

## Consent Token Management

### Generate Consent Token

```bash
python -m pyth --gen-consent example.com

# Output:
# Token: verify-a3f9b2c1d8e4f5a6
# Place at: https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

### Verify via HTTP

```bash
python -m pyth --verify-consent http \
  --domain example.com \
  --token verify-a3f9b2c1d8e4f5a6
```

### Verify via DNS

```bash
python -m pyth --verify-consent dns \
  --domain example.com \
  --token verify-a3f9b2c1d8e4f5a6
```

### Extend Lab Token (localhost)

```bash
# Localhost tokens expire — extend for lab use:
sqlite3 ~/.argos/argos.db "
UPDATE consent_tokens
SET expires_at = datetime('now', '+30 days', 'utc')
WHERE domain = 'localhost'
  AND verified_at IS NOT NULL;
"
```

---

## Aggressive Scanning

All 6 detection methods: error-based, boolean-blind, time-based, UNION-based, second-order, ORDER BY. Requires verified consent token for the target domain.

### Full Workflow

```bash
# 1. Generate token
python -m pyth --gen-consent example.com

# 2. Verify consent
python -m pyth --verify-consent http \
  --domain example.com \
  --token verify-a3f9b2c1d8e4f5a6

# 3. Run aggressive scan
python -m pyth --target http://example.com \
  --aggressive \
  --html -v
```

### With WAF Bypass (Aggressive Only)

WAF bypass payloads are included automatically in `--aggressive` mode:

- Hex encoding: `' OR 0x41=0x41--`
- URL double-encoding: `%2527OR%25271%2527%253D%25271`
- Inline comments: `' /*!OR*/ '1'='1`
- Case variation: `' oR '1'='1`
- Whitespace variants: `'\tOR\t'1'='1`

```bash
# Aggressive automatically includes WAF bypass payloads
python -m pyth --target http://example.com/search?q=test \
  --aggressive \
  --html -v
```

### Deep Crawling

```bash
# More pages, deeper — comprehensive coverage
python -m pyth --target http://example.com \
  --aggressive \
  --max-depth 5 \
  --max-pages 200 \
  --html
```

### JS-Aware Crawling

```bash
# Extracts URLs from onclick/popup links (needed for DVWA high, SPAs)
python -m pyth --target http://example.com \
  --aggressive \
  --js \
  --html -v
```

---

## New Detection Vectors (v0.2.0)

### Second-Order SQL Injection (PYTHIA-SQL-040)

Detects store→retrieve patterns where a payload is stored first and executed later:

```bash
# PHP lab example: POST /register → GET /profile
python -m pyth --target http://localhost:8081 \
  --aggressive \
  --html -vv

# Look for PYTHIA-SQL-040 in report
# Evidence will show: stored at /register, triggered at /profile/<username>
```

**How it works:**

1. Scanner POSTs payloads to store routes (`/register`, `/comment`, `/profile`, `/settings`)
2. Then GETs retrieval routes (`/dashboard`, `/profile`, `/admin`)
3. Detects SQL errors or content changes in the response

### ORDER BY / GROUP BY Injection (PYTHIA-SQL-050)

Detects numeric sort parameter injection — entirely different from quoted-string SQLi:

```bash
# PHP lab: /products?sort=price is injectable
python -m pyth --target http://localhost:8081 \
  --aggressive \
  --html -vv

# Look for PYTHIA-SQL-050 in report
# Detected by comparing responses for valid vs invalid ORDER BY values
```

**Payloads used:**

```
/products?sort=1                              → baseline
/products?sort=(SELECT 1 FROM users)          → subquery
/products?sort=CASE WHEN 1=1 THEN name ELSE price END
```

---

## DBMS-Specific Finding Codes (v0.2.0)

Pythia now uses specific codes per database type:

| Code             | Type          | DBMS                  |
| ---------------- | ------------- | --------------------- |
| `PYTHIA-SQL-001` | Error-Based   | MySQL / MariaDB       |
| `PYTHIA-SQL-002` | Error-Based   | PostgreSQL            |
| `PYTHIA-SQL-003` | Error-Based   | MSSQL / SQL Server    |
| `PYTHIA-SQL-004` | Error-Based   | Oracle                |
| `PYTHIA-SQL-005` | Error-Based   | SQLite                |
| `PYTHIA-SQL-010` | Boolean Blind | Generic               |
| `PYTHIA-SQL-011` | Boolean Blind | Via header injection  |
| `PYTHIA-SQL-020` | Time-Based    | MySQL SLEEP()         |
| `PYTHIA-SQL-021` | Time-Based    | MSSQL WAITFOR DELAY   |
| `PYTHIA-SQL-022` | Time-Based    | PostgreSQL pg_sleep() |
| `PYTHIA-SQL-030` | UNION-Based   | GET/POST parameter    |
| `PYTHIA-SQL-031` | UNION-Based   | Via cookie            |
| `PYTHIA-SQL-040` | Second-Order  | Store → retrieve      |
| `PYTHIA-SQL-050` | ORDER BY      | Numeric sort param    |

All codes: **OWASP A03 Injection** / **CWE-89**

---

## Authentication

### Session Cookie (DVWA, login-based apps)

```bash
# DVWA low security — get PHPSESSID from browser DevTools
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --no-crawl \
  --aggressive \
  --cookie "PHPSESSID=your_session_id; security=low" \
  --html -v

# DVWA medium security
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --no-crawl \
  --aggressive \
  --cookie "PHPSESSID=your_session_id; security=medium" \
  --html -v

# DVWA high security — uses session-var chain (needs --js)
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/" \
  --js \
  --max-pages 2 \
  --aggressive \
  --cookie "PHPSESSID=your_session_id; security=high" \
  --html -v
```

### Auth Headers (Bearer / API Key) — v0.2.0

```bash
# JWT Bearer token
python -m pyth --target https://api.example.com/users \
  --aggressive \
  --auth-header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --html -v

# Multiple headers (pass flag multiple times)
python -m pyth --target https://api.example.com/products \
  --aggressive \
  --auth-header "Authorization: Bearer eyJhbGc..." \
  --auth-header "X-API-Key: sk-prod-xxx" \
  --auth-header "X-Tenant-ID: company-123" \
  --html -v

# API key only
python -m pyth --target https://api.example.com/search \
  --aggressive \
  --auth-header "X-API-Key: your-api-key-here" \
  --html -v
```

### CSRF Token Auto-Extraction

```bash
# Auto-extracts CSRF tokens from forms before submitting
python -m pyth --target http://example.com/login \
  --aggressive \
  --auto-csrf \
  --html -v
```

---

## AI-Powered Analysis

### Basic AI Scan

```bash
export OPENAI_API_KEY="sk-..."
python -m pyth --target http://example.com/products?id=1 \
  --use-ai \
  --html
```

### Tone Options

```bash
# Technical — for engineers (code examples, remediation steps)
python -m pyth --target http://example.com/api/users?id=1 \
  --use-ai --ai-tone technical --html

# Executive — for stakeholders (business impact, compliance)
python -m pyth --target http://example.com/search?q=test \
  --use-ai --ai-tone non_technical --html

# Both — full team (technical + executive in same report)
python -m pyth --target http://example.com/products?id=1 \
  --use-ai --ai-tone both --html
```

### Streaming Output

```bash
# Prints tokens progressively as AI generates them
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-stream \
  --ai-tone technical \
  --html
```

### AI Agent Mode — CVE Lookup

```bash
# Agent autonomously queries NVD for CVEs matching detected DBMS + CWE-89
python -m pyth --target http://localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-agent \
  --html -v

# Each finding enriched with:
# - Real CVE IDs from NVD
# - CVSS scores
# - NVD links (https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX)
# - CWE-89 classification
```

### Multi-Provider Comparison

```bash
# Compare OpenAI vs Anthropic — both appear in separate HTML tabs
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-compare "openai,anthropic" \
  --html

# Compare specific models
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-compare "openai:gpt-4o-mini,anthropic:claude-3-5-haiku-20241022" \
  --html
```

### Budget Control

```bash
# Stop AI analysis if cost exceeds $0.10
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-budget 0.10 \
  --html
```

### Custom Provider & Model

```bash
# Use Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-provider anthropic \
  --ai-model claude-3-5-sonnet-20241022 \
  --html

# Use Ollama (local/offline)
ollama pull llama3.2
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-provider ollama \
  --ai-model llama3.2 \
  --html

# Custom env var for API key
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --api-key-env MY_OPENAI_KEY
```

---

## CI/CD Integration (v0.2.0)

### Exit Codes

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| `0`  | Clean scan — no findings at threshold            |
| `10` | Findings found at `--fail-on` threshold or above |
| `1`  | Technical error (network, consent, etc.)         |

### --fail-on (Pipeline Gate)

```bash
# Block pipeline on critical findings
python -m pyth --target https://staging.example.com \
  --aggressive \
  --fail-on critical
echo "Exit: $?"   # 0 = clean, 10 = critical found

# Block on high or above
python -m pyth --target https://staging.example.com \
  --aggressive \
  --fail-on high

# Block on any finding (strict mode)
python -m pyth --target https://staging.example.com \
  --safe \
  --fail-on low
```

### SARIF Output (GitHub Security, GitLab SAST, Azure DevOps)

```bash
# Output SARIF to stdout; logs go to stderr automatically
python -m pyth --target https://staging.example.com \
  --aggressive \
  --sarif > results.sarif

# Validate SARIF is correct JSON
python3 -c "import json; json.load(open('results.sarif')); print('Valid SARIF 2.1.0')"

# Suppress log output if needed
python -m pyth --target https://staging.example.com \
  --aggressive \
  --sarif 2>/dev/null > results.sarif

# Combined: SARIF + fail-on + AI budget
python -m pyth \
  --target https://staging.example.com \
  --aggressive \
  --use-ai \
  --ai-budget 0.05 \
  --fail-on high \
  --sarif > results.sarif
```

### GitHub Actions

```yaml
# .github/workflows/sqli-security-scan.yml
name: SQL Injection Security Scan

on:
    pull_request:
    schedule:
        - cron: "0 0 * * 0" # Weekly on Sunday
    workflow_dispatch:

jobs:
    sqli-scan:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4

            - name: Setup Python
              uses: actions/setup-python@v5
              with:
                  python-version: "3.11"

            - name: Install Pythia
              run: pip install -r requirements.txt

            - name: Run SQL Injection Scan (SARIF)
              env:
                  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
              run: |
                  python -m pyth \
                    --target ${{ secrets.STAGING_URL }} \
                    --aggressive \
                    --sarif 2>/dev/null > results.sarif || true

            - name: Upload SARIF to GitHub Security
              uses: github/codeql-action/upload-sarif@v3
              with:
                  sarif_file: results.sarif

            - name: Fail on High Findings
              run: |
                  python -m pyth \
                    --target ${{ secrets.STAGING_URL }} \
                    --aggressive \
                    --fail-on high \
                    --quiet --no-color
```

---

## Diff Reports (v0.2.0)

Track vulnerabilities across scans — find new ones, confirm fixed ones.

### Compare vs Last Scan

```bash
# Run baseline scan
python -m pyth --target http://localhost:8081 --aggressive --html -v

# After fixing some issues, re-scan with diff
python -m pyth --target http://localhost:8081 --aggressive --diff last --html -v

# Report will show:
# - NEW findings (appeared since last scan)
# - FIXED findings (gone since last scan)
# - PERSISTING findings (still present)
```

### Compare vs Specific Scan

```bash
# Get scan ID from database
sqlite3 ~/.argos/argos.db \
  "SELECT scan_id, started_at, total_findings FROM scans WHERE tool='pythia' ORDER BY scan_id DESC LIMIT 10;"

# Diff vs scan ID 42
python -m pyth --target http://localhost:8081 \
  --aggressive \
  --diff 42 \
  --html -v
```

---

## Docker Lab — Testing Environment

### Using deploy.sh (Recommended)

```bash
cd docker && ./deploy.sh

# Options:
# 1) Build Pythia Scanner
# 2) Start Testing Lab (DVWA, PHP, Flask)   ← for testing
# 3) Build Scanner + Start Testing Lab
# 4) Stop all services
# 5) Remove all containers and data (reset)
```

### Manual Lab Commands

```bash
# Start
sudo docker compose -f docker/compose.testing.yml up -d

# Status
sudo docker compose -f docker/compose.testing.yml ps

# Stop
sudo docker compose -f docker/compose.testing.yml down

# Full reset (removes volumes)
sudo docker compose -f docker/compose.testing.yml down -v
```

### Lab Services

| Service               | URL                   | Notes                                       |
| --------------------- | --------------------- | ------------------------------------------- |
| DVWA                  | http://localhost:8080 | Requires /setup.php one-time init           |
| PHP Vulnerable Shop   | http://localhost:8081 | MySQL, 26 findings in aggressive            |
| Flask Vulnerable Blog | http://localhost:8082 | MySQL, 18 findings with `--js --aggressive` |
| MySQL Lab DB          | localhost:3307        | root/root123                                |

### Lab Test Scans

```bash
# PHP shop — full aggressive (26 findings expected)
python -m pyth --target http://localhost:8081 --aggressive --html -v

# Flask blog — JS-aware aggressive (18 findings expected)
python -m pyth --target http://localhost:8082 --js --aggressive --html -v

# DVWA low — direct page, no crawl (4 findings expected)
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --no-crawl \
  --aggressive \
  --cookie "PHPSESSID=<your_id>; security=low" \
  --html -v

# DVWA high — session-var chain with JS (4 findings expected)
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/" \
  --js \
  --max-pages 2 \
  --aggressive \
  --cookie "PHPSESSID=<your_id>; security=high" \
  --html -v
```

### Run Pythia Scanner in Docker Container

```bash
# Build image
docker build -f docker/Dockerfile -t pythia:latest .

# Scan from container (use service names for lab targets)
docker run --rm \
  -v $(pwd)/reports:/reports \
  pythia:latest \
  --target http://php-vuln-app --safe --html

# Scan external target from container
docker run --rm \
  -v $(pwd)/reports:/reports \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  pythia:latest \
  --target http://example.com/products?id=1 \
  --use-ai \
  --html
```

---

## Database Operations

### View Scan History

```bash
# Recent Pythia scans
sqlite3 ~/.argos/argos.db \
  "SELECT scan_id, target, total_findings, started_at FROM scans WHERE tool='pythia' ORDER BY scan_id DESC LIMIT 10;"

# All tools in shared DB
sqlite3 ~/.argos/argos.db \
  "SELECT tool, COUNT(*) as scans, SUM(total_findings) as total_findings FROM scans GROUP BY tool;"

# Critical SQLi findings
sqlite3 ~/.argos/argos.db \
  "SELECT f.id, f.title, f.severity, s.target
   FROM findings f
   JOIN scans s ON f.scan_id = s.scan_id
   WHERE s.tool='pythia' AND f.severity='critical'
   ORDER BY s.started_at DESC LIMIT 20;"

# Detection method breakdown
sqlite3 ~/.argos/argos.db \
  "SELECT detection_method, COUNT(*) as count
   FROM findings
   WHERE tool='pythia'
   GROUP BY detection_method;"

# AI cost tracking
sqlite3 ~/.argos/argos.db \
  "SELECT provider, model, SUM(input_tokens) as in_tokens, SUM(output_tokens) as out_tokens,
          ROUND(SUM(cost_usd), 4) as total_usd
   FROM ai_costs WHERE tool='pythia' GROUP BY provider, model;"
```

### Custom Database Path

```bash
python -m pyth --target http://example.com/products?id=1 \
  --db ./projects/client-a/scans.db
```

---

## Advanced Options

### Custom Timeout (Time-Based Detection)

```bash
# Increase for slow servers — important for time-based SQLi
python -m pyth --target http://slow-api.example.com/search?q=test \
  --timeout 60
```

### Custom User-Agent

```bash
python -m pyth --target http://example.com/api/posts?id=1 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Skip SSL Verification (Test Environments)

```bash
python -m pyth --target https://localhost:8443/products?id=1 \
  --no-verify-ssl
```

### Ignore robots.txt

```bash
python -m pyth --target http://example.com \
  --no-robots \
  --aggressive
```

### Domain Restriction

```bash
# Only crawl links within example.com (ignore external links)
python -m pyth --target http://example.com \
  --domain example.com \
  --aggressive
```

---

## Production Workflows

### Full Client Scan

```bash
#!/bin/bash
# client-sqli-scan.sh

TARGET="$1"    # e.g., example.com
CLIENT="$2"    # e.g., acme-corp

echo "Scanning $TARGET for SQL injection vulnerabilities..."

# 1. Generate consent token
python -m pyth --gen-consent $TARGET

# 2. Wait for client to place token
read -p "Press enter after token is placed at /.well-known/..."

# 3. Verify consent
python -m pyth --verify-consent http \
  --domain $TARGET \
  --token $(cat token.txt)

# 4. Run aggressive scan with AI
python -m pyth \
  --target "https://$TARGET" \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --ai-agent \
  --html \
  --report-dir ./clients/$CLIENT/reports \
  --max-depth 5 \
  --max-pages 200 \
  -vv

echo "Complete — check ./clients/$CLIENT/reports/"
```

### Pre-Deployment Check

```bash
#!/bin/bash
# pre-deploy-check.sh

STAGING_URL="http://staging.example.com"

python -m pyth \
  --target "$STAGING_URL" \
  --aggressive \
  --fail-on high \
  --sarif > pre-deploy-results.sarif

RESULT=$?
if [ $RESULT -eq 10 ]; then
  echo "DEPLOYMENT BLOCKED — SQL injection vulnerabilities found"
  exit 1
elif [ $RESULT -eq 0 ]; then
  echo "DEPLOYMENT APPROVED — No SQL injection found"
  exit 0
else
  echo "SCAN ERROR — Check logs"
  exit 1
fi
```

### Authenticated API Scan

```bash
# REST API with Bearer token — test all endpoints
python -m pyth \
  --target https://api.example.com/v1 \
  --aggressive \
  --auth-header "Authorization: Bearer $API_TOKEN" \
  --use-ai \
  --ai-agent \
  --html -vv
```

### Remediation Verification with Diff

```bash
#!/bin/bash
# verify-fix.sh

TARGET=$1

# Scan before fix
echo "Scanning before fix..."
python -m pyth --target "$TARGET" --aggressive --html -v

SCAN_ID=$(sqlite3 ~/.argos/argos.db \
  "SELECT scan_id FROM scans WHERE tool='pythia' ORDER BY scan_id DESC LIMIT 1;")

echo "Baseline scan ID: $SCAN_ID"
read -p "Apply fixes and press enter..."

# Scan after fix with diff
echo "Scanning after fix..."
python -m pyth --target "$TARGET" \
  --aggressive \
  --diff $SCAN_ID \
  --html -v

# Report shows: FIXED / NEW / PERSISTING sections
```

---

## Cron Job / Scheduled Scanning

```bash
# Add to crontab: crontab -e

# Weekly aggressive scan with HTML report
0 2 * * 0 cd /opt/pythia && python -m pyth --target http://myapp.com \
  --aggressive --html --quiet >> /var/log/pythia-weekly.log 2>&1

# Daily safe check
0 1 * * * cd /opt/pythia && python -m pyth --target http://myapp.com \
  --safe --html --quiet >> /var/log/pythia-daily.log 2>&1

# Diff scan — compare vs last (track changes over time)
0 3 * * 1 cd /opt/pythia && python -m pyth --target http://myapp.com \
  --aggressive --diff last --html --quiet >> /var/log/pythia-diff.log 2>&1
```

---

## Quick Reference

### Common Patterns

```bash
# Quick safe scan
python -m pyth --target "http://example.com/products?id=1"

# Client deliverable (full aggressive + AI + HTML)
python -m pyth --target "http://example.com" \
  --aggressive \
  --use-ai --ai-tone both --ai-agent \
  --html -vv

# Local lab testing (PHP shop)
python -m pyth --target http://localhost:8081 \
  --aggressive --html -v

# Local lab testing (Flask blog with JS)
python -m pyth --target http://localhost:8082 \
  --js --aggressive --html -v

# Single endpoint test (no crawl)
python -m pyth --target "http://example.com/api/users?id=5" \
  --no-crawl --aggressive --html

# Authenticated API scan
python -m pyth --target "https://api.example.com/v1" \
  --aggressive \
  --auth-header "Authorization: Bearer $TOKEN" \
  --html

# CI/CD pipeline gate
python -m pyth --target "https://staging.example.com" \
  --aggressive --fail-on high --sarif > results.sarif

# Diff-based tracking (track fixes)
python -m pyth --target "http://example.com" \
  --aggressive --diff last --html -v

# Cheap AI scan (technical only, mini model)
python -m pyth --target "http://example.com/products?id=1" \
  --use-ai --ai-tone technical --html

# Deep authenticated scan
python -m pyth --target "http://example.com/admin" \
  --cookie "PHPSESSID=abc123; csrf_token=xyz" \
  --aggressive \
  --max-depth 5 --max-pages 300
```

### Environment Variables

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Troubleshooting

### No Vulnerabilities Detected

```bash
# Verify target is actually vulnerable
curl "http://localhost:8081/?page=products&id=1'"
# Should return SQL error, not 404

# Use --aggressive instead of --safe
# Use --no-crawl to test the exact URL
python -m pyth --target "http://example.com/products?id=1" --no-crawl --aggressive -vv
```

### SARIF Has Mixed Content (Logs + JSON)

```bash
# --sarif auto-redirects logs to stderr — use 2>/dev/null to suppress
python -m pyth --target http://localhost:8081 --sarif 2>/dev/null > results.sarif
```

### Scan Too Slow

```bash
# Skip crawl for direct endpoint testing
python -m pyth --target "http://example.com/products?id=1" --no-crawl --aggressive

# Limit pages
python -m pyth --target http://example.com --max-pages 10 --aggressive
```

### Consent Denied / Token Expired

```bash
# Re-verify consent
python -m pyth --verify-consent http \
  --domain example.com \
  --token verify-your-token

# Extend localhost token
sqlite3 ~/.argos/argos.db "
UPDATE consent_tokens
SET expires_at = datetime('now', '+30 days', 'utc')
WHERE domain = 'localhost' AND verified_at IS NOT NULL;
"
```

### DVWA Session Expired

```bash
# Re-login via browser, copy fresh PHPSESSID from DevTools
# Application → Cookies → localhost → PHPSESSID
```

### Verify Installation

```bash
# Check version (should be 0.2.0)
python -m pyth --version

# Test dependencies
pip list | grep -E 'requests|beautifulsoup4|langchain'

# Test database connection
python -c "from pyth.core.db import get_db; get_db(); print('DB OK')"

# Test AI provider
python -m pyth.core.ai openai
python -m pyth.core.ai anthropic
```

---

## Tips & Tricks

### 1. Scan Multiple Endpoints

```bash
while read url; do
  echo "Scanning: $url"
  python -m pyth --target "$url" --html --quiet
  sleep 5
done < endpoints.txt
```

### 2. Extract Findings by Severity

```bash
# Critical findings only
jq '.findings[] | select(.severity=="critical")' report.json

# Count by detection method
jq '.findings | group_by(.detection_method) |
    map({method: .[0].detection_method, count: length})' report.json

# All PYTHIA-SQL-040 (second-order)
jq '.findings[] | select(.id=="PYTHIA-SQL-040")' report.json
```

### 3. Track Findings Over Time (DB)

```bash
sqlite3 ~/.argos/argos.db <<EOF
SELECT
  DATE(started_at) as scan_date,
  COUNT(*) as total_findings,
  SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
  SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high
FROM findings
WHERE tool='pythia'
  AND scan_id IN (SELECT scan_id FROM scans WHERE domain='example.com')
GROUP BY DATE(started_at)
ORDER BY scan_date DESC;
EOF
```

### 4. Check DBMS Distribution

```bash
jq -r '.findings[] | "\(.id): \(.evidence.dbms // "unknown")"' report.json | sort | uniq -c
```

### 5. Generate Executive Summary

```bash
jq '{
  target: .target,
  date: .date,
  mode: .mode,
  summary: .summary,
  contextual_score: (.findings[0].contextual_score // null),
  critical_findings: [.findings[] | select(.severity=="critical") | {id: .id, title: .title, parameter: .parameter}]
}' report.json > executive-summary.json
```

### 6. Monitor AI Costs

```bash
# All AI costs across Argos Suite
cat ~/.argos/costs.json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
pythia = [e for e in data.get('entries', []) if e.get('tool') == 'pythia']
total = sum(e.get('cost_usd', 0) for e in pythia)
print(f'Pythia AI scans: {len(pythia)}')
print(f'Total cost: \${total:.4f}')
"
```

---

## Getting Help

```bash
# Show all options
python -m pyth --help

# Show version
python -m pyth --version

# Validate configuration
python -c "from pyth.core.config import Config; c = Config.load(); print('Config OK')"

# Check shared database
sqlite3 ~/.argos/argos.db "SELECT COUNT(*) as scans FROM scans WHERE tool='pythia';"
```

**Issues & feedback:** https://github.com/rodhnin/pythia-sql-clairvoyance/issues

**Quick Start for first scan:**

```bash
python -m pyth --target "http://localhost:8081" --safe --html -v
```

---

_Pythia v0.2.0 — May 2026_
_Author: Rodney Dhavid Jimenez Chacin (rodhnin)_

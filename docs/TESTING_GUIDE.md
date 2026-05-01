# Safe Testing Guide for Pythia SQL Scanner

This guide explains how to safely test Pythia without scanning unauthorized systems.

## Testing Ethics

**CRITICAL RULES:**

1. ✅ **ONLY** test against systems you own or have explicit permission
2. ✅ Use the provided Docker lab environment
3. ✅ Use isolated VMs with snapshots
4. ❌ **NEVER** scan production sites without authorization
5. ❌ **NEVER** scan third-party sites "for practice"

Unauthorized SQL injection scanning is **illegal** in most jurisdictions and can cause database damage.

---

## Method 1: Docker Lab (Recommended)

The safest and fastest way to test Pythia features.

### Quick Start

**Option 1: Using Interactive Script (Recommended)**

```bash
cd docker && ./deploy.sh
# Select option 2 (Testing Lab)
```

**Option 2: Manual**

```bash
# Start the complete lab
sudo docker compose -f docker/compose.testing.yml up -d

# Wait for services to be ready (30-60 seconds)
sudo docker compose -f docker/compose.testing.yml ps

# Expected output:
# NAME             STATUS
# mysql-lab        Up (healthy)
# php-vuln-app     Up
# flask-vuln-app   Up
# dvwa             Up

# Verify all services are accessible
curl -s http://localhost:8081  # PHP App
curl -s http://localhost:8082  # Flask App
curl -s http://localhost:8080/login.php  # DVWA
```

### Lab Services

| Service | URL | Description |
|---------|-----|-------------|
| DVWA | http://localhost:8080 | Damn Vulnerable Web App (MySQL) |
| PHP Vulnerable Shop | http://localhost:8081 | PHP + MySQL, multiple endpoints |
| Flask Vulnerable Blog | http://localhost:8082 | Python/Flask + MySQL |
| MySQL Lab DB | localhost:3307 | root/root123 |

### Initial Setup

#### A. DVWA Configuration (First Time Only)

DVWA requires one-time database setup:

```bash
# 1. Open browser to DVWA setup
firefox http://localhost:8080/setup.php

# 2. Click "Create / Reset Database" and wait 5-10 seconds
# 3. Login with admin/password
# 4. Set security level to "Low" in DVWA Security menu
```

#### B. Verify Database Initialization

```bash
docker compose exec mysql mysql -uroot -proot123 -e "
SELECT 'shop' as db_name, COUNT(*) as products FROM shop.products
UNION ALL
SELECT 'blog' as db_name, COUNT(*) as posts FROM blog.posts;
"
```

---

## Expected Results by Target (v0.2.0)

### PHP Lab (localhost:8081)

| Mode | Expected Findings | Notes |
|------|------------------|-------|
| `--safe` | ~8-10 findings | Error-based + Boolean-blind only |
| `--aggressive` | **26 findings** | All techniques + second-order + ORDER BY |

### Flask Lab (localhost:8082)

| Mode | Expected Findings | Notes |
|------|------------------|-------|
| `--safe` | ~4-5 findings | Error-based + Boolean-blind only |
| `--aggressive` + `--js` | **18 findings** | Includes session-var detection |

### DVWA (localhost:8080)

| Security Level | Command | Expected Findings |
|----------------|---------|------------------|
| Low | `--no-crawl --aggressive --cookie "..."` | 4 findings (all 4 techniques) |
| Medium | `--no-crawl --aggressive --cookie "..."` | 4 findings (all 4 techniques) |
| High | `--js --max-pages 2 --aggressive --cookie "..."` | 4 findings (session-var chain) |

---

## Test Scenarios (v0.2.0)

### Scenario 1: Basic Safe Mode Scan

```bash
# Error-based + Boolean-blind only, no consent required
python -m pyth --target http://localhost:8081 --html -v

# Expected: ~8-10 findings, JSON + HTML reports generated
# Duration: 30-60 seconds
```

### Scenario 2: Full Aggressive Scan

```bash
# Generate and verify consent first
python -m pyth --gen-consent localhost
python -m pyth --verify-consent http --domain localhost --token verify-<token>

# Run aggressive scan
python -m pyth --target http://localhost:8081 --aggressive --html -v

# Expected: 26 findings, all 4 techniques + second-order + ORDER BY
# Duration: 60-180 seconds
```

### Scenario 3: DVWA Low Security

```bash
# Get DVWA session cookie from browser: DevTools → Application → Cookies
# Then scan the SQL injection page directly
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --no-crawl \
  --aggressive \
  --cookie "PHPSESSID=<your_session_id>; security=low" \
  --html -v

# Expected: 4 findings (PYTHIA-SQL-001/010/020/030)
```

### Scenario 4: DVWA High Security (Session-Variable Detection)

DVWA high security uses a session variable pattern — the parameter is submitted on one page and the query runs on another:

```bash
python -m pyth \
  --target "http://localhost:8080/vulnerabilities/sqli/" \
  --js \
  --max-pages 2 \
  --aggressive \
  --cookie "PHPSESSID=<your_session_id>; security=high" \
  --html -v

# Expected: 4 findings via POST→GET session-var chain
# The --js flag enables popup/onclick URL extraction needed for session-input.php
```

### Scenario 5: Flask with JS-Aware Crawling

```bash
python -m pyth \
  --target http://localhost:8082 \
  --js \
  --aggressive \
  --html -v

# Expected: 18 findings
# Session-var at /user-lookup, second-order, ORDER BY injection detected
```

### Scenario 6: Auth Header Testing

```bash
# Test an API endpoint that requires authentication
python -m pyth \
  --target https://staging.example.com/api/v1/users \
  --aggressive \
  --auth-header "Authorization: Bearer eyJhbGc..." \
  --auth-header "X-API-Key: sk-prod-xxx" \
  --html -v
```

### Scenario 7: CI/CD Integration Testing

```bash
# Test exit code behavior
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --fail-on high

echo "Exit code: $?"
# Exit 10 = findings found at high or above
# Exit 0 = no findings at threshold
# Exit 1 = technical error

# SARIF output for GitHub Security
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --sarif > results.sarif

# Verify SARIF is valid JSON
python -c "import json; json.load(open('results.sarif')); print('Valid SARIF')"
```

### Scenario 8: Diff Comparison Testing

```bash
# First scan (baseline)
python -m pyth --target http://localhost:8081 --aggressive --html -v

# Note the scan ID from output or DB
sqlite3 ~/.argos/argos.db "SELECT scan_id FROM scans WHERE tool='pythia' ORDER BY scan_id DESC LIMIT 1;"

# Second scan with diff
python -m pyth --target http://localhost:8081 --aggressive --diff last --html -v

# Should show new/fixed/persisting sections in report
# If same target and mode: persisting findings from first scan appear in diff
```

### Scenario 9: False Positive Verification

```bash
# Test a static URL that has NO SQL injection
# Expected: 0 findings
python -m pyth \
  --target https://www.google.com \
  --safe \
  --no-crawl

echo "Exit code: $?"
# Should be 0 with 0 findings
```

### Scenario 10: Second-Order Detection

```bash
# PHP lab has second-order SQLi at /register → /profile
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --html -vv

# Look for PYTHIA-SQL-040 in report
# The scanner POSTs a payload to /register then GETs /profile to detect stored injection
```

### Scenario 11: ORDER BY Injection

```bash
# PHP lab has ORDER BY injection at /products?sort=price
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --html -vv

# Look for PYTHIA-SQL-050 in report
# Detected by comparing responses for valid vs invalid sort parameters
```

### Scenario 12: AI-Powered Analysis

```bash
export OPENAI_API_KEY="sk-..."

python -m pyth \
  --target http://localhost:8082 \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --html -v

# Expected: 18 findings + AI analysis (technical + executive)
# Cost: ~$0.02-0.05 with gpt-4o-mini (default)
```

### Scenario 13: AI Agent with CVE Lookup

```bash
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-agent \
  --html -v

# Expected: findings enriched with real CVE data from NVD
# The agent queries https://services.nvd.nist.gov/rest/json/cves/2.0 with cweId=CWE-89
# No API key needed for NVD
```

---

## Test Checklist (v0.2.0)

Before reporting issues or marking a feature complete:

**Lab Setup:**
-   [ ] Docker lab starts successfully
-   [ ] All 4 services running (mysql, php, flask, dvwa)
-   [ ] PHP app accessible at http://localhost:8081
-   [ ] Flask app accessible at http://localhost:8082
-   [ ] DVWA accessible at http://localhost:8080
-   [ ] DVWA database initialized via /setup.php

**Core Detection:**
-   [ ] Error-based SQLi detected on PHP lab (≥1 PYTHIA-SQL-001)
-   [ ] Boolean-blind SQLi detected on PHP lab (≥1 PYTHIA-SQL-010)
-   [ ] Time-based SQLi detected in aggressive mode (≥1 PYTHIA-SQL-020)
-   [ ] UNION-based SQLi detected in aggressive mode (≥1 PYTHIA-SQL-030)
-   [ ] Second-order SQLi detected on PHP/Flask (PYTHIA-SQL-040)
-   [ ] ORDER BY injection detected (PYTHIA-SQL-050)

**v0.2.0 Features:**
-   [ ] PHP lab aggressive: 26 findings
-   [ ] Flask lab `--js --aggressive`: 18 findings
-   [ ] DVWA low `--no-crawl --aggressive`: 4 findings (all 4 techniques)
-   [ ] DVWA high `--js --max-pages 2 --aggressive`: 4 findings (session-var chain)
-   [ ] `--fail-on high` returns exit code 10 when findings found
-   [ ] `--fail-on high` returns exit code 0 on static URL (no findings)
-   [ ] `--sarif` outputs valid SARIF 2.1.0 to stdout, logs go to stderr
-   [ ] `--diff last` shows new/fixed/persisting sections
-   [ ] `--auth-header` passes headers to all requests
-   [ ] `--no-crawl` skips crawl, tests only target URL

**Report Quality:**
-   [ ] JSON report validates against schema
-   [ ] HTML report generates correctly
-   [ ] `owasp`, `cwe`, `cvss`, `payload`, `parameter`, `vector` fields present in findings
-   [ ] `contextual_score` present in findings
-   [ ] `notes` section has `scan_duration_seconds`, `requests_sent`, `rate_limit_applied`
-   [ ] DBMS correctly identified (MySQL for PHP/Flask labs)

**False Positive Check (mandatory):**
-   [ ] Static URL with no SQL → 0 findings
-   [ ] No duplicate findings for same parameter/method combination

**AI (if applicable):**
-   [ ] `--use-ai` completes without error when API key is set
-   [ ] Graceful degradation when no API key (scan completes, AI skipped, exit 0)
-   [ ] `--ai-agent` enriches findings with CVE data
-   [ ] `--ai-stream` produces streaming output

---

## Troubleshooting

### No Vulnerabilities Detected

```bash
# Verify target is actually vulnerable
curl "http://localhost:8081/?page=products&id=1'"
# Should return SQL error, not 404
```

### Permission Denied on localhost Consent

```bash
# Localhost needs consent for aggressive mode
# Token expires in 48h by default — extend for lab use:
sqlite3 ~/.argos/argos.db "
UPDATE consent_tokens
SET expires_at = datetime('now', '+30 days', 'utc')
WHERE domain = 'localhost'
  AND verified_at IS NOT NULL;
"
```

### DVWA Session Expired

```bash
# Re-login and get fresh session cookie
# DevTools → Application → Cookies → copy PHPSESSID
```

### Scan Too Slow

```bash
# Use --no-crawl to skip BFS crawl
python -m pyth --target "http://localhost:8081/products.php?id=1" --no-crawl --aggressive

# Or limit pages
python -m pyth --target http://localhost:8081 --max-pages 10 --aggressive
```

### SARIF Has Mixed Content

If you see log lines mixed into the SARIF output:

```bash
# --sarif redirects logs to stderr automatically
# Use 2>/dev/null to suppress stderr if needed
python -m pyth --target http://localhost:8081 --sarif 2>/dev/null > results.sarif
```

### Database Connection Errors

```bash
# Test MySQL connectivity
docker compose exec mysql mysqladmin ping -h localhost -uroot -proot123

# Verify databases exist
docker compose exec mysql mysql -uroot -proot123 -e "SHOW DATABASES;"
# Should list: shop, blog, dvwa
```

---

## Security Best Practices

### Lab Isolation

```bash
# Verify ports are localhost-only
docker compose ps
# Ports should show 127.0.0.1:8081 not 0.0.0.0:8081
```

### Data Protection

```bash
# NEVER use real credentials in lab
# Clear lab data after testing
docker compose down -v  # Removes all data
```

---

## Further Reading

-   [SQL Injection Cheat Sheet - PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
-   [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
-   [DVWA Documentation](https://github.com/digininja/DVWA)
-   [OWASP Top 10 — A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
-   [CWE-89 Reference](https://cwe.mitre.org/data/definitions/89.html)

---

_Pythia v0.2.0 — Testing Guide_

If you find any issues with this testing guide or lab setup, please report them at:
https://github.com/rodhnin/pythia-sql-clairvoyance/issues

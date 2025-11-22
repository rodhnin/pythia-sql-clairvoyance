# Pythia CLI Examples

Comprehensive command-line usage examples for Pythia SQL injection scanner.

---

## Basic Scanning

### Quick Scan (Safe Mode)

```bash
# Minimal command - safe, non-intrusive checks (error-based + boolean-blind)
python -m pyth --target http://example.com/products?id=1

# Same with explicit safe mode
python -m pyth --target http://example.com/products?id=1 --safe
```

### With HTML Report

```bash
# Generate both JSON and HTML reports
python -m pyth --target http://example.com/search?q=test --html
```

### Custom Output Directory

```bash
# Save reports to specific directory
python -m pyth --target http://example.com/users?id=5 \
  --report-dir ./client-reports \
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

# Maximum verbosity (includes HTTP details)
python -m pyth --target http://example.com/search?q=test -vvv
```

### Logging to File

```bash
# Log to custom file
python -m pyth --target http://example.com/items?id=1 \
  --log-file ./logs/sqli-scan.log -vv

# JSON formatted logs (for parsing/SIEM)
python -m pyth --target http://example.com/api/users?id=1 \
  --log-json \
  --log-file ./logs/sqli-scan.json
```

### Quiet Mode (CI/CD)

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
# Generate token for domain
python -m pyth --gen-consent example.com

# Example output:
# Token: verify-a3f9b2c1d8e4
# Place at: https://example.com/.well-known/verify-a3f9b2c1d8e4.txt
```

### Verify via HTTP

```bash
# After placing token file
python -m pyth --verify-consent http \
  --domain example.com \
  --token verify-a3f9b2c1d8e4
```

### Verify via DNS

```bash
# After adding TXT record
python -m pyth --verify-consent dns \
  --domain example.com \
  --token verify-a3f9b2c1d8e4
```

---

## Aggressive Scanning

### Full Workflow

```bash
# 1. Generate token
python -m pyth --gen-consent example.com

# 2. Verify consent (HTTP method)
python -m pyth --verify-consent http \
  --domain example.com \
  --token verify-abc123

# 3. Run aggressive scan (includes time-based + UNION-based)
python -m pyth --target http://example.com/products?id=1 \
  --aggressive \
  --html
```

### With Custom Rate Limit

```bash
# Scan faster (10 req/sec for aggressive mode)
python -m pyth --target http://example.com/search?q=test \
  --aggressive \
  --rate 10 \
  --threads 10
```

### Deep Crawling

```bash
# Crawl deeper and test more pages
python -m pyth --target http://example.com \
  --aggressive \
  --max-depth 5 \
  --max-pages 200
```

---

## AI-Powered Analysis

### Basic AI Scan

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Generate both summaries (executive + technical)
python -m pyth --target http://example.com/products?id=1 \
  --use-ai \
  --html
```

### Technical Summary Only

```bash
# For engineers (code examples, cheaper, faster)
python -m pyth --target http://example.com/api/users?id=1 \
  --use-ai \
  --ai-tone technical \
  --html
```

### Executive Summary Only

```bash
# For stakeholders (business impact, compliance)
python -m pyth --target http://example.com/search?q=test \
  --use-ai \
  --ai-tone non_technical \
  --html
```

### Using Anthropic Claude

```bash
# Set Anthropic API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Edit config to use Claude
nano config/default.yaml
# Change: ai.provider: "anthropic"

# Run scan
python -m pyth --target http://example.com/products?id=1 \
  --use-ai \
  --html
```

### Using Ollama (Local/Offline)

```bash
# Start Ollama server
ollama serve

# Pull model
ollama pull llama3.2

# Edit config to use Ollama
nano config/default.yaml
# Change: ai.provider: "ollama"

# Run scan (100% offline, slower)
python -m pyth --target http://localhost:8081/products?id=1 \
  --use-ai \
  --html
```

---

## SQL Injection-Specific Options

### Crawler Configuration

```bash
# Control crawl depth
python -m pyth --target http://example.com \
  --max-depth 3 \
  --max-pages 100

# Shallow scan (quick)
python -m pyth --target http://example.com \
  --max-depth 1 \
  --max-pages 10
```

### Testing Specific Parameters

```bash
# Test single endpoint
python -m pyth --target "http://example.com/products?id=1&category=books"

# Test POST endpoint (crawler will find forms)
python -m pyth --target http://example.com/login.php --aggressive
```

### Cookie-Based Testing

```bash
# Test with session cookies (authenticated scanning)
python -m pyth --target "http://example.com/admin/users?id=1" \
  --cookie "PHPSESSID=abc123;security=low" \
  --safe

# Multiple cookies
python -m pyth --target "http://example.com/profile?user_id=5" \
  --cookie "session_id=xyz789;auth_token=secret123" \
  --aggressive
```

---

## Advanced Options

### Custom Timeout

```bash
# Increase timeout for slow servers (important for time-based detection)
python -m pyth --target http://slow-api.example.com/search?q=test \
  --timeout 60
```

### Custom User-Agent

```bash
# Spoof user agent
python -m pyth --target http://example.com/api/posts?id=1 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Skip SSL Verification (Local Testing)

```bash
# For self-signed certs (test environments)
python -m pyth --target https://localhost:8443/products?id=1 \
  --no-verify-ssl
```

### Ignore robots.txt

```bash
# Bypass robots.txt restrictions (use with caution)
python -m pyth --target http://example.com \
  --no-robots \
  --aggressive
```

---

## Database Operations

### Custom Database Path

```bash
# Use separate DB for this project
python -m pyth --target http://example.com/products?id=1 \
  --db ./projects/client-a/scans.db
```

### View Scan History (SQLite)

```bash
# Query recent Pythia scans
sqlite3 ~/.argos/argos.db \
  "SELECT * FROM scans WHERE tool='pythia' ORDER BY scan_id DESC LIMIT 10"

# Critical SQL injection findings
sqlite3 ~/.argos/argos.db \
  "SELECT * FROM findings WHERE severity='critical' AND scan_id IN
   (SELECT scan_id FROM scans WHERE tool='pythia')"

# Verified domains (shared with Argos)
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains"

# SQL injection statistics
sqlite3 ~/.argos/argos.db \
  "SELECT detection_method, COUNT(*) as count
   FROM findings
   WHERE tool='pythia'
   GROUP BY detection_method"
```

---

## Docker Usage

### Run in Container

```bash
# Build image
docker build -f docker/Dockerfile -t pythia:latest .

# Show help
docker run --rm pythia:latest --help

# Simple scan
docker run --rm \
  -v $(pwd)/reports:/reports \
  pythia:latest \
  --target http://example.com/products?id=1

# With AI analysis
docker run --rm \
  -v $(pwd)/reports:/reports \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  pythia:latest \
  --target http://example.com/search?q=test \
  --use-ai \
  --html
```

### Scan Docker Lab

```bash
# Start PHP lab
cd docker/lab
docker compose -f docker-compose.php.yml up -d

# Scan from host
python -m pyth --target http://localhost:8081/products.php?id=1 --html

# Start Flask lab
docker compose -f docker-compose.flask.yml up -d

# Scan Flask app
python -m pyth --target http://localhost:8082/api/posts?id=1 --aggressive --html
```

---

## Production Workflows

### Full Client Scan

```bash
#!/bin/bash
# client-sqli-scan.sh

TARGET="$1"
CLIENT="$2"

echo "🔮 Scanning $TARGET for SQL injection vulnerabilities..."
echo "Client: $CLIENT"

# 1. Generate consent token
echo "Step 1/4: Generating consent token..."
python -m pyth --gen-consent $TARGET

# 2. Wait for client to place token
read -p "Step 2/4: Press enter after token is placed at /.well-known/..."

# 3. Verify consent
echo "Step 3/4: Verifying consent..."
python -m pyth --verify-consent http \
  --domain $TARGET \
  --token $(cat token.txt)

# 4. Scan with AI analysis
echo "Step 4/4: Running comprehensive SQL injection scan..."
python -m pyth \
  --target "http://$TARGET" \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --html \
  --report-dir ./clients/$CLIENT/reports \
  --max-depth 5 \
  --max-pages 200 \
  -vv

echo "✅ Scan complete! Check ./clients/$CLIENT/reports/"
```

### CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/sqli-security-scan.yml
name: SQL Injection Security Scan

on:
    schedule:
        - cron: "0 0 * * 0" # Weekly on Sunday
    workflow_dispatch: # Manual trigger

jobs:
    sqli-scan:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v3

            - name: Setup Python
              uses: actions/setup-python@v4
              with:
                  python-version: "3.11"

            - name: Install Pythia
              run: |
                  pip install --upgrade pip
                  pip install -r requirements.txt

            - name: Run SQL Injection Scan
              env:
                  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
              run: |
                  python -m pyth \
                    --target ${{ secrets.TARGET_URL }} \
                    --aggressive \
                    --use-ai \
                    --html \
                    --quiet \
                    --no-color \
                    --report-dir ./reports

            - name: Upload Reports
              uses: actions/upload-artifact@v3
              with:
                  name: sqli-security-reports
                  path: ./reports/

            - name: Check for Critical Findings
              run: |
                  CRITICAL=$(jq '.summary.critical' ./reports/*.json | head -1)
                  if [ "$CRITICAL" -gt 0 ]; then
                    echo "⚠️ Critical SQL injection vulnerabilities found!"
                    exit 1
                  fi
```

### Cron Job (Linux)

```bash
# Add to crontab
crontab -e

# Scan every Sunday at 2 AM
0 2 * * 0 cd /opt/pythia && python -m pyth --target http://myapp.com --aggressive --html >> /var/log/pythia.log 2>&1

# Scan daily (quick safe mode check)
0 1 * * * cd /opt/pythia && python -m pyth --target http://myapp.com --safe --html >> /var/log/pythia-daily.log 2>&1
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        OPENAI_API_KEY = credentials('openai-api-key')
        TARGET_URL = 'http://staging.example.com'
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }

        stage('SQL Injection Scan') {
            steps {
                sh '''
                    python -m pyth \
                      --target ${TARGET_URL} \
                      --aggressive \
                      --use-ai \
                      --html \
                      --quiet \
                      --report-dir ./reports
                '''
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'reports/**/*', fingerprint: true
            }
        }

        stage('Check Results') {
            steps {
                script {
                    def report = readJSON file: 'reports/pythia_sqli_report_*.json'
                    if (report.summary.critical > 0) {
                        error("Critical SQL injection vulnerabilities detected!")
                    }
                }
            }
        }
    }
}
```

---

## Troubleshooting

### Debug Connection Issues

```bash
# Maximum verbosity + extended timeout
python -m pyth --target http://example.com/products?id=1 \
  -vvv \
  --timeout 120
```

### Test Specific Detection Methods

```bash
# Test only error-based (safe mode)
python -m pyth --target http://example.com/search?q=test --safe -vv

# Test all methods including time-based (requires consent)
python -m pyth --target http://example.com/users?id=1 --aggressive -vv
```

### Test Consent Token Manually

```bash
# Check if token file is accessible
curl http://example.com/.well-known/verify-abc123.txt
# Should return: verify-abc123

# Check DNS TXT record
dig TXT example.com +short
# Or: nslookup -type=TXT example.com
```

### Verify Installation

```bash
# Check version
python -m pyth --version

# Check dependencies
pip list | grep -E 'requests|beautifulsoup4|langchain'

# Test database connection (shared with Argos)
python -c "from pyth.core.db import get_db; db = get_db(); print('DB OK')"

# Test HTTP client
python -c "from pyth.core.http_client import HTTPClient; client = HTTPClient(); print('HTTP Client OK')"
```

### Test AI Integration

```bash
# Test OpenAI
python -m pyth.core.ai openai

# Test Anthropic
python -m pyth.core.ai anthropic

# Test Ollama
python -m pyth.core.ai ollama
```

---

## Quick Reference

### Common Patterns

```bash
# Quick safe scan
pyth --target "http://example.com/products?id=1"

# Client deliverable (full scan with AI)
pyth --target "http://example.com/search?q=test" \
  --aggressive \
  --use-ai \
  --html \
  -vv

# Local testing (vulnerable lab)
pyth --target http://localhost:8081/products.php?id=1 \
  --no-verify-ssl \
  --html

# Fast aggressive scan
pyth --target "http://example.com/api/posts?id=1" \
  --aggressive \
  --rate 20 \
  --threads 15

# Quiet mode (for scripts/CI)
pyth --target "http://example.com/users?id=5" \
  --quiet \
  --no-color \
  --log-json \
  --log-file scan.json

# Minimal AI cost (technical only)
pyth --target "http://example.com/products?id=1" \
  --use-ai \
  --ai-tone technical

# Deep authenticated scan
pyth --target "http://example.com/admin/users?id=1" \
  --cookie "PHPSESSID=abc123" \
  --aggressive \
  --max-depth 5
```

### Environment Variables

```bash
# Common env vars
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export PYTHIA_REPORT_DIR="./reports"
export PYTHIA_DATABASE="./pythia.db"
export PYTHIA_LOG_LEVEL="DEBUG"
export PYTHIA_RATE_LIMIT="5.0"
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

# Check shared database status
sqlite3 ~/.argos/argos.db "SELECT COUNT(*) FROM scans WHERE tool='pythia'"
```

---

## Tips & Tricks

### 1. Scan Multiple Endpoints

```bash
# Loop through URLs file
while read url; do
  echo "Scanning: $url"
  python -m pyth --target "$url" --html
  sleep 5  # Be respectful
done < endpoints.txt
```

**Example endpoints.txt:**

```
http://example.com/products?id=1
http://example.com/search?q=test
http://example.com/users?id=5
http://example.com/api/posts?id=10
```

### 2. Compare Scans Over Time

```bash
# Initial baseline scan
python -m pyth --target http://example.com/products?id=1 \
  --html \
  --report-dir ./baseline

# After remediation
python -m pyth --target http://example.com/products?id=1 \
  --html \
  --report-dir ./after-fix

# Compare with jq
jq -s '.[0].summary as $before | .[1].summary as $after |
  {
    before: $before,
    after: $after,
    improvement: {
      critical: ($before.critical - $after.critical),
      high: ($before.high - $after.high)
    }
  }' \
  baseline/pythia_*.json after-fix/pythia_*.json
```

### 3. Filter Findings by Severity

```bash
# Extract only critical SQL injection findings
jq '.findings[] | select(.severity=="critical")' report.json

# Count findings by detection method
jq '.findings | group_by(.detection_method) |
    map({method: .[0].detection_method, count: length})' report.json
```

### 4. Generate Tokens in Batch

```bash
# Generate tokens for multiple domains
for domain in app1.com app2.com app3.com; do
  echo "Generating token for $domain..."
  python -m pyth --gen-consent $domain | tee tokens-$domain.txt
done
```

### 5. Auto-Deploy Token to Server

```bash
#!/bin/bash
# auto-deploy-token.sh

DOMAIN=$1
TOKEN=$2
SERVER=$3

# Create .well-known directory
ssh $SERVER "mkdir -p /var/www/html/.well-known"

# Upload token file
echo "$TOKEN" | ssh $SERVER "cat > /var/www/html/.well-known/$TOKEN.txt"

# Verify it's accessible
curl http://$DOMAIN/.well-known/$TOKEN.txt

# Run verification
python -m pyth --verify-consent http --domain $DOMAIN --token $TOKEN
```

### 6. Automated Remediation Verification

```bash
#!/bin/bash
# verify-fix.sh

TARGET=$1

# Scan before
echo "Scanning before fix..."
python -m pyth --target "$TARGET" \
  --aggressive \
  --report-dir ./before \
  --html

BEFORE_CRITICAL=$(jq '.summary.critical' ./before/pythia_*.json | head -1)

echo "Found $BEFORE_CRITICAL critical issues"
read -p "Apply fixes and press enter..."

# Scan after
echo "Scanning after fix..."
python -m pyth --target "$TARGET" \
  --aggressive \
  --report-dir ./after \
  --html

AFTER_CRITICAL=$(jq '.summary.critical' ./after/pythia_*.json | head -1)

echo "Critical issues remaining: $AFTER_CRITICAL"

if [ "$AFTER_CRITICAL" -eq 0 ]; then
  echo "✅ All critical SQL injection vulnerabilities fixed!"
else
  echo "⚠️ Still $AFTER_CRITICAL critical vulnerabilities remaining"
fi
```

### 7. Extract Database Information

```bash
# Extract detected database types from reports
jq -r '.findings[] | select(.evidence.dbms) |
       "\(.affected_component): \(.evidence.dbms)"' report.json
```

### 8. Generate Executive Summary

```bash
# Create quick summary from JSON
jq '{
  target: .target,
  date: .date,
  mode: .mode,
  summary: .summary,
  critical_findings: [.findings[] | select(.severity=="critical") | .title]
}' report.json > executive-summary.json
```

### 9. Monitor False Positive Rate

```bash
# Track findings over multiple scans
sqlite3 ~/.argos/argos.db <<EOF
SELECT
  DATE(started_at) as scan_date,
  COUNT(*) as total_findings,
  SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical
FROM findings
WHERE tool='pythia'
  AND scan_id IN (SELECT scan_id FROM scans WHERE domain='example.com')
GROUP BY DATE(started_at)
ORDER BY scan_date DESC;
EOF
```

### 10. Create Custom Wordlist for Testing

```bash
# Create endpoint wordlist from sitemap
curl http://example.com/sitemap.xml | \
  grep -oP '(?<=<loc>)[^<]+' | \
  grep '?' > endpoints.txt

# Scan each endpoint
cat endpoints.txt | while read endpoint; do
  python -m pyth --target "$endpoint" --safe
done
```

---

## Real-World Scenarios

### Scenario 1: Pre-Deployment Security Check

```bash
#!/bin/bash
# pre-deploy-check.sh

STAGING_URL="http://staging.example.com"

echo "🔮 Running pre-deployment SQL injection scan..."

python -m pyth \
  --target "$STAGING_URL" \
  --aggressive \
  --use-ai \
  --ai-tone technical \
  --html \
  --report-dir ./pre-deploy

# Check results
CRITICAL=$(jq '.summary.critical' ./pre-deploy/pythia_*.json | head -1)
HIGH=$(jq '.summary.high' ./pre-deploy/pythia_*.json | head -1)

if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 2 ]; then
  echo "❌ DEPLOYMENT BLOCKED"
  echo "Critical: $CRITICAL, High: $HIGH"
  echo "Fix SQL injection vulnerabilities before deploying to production"
  exit 1
else
  echo "✅ DEPLOYMENT APPROVED"
  echo "No critical SQL injection vulnerabilities detected"
  exit 0
fi
```

### Scenario 2: Bug Bounty Reconnaissance

```bash
#!/bin/bash
# bounty-recon.sh

PROGRAM=$1  # e.g., "hackerone-example"
TARGET=$2   # e.g., "https://target.com"

echo "🔮 Starting SQL injection reconnaissance for $PROGRAM..."

# Create project directory
mkdir -p ./bounty/$PROGRAM

# Quick safe scan first
python -m pyth \
  --target "$TARGET" \
  --safe \
  --max-depth 3 \
  --max-pages 50 \
  --report-dir ./bounty/$PROGRAM/quick \
  -vv

# Check if any findings
FINDINGS=$(jq '.summary.critical + .summary.high' ./bounty/$PROGRAM/quick/pythia_*.json | head -1)

if [ "$FINDINGS" -gt 0 ]; then
  echo "⚠️ Potential SQL injection found! Running deep scan..."

  # Deep scan (requires consent for aggressive mode)
  # Only use if you have authorization!
  python -m pyth \
    --target "$TARGET" \
    --safe \
    --max-depth 5 \
    --max-pages 200 \
    --report-dir ./bounty/$PROGRAM/deep \
    --html \
    -vv

  echo "📋 Review findings in ./bounty/$PROGRAM/"
else
  echo "✅ No obvious SQL injection vectors found"
fi
```

### Scenario 3: Compliance Audit

```bash
#!/bin/bash
# compliance-audit.sh

# PCI-DSS, GDPR, HIPAA require protection against SQL injection

COMPANY="acme-corp"
APPLICATIONS=(
  "https://customer-portal.acme.com"
  "https://payment.acme.com"
  "https://api.acme.com"
)

mkdir -p ./compliance/$COMPANY

for app in "${APPLICATIONS[@]}"; do
  APP_NAME=$(echo $app | sed 's/https\?:\/\///' | sed 's/\//-/g')

  echo "Auditing: $app"

  python -m pyth \
    --target "$app" \
    --aggressive \
    --use-ai \
    --ai-tone non_technical \
    --html \
    --report-dir "./compliance/$COMPANY/$APP_NAME" \
    -vv
done

# Generate compliance summary
echo "Generating compliance report..."
python3 << 'PYTHON'
import json
import glob
from pathlib import Path

reports = glob.glob("./compliance/**/pythia_*.json", recursive=True)
summary = {
    "total_apps": len(reports),
    "compliant": 0,
    "non_compliant": 0,
    "critical_issues": 0
}

for report_path in reports:
    with open(report_path) as f:
        data = json.load(f)
        if data['summary']['critical'] == 0 and data['summary']['high'] == 0:
            summary['compliant'] += 1
        else:
            summary['non_compliant'] += 1
            summary['critical_issues'] += data['summary']['critical']

print(json.dumps(summary, indent=2))
PYTHON
```

---

## Advanced Integration Examples

### Slack Notifications

```bash
#!/bin/bash
# scan-and-notify.sh

TARGET=$1
SLACK_WEBHOOK=$2

# Run scan
python -m pyth --target "$TARGET" --aggressive --html --quiet

# Parse results
REPORT=$(ls -t ~/.pythia/reports/pythia_*.json | head -1)
CRITICAL=$(jq '.summary.critical' $REPORT)
HIGH=$(jq '.summary.high' $REPORT)

# Send to Slack
if [ "$CRITICAL" -gt 0 ]; then
  MESSAGE="🚨 *CRITICAL SQL INJECTION* found on $TARGET\nCritical: $CRITICAL | High: $HIGH"
  COLOR="danger"
else
  MESSAGE="✅ SQL injection scan completed for $TARGET\nCritical: $CRITICAL | High: $HIGH"
  COLOR="good"
fi

curl -X POST $SLACK_WEBHOOK \
  -H 'Content-Type: application/json' \
  -d "{\"attachments\": [{\"color\": \"$COLOR\", \"text\": \"$MESSAGE\"}]}"
```

### Jira Ticket Creation

```python
#!/usr/bin/env python3
# create-jira-tickets.py

import json
import sys
from jira import JIRA

# Configuration
JIRA_URL = "https://your-company.atlassian.net"
JIRA_TOKEN = "your-api-token"
PROJECT_KEY = "SEC"

# Load Pythia report
with open(sys.argv[1]) as f:
    report = json.load(f)

# Connect to Jira
jira = JIRA(server=JIRA_URL, token_auth=JIRA_TOKEN)

# Create tickets for critical findings
for finding in report['findings']:
    if finding['severity'] in ['critical', 'high']:
        issue = jira.create_issue(
            project=PROJECT_KEY,
            summary=f"SQL Injection: {finding['title']}",
            description=f"""
*Target:* {report['target']}
*Severity:* {finding['severity'].upper()}
*Detection Method:* {finding['detection_method']}

h3. Description
{finding['description']}

h3. Evidence
{finding['evidence']['context']}

h3. Remediation
{finding['recommendation']}
            """,
            issuetype={'name': 'Security Bug'},
            priority={'name': 'Critical' if finding['severity'] == 'critical' else 'High'}
        )
        print(f"Created ticket: {issue.key}")
```

---

## Performance Tuning

### Fast Scan (Quick Check)

```bash
# Minimal crawling, fast rate
python -m pyth --target http://example.com \
  --safe \
  --max-depth 1 \
  --max-pages 10 \
  --rate 10 \
  --threads 5 \
  --timeout 10
```

### Thorough Scan (Maximum Coverage)

```bash
# Deep crawling, comprehensive testing
python -m pyth --target http://example.com \
  --aggressive \
  --max-depth 5 \
  --max-pages 500 \
  --rate 3 \
  --threads 10 \
  --timeout 60
```

### Resource-Constrained Environment

```bash
# Low memory/CPU usage
python -m pyth --target http://example.com \
  --safe \
  --rate 2 \
  --threads 1 \
  --timeout 30
```

---

**More examples?** Check the [docs/](../docs/) folder or open an issue!

**Quick Start:** For your first scan, just run:

```bash
python -m pyth --target "http://testphp.vulnweb.com/artists.php?artist=1"
```

**Need Help?** Join the discussion: https://github.com/rodhnin/pythia-sql-clairvoyance/discussions

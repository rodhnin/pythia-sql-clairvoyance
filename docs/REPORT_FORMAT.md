# Pythia Report Format Documentation

## Overview

Pythia generates structured security reports in **JSON** (machine-readable) and **HTML** (human-readable) formats for SQL injection vulnerability assessments. All reports conform to the shared Argos ecosystem JSON Schema for consistency and validation across security tools.

---

## JSON Schema

### Location

Reports follow the shared Argos schema at `schema/report.schema.json` (JSON Schema Draft 2020-12)

### Validation

Reports are automatically validated before saving:

```python
from pyth.core.report import ReportGenerator

generator = ReportGenerator()
report = {...}
is_valid = generator.validate_report(report)  # True/False
```

### Top-Level Structure (v0.2.0)

```json
{
  "tool": "pythia",
  "version": "0.2.0",
  "target": "http://example.com/products?id=1",
  "date": "2026-03-18T14:30:00Z",
  "mode": "aggressive",
  "summary": {...},
  "findings": [...],
  "notes": {...},
  "consent": {...},
  "ai_analysis": {...},
  "diff": {...}
}
```

**New in v0.2.0:** `diff` top-level field (present only when `--diff` flag is used).

---

## Field Definitions

### Required Fields

#### `tool` (string)

-   **Value**: `"pythia"`
-   **Purpose**: Identifies the SQL injection scanner in shared Argos database
-   **Example**: `"pythia"`

#### `version` (string)

-   **Format**: Semantic versioning (X.Y.Z)
-   **Example**: `"0.2.0"`

#### `target` (string)

-   **Format**: Full URL with parameters
-   **Examples**:
    -   `"http://example.com/products?id=1"`
    -   `"http://localhost:8081"`
    -   `"https://api.example.com/v1/users"`

#### `date` (string)

-   **Format**: ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`)
-   **Example**: `"2026-03-18T14:30:00Z"`

#### `mode` (string)

-   **Values**: `"safe"` | `"aggressive"`
-   **safe**: Error-based + Boolean-blind only
-   **aggressive**: All 4 techniques + WAF bypass payloads

#### `summary` (object)

```json
{
  "total": 26,
  "critical": 18,
  "high": 6,
  "medium": 2,
  "low": 0
}
```

#### `findings` (array)

Array of finding objects. See [Finding Object](#finding-object) below.

---

### `notes` Object

Scan metadata and disclaimers:

```json
{
  "scan_duration_seconds": 87.3,
  "requests_sent": 342,
  "rate_limit_applied": "5.0 req/s",
  "false_positive_disclaimer": "All findings verified with multiple payloads. Boolean-blind findings require similarity < 0.95 and confirmation with a second payload.",
  "scope_limitations": "Scan limited to same-origin URLs. JavaScript-rendered content requires --js flag."
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `scan_duration_seconds` | float | Total elapsed scan time |
| `requests_sent` | int | Total HTTP requests made |
| `rate_limit_applied` | string | Rate limit in effect during scan |
| `false_positive_disclaimer` | string | False positive mitigation note |
| `scope_limitations` | string | Scope and coverage notes |

---

### Finding Object

Complete v0.2.0 finding structure:

```json
{
  "id": "PYTHIA-SQL-001",
  "title": "Error-Based SQL Injection (MySQL/MariaDB)",
  "description": "The parameter 'id' is vulnerable to error-based SQL injection. The application exposes MySQL error messages in the response, allowing an attacker to infer database structure and extract data.",
  "severity": "critical",
  "confidence": "high",
  "recommendation": "Replace string concatenation with parameterized queries. Use PDO with prepared statements in PHP or SQLAlchemy ORM in Python.",
  "evidence": {
    "type": "error_based",
    "parameter": "id",
    "payload": "' OR '1'='1' --",
    "response_excerpt": "You have an error in your SQL syntax...",
    "url": "http://example.com/products?id=1"
  },
  "references": [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://cwe.mitre.org/data/definitions/89.html"
  ],
  "affected_component": "http://example.com/products?id=1",
  "timestamp": "2026-03-18T14:31:22Z",
  "detection_method": "error-based",
  "parameter": "id",
  "vector": "GET",
  "dbms": "MySQL 8.0.32",
  "cvss": 9.8,
  "contextual_score": 9.9,
  "risk_factors": ["no_ssl", "pii_detected"],
  "payload": "' OR '1'='1' --",
  "owasp": {
    "id": "A03",
    "name": "Injection"
  },
  "cwe": {
    "id": "CWE-89",
    "name": "SQL Injection"
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-21980",
      "title": "MySQL 8.0 SQL Injection via error disclosure",
      "description": "...",
      "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-21980",
      "cvss_score": 9.8,
      "cwe_id": "CWE-89",
      "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command"
    }
  ]
}
```

#### Finding Fields Reference

**Core fields (present in all findings):**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Finding code (e.g. `PYTHIA-SQL-001`) |
| `title` | string | Human-readable finding name |
| `description` | string | Detailed vulnerability description |
| `severity` | string | `critical` / `high` / `medium` / `low` |
| `confidence` | string | `high` / `medium` / `low` |
| `recommendation` | string | Remediation guidance |
| `evidence` | object | Payload, response excerpt, URL |
| `references` | array | OWASP, CWE, NVD links |
| `affected_component` | string | Full URL of affected endpoint |
| `timestamp` | string | ISO 8601 when finding was created |
| `detection_method` | string | `error-based` / `boolean-blind` / `time-based` / `union-based` / `second-order` / `order-by` |

**New in v0.2.0:**

| Field | Type | Description |
|-------|------|-------------|
| `parameter` | string | Vulnerable parameter name (e.g. `id`, `q`, `sort`) |
| `vector` | string | HTTP method: `GET` / `POST` / `COOKIE` / `HEADER` |
| `dbms` | string | Detected database (e.g. `MySQL 8.0.32`, `PostgreSQL 14.1`) |
| `cvss` | float | Base CVSS score (9.8 for CWE-89) |
| `contextual_score` | float | Adjusted score with environmental modifiers |
| `risk_factors` | array | Active modifiers: `no_ssl`, `pii_detected`, `root_db_user` |
| `payload` | string | The injected payload that triggered detection |
| `owasp` | object | OWASP category: `{"id": "A03", "name": "Injection"}` |
| `cwe` | object | CWE entry: `{"id": "CWE-89", "name": "SQL Injection"}` |
| `vulnerabilities` | array | CVE entries from NVD (populated by `--ai-agent`) |

---

## Finding Codes — v0.2.0 Complete Reference

All finding codes → **OWASP A03 Injection** / **CWE-89 SQL Injection**

| Code | Detection Type | DBMS / Vector | Mode |
|------|---------------|---------------|------|
| `PYTHIA-SQL-001` | Error-Based | MySQL / MariaDB | Safe |
| `PYTHIA-SQL-002` | Error-Based | PostgreSQL | Safe |
| `PYTHIA-SQL-003` | Error-Based | MSSQL / SQL Server | Safe |
| `PYTHIA-SQL-004` | Error-Based | Oracle | Safe |
| `PYTHIA-SQL-005` | Error-Based | SQLite | Safe |
| `PYTHIA-SQL-010` | Boolean Blind | Any DBMS (parameter) | Safe |
| `PYTHIA-SQL-011` | Boolean Blind | Via header injection | Safe |
| `PYTHIA-SQL-020` | Time-Based Blind | MySQL SLEEP() | Aggressive |
| `PYTHIA-SQL-021` | Time-Based Blind | MSSQL WAITFOR DELAY | Aggressive |
| `PYTHIA-SQL-022` | Time-Based Blind | PostgreSQL pg_sleep() | Aggressive |
| `PYTHIA-SQL-030` | UNION-Based | GET/POST parameter | Aggressive |
| `PYTHIA-SQL-031` | UNION-Based | Via cookie | Aggressive |
| `PYTHIA-SQL-040` | Second-Order | Store → retrieve pattern | Aggressive |
| `PYTHIA-SQL-050` | ORDER BY Injection | Numeric sort parameter | Aggressive |

---

## OWASP Mapping

All Pythia SQL injection findings map to **OWASP Top 10 2021 — A03: Injection**.

```python
from pyth.core.owasp import get_owasp, get_cwe

owasp = get_owasp("PYTHIA-SQL-001")
# {"id": "A03", "name": "Injection"}

cwe = get_cwe("PYTHIA-SQL-001")
# {"id": "CWE-89", "name": "SQL Injection"}
```

### CWE-89 Canonical Reference

CWE-89 ("Improper Neutralization of Special Elements used in an SQL Command") is the industry-standard classification for all SQL injection vulnerabilities. The NVD uses `cweId=CWE-89` to catalog all SQL injection CVEs, which is how `--ai-agent` searches for applicable vulnerabilities.

---

## Contextual Risk Scoring

Beyond the base CVSS score of 9.8 (CWE-89), Pythia calculates a contextual score based on environmental factors detected during the scan:

| Modifier | Trigger | Effect |
|----------|---------|--------|
| `no_ssl` | Target uses HTTP (not HTTPS) | Score increases |
| `pii_detected` | Email/password patterns found in responses | Score increases significantly |
| `root_db_user` | Root/admin DB privileges detected via error messages | Score increases significantly |

The `contextual_score` field appears in every finding alongside the base `cvss` score. Example: base 9.8 → contextual 9.9 when PII is detected.

---

## Diff Section

When `--diff last` or `--diff <scan_id>` is used, a `diff` object appears at the report top level:

```json
{
  "diff": {
    "ref_scan_id": 38,
    "ref_date": "2026-03-15T10:00:00Z",
    "ref_target": "http://example.com",
    "ref_mode": "aggressive",
    "current_mode": "aggressive",
    "mode_mismatch": false,
    "new": [
      {"id": "PYTHIA-SQL-040", "title": "Second-Order SQL Injection", "severity": "critical"}
    ],
    "fixed": [
      {"id": "PYTHIA-SQL-030", "title": "UNION-Based SQL Injection", "severity": "critical"}
    ],
    "persisting": [
      {"id": "PYTHIA-SQL-001", "title": "Error-Based SQL Injection (MySQL)", "severity": "critical"}
    ]
  }
}
```

**Diff fields:**

| Field | Description |
|-------|-------------|
| `ref_scan_id` | Scan ID of the reference scan |
| `ref_date` | Date of the reference scan |
| `ref_target` | Target URL of the reference scan |
| `ref_mode` | Mode of the reference scan |
| `current_mode` | Mode of the current scan |
| `mode_mismatch` | `true` if modes differ (informational warning only) |
| `new` | Findings present in current scan but not in reference |
| `fixed` | Findings present in reference but not in current scan |
| `persisting` | Findings present in both scans |

---

## SARIF Output

When `--sarif` is passed, Pythia outputs SARIF 2.1.0 to stdout (all other logs redirect to stderr):

```bash
python -m pyth --target http://example.com --aggressive --sarif > results.sarif
```

### SARIF Structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Pythia",
          "version": "0.2.0",
          "rules": [...]
        }
      },
      "results": [
        {
          "ruleId": "PYTHIA-SQL-001",
          "level": "error",
          "message": {
            "text": "Error-Based SQL Injection (MySQL/MariaDB) in GET parameter 'id'"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "http://example.com/products?id=1"
                }
              }
            }
          ],
          "properties": {
            "severity": "critical",
            "cvss": 9.8,
            "owasp": "A03",
            "cwe": "CWE-89"
          }
        }
      ]
    }
  ]
}
```

SARIF output is compatible with:
- GitHub Security tab (Code Scanning)
- GitLab SAST
- Azure DevOps Security

---

## HTML Report

HTML reports are self-contained (no external dependencies) and saved to `~/.pythia/reports/`.

### v0.2.0 Features

-   **Filter bar**: Filter findings by severity, OWASP category, detection method, DBMS
-   **OWASP/CWE/CVE badges**: Per finding, clickable to external references
-   **CVSS score display**: Color-coded (9.0+ = red critical, 7.0-8.9 = orange high)
-   **Contextual score**: Shown alongside CVSS base score when modifiers apply
-   **Payload visualization**: Syntax-highlighted injection payloads
-   **Expandable evidence**: Request/response diff with highlighting
-   **AI tabs**: Standard analysis / Agent mode (with CVEs) / Compare mode (multi-provider)
-   **Diff section**: New/fixed/persisting findings clearly marked
-   **Theme**: Oracle/mystic purple (`#6a11cb`)

---

## Report File Naming

```
~/.pythia/reports/pythia_sqli_report_{domain}_{YYYYMMDD}_{HHMMSS}.json
~/.pythia/reports/pythia_sqli_report_{domain}_{YYYYMMDD}_{HHMMSS}.html
```

Example:
```
~/.pythia/reports/pythia_sqli_report_localhost_20260318_143022.json
~/.pythia/reports/pythia_sqli_report_localhost_20260318_143022.html
```

Use `--report-dir` to change the output directory.

---

## Severity Mapping

| Severity | CVSS Range | Finding Examples |
|----------|-----------|------------------|
| **critical** | 9.0-10.0 | Error-based, time-based, UNION-based, second-order |
| **high** | 7.0-8.9 | Boolean-blind (high confidence), ORDER BY injection |
| **medium** | 4.0-6.9 | Boolean-blind (medium confidence) |
| **low** | 0.1-3.9 | Potential SQLi with inconclusive evidence |

---

## Complete JSON Report Example (v0.2.0)

```json
{
  "tool": "pythia",
  "version": "0.2.0",
  "target": "http://localhost:8081",
  "date": "2026-03-18T14:30:00Z",
  "mode": "aggressive",
  "summary": {
    "total": 4,
    "critical": 3,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "PYTHIA-SQL-001",
      "title": "Error-Based SQL Injection (MySQL/MariaDB)",
      "description": "The GET parameter 'id' is vulnerable to error-based SQL injection exposing MySQL error messages.",
      "severity": "critical",
      "confidence": "high",
      "recommendation": "Use PDO prepared statements: $stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?'); $stmt->execute([$_GET['id']]);",
      "evidence": {
        "type": "error_based",
        "parameter": "id",
        "payload": "' OR '1'='1' --",
        "response_excerpt": "You have an error in your SQL syntax near ''...'",
        "url": "http://localhost:8081/products.php?id=1"
      },
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html"
      ],
      "affected_component": "http://localhost:8081/products.php?id=1",
      "timestamp": "2026-03-18T14:31:22Z",
      "detection_method": "error-based",
      "parameter": "id",
      "vector": "GET",
      "dbms": "MySQL 8.0.32",
      "cvss": 9.8,
      "contextual_score": 9.9,
      "risk_factors": ["no_ssl", "pii_detected"],
      "payload": "' OR '1'='1' --",
      "owasp": {"id": "A03", "name": "Injection"},
      "cwe": {"id": "CWE-89", "name": "SQL Injection"},
      "vulnerabilities": []
    }
  ],
  "notes": {
    "scan_duration_seconds": 87.3,
    "requests_sent": 342,
    "rate_limit_applied": "5.0 req/s",
    "false_positive_disclaimer": "All findings verified with multiple payloads.",
    "scope_limitations": "Scan limited to same-origin URLs."
  },
  "consent": {
    "domain": "localhost",
    "verified": true,
    "method": "http"
  },
  "ai_analysis": null,
  "diff": null
}
```

---

## Python API

### Generating Reports

```python
from pyth.core.report import ReportGenerator

generator = ReportGenerator(report_dir="~/.pythia/reports")

# Generate both formats
json_path, html_path = generator.generate(
    scan_data=scan_result,
    generate_html=True
)

print(f"JSON: {json_path}")
print(f"HTML: {html_path}")
```

### Accessing Reports Programmatically

```python
import json
from pathlib import Path

report_path = Path("~/.pythia/reports/pythia_sqli_report_localhost_20260318_143022.json")
with open(report_path.expanduser()) as f:
    report = json.load(f)

print(f"Total findings: {report['summary']['total']}")
print(f"Critical: {report['summary']['critical']}")

for finding in report['findings']:
    print(f"  {finding['id']}: {finding['title']} ({finding['severity']})")
    print(f"    Parameter: {finding.get('parameter', 'N/A')}")
    print(f"    DBMS: {finding.get('dbms', 'Unknown')}")
    print(f"    CVSS: {finding.get('cvss')} / Contextual: {finding.get('contextual_score')}")
```

---

_Version: 0.2.0 — Pythia SQL Clairvoyance_

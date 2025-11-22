# Pythia Report Format Documentation

## Overview

Pythia generates structured security reports in **JSON** (machine-readable) and **HTML** (human-readable) formats for SQL injection vulnerability assessments. All reports conform to the shared Argos ecosystem JSON Schema for consistency and validation across security tools.

---

## 📋 JSON Schema

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

### Top-Level Structure

```json
{
  "tool": "pythia",
  "version": "0.1.0",
  "target": "http://example.com/products?id=1",
  "date": "2025-11-03T14:30:00Z",
  "mode": "aggressive",
  "summary": {...},
  "findings": [...],
  "notes": {...},
  "consent": {...},
  "ai_analysis": {...}
}
```

---

## 🔍 Field Definitions

### Required Fields

#### `tool` (string)

-   **Value**: `"pythia"`
-   **Purpose**: Identifies the SQL injection scanner
-   **Example**: `"pythia"`

#### `version` (string)

-   **Format**: Semantic versioning (X.Y.Z)
-   **Purpose**: Tool version for compatibility tracking
-   **Example**: `"0.1.0"`

#### `target` (string)

-   **Format**: Full URL with parameters
-   **Purpose**: Scanned endpoint identifier
-   **Examples**:
    -   `"http://example.com/products?id=1"`
    -   `"https://api.example.com/users?search=test"`
    -   `"http://localhost:8081/login.php"`

#### `date` (string)

-   **Format**: ISO 8601 (UTC with Z suffix)
-   **Purpose**: Scan completion timestamp
-   **Example**: `"2025-11-03T14:30:00.123456+00:00Z"`

#### `mode` (string)

-   **Values**: `"safe"` or `"aggressive"`
-   **Purpose**: Scan depth indicator
-   **Details**:
    -   **safe**: Error-based + Boolean-blind detection only
    -   **aggressive**: Includes time-based + UNION-based detection
-   **Example**: `"aggressive"`

#### `summary` (object)

-   **Purpose**: Quick overview of findings by severity
-   **Required keys**: `critical`, `high`, `medium`, `low`, `info`
-   **All values**: Non-negative integers

```json
"summary": {
  "critical": 2,
  "high": 3,
  "medium": 2,
  "low": 1,
  "info": 1
}
```

#### `findings` (array)

-   **Purpose**: Detailed list of SQL injection vulnerabilities
-   **Items**: Finding objects (see below)

---

## 🎯 Finding Categories

Pythia organizes findings into SQL injection-specific categories:

### Error-Based SQL Injection (SQL-001 to SQL-009)

Database error messages exposed in responses, confirming vulnerability

### Boolean-Blind SQL Injection (SQL-010 to SQL-019)

Logic-based inference through TRUE/FALSE condition responses

### Time-Based Blind SQL Injection (SQL-020 to SQL-029)

Timing attacks using SLEEP/WAITFOR payloads to confirm injection

### UNION-Based SQL Injection (SQL-030 to SQL-039)

Data extraction via UNION SELECT with column enumeration

### Custom Findings (SQL-040 to SQL-099)

Application-specific injection patterns, edge cases

---

## 📝 Finding Object Structure

Each finding in the `findings` array:

```json
{
    "id": "PYTHIA-SQL-001",
    "title": "Error-Based SQL Injection - MySQL",
    "description": "SQL injection vulnerability detected in URL parameter 'id'. The application is vulnerable to error-based SQL injection, which allows attackers to extract database information through error messages. The database is MySQL 8.0.",
    "severity": "critical",
    "confidence": "high",
    "detection_method": "error-based",
    "recommendation": "Use parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input directly into SQL queries. Example: $stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?'); $stmt->execute([$id]);",
    "evidence": {
        "type": "parameter",
        "value": "id",
        "context": "Payload: ' | DBMS: MySQL 8.0.32 | Error: You have an error in your SQL syntax",
        "payload": "'",
        "dbms": "MySQL",
        "error_message": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1"
    },
    "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://portswigger.net/web-security/sql-injection"
    ],
    "affected_component": "Parameter: id (GET)"
}
```

#### Finding Fields

| Field                | Required | Type   | Description                                                       |
| -------------------- | -------- | ------ | ----------------------------------------------------------------- |
| `id`                 | ✅ Yes   | string | Unique finding identifier (e.g., `PYTHIA-SQL-001`)                |
| `title`              | ✅ Yes   | string | Short, descriptive title (max 200 chars)                          |
| `description`        | ❌ No    | string | Detailed vulnerability explanation                                |
| `severity`           | ✅ Yes   | enum   | `critical` \| `high` \| `medium` \| `low` \| `info`               |
| `confidence`         | ✅ Yes   | enum   | `high` \| `medium` \| `low`                                       |
| `detection_method`   | ✅ Yes   | enum   | `error-based` \| `boolean-blind` \| `time-based` \| `union-based` |
| `evidence`           | ❌ No    | object | Proof of vulnerability                                            |
| `recommendation`     | ✅ Yes   | string | Actionable remediation guidance with code examples                |
| `references`         | ❌ No    | array  | External links (OWASP, PortSwigger, vendor docs)                  |
| `cve`                | ❌ No    | array  | CVE identifiers (if applicable)                                   |
| `affected_component` | ❌ No    | string | Specific parameter/endpoint affected                              |
| `timestamp`          | ❌ No    | string | When this specific finding was detected (ISO 8601 UTC)            |

---

## 🎯 Severity Levels for SQL Injection

| Level        | Use When                                        | Examples                                                                                                                           |
| ------------ | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Critical** | Confirmed exploitation with data extraction     | Error-based SQLi with database version/data exposed, UNION-based with successful data extraction, time-based with confirmed delays |
| **High**     | Strong evidence of exploitability               | Boolean-blind with consistent TRUE/FALSE differentiation, UNION-based with column enumeration complete                             |
| **Medium**   | Probable vulnerability with moderate confidence | Boolean-blind with inconsistent responses, potential injection points with partial evidence                                        |
| **Low**      | Weak indicators or edge cases                   | Low-confidence detection, heavily filtered inputs, partial pattern matches                                                         |
| **Info**     | Informational only                              | Database type detected, scan metadata, test statistics                                                                             |

### Confidence Levels

| Level      | Meaning                 | Example                                                                                                                       |
| ---------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **High**   | Confirmed vulnerability | SQL error message in response, consistent TRUE/FALSE behavior, measurable time delay (≥2.5s), marker string in UNION response |
| **Medium** | Strong indicators       | Pattern suggests vulnerability, inconsistent but suspicious behavior, partial error messages                                  |
| **Low**    | Heuristic detection     | Weak pattern matching, assumptions based on response variations, edge case detection                                          |

---

## 📋 Finding ID Scheme

### Format

`PYTHIA-SQL-{NUMBER}`

### Category Ranges

| ID Range             | Category         | Description                                                                |
| -------------------- | ---------------- | -------------------------------------------------------------------------- |
| `PYTHIA-SQL-001-009` | Error-Based      | SQL errors exposed in responses (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) |
| `PYTHIA-SQL-010-019` | Boolean-Blind    | Logic-based inference through TRUE/FALSE conditions                        |
| `PYTHIA-SQL-020-029` | Time-Based Blind | Timing attacks with SLEEP/WAITFOR payloads                                 |
| `PYTHIA-SQL-030-039` | UNION-Based      | Data extraction via UNION SELECT                                           |
| `PYTHIA-SQL-040-099` | Custom Findings  | Application-specific patterns, edge cases                                  |

### Common Finding IDs

| ID               | Meaning                                          |
| ---------------- | ------------------------------------------------ |
| `PYTHIA-SQL-001` | Error-Based SQL Injection (generic)              |
| `PYTHIA-SQL-002` | Error-Based SQL Injection - MySQL/MariaDB        |
| `PYTHIA-SQL-003` | Error-Based SQL Injection - PostgreSQL           |
| `PYTHIA-SQL-004` | Error-Based SQL Injection - Microsoft SQL Server |
| `PYTHIA-SQL-005` | Error-Based SQL Injection - Oracle               |
| `PYTHIA-SQL-006` | Error-Based SQL Injection - SQLite               |
| `PYTHIA-SQL-010` | Boolean-Blind SQL Injection (generic)            |
| `PYTHIA-SQL-011` | Boolean-Blind SQL Injection - AND/OR logic       |
| `PYTHIA-SQL-012` | Boolean-Blind SQL Injection - String comparison  |
| `PYTHIA-SQL-020` | Time-Based Blind SQL Injection (generic)         |
| `PYTHIA-SQL-021` | Time-Based Blind - MySQL SLEEP()                 |
| `PYTHIA-SQL-022` | Time-Based Blind - PostgreSQL pg_sleep()         |
| `PYTHIA-SQL-023` | Time-Based Blind - MSSQL WAITFOR DELAY           |
| `PYTHIA-SQL-030` | UNION-Based SQL Injection (generic)              |
| `PYTHIA-SQL-031` | UNION-Based - Column enumeration successful      |
| `PYTHIA-SQL-032` | UNION-Based - Data extraction confirmed          |

---

## 🛡️ Evidence Types for SQL Injection

### Evidence Object Structure

```json
"evidence": {
  "type": "parameter|body|header|cookie",
  "value": "Parameter name or payload",
  "context": "Additional context",
  "payload": "Actual payload used",
  "dbms": "Database type detected",
  "error_message": "Full error message (sanitized)",
  "response_time": 3.42,  // For time-based
  "baseline_time": 0.15   // For time-based
}
```

### Common Evidence Types

#### Parameter Evidence (GET/POST parameters)

```json
"evidence": {
  "type": "parameter",
  "value": "id",
  "context": "Payload: ' | DBMS: MySQL 8.0.32",
  "payload": "'",
  "dbms": "MySQL",
  "error_message": "You have an error in your SQL syntax..."
}
```

#### Body Evidence (POST data, JSON payloads)

```json
"evidence": {
  "type": "body",
  "value": "{\"search\": \"test' OR '1'='1\"}",
  "context": "JSON parameter injection | TRUE response differs from FALSE",
  "payload": "' OR '1'='1",
  "dbms": "PostgreSQL"
}
```

#### Cookie Evidence (Session/authentication cookies)

```json
"evidence": {
  "type": "cookie",
  "value": "session_id",
  "context": "Cookie value vulnerable to injection",
  "payload": "' OR 1=1--",
  "dbms": "MySQL"
}
```

#### Time-Based Evidence

```json
"evidence": {
  "type": "parameter",
  "value": "product_id",
  "context": "Response time: 5.32s (baseline: 0.15s) | Delay: 5s",
  "payload": "1' AND SLEEP(5)--",
  "response_time": 5.32,
  "baseline_time": 0.15,
  "dbms": "MySQL"
}
```

#### UNION-Based Evidence

```json
"evidence": {
  "type": "parameter",
  "value": "category",
  "context": "UNION marker found in response | Columns: 4",
  "payload": "1' UNION SELECT 'PYTH1A','PYTH1A','PYTH1A','PYTH1A'--",
  "union_columns": 4,
  "marker_found": true,
  "dbms": "MySQL"
}
```

---

## 📊 Complete Example Reports

### Minimal Valid Report

```json
{
    "tool": "pythia",
    "version": "0.1.0",
    "target": "http://example.com/search?q=test",
    "date": "2025-11-03T14:30:00Z",
    "mode": "safe",
    "summary": {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    },
    "findings": [
        {
            "id": "PYTHIA-SQL-001",
            "title": "Error-Based SQL Injection - MySQL",
            "severity": "critical",
            "confidence": "high",
            "detection_method": "error-based",
            "recommendation": "Use parameterized queries. Example: $stmt = $pdo->prepare('SELECT * FROM products WHERE name LIKE ?'); $stmt->execute([$search]);"
        }
    ]
}
```

### Full Featured Report with AI Analysis

```json
{
    "tool": "pythia",
    "version": "0.1.0",
    "target": "http://demo.example.com/products?id=1",
    "date": "2025-11-03T14:30:00.123456+00:00Z",
    "mode": "aggressive",
    "summary": {
        "critical": 2,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 1
    },
    "findings": [
        {
            "id": "PYTHIA-SQL-001",
            "title": "Error-Based SQL Injection - MySQL",
            "description": "SQL injection vulnerability detected in URL parameter 'id'. The application is vulnerable to error-based SQL injection, which allows attackers to extract database information through error messages. The database is MySQL 8.0.32.",
            "severity": "critical",
            "confidence": "high",
            "detection_method": "error-based",
            "recommendation": "Use parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input directly into SQL queries. Implement input validation and sanitization. Disable detailed error messages in production. Example fix: $stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?'); $stmt->execute([$id]);",
            "evidence": {
                "type": "parameter",
                "value": "id",
                "context": "Payload: ' | DBMS: MySQL 8.0.32 | Error: You have an error in your SQL syntax",
                "payload": "'",
                "dbms": "MySQL",
                "error_message": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1"
            },
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            "affected_component": "Parameter: id (GET)",
            "timestamp": "2025-11-03T14:30:05.234567+00:00Z"
        },
        {
            "id": "PYTHIA-SQL-010",
            "title": "Boolean-Blind SQL Injection",
            "description": "The application responds differently to TRUE and FALSE conditions, indicating Boolean-blind SQL injection. This allows attackers to extract data bit-by-bit through conditional queries.",
            "severity": "high",
            "confidence": "high",
            "detection_method": "boolean-blind",
            "recommendation": "Use parameterized queries for all database operations. Implement consistent error handling to prevent information leakage through response differences. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "evidence": {
                "type": "parameter",
                "value": "category",
                "context": "TRUE condition (1' AND '1'='1) returns different response than FALSE condition (1' AND '1'='2)",
                "payload_true": "1' AND '1'='1",
                "payload_false": "1' AND '1'='2",
                "response_difference": "Content length differs by 1,234 bytes"
            },
            "references": [
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                "https://portswigger.net/web-security/sql-injection/blind"
            ],
            "affected_component": "Parameter: category (GET)",
            "timestamp": "2025-11-03T14:30:12.456789+00:00Z"
        },
        {
            "id": "PYTHIA-SQL-020",
            "title": "Time-Based Blind SQL Injection - MySQL SLEEP()",
            "description": "The application is vulnerable to time-based blind SQL injection. By injecting SLEEP() payloads, attackers can confirm injection points and extract data through timing differences.",
            "severity": "critical",
            "confidence": "high",
            "detection_method": "time-based",
            "recommendation": "Use parameterized queries exclusively. Never concatenate user input into SQL statements. Set database query timeouts to limit impact of time-based attacks. Example: $stmt = $pdo->prepare('SELECT * FROM orders WHERE user_id = ?'); $stmt->execute([$user_id]);",
            "evidence": {
                "type": "parameter",
                "value": "user_id",
                "context": "Response time: 5.32s (baseline: 0.15s) | Delay: 5s | Payload triggered 5-second sleep",
                "payload": "1' AND SLEEP(5)--",
                "response_time": 5.32,
                "baseline_time": 0.15,
                "dbms": "MySQL"
            },
            "references": [
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                "https://portswigger.net/web-security/sql-injection/blind"
            ],
            "affected_component": "Parameter: user_id (GET)",
            "timestamp": "2025-11-03T14:30:25.789012+00:00Z"
        },
        {
            "id": "PYTHIA-SQL-030",
            "title": "UNION-Based SQL Injection",
            "description": "UNION-based SQL injection detected with 4 columns. Attackers can extract data from arbitrary database tables using UNION SELECT statements. Database schema and sensitive data are at risk.",
            "severity": "critical",
            "confidence": "high",
            "detection_method": "union-based",
            "recommendation": "Use parameterized queries to prevent SQL injection. Implement principle of least privilege for database accounts. Use database views to limit data exposure. Example: connection.execute('SELECT * FROM products WHERE type = ?', [product_type])",
            "evidence": {
                "type": "parameter",
                "value": "sort",
                "context": "UNION marker 'PYTH1A' found in response | Columns: 4 | Full exploitation possible",
                "payload": "1' UNION SELECT 'PYTH1A','PYTH1A','PYTH1A','PYTH1A'--",
                "union_columns": 4,
                "marker_found": true,
                "dbms": "PostgreSQL"
            },
            "references": [
                "https://portswigger.net/web-security/sql-injection/union-attacks",
                "https://owasp.org/www-community/attacks/SQL_Injection"
            ],
            "affected_component": "Parameter: sort (GET)",
            "timestamp": "2025-11-03T14:30:38.123456+00:00Z"
        }
    ],
    "notes": {
        "scan_duration_seconds": 87.45,
        "requests_sent": 342,
        "rate_limit_applied": true,
        "scope_limitations": "Scan performed in aggressive mode with consent verification. All detection methods enabled: error-based, boolean-blind, time-based, and UNION-based.",
        "false_positive_disclaimer": "Manual verification recommended for all SQL injection findings before remediation. Some findings may be false positives due to WAF filtering or application-specific input handling.",
        "scan_statistics": {
            "endpoints_scanned": 8,
            "forms_tested": 3,
            "unique_parameters_tested": 15
        },
        "detection_statistics": {
            "error_based_tests": 45,
            "boolean_blind_tests": 450,
            "time_based_tests": 90,
            "union_based_tests": 135,
            "total_payloads": 720
        }
    },
    "consent": {
        "method": "http",
        "token": "verify-a1b2c3d4e5f6g7h8",
        "verified_at": "2025-11-03T10:15:00.000000+00:00Z"
    },
    "ai_analysis": {
        "executive_summary": "<h3>Executive Summary: Critical SQL Injection Vulnerabilities Detected</h3>\n<p>Our automated security scan has identified <strong>9 SQL injection vulnerabilities</strong> across your web application, including <strong>2 critical-severity</strong> and <strong>3 high-severity</strong> issues...</p>",
        "technical_remediation": "<h3>Technical Remediation Guide: SQL Injection Vulnerabilities</h3>\n<p>This guide provides step-by-step instructions for your development team to remediate the detected SQL injection vulnerabilities...</p>",
        "generated_at": "2025-11-03T14:31:00.000000+00:00Z",
        "model_used": "gpt-4-turbo-2024-04-09"
    }
}
```

---

## 🌐 HTML Report

### Template Location

`templates/report.html.j2` (Jinja2)

### Theme

**Pythia Mystic Oracle Theme**: Deep purple/blue gradient (#6a11cb to #2575fc) with crystal ball emoji 🔮 representing the oracle's vision into hidden vulnerabilities.

### Sections

1. **Header**

    - Pythia branding with crystal ball emoji 🔮
    - Target URL and scan parameters
    - Scan date, mode (SAFE/AGGRESSIVE), and version
    - Summary pills with severity counts and colors

2. **AI-Powered SQL Injection Analysis** (if `--use-ai` enabled)

    - **Executive Summary (Business Impact)**: Non-technical overview for stakeholders
        - Key risks in business terms
        - Regulatory compliance implications (GDPR, PCI-DSS, HIPAA)
        - Estimated remediation effort
        - Priority timeline
    - **Technical Hardening Guide**: Step-by-step fixes with code examples
        - Parameterized query implementations (Python, PHP, Node.js, Java)
        - Input validation patterns
        - Security hardening measures
        - Testing and verification steps

3. **SQL Injection Findings Table**

    - Sortable by ID, Severity, Confidence
    - Expandable evidence sections with payloads
    - Color-coded severity badges
    - Detection method indicators
    - Copy-paste code remediation examples
    - Direct links to OWASP, PortSwigger documentation

4. **Scan Metadata**

    - Scan duration and HTTP request count
    - Detection statistics breakdown:
        - Error-based tests performed
        - Boolean-blind test count
        - Time-based test count
        - UNION-based test count
    - Rate limiting status
    - Scope limitations (safe vs aggressive)
    - False positive disclaimer

5. **Consent Verification** (if aggressive/AI mode)

    - Verification method (HTTP/.well-known or DNS TXT)
    - Token displayed
    - Verification timestamp

6. **Footer**
    - Pythia attribution with tagline: "The Oracle reveals what lies beneath the surface..."
    - GitHub repository link
    - Legal disclaimer
    - License information (MIT)

### Styling Features

-   **Mystic Oracle theme**: Purple/blue gradient (#6a11cb to #2575fc)
-   **Crystal ball icon**: 🔮 throughout the design
-   **Responsive layout**: Mobile-first, optimized for tablets and desktops
-   **Print-friendly**: Clean page breaks, grayscale-optimized
-   **Accessibility**: WCAG 2.1 AA compliant
-   **Interactive elements**: Expandable findings, syntax-highlighted code
-   **Professional typography**: System font stack for performance

### Example HTML Structure

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="generator" content="Pythia 0.1.0" />
        <title>Pythia SQL Injection Report — http://example.com</title>
        <style>
            /* Embedded CSS for portability */
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background: #f5f5f5;
                color: #2c3e50;
            }
            header {
                background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
                color: white;
                padding: 40px 50px;
            }
            .severity-badge.severity-critical {
                background: #dc3545;
                color: white;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔮 Pythia SQL Injection Report</h1>
                <div class="meta">
                    <div class="meta-item"><strong>🎯 Target:</strong> http://example.com/products?id=1</div>
                    <div class="meta-item"><strong>📅 Date:</strong> 2025-11-03T14:30:00Z</div>
                    <div class="meta-item"><strong>🔒 Mode:</strong> AGGRESSIVE</div>
                    <div class="meta-item"><strong>⚙️ Version:</strong> Pythia 0.1.0</div>
                </div>
                <div class="summary-pills">
                    <span class="pill pill-critical">Critical: 2</span>
                    <span class="pill pill-high">High: 3</span>
                    <span class="pill pill-medium">Medium: 2</span>
                    <span class="pill pill-low">Low: 1</span>
                    <span class="pill pill-info">Info: 1</span>
                </div>
            </header>

            <div class="content">
                <!-- AI Analysis Section -->
                <section id="ai-analysis">
                    <h2>🤖 AI-Powered SQL Injection Analysis</h2>
                    <div class="ai-summary">
                        <h3>📊 Executive Summary (Business Impact)</h3>
                        <!-- AI-generated HTML content -->
                    </div>
                    <div class="ai-summary">
                        <h3>🔧 Technical Hardening Guide</h3>
                        <!-- AI-generated remediation steps -->
                    </div>
                </section>

                <!-- Findings Table -->
                <section id="findings">
                    <h2>🔍 SQL Injection Findings</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Finding</th>
                                <th>Severity</th>
                                <th>Confidence</th>
                                <th>Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><code>PYTHIA-SQL-001</code></td>
                                <td>
                                    <strong>Error-Based SQL Injection - MySQL</strong>
                                    <p>SQL injection vulnerability detected in parameter 'id'...</p>
                                    <p>📍 Parameter: id (GET)</p>
                                    <div class="evidence">
                                        <strong>PARAMETER:</strong> id<br />
                                        <small>Payload: ' | DBMS: MySQL 8.0.32 | Error: You have an error...</small>
                                    </div>
                                </td>
                                <td>
                                    <span class="severity-badge severity-critical">CRITICAL</span>
                                </td>
                                <td>
                                    <span class="confidence-badge">high</span>
                                </td>
                                <td>Use parameterized queries. Example: $stmt = $pdo->prepare(...)...</td>
                            </tr>
                            <!-- More findings... -->
                        </tbody>
                    </table>
                </section>

                <!-- Scan Metadata -->
                <section id="notes">
                    <h2>📝 Scan Metadata</h2>
                    <table>
                        <tr>
                            <td><strong>⏱️ Scan Duration</strong></td>
                            <td>87.45 seconds</td>
                        </tr>
                        <tr>
                            <td><strong>📡 HTTP Requests</strong></td>
                            <td>342 (rate limited)</td>
                        </tr>
                        <tr>
                            <td><strong>🔍 Detection Tests</strong></td>
                            <td>Error-based: 45 | Boolean-blind: 450 | Time-based: 90 | UNION: 135</td>
                        </tr>
                    </table>
                </section>
            </div>

            <footer>
                <p><strong>Generated by Pythia v0.1.0</strong> — SQL Injection Detection Scanner</p>
                <p>"The Oracle reveals what lies beneath the surface..."</p>
                <p>Use only on authorized targets. Report is for informational purposes.</p>
                <p>© 2025 Rodney Dhavid Jimenez Chacin (rodhnin) — MIT License</p>
            </footer>
        </div>
    </body>
</html>
```

---

## 🔧 Programmatic Usage

### Generating Reports

```python
from pyth.core.report import ReportGenerator
from pyth.scanner import SQLInjectionScanner

# Perform SQL injection scan
scanner = SQLInjectionScanner(target='http://example.com/products?id=1')
findings = scanner.scan()

# Generate report
generator = ReportGenerator()
report = generator.create_report(
    tool='pythia',
    version='0.1.0',
    target='http://example.com/products?id=1',
    mode='aggressive',
    findings=findings,
    scan_duration=87.45,
    requests_sent=342
)

# Validate
if generator.validate_report(report):
    # Save JSON
    json_path = generator.save_json(report)
    print(f"JSON report: {json_path}")

    # Generate HTML
    html_path = generator.generate_html(report, json_path)
    print(f"HTML report: {html_path}")
```

### Creating SQL Injection-Specific Findings

```python
# Error-based SQL injection
finding = {
    'id': 'PYTHIA-SQL-001',
    'title': 'Error-Based SQL Injection - MySQL',
    'description': 'SQL injection vulnerability detected in URL parameter "id"',
    'severity': 'critical',
    'confidence': 'high',
    'detection_method': 'error-based',
    'evidence': {
        'type': 'parameter',
        'value': 'id',
        'context': "Payload: ' | DBMS: MySQL 8.0.32",
        'payload': "'",
        'dbms': 'MySQL',
        'error_message': "You have an error in your SQL syntax..."
    },
    'recommendation': "Use parameterized queries: $stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?'); $stmt->execute([$id]);",
    'references': [
        'https://owasp.org/www-community/attacks/SQL_Injection'
    ],
    'affected_component': 'Parameter: id (GET)'
}

# Boolean-blind SQL injection
finding = {
    'id': 'PYTHIA-SQL-010',
    'title': 'Boolean-Blind SQL Injection',
    'description': 'Application responds differently to TRUE and FALSE conditions',
    'severity': 'high',
    'confidence': 'high',
    'detection_method': 'boolean-blind',
    'evidence': {
        'type': 'parameter',
        'value': 'search',
        'context': "TRUE payload length: 5,432 bytes | FALSE payload length: 1,234 bytes",
        'payload_true': "1' AND '1'='1",
        'payload_false': "1' AND '1'='2",
        'response_difference': "Content length differs by 4,198 bytes"
    },
    'recommendation': "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name LIKE ?', (search,))",
    'references': [
        'https://portswigger.net/web-security/sql-injection/blind'
    ],
    'affected_component': 'Parameter: search (GET)'
}

# Time-based blind SQL injection
finding = {
    'id': 'PYTHIA-SQL-020',
    'title': 'Time-Based Blind SQL Injection - MySQL SLEEP()',
    'description': 'Application vulnerable to time-based blind SQL injection',
    'severity': 'critical',
    'confidence': 'high',
    'detection_method': 'time-based',
    'evidence': {
        'type': 'parameter',
        'value': 'user_id',
        'context': "Response time: 5.32s (baseline: 0.15s) | Delay: 5s",
        'payload': "1' AND SLEEP(5)--",
        'response_time': 5.32,
        'baseline_time': 0.15,
        'dbms': 'MySQL'
    },
    'recommendation': "Use parameterized queries: $stmt = $mysqli->prepare('SELECT * FROM orders WHERE user_id = ?'); $stmt->bind_param('i', $user_id);",
    'references': [
        'https://owasp.org/www-community/attacks/Blind_SQL_Injection'
    ],
    'affected_component': 'Parameter: user_id (GET)'
}

# UNION-based SQL injection
finding = {
    'id': 'PYTHIA-SQL-030',
    'title': 'UNION-Based SQL Injection',
    'description': 'UNION-based SQL injection with 4 columns enumerated',
    'severity': 'critical',
    'confidence': 'high',
    'detection_method': 'union-based',
    'evidence': {
        'type': 'parameter',
        'value': 'category',
        'context': "UNION marker 'PYTH1A' found in response | Columns: 4",
        'payload': "1' UNION SELECT 'PYTH1A','PYTH1A','PYTH1A','PYTH1A'--",
        'union_columns': 4,
        'marker_found': True,
        'dbms': 'PostgreSQL'
    },
    'recommendation': "Use parameterized queries: connection.execute('SELECT * FROM products WHERE category = ?', [category])",
    'references': [
        'https://portswigger.net/web-security/sql-injection/union-attacks'
    ],
    'affected_component': 'Parameter: category (GET)'
}
```

---

## 📊 Report Analysis

### SQLite Queries for SQL Injection Trends

```sql
-- Most common SQL injection types detected
SELECT
    finding_code,
    title,
    COUNT(*) as occurrence_count,
    AVG(CASE severity
        WHEN 'critical' THEN 4
        WHEN 'high' THEN 3
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 1
        ELSE 0
    END) as avg_severity_score
FROM findings
WHERE tool = 'pythia'
    AND severity IN ('critical', 'high', 'medium')
GROUP BY finding_code, title
ORDER BY occurrence_count DESC, avg_severity_score DESC
LIMIT 10;

-- Applications with critical SQL injection vulnerabilities
SELECT
    s.domain,
    COUNT(f.finding_id) as total_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high,
    MAX(s.started_at) as last_scan
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'pythia'
    AND s.status = 'completed'
GROUP BY s.domain
HAVING critical > 0 OR high > 2
ORDER BY critical DESC, high DESC;

-- Detection method effectiveness
SELECT
    JSON_EXTRACT(evidence, '$.dbms') as database_type,
    detection_method,
    COUNT(*) as detections,
    AVG(CASE severity
        WHEN 'critical' THEN 10
        WHEN 'high' THEN 7
        WHEN 'medium' THEN 4
        WHEN 'low' THEN 1
    END) as avg_severity_numeric
FROM findings
WHERE tool = 'pythia'
    AND detection_method IS NOT NULL
GROUP BY database_type, detection_method
ORDER BY detections DESC;

-- Database technology distribution in vulnerable applications
SELECT
    JSON_EXTRACT(evidence, '$.dbms') as database_type,
    COUNT(DISTINCT scan_id) as vulnerable_apps,
    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_vulns
FROM findings
WHERE tool = 'pythia'
    AND JSON_EXTRACT(evidence, '$.dbms') IS NOT NULL
GROUP BY database_type
ORDER BY vulnerable_apps DESC;

-- Average scan statistics over time
SELECT
    DATE(started_at) as scan_date,
    COUNT(*) as scans_performed,
    AVG(JSON_EXTRACT(summary, '$.critical')) as avg_critical,
    AVG(JSON_EXTRACT(summary, '$.high')) as avg_high,
    AVG(JSON_EXTRACT(summary, '$.medium')) as avg_medium
FROM scans
WHERE tool = 'pythia'
    AND status = 'completed'
    AND started_at > datetime('now', '-30 days')
GROUP BY DATE(started_at)
ORDER BY scan_date DESC;
```

### Python Analysis Examples

```python
import sqlite3
import json
from collections import Counter, defaultdict

db = sqlite3.connect('~/.argos/argos.db')

# Analyze database types targeted
cursor = db.execute("""
    SELECT JSON_EXTRACT(evidence, '$.dbms') as dbms, COUNT(*) as count
    FROM findings
    WHERE tool = 'pythia'
        AND JSON_EXTRACT(evidence, '$.dbms') IS NOT NULL
    GROUP BY dbms
    ORDER BY count DESC
""")

print("Database types in vulnerable applications:")
for dbms, count in cursor:
    print(f"  {dbms}: {count} vulnerable endpoints")

# Find most common vulnerable parameters
cursor = db.execute("""
    SELECT JSON_EXTRACT(evidence, '$.value') as parameter,
           COUNT(*) as vulnerability_count,
           GROUP_CONCAT(DISTINCT severity) as severities
    FROM findings
    WHERE tool = 'pythia'
        AND JSON_EXTRACT(evidence, '$.type') = 'parameter'
    GROUP BY parameter
    ORDER BY vulnerability_count DESC
    LIMIT 10
""")

print("\nMost commonly vulnerable parameter names:")
for param, count, severities in cursor:
    print(f"  {param}: {count} occurrences ({severities})")

# Calculate risk scores for applications
cursor = db.execute("""
    SELECT
        s.domain,
        s.scan_id,
        s.summary
    FROM scans s
    WHERE s.tool = 'pythia'
        AND s.status = 'completed'
    ORDER BY s.started_at DESC
    LIMIT 50
""")

risk_scores = []
for domain, scan_id, summary_json in cursor:
    summary = json.loads(summary_json)
    # Risk score: critical×10 + high×5 + medium×2 + low×1
    risk = (summary['critical'] * 10 +
            summary['high'] * 5 +
            summary['medium'] * 2 +
            summary['low'] * 1)
    risk_scores.append((domain, risk, summary))

print("\nTop 10 highest risk applications:")
for domain, risk, summary in sorted(risk_scores, key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {domain}: Risk Score {risk} "
          f"(C:{summary['critical']} H:{summary['high']} M:{summary['medium']})")

# Detection method effectiveness analysis
cursor = db.execute("""
    SELECT
        detection_method,
        COUNT(*) as total_detections,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_findings,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_findings
    FROM findings
    WHERE tool = 'pythia'
        AND detection_method IS NOT NULL
    GROUP BY detection_method
    ORDER BY total_detections DESC
""")

print("\nDetection method effectiveness:")
for method, total, critical, high in cursor:
    print(f"  {method}: {total} total ({critical} critical, {high} high)")
```

---

## ✅ Best Practices for SQL Injection Reports

### 1. Evidence Collection

```python
# Good: Detailed SQL injection evidence
evidence = {
    'type': 'parameter',
    'value': 'product_id',
    'context': "Payload: ' | DBMS: MySQL 8.0.32 | Error: You have an error in your SQL syntax",
    'payload': "'",
    'dbms': 'MySQL',
    'error_message': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1",
    'url': 'http://example.com/products?id=1'
}

# Bad: Vague evidence
evidence = {
    'type': 'other',
    'value': 'SQL injection found'
}
```

### 2. SQL Injection-Specific Recommendations

```python
# Good: Actionable SQL injection fixes with code examples
recommendation = """Use parameterized queries (prepared statements) to prevent SQL injection:

**PHP (PDO):**
$stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?');
$stmt->execute([$product_id]);

**Python (SQLite/PostgreSQL):**
cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))

**Node.js (MySQL2):**
const [rows] = await connection.execute('SELECT * FROM products WHERE id = ?', [productId]);

**Additional Security:**
1. Validate and sanitize all user inputs
2. Use principle of least privilege for database accounts
3. Disable detailed error messages in production
4. Implement WAF rules to filter common SQLi patterns
5. Regular security audits and penetration testing
"""

# Bad: Generic advice
recommendation = "Fix the SQL injection vulnerability"
```

### 3. Severity Assignment for SQL Injection

**Critical**: Direct data exposure or manipulation

-   Error-based SQLi with database information disclosed
-   Time-based SQLi with confirmed 5+ second delays
-   UNION-based SQLi with successful column enumeration
-   Authentication bypass via SQLi

**High**: Exploitable but requires more effort

-   Boolean-blind SQLi with consistent TRUE/FALSE differentiation
-   UNION-based SQLi with partial column enumeration
-   SQLi in administrative interfaces

**Medium**: Probable vulnerability with moderate confidence

-   Boolean-blind SQLi with inconsistent responses
-   Potential injection points with partial evidence
-   SQLi with WAF protection but still exploitable

**Low**: Weak indicators or heavily mitigated

-   Low-confidence detection
-   Heavily filtered inputs with minimal injection capability
-   Partial pattern matches

**Info**: Detection metadata only

-   Database type detected (no vulnerability)
-   Scan statistics
-   Test coverage information

### 4. Detection Method Documentation

```python
# Always specify detection method
finding = {
    'id': 'PYTHIA-SQL-001',
    'title': 'Error-Based SQL Injection - MySQL',
    'detection_method': 'error-based',  # REQUIRED
    'severity': 'critical',
    'confidence': 'high',
    'evidence': {
        'type': 'parameter',
        'value': 'id',
        'payload': "'",  # Show actual payload used
        'dbms': 'MySQL',  # Specify database type
        'error_message': "You have an error..."  # Include error
    },
    'recommendation': "Use parameterized queries..."
}
```

### 5. Report Storage and Organization

```python
from pathlib import Path
from datetime import datetime, timezone

# Organize by target domain
target_domain = 'example.com'
timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
scan_id = 42

report_dir = Path.home() / '.pythia' / 'reports' / target_domain
report_dir.mkdir(parents=True, exist_ok=True)

json_file = report_dir / f"pythia_{timestamp}_scan{scan_id}.json"
html_file = report_dir / f"pythia_{timestamp}_scan{scan_id}.html"

# Keep historical reports for trend analysis
```

### 6. AI Analysis Prompts for SQL Injection

When generating AI summaries:

```python
executive_prompt = f"""
Analyze this SQL injection security scan with {critical} critical, {high} high,
and {medium} medium severity vulnerabilities.

Create an executive summary that:
1. Explains SQL injection risks in business terms
2. Highlights data breach potential (customer data, credentials, PII)
3. Discusses regulatory compliance implications (GDPR, PCI-DSS, HIPAA)
4. Prioritizes remediation actions by urgency (hours, days, weeks)
5. Estimates remediation effort and timeline

Target audience: C-suite executives, business stakeholders, compliance officers.
Avoid technical jargon. Focus on business impact and risk.
"""

technical_prompt = f"""
Create a technical remediation guide for SQL injection vulnerabilities with:
1. Numbered priority levels (P0 Critical, P1 High, P2 Medium)
2. Code examples for parameterized queries in PHP, Python, Node.js, Java
3. Input validation patterns and best practices
4. Database security hardening recommendations
5. Testing and verification procedures
6. Deployment checklist

Target audience: Software developers, DevOps engineers, security engineers.
Include actual code snippets that can be copy-pasted.
"""
```

---

## 🎨 Customization

### Custom SQL Injection Checks

Extend Pythia with custom detection methods:

```python
from pyth.checks.base import BaseCheck

class CustomSQLiCheck(BaseCheck):
    """Custom SQL injection detection method"""

    def run(self) -> list[dict]:
        findings = []

        # Custom detection logic
        response = self.http_get('/api/custom?param=test')

        if self.is_vulnerable(response):
            findings.append({
                'id': 'PYTHIA-SQL-099',
                'title': 'Custom SQL Injection Pattern Detected',
                'description': 'Application-specific SQL injection vulnerability',
                'severity': 'high',
                'confidence': 'medium',
                'detection_method': 'other',
                'evidence': {
                    'type': 'parameter',
                    'value': 'param',
                    'context': f'HTTP {response.status_code}',
                    'payload': 'custom_payload'
                },
                'recommendation': 'Use parameterized queries for this custom endpoint',
                'references': [],
                'affected_component': 'Parameter: param (GET)'
            })

        return findings
```

### Custom HTML Template

Override default template for branding:

```python
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Use custom template
template_dir = Path('/path/to/custom/templates')
env = Environment(loader=FileSystemLoader(template_dir))
template = env.get_template('custom_pythia_report.html.j2')

html_output = template.render(
    report=report,
    company_logo='https://yourcompany.com/logo.png',
    custom_branding='YourCompany Security Team'
)
```

---

## 📊 Report Metrics and KPIs

### Key Performance Indicators for SQL Injection Security

```python
# Security Posture Score (0-100)
def calculate_sqli_security_score(summary):
    base_score = 100
    penalties = {
        'critical': 30,  # -30 per critical SQLi
        'high': 15,      # -15 per high
        'medium': 5,     # -5 per medium
        'low': 2         # -2 per low
    }

    score = base_score
    for severity, penalty in penalties.items():
        score -= summary[severity] * penalty

    return max(0, score)  # Floor at 0

# Risk Level Classification
def classify_sqli_risk(summary):
    critical = summary['critical']
    high = summary['high']

    if critical >= 1:
        return 'CRITICAL'  # Any critical SQLi is critical risk
    elif high >= 3:
        return 'HIGH'
    elif high >= 1 or summary['medium'] >= 5:
        return 'MODERATE'
    elif summary['medium'] >= 1:
        return 'LOW'
    else:
        return 'MINIMAL'

# Remediation Priority Score
def calculate_remediation_priority(finding):
    """Calculate priority score (higher = more urgent)"""
    score = 0

    # Severity weight
    severity_weights = {
        'critical': 100,
        'high': 50,
        'medium': 20,
        'low': 5
    }
    score += severity_weights.get(finding['severity'], 0)

    # Detection method weight (easier to exploit = higher priority)
    method_weights = {
        'error-based': 30,
        'time-based': 25,
        'union-based': 20,
        'boolean-blind': 15
    }
    score += method_weights.get(finding.get('detection_method'), 0)

    # Confidence weight
    if finding.get('confidence') == 'high':
        score += 10

    return score
```

---

## 🔐 Security Considerations

### Protecting Sensitive Report Data

```python
from cryptography.fernet import Fernet
import json
import os

class EncryptedReportStorage:
    """Store SQL injection reports encrypted"""

    def __init__(self, key_file=None):
        if key_file and Path(key_file).exists():
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            # Generate new key
            self.key = Fernet.generate_key()
            if key_file:
                with open(key_file, 'wb') as f:
                    f.write(self.key)
                os.chmod(key_file, 0o600)

        self.cipher = Fernet(self.key)

    def encrypt_report(self, report: dict) -> bytes:
        """Encrypt SQL injection report"""
        report_json = json.dumps(report)
        return self.cipher.encrypt(report_json.encode())

    def decrypt_report(self, encrypted: bytes) -> dict:
        """Decrypt SQL injection report"""
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

# Usage
storage = EncryptedReportStorage('~/.pythia/report.key')
encrypted = storage.encrypt_report(report)

# Save encrypted
with open('report_encrypted.bin', 'wb') as f:
    f.write(encrypted)
```

### Access Control for Reports

```python
import os
from pathlib import Path

def secure_report_file(report_path: Path):
    """Set restrictive permissions on SQL injection report files"""
    # Owner read/write only (0o600)
    os.chmod(report_path, 0o600)

    # Verify permissions
    stat = os.stat(report_path)
    mode = oct(stat.st_mode)[-3:]
    if mode != '600':
        raise PermissionError(f"Failed to set secure permissions on {report_path}")
```

---

## 📚 Additional Resources

### SQL Injection Documentation

-   **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
-   **PortSwigger SQL Injection**: https://portswigger.net/web-security/sql-injection
-   **OWASP Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
-   **SQLMap Documentation**: https://github.com/sqlmapproject/sqlmap/wiki

### Support and Community

-   **Issues**: https://github.com/rodhnin/pythia-sql-clairvoyance/issues
-   **Discussions**: https://github.com/rodhnin/pythia-sql-clairvoyance/discussions
-   **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

### Related Tools

-   **SQLMap**: https://sqlmap.org/
-   **Havij**: SQL injection automation tool
-   **jSQL Injection**: Open-source Java-based tool
-   **Burp Suite**: Web vulnerability scanner with SQLi detection

---

_Last Updated: November 2025_  
_Version: 1.0_  
_Tool: Pythia v0.1.0_

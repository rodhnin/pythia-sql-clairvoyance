# Pythia Database Guide

**Database:** SQLite 3.x  
**Location:** `~/.argos/argos.db` (shared with Argus/Hephaestus)  
**Schema Version:** 1.0

---

## Overview

Pythia uses **SQLite** for persistent storage of:

-   Client/project information (shared)
-   SQL injection scan history and metadata
-   SQL injection findings and evidence
-   Consent verification tokens (shared)

**Important:** Pythia shares the database with Argus (WordPress scanner) and Hephaestus (API security tester). This enables unified security reporting across all tools in the Argos ecosystem.

**Note:** This guide provides SQL query examples until **IMPROV-011 (Interactive Database CLI)** is implemented in v0.3.0.

---

## Database Schema

### Tables

#### 1. `clients`

Stores information about clients or projects (shared across all tools).

```sql
CREATE TABLE clients (
    client_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    contact_email TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX idx_clients_domain ON clients(domain);
```

**Columns:**

-   `client_id`: Auto-increment primary key
-   `name`: Client or project name
-   `domain`: Primary domain (UNIQUE constraint)
-   `contact_email`: Contact email address
-   `notes`: Additional notes
-   `created_at`: Creation timestamp (UTC)
-   `updated_at`: Last update timestamp (UTC)

---

#### 2. `consent_tokens`

Tracks ownership verification tokens (shared across all tools).

```sql
CREATE TABLE consent_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    method TEXT NOT NULL CHECK(method IN ('http', 'dns')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    verified_at TEXT DEFAULT NULL,
    proof_path TEXT DEFAULT NULL,
    expires_at TEXT NOT NULL,
    notes TEXT
);

CREATE INDEX idx_consent_tokens_domain ON consent_tokens(domain);
CREATE INDEX idx_consent_tokens_token ON consent_tokens(token);
CREATE INDEX idx_consent_tokens_verified ON consent_tokens(verified_at);
```

**Columns:**

-   `token_id`: Auto-increment primary key
-   `domain`: Target domain
-   `token`: Generated verification token (format: `verify-XXXX`)
-   `method`: Verification method (`http` or `dns`)
-   `created_at`: Token generation time (UTC)
-   `expires_at`: Expiration time (48 hours after creation)
-   `verified_at`: Verification timestamp (NULL until verified)
-   `proof_path`: Path to proof file (for HTTP method)
-   `notes`: Additional notes

---

#### 3. `scans`

Stores scan execution history (shared, with `tool` column to distinguish).

```sql
CREATE TABLE scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL CHECK(tool IN ('argus', 'hephaestus', 'pythia')),
    client_id INTEGER DEFAULT NULL,
    domain TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('safe', 'aggressive')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    finished_at TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'completed', 'failed', 'aborted')),
    report_json_path TEXT,
    report_html_path TEXT,
    summary TEXT,  -- JSON string with counts
    error_message TEXT DEFAULT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE SET NULL
);

CREATE INDEX idx_scans_tool ON scans(tool);
CREATE INDEX idx_scans_domain ON scans(domain);
CREATE INDEX idx_scans_started ON scans(started_at);
CREATE INDEX idx_scans_status ON scans(status);
```

**Columns:**

-   `scan_id`: Auto-increment primary key
-   `tool`: Scanner tool name (`pythia` for SQL injection scans)
-   `client_id`: Foreign key to clients table (nullable)
-   `domain`: Scanned domain
-   `target_url`: Full target URL
-   `mode`: Scan mode (`safe` or `aggressive`)
-   `started_at`: Scan start time (UTC)
-   `finished_at`: Scan completion time (UTC)
-   `status`: Current status (`running`, `completed`, `failed`, `aborted`)
-   `report_json_path`: Path to JSON report
-   `report_html_path`: Path to HTML report
-   `summary`: JSON object with severity counts (e.g., `{"critical": 10, "high": 3, "medium": 1}`)
-   `error_message`: Error description (if failed)

**Status Values:**

-   `running`: Scan in progress
-   `completed`: Scan finished successfully
-   `failed`: Technical error (connection, timeout, DB)
-   `aborted`: User cancelled or target unreachable

---

#### 4. `findings`

Stores individual SQL injection findings from scans.

```sql
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_code TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'low')),
    evidence_type TEXT,
    evidence_value TEXT,
    recommendation TEXT NOT NULL,
    "references" TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_code ON findings(finding_code);
```

**Columns:**

-   `finding_id`: Auto-increment primary key
-   `scan_id`: Foreign key to scans table (CASCADE delete)
-   `finding_code`: Finding identifier (e.g., `PYTHIA-SQL-001`, `PYTHIA-SQL-010`, `PYTHIA-SQL-020`)
-   `title`: Finding title/description
-   `severity`: Severity level (`critical`, `high`, `medium`, `low`, `info`)
-   `confidence`: Confidence level (`high`, `medium`, `low`)
-   `evidence_type`: Type of evidence (`http_response`, `boolean_blind`, `time_based`, `union_based`)
-   `evidence_value`: JSON string with SQL injection evidence (payload, response, timing, etc.)
-   `recommendation`: Remediation guidance
-   `references`: JSON array of reference URLs (OWASP, CWE)
-   `created_at`: Finding creation time (UTC)

**Pythia Finding Codes:**

-   `PYTHIA-SQL-001`: Error-Based SQL Injection
-   `PYTHIA-SQL-010`: Boolean Blind SQL Injection
-   `PYTHIA-SQL-020`: Time-Based Blind SQL Injection
-   `PYTHIA-SQL-030`: UNION-Based SQL Injection

---

### Views

#### 1. `v_recent_scans`

Recent scans with finding counts (all tools).

```sql
CREATE VIEW v_recent_scans AS
SELECT
    s.scan_id,
    s.tool,
    s.domain,
    s.mode,
    s.started_at,
    s.finished_at,
    s.status,
    c.name AS client_name,
    s.summary,
    COUNT(f.finding_id) AS total_findings
FROM scans s
LEFT JOIN clients c ON s.client_id = c.client_id
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.scan_id
ORDER BY s.started_at DESC;
```

---

#### 2. `v_critical_findings`

Critical and high severity findings (all tools).

```sql
CREATE VIEW v_critical_findings AS
SELECT
    f.finding_id,
    s.tool,
    s.domain,
    s.started_at,
    f.finding_code,
    f.title,
    f.severity,
    f.confidence,
    f.evidence_value,
    f.recommendation
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.severity IN ('critical', 'high')
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
    END,
    s.started_at DESC;
```

---

#### 3. `v_verified_domains`

Verified domains with expiration status (shared).

```sql
CREATE VIEW v_verified_domains AS
SELECT
    domain,
    token,
    method,
    verified_at,
    expires_at,
    CASE
        WHEN datetime('now', 'utc') < expires_at THEN 'valid'
        ELSE 'expired'
    END AS status
FROM consent_tokens
WHERE verified_at IS NOT NULL
ORDER BY verified_at DESC;
```

---

## Common Query Examples

### Pythia-Specific Queries

#### List All Pythia Scans

```sql
SELECT
    scan_id,
    domain,
    mode,
    status,
    started_at,
    finished_at
FROM scans
WHERE tool = 'pythia'
ORDER BY started_at DESC;
```

#### Get Pythia Scan Details

```sql
SELECT
    s.*,
    c.name AS client_name,
    COUNT(f.finding_id) AS total_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high
FROM scans s
LEFT JOIN clients c ON s.client_id = c.client_id
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.scan_id = 617
  AND s.tool = 'pythia'
GROUP BY s.scan_id;
```

#### List SQL Injection Findings for a Scan

```sql
SELECT
    finding_id,
    finding_code,
    title,
    severity,
    confidence,
    json_extract(evidence_value, '$.parameter') AS vulnerable_param,
    json_extract(evidence_value, '$.payload') AS sqli_payload
FROM findings
WHERE scan_id = 617
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;
```

#### Get Error-Based SQL Injection Findings

```sql
SELECT
    s.domain,
    s.scan_id,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.dbms') AS database,
    f.created_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code = 'PYTHIA-SQL-001'
  AND s.tool = 'pythia'
ORDER BY f.created_at DESC;
```

#### Get Time-Based Blind SQLi Findings

```sql
SELECT
    s.domain,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.avg_delay_seconds') AS delay,
    json_extract(f.evidence_value, '$.baseline_time_seconds') AS baseline
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code = 'PYTHIA-SQL-020'
  AND s.tool = 'pythia'
ORDER BY s.started_at DESC;
```

#### Get UNION-Based SQL Injection with Column Info

```sql
SELECT
    s.domain,
    f.title,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.columns_detected') AS columns,
    json_extract(f.evidence_value, '$.injectable_columns') AS injectable_cols,
    f.recommendation
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code = 'PYTHIA-SQL-030'
  AND s.tool = 'pythia';
```

---

### Client Management

#### List All Clients

```sql
SELECT
    client_id,
    name,
    domain,
    contact_email,
    created_at
FROM clients
ORDER BY created_at DESC;
```

#### Find Client by Domain

```sql
SELECT *
FROM clients
WHERE domain LIKE '%example.com%';
```

#### Add New Client

```sql
INSERT INTO clients (name, domain, contact_email, notes)
VALUES ('Acme Corp', 'acme.com', 'admin@acme.com', 'E-commerce client with SQL injection concerns');
```

#### Update Client

```sql
UPDATE clients
SET contact_email = 'security@acme.com',
    notes = 'Upgraded to aggressive SQL injection testing',
    updated_at = datetime('now', 'utc')
WHERE client_id = 1;
```

#### Delete Client

```sql
DELETE FROM clients WHERE client_id = 1;
```

---

### Scan Management

#### List Recent Pythia Scans (Last 10)

```sql
SELECT
    scan_id,
    domain,
    mode,
    status,
    started_at,
    total_findings
FROM v_recent_scans
WHERE tool = 'pythia'
LIMIT 10;
```

#### Filter Pythia Scans by Domain

```sql
SELECT
    scan_id,
    mode,
    status,
    started_at,
    finished_at,
    summary
FROM scans
WHERE tool = 'pythia'
  AND domain = 'localhost:8081'
ORDER BY started_at DESC;
```

#### Filter Scans by Status (Failed)

```sql
SELECT
    scan_id,
    domain,
    started_at,
    error_message
FROM scans
WHERE tool = 'pythia'
  AND status = 'failed'
ORDER BY started_at DESC;
```

#### Get Pythia Scan Statistics

```sql
SELECT
    mode,
    status,
    COUNT(*) AS scan_count,
    AVG(
        (julianday(finished_at) - julianday(started_at)) * 86400
    ) AS avg_duration_seconds
FROM scans
WHERE tool = 'pythia'
  AND finished_at IS NOT NULL
GROUP BY mode, status;
```

#### Count Scans by Tool (Pythia vs Argus vs Hephaestus)

```sql
SELECT
    tool,
    COUNT(*) AS total_scans,
    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
    SUM(CASE WHEN status = 'aborted' THEN 1 ELSE 0 END) AS aborted
FROM scans
GROUP BY tool
ORDER BY tool;
```

---

### Finding Management

#### List All SQL Injection Findings for a Scan

```sql
SELECT
    finding_id,
    finding_code,
    title,
    severity,
    confidence,
    json_extract(evidence_value, '$.method') AS http_method,
    json_extract(evidence_value, '$.parameter') AS param
FROM findings
WHERE scan_id = 617
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;
```

#### Get Critical SQL Injection Findings (Last 20)

```sql
SELECT
    s.domain,
    f.finding_code,
    f.title,
    f.severity,
    f.confidence,
    s.started_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia'
  AND f.severity IN ('critical', 'high')
ORDER BY f.created_at DESC
LIMIT 20;
```

#### Search Findings by Code

```sql
SELECT
    s.domain,
    s.scan_id,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.payload') AS payload,
    f.created_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code = 'PYTHIA-SQL-001'
  AND s.tool = 'pythia'
ORDER BY f.created_at DESC;
```

#### Count SQL Injection Findings by Severity for Domain

```sql
SELECT
    f.severity,
    COUNT(*) AS count
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia'
  AND s.domain = 'localhost:8081'
GROUP BY f.severity
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;
```

#### Get SQL Injection Findings with Evidence Details

```sql
SELECT
    finding_code,
    title,
    severity,
    json_extract(evidence_value, '$.type') AS evidence_type,
    json_extract(evidence_value, '$.parameter') AS param,
    json_extract(evidence_value, '$.payload') AS payload,
    json_extract(evidence_value, '$.dbms') AS database,
    recommendation
FROM findings
WHERE scan_id = 617
  AND evidence_value IS NOT NULL
ORDER BY severity;
```

#### Get All Blind SQL Injection Findings (Boolean + Time-Based)

```sql
SELECT
    s.domain,
    f.finding_code,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    CASE
        WHEN f.finding_code = 'PYTHIA-SQL-010' THEN 'Boolean Blind'
        WHEN f.finding_code = 'PYTHIA-SQL-020' THEN 'Time-Based Blind'
    END AS sqli_type,
    f.created_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code IN ('PYTHIA-SQL-010', 'PYTHIA-SQL-020')
  AND s.tool = 'pythia'
ORDER BY f.created_at DESC;
```

---

### Consent Token Management

#### List Verified Tokens

```sql
SELECT
    domain,
    method,
    verified_at,
    expires_at,
    status
FROM v_verified_domains
ORDER BY verified_at DESC;
```

#### Check Domain Verification Status

```sql
SELECT
    domain,
    token,
    method,
    CASE
        WHEN verified_at IS NOT NULL AND datetime('now', 'utc') < expires_at
        THEN 'verified'
        WHEN verified_at IS NOT NULL AND datetime('now', 'utc') >= expires_at
        THEN 'expired'
        ELSE 'pending'
    END AS status,
    expires_at
FROM consent_tokens
WHERE domain = 'example.com'
ORDER BY created_at DESC
LIMIT 1;
```

#### List Expired Tokens

```sql
SELECT
    domain,
    token,
    verified_at,
    expires_at
FROM consent_tokens
WHERE verified_at IS NOT NULL
  AND datetime('now', 'utc') >= expires_at
ORDER BY expires_at DESC;
```

#### Revoke Token (Delete)

```sql
DELETE FROM consent_tokens
WHERE domain = 'example.com';
```

---

### Statistics & Reports

#### Pythia Database Statistics

```sql
SELECT
    'Total Pythia Scans' AS category,
    COUNT(*) AS count
FROM scans
WHERE tool = 'pythia'
UNION ALL
SELECT
    'Pythia SQL Injection Findings',
    COUNT(*)
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia'
UNION ALL
SELECT
    'Critical SQL Injections',
    COUNT(*)
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia'
  AND f.severity = 'critical'
UNION ALL
SELECT
    'High Severity SQL Injections',
    COUNT(*)
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia'
  AND f.severity = 'high';
```

#### Pythia Scan Success Rate

```sql
SELECT
    status,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM scans WHERE tool = 'pythia'), 2) AS percentage
FROM scans
WHERE tool = 'pythia'
GROUP BY status
ORDER BY count DESC;
```

#### Top 10 Domains by SQL Injection Findings

```sql
SELECT
    s.domain,
    COUNT(f.finding_id) AS total_sqli_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
    SUM(CASE WHEN f.finding_code = 'PYTHIA-SQL-001' THEN 1 ELSE 0 END) AS error_based,
    SUM(CASE WHEN f.finding_code = 'PYTHIA-SQL-020' THEN 1 ELSE 0 END) AS time_based,
    SUM(CASE WHEN f.finding_code = 'PYTHIA-SQL-030' THEN 1 ELSE 0 END) AS union_based
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'pythia'
GROUP BY s.domain
ORDER BY total_sqli_findings DESC
LIMIT 10;
```

#### SQL Injection Findings Trend (Last 30 Days)

```sql
SELECT
    DATE(s.started_at) AS scan_date,
    COUNT(DISTINCT s.scan_id) AS pythia_scans,
    COUNT(f.finding_id) AS sqli_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'pythia'
  AND s.started_at >= datetime('now', '-30 days')
GROUP BY DATE(s.started_at)
ORDER BY scan_date DESC;
```

#### SQL Injection Types Distribution

```sql
SELECT
    CASE f.finding_code
        WHEN 'PYTHIA-SQL-001' THEN 'Error-Based'
        WHEN 'PYTHIA-SQL-010' THEN 'Boolean Blind'
        WHEN 'PYTHIA-SQL-020' THEN 'Time-Based Blind'
        WHEN 'PYTHIA-SQL-030' THEN 'UNION-Based'
        ELSE 'Other'
    END AS sqli_type,
    COUNT(*) AS count,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia'
GROUP BY f.finding_code
ORDER BY count DESC;
```

---

### Maintenance

#### Backup Database

```bash
# Command line
sqlite3 ~/.argos/argos.db ".backup /tmp/pythia-backup-$(date +%Y%m%d).db"

# Or copy file directly
cp ~/.argos/argos.db ~/backups/argos-backup-$(date +%Y%m%d).db
```

#### Database Size

```sql
SELECT page_count * page_size / 1024.0 / 1024.0 AS size_mb
FROM pragma_page_count(), pragma_page_size();
```

#### Vacuum (Optimize)

```sql
VACUUM;
```

#### Check Integrity

```sql
PRAGMA integrity_check;
```

#### Delete Old Pythia Scans (Older than 90 Days)

```sql
DELETE FROM scans
WHERE tool = 'pythia'
  AND started_at < datetime('now', '-90 days');
-- Findings will auto-delete (CASCADE)
```

#### Delete Pythia Scans Without Findings

```sql
DELETE FROM scans
WHERE tool = 'pythia'
  AND scan_id NOT IN (SELECT DISTINCT scan_id FROM findings);
```

---

## Database Access from Python

### Using pyth.core.db Module

```python
from pyth.core.db import ArgosDB

# Get database instance
db = ArgosDB()

# Start a new scan
scan_id = db.start_scan(
    tool='pythia',
    domain='example.com',
    target_url='http://example.com:8080',
    mode='aggressive'
)

# Save a SQL injection finding
db.save_finding(
    scan_id=scan_id,
    finding_code='PYTHIA-SQL-001',
    title='Error-Based SQL Injection - MySQL',
    severity='critical',
    confidence='high',
    evidence_type='http_response',
    evidence_value='{"parameter": "id", "payload": "\'", "dbms": "MySQL"}',
    recommendation='Use parameterized queries'
)

# Finish scan
db.finish_scan(scan_id, status='completed')

# Get scan details
scan = db.get_scan(scan_id)
print(f"Scan status: {scan['status']}")

# Get findings
findings = db.get_findings(scan_id)
print(f"Total SQL injection findings: {len(findings)}")
```

### Direct SQL Access

```python
import sqlite3
from pathlib import Path

# Connect to database
db_path = Path.home() / ".argos" / "argos.db"
conn = sqlite3.connect(str(db_path))
conn.row_factory = sqlite3.Row  # Access columns by name

# Execute query
cursor = conn.execute("""
    SELECT * FROM scans
    WHERE tool = 'pythia'
      AND status = 'completed'
    LIMIT 10
""")

rows = cursor.fetchall()
for row in rows:
    print(f"Scan {row['scan_id']}: {row['domain']} - {row['started_at']}")

# Get SQL injection findings
cursor = conn.execute("""
    SELECT
        f.finding_code,
        f.title,
        f.severity,
        json_extract(f.evidence_value, '$.parameter') AS param
    FROM findings f
    JOIN scans s ON f.scan_id = s.scan_id
    WHERE s.tool = 'pythia'
      AND s.scan_id = ?
""", (scan_id,))

findings = cursor.fetchall()
for finding in findings:
    print(f"{finding['finding_code']}: {finding['title']} (param: {finding['param']})")

conn.close()
```

---

## Future: Interactive CLI (IMPROV-011 - v0.3.0)

In v0.3.0, these SQL queries will be replaced with intuitive commands:

```bash
# Instead of SQL:
sqlite3 ~/.argos/argos.db "SELECT * FROM scans WHERE tool = 'pythia' LIMIT 10"

# Future (v0.3.0):
python -m pyth db scans list --limit 10

# Instead of:
sqlite3 ~/.argos/argos.db "SELECT * FROM findings WHERE finding_code = 'PYTHIA-SQL-001'"

# Future:
python -m pyth db findings search --code PYTHIA-SQL-001

# Instead of:
sqlite3 ~/.argos/argos.db "SELECT * FROM v_critical_findings WHERE tool = 'pythia' LIMIT 20"

# Future:
python -m pyth db findings critical --limit 20
```

**Until then, use the SQL queries provided in this guide.**

---

## Troubleshooting

### Database Locked Error

```
Error: database is locked
```

**Solution:** Another process is using the database. Wait or:

```bash
lsof ~/.argos/argos.db  # Find process
kill <PID>  # Kill if needed
```

### Database Corrupted

```
Error: file is not a database
```

**Solution:** Pythia auto-recovers. Manual recovery:

```bash
# Backup corrupted file
mv ~/.argos/argos.db ~/.argos/argos.db.corrupted

# Run scan (creates fresh DB)
python -m pyth --target http://localhost:8081 --safe
```

### Read-Only Database

```
Warning: Database is read-only
```

**Solution:** Fix permissions:

```bash
chmod 644 ~/.argos/argos.db
chmod 755 ~/.argos
```

### Foreign Key Constraint Error

```
Error: FOREIGN KEY constraint failed
```

**Solution:** This happens if you try to insert a scan with a non-existent client_id. Either:

-   Set `client_id = NULL` (default)
-   Create the client first with `INSERT INTO clients...`

---

## Advanced Queries

### Compare SQL Injection Findings Across Multiple Scans

```sql
SELECT
    s1.scan_id AS scan1,
    s2.scan_id AS scan2,
    s1.domain,
    COUNT(DISTINCT f1.finding_code) AS unique_to_scan1,
    COUNT(DISTINCT f2.finding_code) AS unique_to_scan2,
    COUNT(DISTINCT CASE WHEN f1.finding_code = f2.finding_code THEN f1.finding_code END) AS common
FROM scans s1
JOIN scans s2 ON s1.domain = s2.domain AND s1.scan_id < s2.scan_id
LEFT JOIN findings f1 ON s1.scan_id = f1.scan_id
LEFT JOIN findings f2 ON s2.scan_id = f2.scan_id
WHERE s1.tool = 'pythia' AND s2.tool = 'pythia'
GROUP BY s1.scan_id, s2.scan_id, s1.domain;
```

### Find Domains with No SQL Injection Findings

```sql
SELECT
    s.domain,
    s.scan_id,
    s.started_at,
    s.mode
FROM scans s
WHERE s.tool = 'pythia'
  AND s.status = 'completed'
  AND s.scan_id NOT IN (
      SELECT DISTINCT scan_id FROM findings
  )
ORDER BY s.started_at DESC;
```

### Get Average Scan Duration by Mode

```sql
SELECT
    mode,
    COUNT(*) AS total_scans,
    ROUND(AVG((julianday(finished_at) - julianday(started_at)) * 86400), 2) AS avg_seconds,
    ROUND(MIN((julianday(finished_at) - julianday(started_at)) * 86400), 2) AS min_seconds,
    ROUND(MAX((julianday(finished_at) - julianday(started_at)) * 86400), 2) AS max_seconds
FROM scans
WHERE tool = 'pythia'
  AND finished_at IS NOT NULL
GROUP BY mode;
```

---

## Schema Version History

| Version | Date     | Changes                                       |
| ------- | -------- | --------------------------------------------- |
| **1.0** | Nov 2025 | Initial schema (shared with Argus/Hephaestus) |

---

**Schema Version:** 1.0  
**Shared Database:** `~/.argos/argos.db` (Argus, Hephaestus, Pythia)  
**Next Update:** v0.3.0 (Interactive CLI - IMPROV-011)

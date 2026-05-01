# Pythia Database Guide

**Database:** SQLite 3.x
**Location:** `~/.argos/argos.db` (shared with Argus/Hephaestus)
**Schema Version:** 1.1

---

## Overview

Pythia uses **SQLite** for persistent storage of:

-   Client/project information (shared)
-   SQL injection scan history and metadata
-   SQL injection findings and evidence
-   Consent verification tokens (shared)
-   AI cost tracking (shared)

**Important:** Pythia shares the database with Argus (WordPress scanner) and Hephaestus (API security tester). This enables unified security reporting across all tools in the Argos ecosystem.

**Note:** This guide provides SQL query examples until **IMPROV-011 (Interactive Database CLI)** is planned for v0.3.0.

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
-   `expires_at`: Expiration time (48 hours after creation by default)
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
-   `summary`: JSON object with severity counts
-   `error_message`: Error description (if failed)

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

**Pythia Finding Codes (v0.2.0):**

| Code | Type | DBMS / Vector |
|------|------|---------------|
| `PYTHIA-SQL-001` | Error-Based | MySQL / MariaDB |
| `PYTHIA-SQL-002` | Error-Based | PostgreSQL |
| `PYTHIA-SQL-003` | Error-Based | MSSQL / SQL Server |
| `PYTHIA-SQL-004` | Error-Based | Oracle |
| `PYTHIA-SQL-005` | Error-Based | SQLite |
| `PYTHIA-SQL-010` | Boolean Blind | Any DBMS |
| `PYTHIA-SQL-011` | Boolean Blind | Via header injection |
| `PYTHIA-SQL-020` | Time-Based Blind | MySQL SLEEP() |
| `PYTHIA-SQL-021` | Time-Based Blind | MSSQL WAITFOR DELAY |
| `PYTHIA-SQL-022` | Time-Based Blind | PostgreSQL pg_sleep() |
| `PYTHIA-SQL-030` | UNION-Based | GET/POST parameter |
| `PYTHIA-SQL-031` | UNION-Based | Via cookie |
| `PYTHIA-SQL-040` | Second-Order | Store → retrieve pattern |
| `PYTHIA-SQL-050` | ORDER BY Injection | Numeric sort parameter |

---

#### 5. `ai_costs` (added v0.2.0)

Tracks AI provider usage and costs per scan, shared across the Argos Suite.

```sql
CREATE TABLE ai_costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0.0,
    scan_id INTEGER DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE SET NULL
);

CREATE INDEX idx_ai_costs_tool ON ai_costs(tool);
CREATE INDEX idx_ai_costs_scan_id ON ai_costs(scan_id);
CREATE INDEX idx_ai_costs_created ON ai_costs(created_at);
```

**Columns:**

-   `cost_id`: Auto-increment primary key
-   `tool`: Tool name (`pythia`, `argus`, `hephaestus`)
-   `provider`: AI provider (`openai`, `anthropic`, `ollama`)
-   `model`: Model identifier (e.g., `gpt-4o-mini-2024-07-18`)
-   `input_tokens`: Number of input tokens used
-   `output_tokens`: Number of output tokens generated
-   `cost_usd`: Total cost in USD for this request
-   `scan_id`: Associated scan (nullable)
-   `created_at`: Timestamp (UTC)

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
WHERE s.scan_id = 42
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
WHERE scan_id = 42
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;
```

#### Get Error-Based SQL Injection Findings (All DBMS Types)

```sql
SELECT
    s.domain,
    s.scan_id,
    f.finding_code,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.dbms') AS database,
    f.created_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code IN ('PYTHIA-SQL-001','PYTHIA-SQL-002','PYTHIA-SQL-003','PYTHIA-SQL-004','PYTHIA-SQL-005')
  AND s.tool = 'pythia'
ORDER BY f.created_at DESC;
```

#### Get Time-Based Blind SQLi Findings (All DBMS)

```sql
SELECT
    s.domain,
    f.finding_code,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.avg_delay_seconds') AS delay,
    json_extract(f.evidence_value, '$.baseline_time_seconds') AS baseline
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code IN ('PYTHIA-SQL-020','PYTHIA-SQL-021','PYTHIA-SQL-022')
  AND s.tool = 'pythia'
ORDER BY s.started_at DESC;
```

#### Get UNION-Based SQL Injection Findings

```sql
SELECT
    s.domain,
    f.finding_code,
    f.title,
    json_extract(f.evidence_value, '$.parameter') AS param,
    json_extract(f.evidence_value, '$.columns_detected') AS columns,
    json_extract(f.evidence_value, '$.injectable_columns') AS injectable_cols,
    f.recommendation
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code IN ('PYTHIA-SQL-030','PYTHIA-SQL-031')
  AND s.tool = 'pythia';
```

#### Get Second-Order and ORDER BY Injection Findings

```sql
SELECT
    s.domain,
    f.finding_code,
    f.title,
    f.severity,
    json_extract(f.evidence_value, '$.parameter') AS param,
    f.created_at
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code IN ('PYTHIA-SQL-040','PYTHIA-SQL-050')
  AND s.tool = 'pythia'
ORDER BY f.created_at DESC;
```

---

### Client Management

#### List All Clients

```sql
SELECT client_id, name, domain, contact_email, created_at
FROM clients
ORDER BY created_at DESC;
```

#### Add New Client

```sql
INSERT INTO clients (name, domain, contact_email, notes)
VALUES ('Acme Corp', 'acme.com', 'admin@acme.com', 'E-commerce client');
```

---

### Scan Management

#### List Recent Pythia Scans (Last 10)

```sql
SELECT scan_id, domain, mode, status, started_at, total_findings
FROM v_recent_scans
WHERE tool = 'pythia'
LIMIT 10;
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

#### Count Scans by Tool

```sql
SELECT
    tool,
    COUNT(*) AS total_scans,
    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
FROM scans
GROUP BY tool
ORDER BY tool;
```

---

### Finding Management

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

#### SQL Injection Types Distribution (All Codes)

```sql
SELECT
    CASE f.finding_code
        WHEN 'PYTHIA-SQL-001' THEN 'Error-Based (MySQL)'
        WHEN 'PYTHIA-SQL-002' THEN 'Error-Based (PostgreSQL)'
        WHEN 'PYTHIA-SQL-003' THEN 'Error-Based (MSSQL)'
        WHEN 'PYTHIA-SQL-004' THEN 'Error-Based (Oracle)'
        WHEN 'PYTHIA-SQL-005' THEN 'Error-Based (SQLite)'
        WHEN 'PYTHIA-SQL-010' THEN 'Boolean Blind'
        WHEN 'PYTHIA-SQL-011' THEN 'Boolean Blind (Header)'
        WHEN 'PYTHIA-SQL-020' THEN 'Time-Based (MySQL)'
        WHEN 'PYTHIA-SQL-021' THEN 'Time-Based (MSSQL)'
        WHEN 'PYTHIA-SQL-022' THEN 'Time-Based (PostgreSQL)'
        WHEN 'PYTHIA-SQL-030' THEN 'UNION-Based'
        WHEN 'PYTHIA-SQL-031' THEN 'UNION-Based (Cookie)'
        WHEN 'PYTHIA-SQL-040' THEN 'Second-Order'
        WHEN 'PYTHIA-SQL-050' THEN 'ORDER BY Injection'
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

### AI Cost Queries (v0.2.0)

#### View Total AI Costs for Pythia

```sql
SELECT
    provider,
    model,
    COUNT(*) AS requests,
    SUM(input_tokens) AS total_input_tokens,
    SUM(output_tokens) AS total_output_tokens,
    ROUND(SUM(cost_usd), 4) AS total_cost_usd
FROM ai_costs
WHERE tool = 'pythia'
GROUP BY provider, model
ORDER BY total_cost_usd DESC;
```

#### View AI Costs for a Specific Scan

```sql
SELECT
    provider,
    model,
    input_tokens,
    output_tokens,
    cost_usd,
    created_at
FROM ai_costs
WHERE tool = 'pythia'
  AND scan_id = 42;
```

#### AI Costs Across All Tools (Argos Suite)

```sql
SELECT
    tool,
    provider,
    ROUND(SUM(cost_usd), 4) AS total_cost_usd
FROM ai_costs
GROUP BY tool, provider
ORDER BY total_cost_usd DESC;
```

---

### Consent Token Management

#### List Verified Tokens

```sql
SELECT domain, method, verified_at, expires_at, status
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

#### Extend Token Expiry (for lab environments)

```sql
-- Extend localhost token by 30 days (useful for lab testing)
UPDATE consent_tokens
SET expires_at = datetime('now', '+30 days', 'utc')
WHERE domain = 'localhost'
  AND verified_at IS NOT NULL;
```

---

### Statistics & Reports

#### Pythia Database Statistics

```sql
SELECT 'Total Pythia Scans' AS category, COUNT(*) AS count
FROM scans WHERE tool = 'pythia'
UNION ALL
SELECT 'Pythia SQL Injection Findings', COUNT(*)
FROM findings f JOIN scans s ON f.scan_id = s.scan_id WHERE s.tool = 'pythia'
UNION ALL
SELECT 'Critical SQL Injections', COUNT(*)
FROM findings f JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'pythia' AND f.severity = 'critical'
UNION ALL
SELECT 'Total AI Cost (USD)', ROUND(SUM(cost_usd), 4)
FROM ai_costs WHERE tool = 'pythia';
```

#### Top 10 Domains by SQL Injection Findings

```sql
SELECT
    s.domain,
    COUNT(f.finding_id) AS total_sqli_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
    SUM(CASE WHEN f.finding_code LIKE 'PYTHIA-SQL-00%' THEN 1 ELSE 0 END) AS error_based,
    SUM(CASE WHEN f.finding_code LIKE 'PYTHIA-SQL-02%' THEN 1 ELSE 0 END) AS time_based,
    SUM(CASE WHEN f.finding_code LIKE 'PYTHIA-SQL-03%' THEN 1 ELSE 0 END) AS union_based
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'pythia'
GROUP BY s.domain
ORDER BY total_sqli_findings DESC
LIMIT 10;
```

---

### Maintenance

#### Backup Database

```bash
sqlite3 ~/.argos/argos.db ".backup /tmp/pythia-backup-$(date +%Y%m%d).db"
cp ~/.argos/argos.db ~/backups/argos-backup-$(date +%Y%m%d).db
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

---

## Database Access from Python

### Using pyth.core.db Module

```python
from pyth.core.db import ArgosDB

db = ArgosDB()

# Start a new scan
scan_id = db.start_scan(
    tool='pythia',
    domain='example.com',
    target_url='http://example.com:8081',
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
    evidence_value='{"parameter": "id", "payload": "\'", "dbms": "MySQL 8.0.32"}',
    recommendation='Use parameterized queries'
)

# Save AI cost (v0.2.0)
db.save_ai_cost(
    tool='pythia',
    provider='openai',
    model='gpt-4o-mini-2024-07-18',
    input_tokens=2500,
    output_tokens=1500,
    cost_usd=0.02,
    scan_id=scan_id
)

# Get findings
findings = db.get_findings(scan_id)
print(f"Total SQL injection findings: {len(findings)}")

# List recent scans
scans = db.list_scans(tool='pythia', limit=10)

# Finish scan
db.finish_scan(scan_id, status='completed')
```

### Direct SQL Access

```python
import sqlite3
from pathlib import Path

db_path = Path.home() / ".argos" / "argos.db"
conn = sqlite3.connect(str(db_path))
conn.row_factory = sqlite3.Row

cursor = conn.execute("""
    SELECT * FROM scans
    WHERE tool = 'pythia'
      AND status = 'completed'
    ORDER BY started_at DESC
    LIMIT 10
""")

rows = cursor.fetchall()
for row in rows:
    print(f"Scan {row['scan_id']}: {row['domain']} - {row['started_at']}")

conn.close()
```

---

## Future: Interactive CLI (IMPROV-011 - v0.3.0)

In v0.3.0, these SQL queries will be replaced with intuitive commands:

```bash
# Future (v0.3.0):
python -m pyth db scans list --limit 10
python -m pyth db findings search --code PYTHIA-SQL-001
python -m pyth db findings critical --limit 20
python -m pyth db costs summary
```

**Until then, use the SQL queries provided in this guide.**

---

## Troubleshooting

### Database Locked Error

```
Error: database is locked
```

**Solution:** Another process is using the database.

```bash
lsof ~/.argos/argos.db  # Find process
```

### Database Corrupted

**Solution:** Pythia auto-recovers. Manual recovery:

```bash
mv ~/.argos/argos.db ~/.argos/argos.db.corrupted
python -m pyth --target http://localhost:8081 --safe  # Creates fresh DB
```

### Read-Only Database

```bash
chmod 644 ~/.argos/argos.db
chmod 755 ~/.argos
```

---

## Schema Version History

| Version | Date     | Changes                                       |
| ------- | -------- | --------------------------------------------- |
| **1.0** | Nov 2025 | Initial schema (shared with Argus/Hephaestus) |
| **1.1** | Mar 2026 | Added `ai_costs` table (v0.2.0); `save_ai_cost()` Python API |

---

**Schema Version:** 1.1
**Shared Database:** `~/.argos/argos.db` (Argus, Hephaestus, Pythia)
**Next Update:** v0.3.0 (Interactive CLI - IMPROV-011)

"""
OWASP Top 10 2021 + CWE Mapping for Pythia Findings

Maps each PYTHIA-SQL-XXX finding ID to its OWASP Top 10 2021 category and CWE.
Applied automatically during report generation — no changes needed in check modules.

All SQL injection findings → A03 Injection + CWE-89 (canonical for SQLi in NVD).

Reference:
  OWASP Top 10: https://owasp.org/Top10/
  CWE-89: https://cwe.mitre.org/data/definitions/89.html
  NVD CWE filter: cweId=CWE-89

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

# OWASP Top 10 2021 categories
OWASP_CATEGORIES = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
}

# All PYTHIA-SQL-* → A03 Injection
FINDING_TO_OWASP = {
    # Error-Based (001-007: DBMS-specific)
    'PYTHIA-SQL-000': 'A03',   # Error-based — Unknown DBMS
    'PYTHIA-SQL-001': 'A03',   # MySQL / MariaDB error-based
    'PYTHIA-SQL-002': 'A03',   # PostgreSQL error-based
    'PYTHIA-SQL-003': 'A03',   # MSSQL / SQL Server error-based
    'PYTHIA-SQL-004': 'A03',   # Oracle error-based
    'PYTHIA-SQL-005': 'A03',   # SQLite error-based
    'PYTHIA-SQL-006': 'A03',   # IBM Db2 error-based
    'PYTHIA-SQL-007': 'A03',   # SAP HANA error-based

    # Boolean Blind (010-011)
    'PYTHIA-SQL-010': 'A03',   # Boolean blind (generic, any DBMS)
    'PYTHIA-SQL-011': 'A03',   # Boolean blind via header injection

    # Time-Based (020-022: DBMS-specific)
    'PYTHIA-SQL-020': 'A03',   # Time-based — MySQL SLEEP()
    'PYTHIA-SQL-021': 'A03',   # Time-based — MSSQL WAITFOR DELAY
    'PYTHIA-SQL-022': 'A03',   # Time-based — PostgreSQL pg_sleep()

    # UNION-Based (030-031)
    'PYTHIA-SQL-030': 'A03',   # UNION-based — GET/POST parameter
    'PYTHIA-SQL-031': 'A03',   # UNION-based — via cookie

    # Second-Order (040)
    'PYTHIA-SQL-040': 'A03',   # Second-order SQLi (store → retrieve)

    # ORDER BY Injection (050)
    'PYTHIA-SQL-050': 'A03',   # ORDER BY / GROUP BY injection
}

# CWE-89 is the canonical CWE for SQL Injection (used by NVD to catalog all SQLi CVEs).
# When querying NVD: ?cweId=CWE-89 returns all relevant CVEs for SQL injection.
FINDING_TO_CWE = {
    code: {
        'id': 'CWE-89',
        'name': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
    }
    for code in FINDING_TO_OWASP
}


def get_owasp(finding_id: str) -> dict:
    """
    Return OWASP Top 10 2021 mapping for a PYTHIA-SQL-XXX finding ID.

    Returns a dict with 'id' and 'name', or None if no mapping exists.

    Example:
        get_owasp('PYTHIA-SQL-001')
        → {'id': 'A03', 'name': 'Injection'}
    """
    category_id = FINDING_TO_OWASP.get(finding_id)
    if category_id is None:
        return None
    return {
        'id': category_id,
        'name': OWASP_CATEGORIES[category_id],
    }


def get_cwe(finding_id: str) -> dict:
    """
    Return CWE mapping for a PYTHIA-SQL-XXX finding ID.

    Returns a dict with 'id' and 'name', or None if no mapping exists.

    Example:
        get_cwe('PYTHIA-SQL-001')
        → {'id': 'CWE-89', 'name': 'Improper Neutralization...'}
    """
    return FINDING_TO_CWE.get(finding_id)


def enrich_findings_with_owasp(findings: list) -> list:
    """
    Add 'owasp' and 'cwe' fields to each finding with a known mapping.
    Modifies findings in-place and returns the list.

    Called automatically by ReportGenerator before writing the report.
    """
    for finding in findings:
        fid = finding.get('id', '')
        owasp = get_owasp(fid)
        if owasp:
            finding['owasp'] = owasp
        cwe = get_cwe(fid)
        if cwe:
            finding['cwe'] = cwe
    return findings

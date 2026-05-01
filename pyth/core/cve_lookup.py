"""
CVE Lookup Module — NVD API v2 + CIRCL Fallback (v0.2.0)

Adapted from Hephaestus cve_lookup.py for Pythia SQL injection scanner.

Strategy:
  1. NVD API v2 with virtualMatchString CPE (version-aware, highest accuracy)
  2. NVD keyword search + CWE-89 (when no version — SQL injection focused)
  3. CIRCL CVE Search fallback (when NVD is rate-limited or CPE is unknown)
  4. In-memory cache — avoids duplicate API calls within the same scan

Rate limits:
  NVD without key: 5 req / 30s  → sleep 7s between calls
  NVD with key:   50 req / 30s  → sleep 0.6s between calls

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
import time
import threading
import requests
from typing import Any, Dict, List, Optional, Tuple

from .logging import get_logger

logger = get_logger(__name__)

# ─── NVD API ──────────────────────────────────────────────────────────────────
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_BASE = "https://cve.circl.lu/api"

# ─── CPE vendor / product mapping ────────────────────────────────────────────
# Format: normalized_software_key → (nvd_vendor, nvd_product)
CPE_MAP: Dict[str, Tuple[str, str]] = {
    # Databases (primary focus for Pythia)
    "mysql":                ("oracle",      "mysql"),
    "mariadb":              ("mariadb",     "mariadb"),
    "postgresql":           ("postgresql",  "postgresql"),
    "postgres":             ("postgresql",  "postgresql"),
    "mssql":                ("microsoft",   "sql_server"),
    "sqlserver":            ("microsoft",   "sql_server"),
    "sqlite":               ("sqlite",      "sqlite"),
    "oracle":               ("oracle",      "database_server"),
    "mongodb":              ("mongodb",     "mongodb"),
    "redis":                ("redis",       "redis"),
    "memcached":            ("memcached",   "memcached"),
    "elasticsearch":        ("elastic",     "elasticsearch"),
    # Web servers / runtimes (useful for stack detection)
    "apache":               ("apache",      "http_server"),
    "nginx":                ("f5",          "nginx"),
    "php":                  ("php",         "php"),
    "python":               ("python",      "python"),
    "nodejs":               ("nodejs",      "node.js"),
    "node":                 ("nodejs",      "node.js"),
    "ruby":                 ("ruby-lang",   "ruby"),
    "java":                 ("oracle",      "jdk"),
    "openssl":              ("openssl",     "openssl"),
    # Frameworks
    "django":               ("djangoproject", "django"),
    "flask":                ("palletsprojects", "flask"),
    "laravel":              ("laravel",     "laravel"),
    "rails":                ("rubyonrails", "ruby_on_rails"),
    "wordpress":            ("wordpress",   "wordpress"),
}

# ─── DBMS keyword map for NVD CWE-89 search (when no version is known) ───────
# Maps detected DBMS name (from error message) → NVD search keyword
DBMS_KEYWORD_MAP: Dict[str, str] = {
    "MySQL":      "MySQL SQL injection",
    "MariaDB":    "MariaDB SQL injection",
    "PostgreSQL": "PostgreSQL SQL injection",
    "MSSQL":      "Microsoft SQL Server SQL injection",
    "Oracle":     "Oracle SQL injection",
    "SQLite":     "SQLite SQL injection",
}

# ─── In-memory cache (thread-safe) ───────────────────────────────────────────
_CACHE: Dict[str, List[Dict]] = {}
_CACHE_LOCK = threading.Lock()

# ─── Common CWE names (offline lookup) ───────────────────────────────────────
_CWE_NAMES: Dict[str, str] = {
    "CWE-20":  "Improper Input Validation",
    "CWE-22":  "Path Traversal",
    "CWE-77":  "Command Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Sensitive Information Exposure",
    "CWE-264": "Permissions / Privilege Issues",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken/Risky Cryptographic Algorithm",
    "CWE-352": "CSRF",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-444": "HTTP Request Smuggling",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-787": "Out-of-bounds Write",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def lookup_cves(
    software: str,
    version: str,
    max_results: int = 5,
    api_key: Optional[str] = None,
    timeout: int = 12,
) -> List[Dict[str, Any]]:
    """
    Look up CVEs for a specific software+version from NVD API.

    Uses CPE virtualMatchString for precise version-aware matching.

    Args:
        software: Software name (e.g. 'mysql', 'postgresql', 'php')
        version:  Version string (e.g. '8.0.32', '14.1', '8.0')
        max_results: Max CVEs to return (highest CVSS first)
        api_key:  Optional NVD API key for higher rate limits
        timeout:  HTTP request timeout in seconds

    Returns:
        List of dicts with: cve_id, title, description, link,
        cvss_score, cvss_severity, cwe_id, cwe_name, published
    """
    if not version or not version.strip() or version.strip().lower() in ("unknown", "n/a", "-", ""):
        logger.debug(f"Skipping version-based CVE lookup for '{software}': no valid version")
        return []

    key = software.lower().replace("-", "").replace(" ", "").replace("_", "")
    cpe_entry = CPE_MAP.get(key)
    if not cpe_entry:
        logger.debug(f"No CPE mapping for '{software}' — trying CIRCL fallback")
        return _circl_fallback(software, version, max_results, timeout)

    vendor, product = cpe_entry
    cache_key = f"cpe:{vendor}:{product}:{version}"

    with _CACHE_LOCK:
        if cache_key in _CACHE:
            logger.debug(f"CVE cache hit: {vendor}/{product} {version}")
            return _CACHE[cache_key][:max_results]

    results = _query_nvd_cpe(vendor, product, version, api_key, timeout)

    with _CACHE_LOCK:
        _CACHE[cache_key] = results

    return results[:max_results]


def lookup_sqli_cves(
    dbms_name: str,
    max_results: int = 5,
    api_key: Optional[str] = None,
    timeout: int = 12,
) -> List[Dict[str, Any]]:
    """
    Look up SQL injection CVEs for a detected DBMS using NVD keyword+CWE-89 search.

    Used when we know the DBMS (e.g. MySQL) but not the exact version.
    Searches NVD for CWE-89 + DBMS keyword to find relevant SQLi CVEs.

    Args:
        dbms_name: Detected DBMS name (e.g. 'MySQL', 'PostgreSQL', 'MSSQL')
        max_results: Max CVEs to return (highest CVSS first)
        api_key:  Optional NVD API key
        timeout:  HTTP request timeout in seconds

    Returns:
        List of CVE dicts (same schema as lookup_cves)
    """
    keyword = DBMS_KEYWORD_MAP.get(dbms_name, f"{dbms_name} SQL injection")
    cache_key = f"sqli:{dbms_name.lower()}"

    with _CACHE_LOCK:
        if cache_key in _CACHE:
            logger.debug(f"CVE cache hit: SQLi/{dbms_name}")
            return _CACHE[cache_key][:max_results]

    try:
        params = {
            'cweId':          'CWE-89',
            'keywordSearch':  keyword,
            'resultsPerPage': max(max_results * 2, 10),
        }
        headers = {'User-Agent': 'Pythia-SQLi-Scanner/0.2.0'}
        if api_key:
            headers['apiKey'] = api_key

        logger.debug(f"NVD SQLi search: cweId=CWE-89 keyword='{keyword}'")
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code == 403:
            logger.warning("NVD rate limited — sleeping 30s then retrying")
            time.sleep(30)
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code != 200:
            logger.debug(f"NVD SQLi search failed: HTTP {resp.status_code}")
            return []

        data   = resp.json()
        total  = data.get('totalResults', 0)
        vulns  = data.get('vulnerabilities', [])
        logger.info(f"NVD: {total} SQLi CVE(s) for {dbms_name} (showing top {max_results})")

        results = [r for r in (_parse_nvd(v) for v in vulns) if r]
        # Sort by CVSS score descending, then by published date descending
        results.sort(
            key=lambda x: (x.get("cvss_score") or 0.0, x.get("published", "")),
            reverse=True,
        )
        results = results[:max_results]

        with _CACHE_LOCK:
            _CACHE[cache_key] = results

        return results

    except requests.exceptions.Timeout:
        logger.warning(f"NVD timeout for SQLi search '{dbms_name}'")
        return []
    except Exception as e:
        logger.warning(f"NVD SQLi search error: {e}")
        return []


def _query_nvd_cpe(
    vendor: str,
    product: str,
    version: str,
    api_key: Optional[str],
    timeout: int,
) -> List[Dict[str, Any]]:
    """Query NVD API v2 using virtualMatchString CPE lookup."""
    cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}"
    params = {
        "virtualMatchString": cpe_string,
        "resultsPerPage": 2000,
    }
    headers = {"User-Agent": "Pythia-SQLi-Scanner/0.2.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        logger.debug(f"NVD CPE query: {cpe_string}")
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code == 403:
            logger.warning("NVD rate limited — sleeping 30s then retrying")
            time.sleep(30)
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code in (404, 204):
            logger.debug(f"NVD: no results for {cpe_string}")
            return []

        resp.raise_for_status()
        data  = resp.json()
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        logger.info(f"NVD: {total} CVE(s) for {vendor}/{product} {version}")

        results = [r for r in (_parse_nvd(v) for v in vulns) if r]
        results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        return results

    except requests.exceptions.Timeout:
        logger.warning(f"NVD timeout for {vendor}/{product} {version} — trying CIRCL")
        return _circl_fallback(f"{vendor} {product}", version, 10, timeout)
    except requests.exceptions.RequestException as e:
        logger.warning(f"NVD request error: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected NVD error: {e}")
        return []


def _parse_nvd(vuln: Dict) -> Optional[Dict[str, Any]]:
    """Parse one NVD vulnerability entry into our schema format."""
    try:
        cve     = vuln["cve"]
        cve_id  = cve["id"]
        desc_en = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "",
        )

        # CVSS: prefer v3.1 → v3.0 → v2.0
        metrics       = cve.get("metrics", {})
        cvss_score    = None
        cvss_severity = None

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                d             = entries[0]["cvssData"]
                cvss_score    = d.get("baseScore")
                cvss_severity = d.get("baseSeverity")
                break

        if cvss_score is None:
            entries = metrics.get("cvssMetricV2", [])
            if entries:
                cvss_score    = entries[0]["cvssData"].get("baseScore")
                cvss_severity = entries[0].get("baseSeverity", "")

        # CWE
        cwe_ids = [
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")
        ]
        cwe_id = cwe_ids[0] if cwe_ids else None

        record: Dict[str, Any] = {
            "cve_id":        cve_id,
            "title":         desc_en[:120] or cve_id,
            "description":   desc_en,
            "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cvss_score":    cvss_score,
            "cvss_severity": cvss_severity,
            "published":     cve.get("published", "")[:10],
        }
        if cwe_id:
            record["cwe_id"]   = cwe_id
            record["cwe_name"] = _CWE_NAMES.get(cwe_id, "")
        return record

    except Exception as e:
        logger.debug(f"CVE parse error: {e}")
        return None


def _circl_fallback(
    software: str,
    version: str,
    max_results: int,
    timeout: int,
) -> List[Dict[str, Any]]:
    """CIRCL CVE Search API fallback — returns most recent CVEs for a product."""
    parts   = software.lower().replace("-", "_").split()
    vendor  = parts[0] if parts else software.lower()
    product = "_".join(parts) if parts else software.lower()

    url = f"{CIRCL_BASE}/search/{vendor}/{product}"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []

        data    = resp.json()
        results = []
        items   = data if isinstance(data, list) else data.get("data", [])

        for item in items:
            cve_id  = item.get("id", "")
            summary = item.get("summary", "")
            cvss    = item.get("cvss")
            cwe     = item.get("cwe", "")

            try:
                cvss_f = float(cvss) if cvss else None
            except (TypeError, ValueError):
                cvss_f = None

            record: Dict[str, Any] = {
                "cve_id":        cve_id,
                "title":         summary[:120] or cve_id,
                "description":   summary,
                "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cvss_score":    cvss_f,
                "cvss_severity": _score_to_severity(cvss_f),
                "published":     item.get("Published", "")[:10],
            }
            if isinstance(cwe, str) and cwe.startswith("CWE-"):
                record["cwe_id"]   = cwe
                record["cwe_name"] = _CWE_NAMES.get(cwe, "")
            results.append(record)

        results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        return results[:max_results]

    except Exception as e:
        logger.debug(f"CIRCL fallback error: {e}")
        return []


def _score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def extract_version_from_error(error_snippet: str, dbms: str) -> Optional[str]:
    """
    Try to extract DBMS version from an error snippet.

    MySQL/MariaDB errors sometimes include the version in their messages.
    e.g. "MySQL 8.0.32" or "MariaDB 10.5.18"

    Args:
        error_snippet: The error message text from the HTTP response
        dbms: The detected DBMS name

    Returns:
        Version string if found (e.g. '8.0.32'), None otherwise
    """
    if not error_snippet:
        return None

    version_patterns = [
        # "MySQL 8.0.32" or "MariaDB 10.5.18"
        rf'{re.escape(dbms)}\s+(\d+\.\d+[\.\d]*)',
        # "Ver 8.0.32" or "version 5.7.38"
        r'[Vv]ersion\s+(\d+\.\d+[\.\d]*)',
        r'[Vv]er(?:sion)?\s+(\d+\.\d+[\.\d]*)',
        # Bare version-like pattern: "8.0.32" in error context
        r'\b(\d+\.\d+\.\d+)\b',
    ]

    for pattern in version_patterns:
        m = re.search(pattern, error_snippet)
        if m:
            return m.group(1)

    return None


def enrich_finding_with_cves(
    finding: Dict[str, Any],
    software: str,
    version: str,
    max_cves: int = 5,
    api_key: Optional[str] = None,
) -> None:
    """
    Enrich a finding dict in-place with CVE data from NVD (version-based).

    Uses CPE matching — requires a valid version string.
    Falls back to lookup_sqli_cves() if no version available.

    Adds / updates:
      - finding['vulnerabilities'] : list of CVE records
      - finding['cve']             : list of CVE IDs
      - finding['cvss']            : highest CVSS score found
    """
    if not version or version in ("unknown", ""):
        return

    cves = lookup_cves(software, version, max_results=max_cves, api_key=api_key)
    if not cves:
        return

    _apply_cves_to_finding(finding, cves)
    logger.debug(
        f"Enriched finding {finding.get('id')} with {len(cves)} CVEs "
        f"for {software} {version} (top CVSS: {finding.get('cvss')})"
    )


def enrich_sqli_findings(
    findings: List[Dict[str, Any]],
    max_cves: int = 5,
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Enrich SQL injection findings in-place with relevant CVE data.

    For each finding:
      1. Promote evidence.dbms → finding['dbms'] (top-level field for template)
      2. Try to extract version from error snippet
      3. If version known → version-based CPE lookup
      4. If version unknown → CWE-89 + DBMS keyword search
      5. Populate finding['vulnerabilities'], finding['cve'], finding['cvss']

    Deduplicates NVD calls: same DBMS → same CVE set (cached).

    Args:
        findings: List of finding dicts (mutated in-place)
        max_cves: Max CVEs per finding (default 5)
        api_key:  Optional NVD API key

    Returns:
        The same findings list (mutated in-place)
    """
    # Cache keyed by (dbms, version) to avoid duplicate NVD calls.
    dbms_cve_cache: Dict[str, List[Dict]] = {}

    for finding in findings:
        # Skip info-level findings — they don't have real vulns
        if finding.get('severity', 'info') == 'info':
            continue

        # Promote evidence.dbms → finding['dbms'] (needed by template)
        evidence = finding.get('evidence', {})
        dbms = (
            finding.get('dbms')
            or evidence.get('dbms')
            or ''
        )
        if dbms:
            finding['dbms'] = dbms

        if not dbms:
            continue

        # Try to extract version from error snippet
        error_snippet = evidence.get('error_snippet', '') or evidence.get('value', '')
        version = extract_version_from_error(error_snippet, dbms)

        if not version:
            # No version extracted — skip CVE lookup to avoid misleading results.
            logger.debug(f"CVE lookup skipped for {dbms}: no version detected in error")
            continue

        # Check cache by (dbms, version)
        cache_key = f"{dbms}:{version}"
        if cache_key in dbms_cve_cache:
            cves = dbms_cve_cache[cache_key]
            if cves:
                _apply_cves_to_finding(finding, cves)
            continue

        # Version-aware CPE lookup
        logger.info(f"CVE lookup: {dbms} {version} (CPE-based)")
        cves = lookup_cves(dbms, version, max_results=max_cves, api_key=api_key)
        dbms_cve_cache[cache_key] = cves

        if cves:
            _apply_cves_to_finding(finding, cves)
            logger.info(
                f"Finding {finding.get('id')} enriched: {len(cves)} CVEs for {dbms} {version}"
            )

    return findings


def _apply_cves_to_finding(finding: Dict[str, Any], cves: List[Dict]) -> None:
    """Apply a CVE list to a finding (in-place)."""
    finding['vulnerabilities'] = cves
    finding['cve'] = [c['cve_id'] for c in cves if c.get('cve_id')]
    scores = [c['cvss_score'] for c in cves if c.get('cvss_score') is not None]
    if scores:
        finding['cvss'] = max(scores)


def clear_cache() -> None:
    """Clear in-memory CVE cache (useful between test runs)."""
    with _CACHE_LOCK:
        _CACHE.clear()
    logger.debug("CVE cache cleared")

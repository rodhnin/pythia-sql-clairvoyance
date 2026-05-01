"""
Pythia Contextual Risk Scoring
================================
Computes a contextual CVSS-like score for SQL injection findings by applying
modifiers based on observable runtime evidence.

Base score for SQL injection: 9.8 (CVSS v3.1 Critical — CWE-89)

Modifiers (additive flags, score capped at 10.0):
  +crit: PII detected in HTTP responses (emails, passwords, SSN, credit cards)
  +crit: DB root/admin user privileges detected (@@user, CURRENT_USER output)
  +high: HTTP (not HTTPS) — data in cleartext
  +high: UNION data extraction confirmed (actual data retrieved from DB)
  +med:  Multiple parameters vulnerable in same endpoint
  +low:  Only reflection (no error, no data extraction)

Score bands:
  9.5-10.0 → Critical+  (privilege + PII)
  9.0-9.4  → Critical   (default SQLi)
  7.0-8.9  → High
  4.0-6.9  → Medium
  0.0-3.9  → Low

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

from .logging import get_logger

logger = get_logger(__name__)


# -----------------------------------------------------------------------
# PII detection patterns
# -----------------------------------------------------------------------

_PII_PATTERNS = {
    'email': re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    'credit_card': re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?'          # Visa
        r'|5[1-5][0-9]{14}'                        # MasterCard
        r'|3[47][0-9]{13}'                         # Amex
        r'|6(?:011|5[0-9]{2})[0-9]{12})\b'        # Discover
    ),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'password_field': re.compile(
        r'(?:password|passwd|pwd|pass)\s*[:=]\s*[^\s,<]{4,}',
        re.IGNORECASE
    ),
    'db_credential': re.compile(
        r'(?:mysql|postgres|oracle|mssql)\s+(?:password|user)',
        re.IGNORECASE
    ),
}

# DB root/admin user signatures
_PRIVILEGED_USER_PATTERNS = re.compile(
    r'(?:root@|@localhost|dbo@|sa@|admin@|sys@|system@'
    r'|CURRENT_USER\(\)\s*=\s*["\']?(?:root|admin|dbo|sa|sys)'
    r'|@@user\s*=\s*["\']?(?:root|admin|dbo|sa|sys))',
    re.IGNORECASE
)


# -----------------------------------------------------------------------
# Scoring logic
# -----------------------------------------------------------------------

_BASE_SCORE = 9.8  # CVSS v3.1 for CWE-89 SQL Injection


def _detect_pii(text: str) -> List[str]:
    """Return list of PII type names found in text."""
    found = []
    for pii_type, pattern in _PII_PATTERNS.items():
        if pattern.search(text):
            found.append(pii_type)
    return found


def _detect_privileged_user(text: str) -> bool:
    """Return True if response suggests root/admin DB user."""
    return bool(_PRIVILEGED_USER_PATTERNS.search(text))


def score_finding(
    finding: Dict,
    response_text: Optional[str] = None,
    target_url: Optional[str] = None,
    all_findings: Optional[List[Dict]] = None,
) -> Tuple[float, List[str]]:
    """
    Compute contextual risk score and risk factors for a finding.

    Args:
        finding:       The finding dict (must have 'evidence', 'detection_method')
        response_text: Raw HTTP response text from the vulnerable request (if available)
        target_url:    The target URL (used for HTTP vs HTTPS check)
        all_findings:  All findings from the scan (for multi-param check)

    Returns:
        Tuple of (contextual_score: float, risk_factors: List[str])
    """
    score = _BASE_SCORE
    risk_factors: List[str] = []

    evidence = finding.get('evidence', {})
    detection_method = finding.get('detection_method', '')
    url = evidence.get('url', '') or target_url or ''

    # ── 1. HTTP (not HTTPS) ─────────────────────────────────────────────
    if url.startswith('http://'):
        score = min(10.0, score + 0.1)
        risk_factors.append('HTTP (unencrypted) — credentials/data transmitted in cleartext')

    # ── 2. Privileged DB user detected ──────────────────────────────────
    if response_text and _detect_privileged_user(response_text):
        score = min(10.0, score + 0.15)
        risk_factors.append(
            'Privileged DB user detected (root/admin/dbo) — '
            'full database access possible'
        )

    # ── 3. PII in response ───────────────────────────────────────────────
    if response_text:
        pii_types = _detect_pii(response_text)
        if pii_types:
            score = min(10.0, score + 0.2)
            risk_factors.append(
                f'PII detected in response: {", ".join(pii_types)} — '
                f'data exfiltration risk'
            )

    # ── 4. UNION data extraction confirmed ──────────────────────────────
    if detection_method == 'union-based':
        score = min(10.0, score + 0.1)
        risk_factors.append(
            'UNION-based extraction confirmed — '
            'attacker can read arbitrary database content'
        )

    # ── 5. Second-order (most dangerous variant) ─────────────────────────
    if detection_method == 'second-order':
        score = min(10.0, score + 0.1)
        risk_factors.append(
            'Second-order injection — '
            'payload survives sanitization at input and executes later'
        )

    # ── 6. Multiple parameters in same endpoint ──────────────────────────
    if all_findings:
        same_endpoint_params = set()
        for f in all_findings:
            f_url = f.get('evidence', {}).get('url', '')
            f_param = f.get('evidence', {}).get('parameter', '')
            if f_url and f_param:
                parsed_f = urlparse(f_url)
                parsed_cur = urlparse(url)
                if (parsed_f.netloc == parsed_cur.netloc and
                        parsed_f.path == parsed_cur.path and
                        f_param != evidence.get('parameter', '')):
                    same_endpoint_params.add(f_param)

        if same_endpoint_params:
            risk_factors.append(
                f'Multiple parameters vulnerable in same endpoint: '
                f'{", ".join(sorted(same_endpoint_params))}'
            )

    # Round to 1 decimal
    score = round(min(10.0, score), 1)

    return score, risk_factors


def enrich_findings_with_risk(
    findings: List[Dict],
    target_url: Optional[str] = None,
) -> List[Dict]:
    """
    Add contextual_score and risk_factors to every finding.

    For findings that don't have response_text in evidence (most do not),
    the scoring still works — it just skips PII/user checks.
    """
    for finding in findings:
        evidence = finding.get('evidence', {})
        # Some evidence dicts carry the raw response text
        response_text = evidence.get('response_body') or evidence.get('error_snippet') or ''

        score, factors = score_finding(
            finding=finding,
            response_text=response_text,
            target_url=target_url,
            all_findings=findings,
        )

        finding['contextual_score'] = score
        finding['risk_factors'] = factors

        logger.debug(
            f"[RISK] {finding.get('id', '?')} "
            f"param={evidence.get('parameter', '?')} "
            f"score={score} factors={len(factors)}"
        )

    return findings


def get_score_band(score: float) -> str:
    """Return human-readable risk band for a contextual score."""
    if score >= 9.5:
        return 'Critical+'
    elif score >= 9.0:
        return 'Critical'
    elif score >= 7.0:
        return 'High'
    elif score >= 4.0:
        return 'Medium'
    else:
        return 'Low'

"""
Pythia ORDER BY / GROUP BY SQL Injection Detection
====================================================
Detects ORDER BY injection by testing numeric sort parameters.
This vector does not use quotes — it injects SQL expressions into
parameters that control result ordering.

PYTHIA-SQL-050

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..core.logging import get_logger

logger = get_logger(__name__)


# Numeric-context sort parameter name heuristics
SORT_PARAM_PATTERNS = re.compile(
    r'^(sort|order|orderby|order_by|sortby|sort_by|col|column|dir|direction|'
    r'asc|desc|field|idx|index|by|sb|ob)$',
    re.IGNORECASE,
)

# SQL error patterns that indicate ORDER BY injection worked
SQLI_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'you have an error in your sql syntax',
        r'unknown column',
        r'error in your sql',
        r'quoted string not properly terminated',
        r'unclosed quotation mark',
        r'syntax error.*sql',
        r'pg_query\(\).*error',
        r'supplied argument is not a valid.*result',
        r'division by zero',        # CASE WHEN 1=0 THEN 1/0
        r'invalid input syntax for',
        r'xpath syntax error',      # MySQL EXTRACTVALUE injection
        r'sqlstate\[',              # PDO SQLSTATE error prefix
        r'general error.*\d{4}',   # MySQL general error codes
        r'sql error:',              # Generic SQL Error: label
    ]
]


class OrderByDetector:
    """
    ORDER BY / GROUP BY SQL injection detector.

    Targets numeric sort parameters (e.g. ?sort=price, ?order=1).
    Detection strategy:
      1. Error-based: inject CASE WHEN 1=0 THEN 1/0 ELSE 1 END — triggers
         a DB error only when the expression evaluates (proving SQL execution).
      2. Behavioral: compare ordering of response content with valid numeric
         values (1 vs 2) vs an invalid expression — if order changes, injection
         is likely.
      3. Requires 2 independent detections to report a finding (FP hardening).
    """

    # Payloads that cause DB-visible errors in ORDER BY context
    ERROR_PAYLOADS = [
        # Division-by-zero on false condition
        "CASE WHEN 1=0 THEN 1/0 ELSE 1 END",
        "(SELECT CASE WHEN 1=0 THEN 1/0 ELSE 1 END)",
        # MySQL: EXTRACTVALUE causes XPATH error in ORDER BY
        "EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1)))",
        # PostgreSQL: syntax error trick
        "(SELECT 1 FROM information_schema.tables LIMIT 1)",
    ]

    # Payloads using CASE WHEN to change sort order (behavioral detection)
    # True condition → sort by column 1; False condition → sort by column 2
    CASE_TRUE_PAYLOAD = "CASE WHEN 1=1 THEN 1 ELSE 2 END"
    CASE_FALSE_PAYLOAD = "CASE WHEN 1=0 THEN 1 ELSE 2 END"

    def __init__(self, config, http_client):
        self.config = config
        self.http = http_client
        logger.debug("OrderByDetector initialized")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_sort_param(self, param_name: str, value: str) -> bool:
        """Return True if the param looks like a sort/order parameter."""
        if SORT_PARAM_PATTERNS.match(param_name):
            return True
        # Also flag any param whose current value is a small integer (1-99)
        try:
            n = int(value.strip())
            if 0 < n < 100:
                return True
        except (ValueError, AttributeError):
            pass
        return False

    def _build_url(self, base_url: str, params: Dict[str, str]) -> str:
        parsed = urlparse(base_url)
        new_query = urlencode(params, doseq=False)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    def _has_sql_error(self, text: str) -> bool:
        for pat in SQLI_ERROR_PATTERNS:
            if pat.search(text):
                return True
        return False

    def _extract_error_snippet(self, text: str, max_len: int = 200) -> str:
        """Extract the SQL error message from a response body."""
        for pat in SQLI_ERROR_PATTERNS:
            m = pat.search(text)
            if m:
                start = max(0, m.start() - 20)
                end = min(len(text), m.end() + 80)
                return text[start:end].strip()
        return text[:max_len]

    def _content_similarity(self, a: str, b: str) -> float:
        max_len = 8000
        return SequenceMatcher(None, a[:max_len], b[:max_len]).ratio()

    # ------------------------------------------------------------------
    # Core detection
    # ------------------------------------------------------------------

    def _test_param(
        self,
        base_url: str,
        all_params: Dict[str, str],
        param_name: str,
        original_value: str,
    ) -> Optional[Dict]:
        """
        Test a single parameter for ORDER BY injection.
        Returns a finding dict or None.
        """
        detections = []

        # ---- 1. Get baseline response --------------------------------
        try:
            baseline_resp = self.http.get(self._build_url(base_url, all_params))
        except Exception as e:
            logger.debug(f"Baseline request failed for {param_name}: {e}")
            return None

        # ---- 2. Error-based detection --------------------------------
        for payload in self.ERROR_PAYLOADS:
            injected_params = dict(all_params)
            injected_params[param_name] = payload
            try:
                resp = self.http.get(self._build_url(base_url, injected_params))
                if self._has_sql_error(resp.text):
                    detections.append({
                        'method': 'error_based',
                        'payload': payload,
                        'evidence': self._extract_error_snippet(resp.text),
                    })
                    logger.info(
                        f"ORDER BY error injection detected in '{param_name}' "
                        f"at {base_url}"
                    )
                    break
            except Exception as e:
                logger.debug(f"Error-based ORDER BY test failed: {e}")

        # ---- 3. Behavioral detection (CASE WHEN) ---------------------
        try:
            true_params = dict(all_params)
            true_params[param_name] = self.CASE_TRUE_PAYLOAD
            true_resp = self.http.get(self._build_url(base_url, true_params))

            false_params = dict(all_params)
            false_params[param_name] = self.CASE_FALSE_PAYLOAD
            false_resp = self.http.get(self._build_url(base_url, false_params))

            sim_true_base = self._content_similarity(
                baseline_resp.text, true_resp.text
            )
            sim_false_base = self._content_similarity(
                baseline_resp.text, false_resp.text
            )
            sim_true_false = self._content_similarity(
                true_resp.text, false_resp.text
            )

            # True condition response ≈ baseline but differs from false → injection
            if (
                sim_true_base > 0.80
                and sim_false_base < 0.70
                and sim_true_false < 0.80
            ):
                detections.append({
                    'method': 'behavioral',
                    'payload': f"{self.CASE_TRUE_PAYLOAD} vs {self.CASE_FALSE_PAYLOAD}",
                    'evidence': (
                        f"Similarity true/base={sim_true_base:.2f}, "
                        f"false/base={sim_false_base:.2f}"
                    ),
                })
                logger.info(
                    f"ORDER BY behavioral injection detected in '{param_name}' "
                    f"at {base_url} (sim true={sim_true_base:.2f}, "
                    f"false={sim_false_base:.2f})"
                )
        except Exception as e:
            logger.debug(f"Behavioral ORDER BY test failed: {e}")

        # ---- 4. Require at least 2 independent detections (FP hardening) ---
        # OR 1 detection if it's error-based (which is high-confidence by itself)
        error_detections = [d for d in detections if d['method'] == 'error_based']
        if not detections:
            return None
        if len(detections) < 2 and not error_detections:
            logger.debug(
                f"ORDER BY possible in '{param_name}' but only 1 behavioral "
                f"detection — skipping (need 2 for FP hardening)"
            )
            return None

        best = detections[0]
        confidence = 'high' if error_detections else 'medium'

        return self._create_finding(
            url=base_url,
            parameter=param_name,
            original_value=original_value,
            payload=best['payload'],
            method='GET',
            confidence=confidence,
            evidence_detail=best['evidence'],
            num_detections=len(detections),
        )

    def _create_finding(
        self,
        url: str,
        parameter: str,
        original_value: str,
        payload: str,
        method: str,
        confidence: str,
        evidence_detail: str,
        num_detections: int,
    ) -> Dict:
        evidence = {
            'type': 'order_by_injection',
            'value': evidence_detail,
            'method': method,
            'url': url,
            'parameter': parameter,
            'original_value': original_value,
            'payload': payload,
            'detections': num_detections,
        }

        description = (
            f"ORDER BY SQL injection detected in parameter '{parameter}'. "
            f"The application passes a user-controlled value directly into an "
            f"ORDER BY / GROUP BY clause without sanitization. Unlike conventional "
            f"SQL injection, this vector does not require quotes and bypasses many "
            f"WAF rules. An attacker can manipulate result ordering, trigger "
            f"conditional errors, or enumerate the database schema."
        )

        recommendation = (
            "Never pass user input directly into ORDER BY clauses. "
            "Use a whitelist of allowed column names and directions (ASC/DESC). "
            "Example: map the 'sort' parameter to a safe column name in code before "
            "constructing the query. Use parameterized queries for all other clauses."
        )

        return {
            'id': 'PYTHIA-SQL-050',
            'title': 'ORDER BY / GROUP BY SQL Injection',
            'description': description,
            'severity': 'high',
            'confidence': confidence,
            'recommendation': recommendation,
            'evidence': evidence,
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection/blind',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            ],
            'affected_component': f"{method} {url} (parameter: {parameter})",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'detection_method': 'order-injection',
            'parameter': parameter,
            'vector': method,
        }

    # ------------------------------------------------------------------
    # Public scan interface
    # ------------------------------------------------------------------

    def scan(
        self,
        urls_with_params: List[Dict],
        forms: List[Dict],
    ) -> List[Dict]:
        """
        Scan for ORDER BY injection vulnerabilities.

        Args:
            urls_with_params: List of URL dicts from crawler
            forms: List of form dicts (not tested — ORDER BY is GET-only)

        Returns:
            List of findings
        """
        findings = []
        seen: set = set()

        logger.info(f"[ORDER BY] Starting scan — {len(urls_with_params)} URLs")

        for url_info in urls_with_params:
            # Support both formats:
            # 1. {'base_url': ..., 'parameters': {...}, 'original_url': ...}
            #    (from scanner._extract_params_from_urls)
            # 2. {'url': ...} (raw URL dict)
            if 'base_url' in url_info and 'parameters' in url_info:
                base_url = url_info['base_url']
                flat_params = url_info['parameters']
                if not flat_params:
                    continue
            elif 'url' in url_info:
                url = url_info['url']
                if not url:
                    continue
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if not params:
                    continue
                flat_params = {
                    k: (v[0] if isinstance(v, list) else v)
                    for k, v in params.items()
                }
                base_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, '', parsed.fragment,
                ))
            else:
                continue

            for param_name, value in flat_params.items():
                target_key = (base_url, param_name)
                if target_key in seen:
                    continue

                if not self._is_sort_param(param_name, value):
                    continue

                seen.add(target_key)
                logger.debug(
                    f"[ORDER BY] Testing '{param_name}'={value!r} at {base_url}"
                )

                finding = self._test_param(base_url, flat_params, param_name, value)
                if finding:
                    findings.append(finding)
                    logger.info(
                        f"✓ ORDER BY SQLi found: {param_name} at {base_url}"
                    )

        logger.info(
            f"[ORDER BY] Scan complete: {len(findings)} vulnerabilities found"
        )
        return findings

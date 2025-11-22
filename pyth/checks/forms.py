"""
Pythia Form Parser & Tester
===========================

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class FormTester:
    """
    HTML form parser and SQL injection tester.
    """
    
    # Testable input types (configured in defaults.yaml)
    DEFAULT_TESTABLE_TYPES = ['text', 'search', 'email', 'url', 'tel', 'number', 'hidden']
    
    # Skip patterns for form names/IDs (avoid destructive actions)
    DEFAULT_SKIP_PATTERNS = ['logout', 'signout', 'delete', 'remove', 'unsubscribe']
    
    # CSRF token field name patterns
    CSRF_PATTERNS = [
        'csrf',
        'token',
        '_token',
        'authenticity',
        'xsrf',
        'user_token',
        'security_token',
        'form_token',
        'request_token'
    ]
    
    def __init__(self, config, http_client, auto_csrf: bool = False):
        """
        Initialize form tester.
        
        Args:
            config: Configuration object
            http_client: HTTP client for making requests
            auto_csrf: Enable automatic CSRF token extraction
        """
        self.config = config
        self.http = http_client
        self.auto_csrf = auto_csrf
        
        # Load testable input types from config
        if hasattr(config, 'forms_testable_input_types'):
            self.testable_types = config.forms_testable_input_types
        else:
            self.testable_types = self.DEFAULT_TESTABLE_TYPES
        
        # Load skip patterns from config
        if hasattr(config, 'forms_skip_form_patterns'):
            self.skip_patterns = config.forms_skip_form_patterns
        else:
            self.skip_patterns = self.DEFAULT_SKIP_PATTERNS
        
        # Whether to preserve hidden fields
        self.preserve_hidden = getattr(config, 'forms_preserve_hidden_fields', True)
        
        # Maximum inputs to test per form
        self.max_inputs = getattr(config, 'forms_max_inputs_per_form', 20)
        
        logger.info(f"Form tester initialized")
        logger.debug(f"  Testable types: {self.testable_types}")
        logger.debug(f"  Skip patterns: {self.skip_patterns}")
        if auto_csrf:
            logger.info(f"  CSRF auto-extraction: ENABLED")
            logger.info(f"  CSRF token refresh: ENABLED (before each request)")
    
    # Merge URL and params without duplicates
    def _merge_url_and_params(self, url: str, params: Dict[str, str]) -> str:
        """
        Merge URL and params, avoiding duplicate parameters.
        
        Args:
            url: Form action URL (may have query params)
            params: Form data to add as query params
        
        Returns:
            Clean URL with merged parameters (no duplicates)
        
        Example:
            url = "http://example.com?page=search"
            params = {"page": "search", "q": "test"}
            
            # WRONG: http://example.com?page=search&page=search&q=test
            # RIGHT: http://example.com?page=search&q=test
        """
        # Parse URL
        parsed = urlparse(url)
        
        # Extract existing query params
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Flatten existing params (parse_qs returns lists)
        # Example: {'page': ['search']} → {'page': 'search'}
        existing_flat = {}
        for k, v in existing_params.items():
            if isinstance(v, list) and len(v) > 0:
                existing_flat[k] = v[0]  # Take first value
            else:
                existing_flat[k] = v
        
        # If both URL and form_data have 'page', form_data wins
        merged_params = {**existing_flat, **params}
        
        # Rebuild query string
        new_query = urlencode(merged_params, doseq=False)
        
        # Rebuild URL with clean query
        clean_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            '',  # params (unused)
            new_query,
            ''   # fragment
        ))
        
        logger.debug(f"[URL MERGE] Original: {url}")
        logger.debug(f"[URL MERGE] Params: {params}")
        logger.debug(f"[URL MERGE] Clean: {clean_url}")
        
        return clean_url
    
    def should_skip_form(self, form: Dict) -> bool:
        """
        Check if form should be skipped (e.g., logout, delete forms).
        
        Args:
            form: Form dictionary from crawler
        
        Returns:
            True if form should be skipped, False otherwise
        """
        # Check form ID, name, and action URL
        form_id = form.get('id', '').lower()
        form_name = form.get('name', '').lower()
        action_url = form.get('action', '').lower()
        
        for pattern in self.skip_patterns:
            pattern_lower = pattern.lower()
            if (pattern_lower in form_id or 
                pattern_lower in form_name or 
                pattern_lower in action_url):
                logger.debug(f"Skipping form (matches pattern '{pattern}'): {action_url}")
                return True
        
        return False
    
    def get_testable_inputs(self, form: Dict) -> List[Dict]:
        """
        Get list of testable input fields from form.
        
        Args:
            form: Form dictionary from crawler
        
        Returns:
            List of input dictionaries that should be tested
        """
        testable = []
        
        for input_field in form.get('inputs', []):
            input_type = input_field.get('type', 'text').lower()
            input_name = input_field.get('name', '')
            
            # Skip if no name
            if not input_name:
                continue
            
            # Skip CSRF tokens (don't inject into these)
            if self.is_csrf_token(input_field):
                logger.debug(f"Skipping CSRF token field: {input_name}")
                continue
            
            # Skip if input type is not testable
            if input_type not in self.testable_types:
                logger.debug(f"Skipping non-testable input type: {input_type} ({input_name})")
                continue
            
            # Skip if input name matches skip pattern
            skip = False
            for pattern in self.skip_patterns:
                if pattern.lower() in input_name.lower():
                    logger.debug(f"Skipping input (matches pattern '{pattern}'): {input_name}")
                    skip = True
                    break
            
            if not skip:
                testable.append(input_field)
        
        # Limit number of inputs per form
        if len(testable) > self.max_inputs:
            logger.warning(f"Form has {len(testable)} inputs, limiting to {self.max_inputs}")
            testable = testable[:self.max_inputs]
        
        return testable
    
    def extract_csrf_token(self, form: Dict) -> Optional[Dict]:
        """
        Extract CSRF token from form.
        
        Looks for hidden fields with CSRF-like names.
        
        Args:
            form: Form dictionary
        
        Returns:
            Dict with 'name' and 'value' if found, None otherwise
        
        Example:
            >>> token = tester.extract_csrf_token(form)
            >>> if token:
            >>>     print(f"Found CSRF token: {token['name']}={token['value']}")
        """
        for input_field in form.get('inputs', []):
            if self.is_csrf_token(input_field):
                token_name = input_field['name']
                token_value = input_field.get('value', '')
                
                if token_value:
                    logger.info(f"✓ CSRF token extracted: {token_name}")
                    logger.debug(f"  Token value: {token_value[:20]}...")
                    return {
                        'name': token_name,
                        'value': token_value
                    }
        
        return None
    
    def _refresh_form_and_extract_csrf(self, form_url: str) -> Optional[Dict]:
        """
        Fetch page and extract fresh CSRF token.
        
        This method solves the token reuse problem by:
        1. GET the form page to obtain fresh HTML
        2. Parse HTML to extract forms
        3. Find the target form
        4. Extract fresh CSRF token
        
        Args:
            form_url: URL of the form page
        
        Returns:
            Dict with 'name' and 'value' if fresh token found, None otherwise
        """
        try:
            logger.debug(f"[CSRF REFRESH] Fetching fresh token from: {form_url}")
            
            # GET the page
            response = self.http.get(form_url, allow_redirects=True)
            
            if response.status_code != 200:
                logger.warning(f"[CSRF REFRESH] Non-200 response: {response.status_code}")
                return None
            
            # Parse HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all forms from fresh HTML
            fresh_forms = self._extract_forms_from_soup(soup, response.url)
            
            if not fresh_forms:
                logger.warning(f"[CSRF REFRESH] No forms found in fresh page")
                return None
            
            # Find form that matches our target
            target_form = fresh_forms[0]
            
            # Try to match by action URL if multiple forms
            if len(fresh_forms) > 1:
                for form in fresh_forms:
                    # Simple match: same path
                    if urlparse(form['action']).path == urlparse(form_url).path:
                        target_form = form
                        break
            
            # Extract CSRF token from fresh form
            fresh_token = self.extract_csrf_token(target_form)
            
            if fresh_token:
                logger.info(f"[CSRF REFRESH] ✓ Fresh token obtained: {fresh_token['name']}={fresh_token['value'][:20]}...")
                return fresh_token
            else:
                logger.debug(f"[CSRF REFRESH] No CSRF token in fresh form")
                return None
        
        except Exception as e:
            logger.error(f"[CSRF REFRESH] Error fetching fresh token: {e}")
            return None
    
    def _extract_forms_from_soup(self, soup, page_url: str) -> List[Dict]:
        """
        Extract forms from BeautifulSoup object (helper for CSRF token refresh).
        
        This is a simplified version of crawler._extract_forms() that works
        without needing the full crawler instance.
        
        Args:
            soup: BeautifulSoup parsed HTML
            page_url: Current page URL (for resolving relative actions)
        
        Returns:
            List of form dictionaries
        """
        forms = []
        
        for form_tag in soup.find_all('form'):
            # Get form attributes
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'get').lower()
            form_id = form_tag.get('id', '')
            form_name = form_tag.get('name', '')
            
            # Resolve relative action URL
            if action:
                action = urljoin(page_url, action)
            else:
                action = page_url
            
            # Extract input fields
            inputs = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text').lower()
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                
                if input_name:
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            forms.append({
                'action': action,
                'method': method,
                'id': form_id,
                'name': form_name,
                'inputs': inputs
            })
        
        return forms
    
    def build_form_data(
        self,
        form: Dict,
        test_field: str,
        test_value: str,
        csrf_token: Optional[Dict] = None
    ) -> Dict[str, str]:
        """
        Build form data dictionary for submission.
        
        Args:
            form: Form dictionary
            test_field: Name of field to inject test payload
            test_value: SQLi test payload value
            csrf_token: Optional CSRF token dict
        
        Returns:
            Dictionary of form data (name -> value)
        """
        form_data = {}
        
        for input_field in form.get('inputs', []):
            input_name = input_field['name']
            input_type = input_field.get('type', 'text')
            input_value = input_field.get('value', '')
            
            if input_name == test_field:
                # This is the field we're testing - inject payload
                form_data[input_name] = test_value
            
            elif input_type == 'hidden' and self.preserve_hidden:
                # Preserve hidden fields (CSRF tokens, session IDs, etc.)
                # If we have a CSRF token override, use it
                if csrf_token and input_name == csrf_token['name']:
                    form_data[input_name] = csrf_token['value']
                else:
                    form_data[input_name] = input_value
            
            elif input_type == 'submit':
                # Preserve submit button value if it exists
                if input_value:
                    form_data[input_name] = input_value
            
            else:
                # For other fields, use original value or empty string
                form_data[input_name] = input_value if input_value else ''
        
        return form_data
    
    def test_form(
        self, 
        form: Dict, 
        payloads: List[str], 
        detection_callback
    ) -> List[Dict]:
        """
        Test form for SQL injection vulnerabilities.

        Args:
            form: Form dictionary from crawler
            payloads: List of SQLi payloads to test
            detection_callback: Callback function(response, payload, field) -> Optional[Dict]
                Should return finding dict if vulnerability detected, None otherwise
        
        Returns:
            List of finding dictionaries
        """
        findings = []
        
        # Check if form should be skipped
        if self.should_skip_form(form):
            return findings
        
        # Get testable inputs
        testable_inputs = self.get_testable_inputs(form)
        
        if not testable_inputs:
            logger.debug(f"No testable inputs in form: {form['action']}")
            return findings
        
        logger.info(f"Testing form: {form['method'].upper()} {form['action']} ({len(testable_inputs)} inputs)")
        
        # Test each field with each payload
        for input_field in testable_inputs:
            field_name = input_field['name']
            field_type = input_field.get('type', 'text')
            
            logger.debug(f"  Testing field: {field_name} (type={field_type})")
            
            for payload in payloads:
                try:
                    csrf_token = None
                    if self.auto_csrf:
                        logger.debug(f"    [CSRF] Refreshing token for payload: {payload[:30]}...")
                        
                        # Fetch fresh token from form page
                        csrf_token = self._refresh_form_and_extract_csrf(form['action'])
                        
                        if csrf_token:
                            logger.debug(f"    [CSRF] Using fresh token: {csrf_token['name']}={csrf_token['value'][:10]}...")
                        else:
                            logger.debug(f"    [CSRF] No fresh token obtained, using original")
                            # Fallback to original token extraction
                            csrf_token = self.extract_csrf_token(form)
                    
                    # Build form data with payload in this field
                    form_data = self.build_form_data(
                        form,
                        field_name,
                        payload,
                        csrf_token=csrf_token  # Use FRESH token
                    )
                    
                    # Submit form
                    if form['method'] == 'post':
                        response = self.http.post(
                            form['action'],
                            data=form_data,
                            allow_redirects=True
                        )
                    else:
                        clean_url = self._merge_url_and_params(form['action'], form_data)
                        
                        response = self.http.get(
                            clean_url,  # ← URL already has all params merged cleanly
                            allow_redirects=True
                        )
                        
                        logger.debug(f"    GET request URL: {clean_url}")
                    
                    # Check response for vulnerability
                    finding = detection_callback(response, payload, field_name, form)
                    
                    if finding:
                        findings.append(finding)
                        # Don't test more payloads for this field once vulnerability found
                        logger.info(f"    ✓ Vulnerability found in field '{field_name}'")
                        break
                
                except Exception as e:
                    logger.error(f"Error testing form field {field_name}: {e}")
                    continue
        
        return findings
    
    def generate_field_variations(self, field_name: str, base_value: str) -> List[str]:
        """
        Generate variations of a field value for testing.
        
        Useful for testing different injection points:
        - Original value
        - Value with quotes
        - Value with SQL operators
        
        Args:
            field_name: Name of the field
            base_value: Base value to vary
        
        Returns:
            List of value variations
        """
        variations = [base_value]
        
        # Add variations with SQL characters
        if base_value:
            variations.append(f"{base_value}'")  # Add quote
            variations.append(f"{base_value}\"")  # Add double quote
            variations.append(f"{base_value} AND 1=1")  # Add AND operator
            variations.append(f"{base_value} OR 1=1")  # Add OR operator
        
        return variations
    
    def extract_form_context(self, form: Dict) -> str:
        """
        Extract human-readable context about form for reporting.
        
        Args:
            form: Form dictionary
        
        Returns:
            String describing the form
        """
        method = form['method'].upper()
        action = form['action']
        
        # Count input types
        input_types = {}
        for input_field in form.get('inputs', []):
            input_type = input_field.get('type', 'text')
            input_types[input_type] = input_types.get(input_type, 0) + 1
        
        # Build description
        inputs_desc = ', '.join([f"{count} {type}" for type, count in input_types.items()])
        
        context = f"{method} form at {action} ({inputs_desc})"
        
        # Add form name/ID if available
        if form.get('name'):
            context += f" [name={form['name']}]"
        elif form.get('id'):
            context += f" [id={form['id']}]"
        
        return context
    
    def is_password_field(self, field: Dict) -> bool:
        """
        Check if field is a password field.
        
        Args:
            field: Input field dictionary
        
        Returns:
            True if password field, False otherwise
        """
        field_type = field.get('type', '').lower()
        field_name = field.get('name', '').lower()
        
        return (field_type == 'password' or 
                'password' in field_name or 
                'passwd' in field_name or
                'pwd' in field_name)
    
    def is_csrf_token(self, field: Dict) -> bool:
        """
        Check if field is likely a CSRF token.
        
        Args:
            field: Input field dictionary
        
        Returns:
            True if likely CSRF token, False otherwise
        """
        field_name = field.get('name', '').lower()
        field_type = field.get('type', '').lower()
        
        # Must be hidden field
        if field_type != 'hidden':
            return False
        
        # Check if name matches any CSRF pattern
        for pattern in self.CSRF_PATTERNS:
            if pattern.lower() in field_name:
                return True
        
        return False


def analyze_form_complexity(form: Dict) -> str:
    """
    Analyze form complexity (simple, medium, complex).
    
    Args:
        form: Form dictionary
    
    Returns:
        Complexity level string
    """
    num_inputs = len(form.get('inputs', []))
    
    if num_inputs <= 3:
        return "simple"
    elif num_inputs <= 8:
        return "medium"
    else:
        return "complex"


def estimate_test_time(num_forms: int, num_payloads: int, avg_inputs_per_form: int) -> float:
    """
    Estimate time required to test all forms.
    
    Args:
        num_forms: Number of forms to test
        num_payloads: Number of payloads per field
        avg_inputs_per_form: Average testable inputs per form
    
    Returns:
        Estimated time in seconds
    """
    # Assume ~1 second per request (including rate limiting)
    requests_per_form = avg_inputs_per_form * num_payloads
    total_requests = num_forms * requests_per_form
    
    return total_requests * 1.0  # seconds


if __name__ == '__main__':
    # Test form parser
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    http_client = create_http_client(mode='safe', config=config)
    
    tester = FormTester(config, http_client, auto_csrf=True)
    
    # Example form with CSRF token
    example_form = {
        'action': 'https://example.com/search',
        'method': 'get',
        'id': 'search-form',
        'name': 'search',
        'inputs': [
            {'type': 'text', 'name': 'q', 'value': ''},
            {'type': 'hidden', 'name': 'csrf_token', 'value': 'abc123xyz'},
            {'type': 'submit', 'name': 'submit', 'value': 'Search'}
        ]
    }
    
    # Test CSRF extraction
    csrf = tester.extract_csrf_token(example_form)
    print(f"CSRF token: {csrf}")
    
    # Test testable inputs
    testable = tester.get_testable_inputs(example_form)
    print(f"Testable inputs: {[f['name'] for f in testable]}")
    
    # Test form data building
    form_data = tester.build_form_data(example_form, 'q', "test'", csrf_token=csrf)
    print(f"Form data: {form_data}")
    
    # Test URL merging
    test_url = "https://example.com/search?page=search"
    test_params = {'page': 'search', 'q': 'test'}
    clean_url = tester._merge_url_and_params(test_url, test_params)
    print(f"Clean URL: {clean_url}")

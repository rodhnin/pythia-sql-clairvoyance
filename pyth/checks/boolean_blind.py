"""
Pythia Boolean Blind SQL Injection Detection
============================================================
Detects blind SQL injection by comparing responses to true vs false conditions.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlunparse, urlencode
from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class BooleanBlindDetector:
    """
    Boolean blind SQL injection detector.
    
    Compares HTTP responses when injecting TRUE vs FALSE SQL conditions
    to detect blind SQL injection vulnerabilities.
    """
    
    def __init__(self, config, http_client, auto_csrf: bool = False):
        """
        Initialize boolean blind detector.
        
        Args:
            config: Configuration object
            http_client: HTTP client for requests
            auto_csrf: Enable automatic CSRF token extraction
        """
        self.config = config
        self.http = http_client
        self.auto_csrf = auto_csrf
        
        from .forms import FormTester
        self.form_tester = FormTester(config, http_client, auto_csrf)
        logger.debug("FormTester imported for URL merging support")
        
        # Load payloads from config
        if hasattr(config, 'sqli_boolean_payloads'):
            payload_config = config.sqli_boolean_payloads
            self.true_payloads = payload_config.get('true', [])
            self.false_payloads = payload_config.get('false', [])
        else:
            self.true_payloads = self._get_default_true_payloads()
            self.false_payloads = self._get_default_false_payloads()
        
        # Confidence thresholds from config
        if hasattr(config, 'sqli_boolean_blind'):
            blind_config = config.sqli_boolean_blind
            self.min_length_diff = blind_config.get('min_length_diff', 500)
            self.high_confidence_diff = blind_config.get('high_confidence_length_diff', 1000)
            self.medium_confidence_diff = blind_config.get('medium_confidence_length_diff', 500)
            self.min_consistent_results = blind_config.get('min_consistent_results', 2)
        else:
            self.min_length_diff = 500
            self.high_confidence_diff = 1000
            self.medium_confidence_diff = 500
            self.min_consistent_results = 2
        
        logger.info(f"Boolean blind detector initialized")
        logger.info(f"  TRUE payloads: {len(self.true_payloads)}")
        logger.info(f"  FALSE payloads: {len(self.false_payloads)}")
        logger.info(f"  Min length diff: {self.min_length_diff} bytes")
        logger.info(f"  Anti-false-positive validation: ENABLED")
        logger.info(f"  URL merging: ENABLED (imported from forms.py)")
    
    def _get_default_true_payloads(self) -> List[str]:
        """Get default TRUE condition payloads."""
        return [
            # PRIORITY 1: LIKE contexts (most common in search)
            "' OR 1=1-- ",
            "%' OR 1=1-- ",
            "' OR '1'='1'-- ",
            
            # PRIORITY 2: WHERE clauses
            " OR 1=1-- ",
            "' OR 1=1#",
            '" OR 1=1-- ',
            
            # PRIORITY 3: Additional variants
            "%' OR '1'='1'-- ",
            "' OR 1=1/*",
            " OR 1=1/*",
            
            # PRIORITY 4: TRUE condition variations
            "' AND 1=1-- ",
            " AND 1=1-- ",
            "' OR 'x'='x'-- ",
            " OR true-- ",
            " AND true-- ",
            
            # LEGACY: Without comments
            "' OR '1'='1",
            " OR 1=1",
            " AND 1=1",
            " OR 'x'='x",
        ]
    
    def _get_default_false_payloads(self) -> List[str]:
        """Get default FALSE condition payloads."""
        return [
            # PRIORITY 1: LIKE contexts
            "' AND 1=0-- ",
            "%' AND 1=0-- ",
            "' AND '1'='0'-- ",
            
            # PRIORITY 2: WHERE clauses
            " AND 1=0-- ",
            "' AND 1=0#",
            '" AND 1=0-- ',
            
            # PRIORITY 3: Additional variants
            "%' AND '1'='0'-- ",
            "' AND 1=0/*",
            " AND 1=0/*",
            
            # PRIORITY 4: FALSE condition variations
            "' OR 1=0-- ",
            " OR 1=0-- ",
            "' AND 'x'='y'-- ",
            " AND false-- ",
            " OR false-- ",
            
            # LEGACY: Without comments
            "' AND '1'='0",
            " AND 1=0",
            " OR 1=0",
            " AND 'x'='y",
        ]
    
    def compare_responses(
        self, 
        baseline_response, 
        true_response, 
        false_response
    ) -> Tuple[bool, str, Dict]:
        """
        Compare responses to detect boolean blind SQLi.
        """
        details = {}
        
        # Get response properties
        baseline_len = len(baseline_response.text)
        true_len = len(true_response.text)
        false_len = len(false_response.text)
        
        baseline_status = baseline_response.status_code
        true_status = true_response.status_code
        false_status = false_response.status_code
        
        length_diff_true_false = abs(true_len - false_len)
        length_diff_baseline_true = abs(baseline_len - true_len)
        length_diff_baseline_false = abs(baseline_len - false_len)
        
        baseline_len_safe = max(baseline_len, 1)
        
        relative_diff_true_false_pct = (length_diff_true_false / baseline_len_safe) * 100
        relative_diff_baseline_true_pct = (length_diff_baseline_true / baseline_len_safe) * 100
        relative_diff_baseline_false_pct = (length_diff_baseline_false / baseline_len_safe) * 100
        
        details.update({
            'baseline_length': baseline_len,
            'true_length': true_len,
            'false_length': false_len,
            'baseline_status': baseline_status,
            'true_status': true_status,
            'false_status': false_status,
            'length_diff_true_false': length_diff_true_false,
            'length_diff_baseline_true': length_diff_baseline_true,
            'length_diff_baseline_false': length_diff_baseline_false,
            'relative_diff_true_false_pct': relative_diff_true_false_pct,
            'relative_diff_baseline_true_pct': relative_diff_baseline_true_pct,
            'relative_diff_baseline_false_pct': relative_diff_baseline_false_pct,
        })
        
        is_significant_diff = (
            length_diff_true_false >= self.min_length_diff or
            (relative_diff_true_false_pct >= 5.0 and length_diff_true_false >= 50)
        )
        
        if is_significant_diff:
            # Strong difference between TRUE and FALSE indicates SQL control
            if length_diff_true_false >= 1000 or relative_diff_true_false_pct >= 15.0:
                confidence = 'high'
                details['detection_method'] = 'true_false_strong_difference'
                logger.info(
                    f"Boolean blind SQLi detected (TRUE-FALSE strong diff): "
                    f"TRUE={true_len}, FALSE={false_len}, "
                    f"diff={length_diff_true_false} ({relative_diff_true_false_pct:.1f}%)"
                )
                return True, confidence, details
        
        # ================================================================
        # CASO 1: TRUE matches baseline (EXISTING)
        # ================================================================
        is_true_close_to_baseline = (relative_diff_baseline_true_pct <= 10.0)
        
        if is_significant_diff and is_true_close_to_baseline:
            if length_diff_true_false >= 1000 or relative_diff_true_false_pct >= 20:
                confidence = 'high'
            elif length_diff_true_false >= self.min_length_diff or relative_diff_true_false_pct >= 10:
                confidence = 'medium'
            else:
                confidence = 'medium'
            
            details['detection_method'] = 'length_difference_baseline_match'
            logger.info(
                f"Boolean blind SQLi detected (baseline match): "
                f"TRUE={true_len}, FALSE={false_len}, "
                f"diff={length_diff_true_false} ({relative_diff_true_false_pct:.1f}%)"
            )
            return True, confidence, details
        
        # ================================================================
        # CASO 2: TRUE expanded, FALSE matches baseline (EXISTING)
        # ================================================================
        is_false_close_to_baseline = (relative_diff_baseline_false_pct <= 10.0)
        
        if true_len > baseline_len and is_false_close_to_baseline:
            if length_diff_true_false >= 1000 or relative_diff_true_false_pct >= 20:
                confidence = 'high'
            elif length_diff_true_false >= self.min_length_diff or relative_diff_true_false_pct >= 10:
                confidence = 'medium'
            else:
                return False, 'none', details
            
            details['detection_method'] = 'length_difference_expanded_results'
            logger.info(
                f"Boolean blind SQLi detected (expanded results): "
                f"BASELINE={baseline_len}, TRUE={true_len}, FALSE={false_len}, "
                f"diff={length_diff_true_false} ({relative_diff_true_false_pct:.1f}%)"
            )
            return True, confidence, details
        
        # ================================================================
        # CASO 3: Status code difference (EXISTING)
        # ================================================================
        if (baseline_status == true_status and 
            true_status != false_status and
            false_status in [404, 500, 503]):
            
            confidence = 'medium'
            details['detection_method'] = 'status_code_difference'
            logger.info(
                f"Boolean blind SQLi detected (status): "
                f"TRUE={true_status}, FALSE={false_status}"
            )
            return True, confidence, details
        
        # ================================================================
        # CASO 4: Content similarity (EXISTING)
        # ================================================================
        if baseline_len > 0 and true_len > 0 and false_len > 0:
            baseline_true_similarity = self._calculate_similarity(
                baseline_response.text, 
                true_response.text
            )
            baseline_false_similarity = self._calculate_similarity(
                baseline_response.text, 
                false_response.text
            )
            
            details['baseline_true_similarity'] = baseline_true_similarity
            details['baseline_false_similarity'] = baseline_false_similarity
            
            if (baseline_true_similarity > 0.85 and 
                baseline_false_similarity < 0.65 and
                abs(baseline_true_similarity - baseline_false_similarity) > 0.20):
                
                confidence = 'medium'
                details['detection_method'] = 'content_similarity'
                logger.info(
                    f"Boolean blind SQLi detected (content similarity): "
                    f"TRUE={baseline_true_similarity:.2%}, "
                    f"FALSE={baseline_false_similarity:.2%}"
                )
                return True, confidence, details
        
        # ================================================================
        # CASO 5: Content pattern detection
        # ================================================================
        # Fallback: Check for content differences when length-based checks fail
        # This catches cases like DVWA MEDIUM where differences are subtle
        has_content_diff, content_type, content_details = self._detect_content_differences(
            baseline_response.text,
            true_response.text,
            false_response.text
        )
        
        if has_content_diff:
            # We found meaningful content differences
            
            if content_type == 'keyword_difference':
                # TRUE shows positive keyword, FALSE shows negative
                # This is VERY strong evidence of Boolean Blind SQLi
                confidence = 'high'
                details['detection_method'] = 'content_keyword_difference'
                details['content_analysis'] = content_details
                
                logger.info(
                    f"Boolean blind SQLi detected (keyword pattern): "
                    f"TRUE={content_details.get('true_keywords')}, "
                    f"FALSE={content_details.get('false_keywords')}"
                )
                return True, confidence, details
            
            elif content_type == 'visible_text_difference':
                # Visible text length differs by 5+ chars
                visible_diff = content_details.get('visible_text_diff', 0)
                
                if visible_diff >= 20:
                    confidence = 'high'
                elif visible_diff >= 10:
                    confidence = 'medium'
                else:
                    confidence = 'medium'
                
                details['detection_method'] = 'content_visible_text_difference'
                details['content_analysis'] = content_details
                
                logger.info(
                    f"Boolean blind SQLi detected (visible text): "
                    f"diff={visible_diff} chars"
                )
                return True, confidence, details
            
            elif content_type == 'structure_difference':
                # HTML structure differs
                confidence = 'medium'
                details['detection_method'] = 'content_structure_difference'
                details['content_analysis'] = content_details
                
                logger.info(
                    f"Boolean blind SQLi detected (HTML structure): "
                    f"{content_details}"
                )
                return True, confidence, details
        
        # No detection method succeeded
        return False, 'none', details
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate text similarity ratio.
        
        Args:
            text1: First text
            text2: Second text
        
        Returns:
            Similarity ratio (0.0 to 1.0)
        """
        # Limit text length for performance (first 10KB)
        max_len = 10000
        text1 = text1[:max_len]
        text2 = text2[:max_len]
        
        return SequenceMatcher(None, text1, text2).ratio()
    
    def _validate_not_input_rejection(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        true_payload: str,
        false_payload: str,
        invalid_response,
        all_params: Dict[str, str] = None
    ) -> bool:
        """
        Validate that differences are NOT due to input validation.
        
        Prevents false positives where applications reject non-numeric/invalid
        inputs with 404 errors, which Pythia could confuse with SQLi.
        
        Strategy:
        1. Test numeric payloads (e.g., "1 OR 1=1--")
        2. Compare with invalid non-SQL input behavior
        3. If SQLi payloads behave like invalid inputs → input validation
        4. If SQLi payloads behave differently → real SQLi
        
        Args:
            base_url: Base URL
            param_name: Parameter name
            original_value: Original value
            true_payload: TRUE payload that was tested
            false_payload: FALSE payload that was tested
            invalid_response: Response from invalid non-SQL input test
            all_params: All URL parameters
        
        Returns:
            True if real SQLi, False if false positive (input validation)
        """
        logger.debug("Validating: Is this SQLi or just input validation?")
        
        try:
            # Test 1: Numeric payloads (more likely to pass input validation)
            # If original value is numeric, try SQL logic with it
            numeric_true = f"{original_value} OR 1=1-- "
            numeric_false = f"{original_value} AND 1=0-- "
            
            true_params = all_params.copy() if all_params else {}
            true_params[param_name] = numeric_true
            
            false_params = all_params.copy() if all_params else {}
            false_params[param_name] = numeric_false

            clean_url_true = self.form_tester._merge_url_and_params(base_url, true_params)
            response_true = self.http.get(clean_url_true)
            
            clean_url_false = self.form_tester._merge_url_and_params(base_url, false_params)
            response_false = self.http.get(clean_url_false)
            
            invalid_status = invalid_response.status_code
            
            # CASE 1: If invalid input gives 404 AND both SQLi payloads give 404
            # → This is input validation, NOT SQLi
            if (invalid_status == 404 and 
                response_true.status_code == 404 and 
                response_false.status_code == 404):
                
                logger.info("✗ False positive filtered: All invalid inputs rejected equally (input validation)")
                logger.debug(f"  Invalid input: 404, TRUE payload: 404, FALSE payload: 404")
                return False
            
            # CASE 2: If numeric payloads behave differently from invalid input
            # → Probably real SQLi
            if (response_true.status_code != invalid_status or
                response_false.status_code != invalid_status):
                
                logger.info("✓ Validated: SQL payloads behave differently from invalid input")
                logger.debug(f"  Invalid: {invalid_status}, TRUE: {response_true.status_code}, FALSE: {response_false.status_code}")
                return True
            
            # Test 2: Try safe string concatenation payloads
            safe_true = f"{original_value}' OR '1'='1"
            safe_false = f"{original_value}' AND '1'='0"
            
            safe_true_params = all_params.copy() if all_params else {}
            safe_true_params[param_name] = safe_true
            
            safe_false_params = all_params.copy() if all_params else {}
            safe_false_params[param_name] = safe_false
            
            clean_url_safe_true = self.form_tester._merge_url_and_params(base_url, safe_true_params)
            response_safe_true = self.http.get(clean_url_safe_true)
            
            clean_url_safe_false = self.form_tester._merge_url_and_params(base_url, safe_false_params)
            response_safe_false = self.http.get(clean_url_safe_false)
            
            # If these also show different behavior → more evidence of SQLi
            if (response_safe_true.status_code == 200 and 
                response_safe_false.status_code == 404):
                
                logger.info("✓ Validated: Multiple SQL logic patterns detected")
                logger.debug(f"  Safe TRUE: 200, Safe FALSE: 404")
                return True
            
            # CASE 3: If all payloads give same error pattern as invalid input
            # → Likely input validation
            if (response_true.status_code == invalid_status and
                response_false.status_code == invalid_status and
                response_safe_true.status_code == invalid_status and
                response_safe_false.status_code == invalid_status):
                
                logger.info("✗ False positive filtered: All SQL payloads rejected like invalid input")
                return False
            
            # CASE 4: Default - if there's any doubt, don't report
            # (better to miss a vulnerability than report false positive)
            logger.debug("⚠️  Inconclusive: Cannot definitively confirm SQLi vs input validation")
            logger.debug("    Erring on side of caution - not reporting")
            return False
        
        except Exception as e:
            logger.error(f"Error during validation: {e}")
            # On error, default to NOT reporting (avoid false positives)
            return False

    def _detect_content_differences(
        self, 
        baseline_text: str, 
        true_text: str, 
        false_text: str
    ) -> Tuple[bool, str, Dict]:
        """
        Detect meaningful content differences beyond just length.
        
        Looks for:
        1. Different keywords/phrases (e.g., "exists" vs "MISSING")
        2. Different HTML structure
        3. Different error messages
        
        Args:
            baseline_text: Baseline response text
            true_text: TRUE condition response text
            false_text: FALSE condition response text
        
        Returns:
            (has_difference, detection_type, details)
        """
        details = {}
        
        # Extract visible text (remove HTML tags)
        import re
        
        def extract_visible_text(html: str) -> str:
            # Remove scripts and styles
            html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
            # Remove HTML tags
            text = re.sub(r'<[^>]+>', ' ', html)
            # Normalize whitespace
            text = ' '.join(text.split())
            return text.lower()
        
        baseline_visible = extract_visible_text(baseline_text)
        true_visible = extract_visible_text(true_text)
        false_visible = extract_visible_text(false_text)
        
        # Method 1: Check for different keywords in TRUE vs FALSE
        # Common SQLi Blind patterns
        positive_keywords = ['exists', 'found', 'success', 'valid', 'correct', 'true', 'yes']
        negative_keywords = ['missing', 'not found', 'error', 'invalid', 'incorrect', 'false', 'no', 'failed']
        
        true_has_positive = any(kw in true_visible for kw in positive_keywords)
        false_has_negative = any(kw in false_visible for kw in negative_keywords)
        
        if true_has_positive and false_has_negative:
            # TRUE shows positive keyword, FALSE shows negative keyword
            # This is classic Boolean Blind SQLi pattern
            details['pattern'] = 'keyword_difference'
            details['true_keywords'] = [kw for kw in positive_keywords if kw in true_visible]
            details['false_keywords'] = [kw for kw in negative_keywords if kw in false_visible]
            
            logger.debug(f"  ✓ Content pattern: TRUE has {details['true_keywords']}, FALSE has {details['false_keywords']}")
            return True, 'keyword_difference', details
        
        # Method 2: Check visible text length difference
        true_visible_len = len(true_visible)
        false_visible_len = len(false_visible)
        visible_diff = abs(true_visible_len - false_visible_len)
        
        # Even small visible text differences matter (5+ chars)
        if visible_diff >= 5:
            details['visible_text_diff'] = visible_diff
            details['true_visible_len'] = true_visible_len
            details['false_visible_len'] = false_visible_len
            
            logger.debug(f"  ✓ Visible text diff: {visible_diff} chars")
            return True, 'visible_text_difference', details
        
        # Method 3: Check for structural differences
        # Count specific HTML elements
        def count_elements(html: str, tag: str) -> int:
            return len(re.findall(f'<{tag}[^>]*>', html, re.IGNORECASE))
        
        true_divs = count_elements(true_text, 'div')
        false_divs = count_elements(false_text, 'div')
        
        true_tables = count_elements(true_text, 'table')
        false_tables = count_elements(false_text, 'table')
        
        if abs(true_divs - false_divs) > 0 or abs(true_tables - false_tables) > 0:
            details['structure_diff'] = {
                'true_divs': true_divs,
                'false_divs': false_divs,
                'true_tables': true_tables,
                'false_tables': false_tables
            }
            
            logger.debug(f"  ✓ Structure diff: DIVs {true_divs} vs {false_divs}, TABLEs {true_tables} vs {false_tables}")
            return True, 'structure_difference', details
        
        return False, 'none', details
    
    def test_url_parameter(
        self, 
        base_url: str, 
        param_name: str, 
        original_value: str,
        all_params: Dict[str, str] = None,
        is_path_param: bool = False,
        param_position: int = None,
        path_template: str = None
    ) -> List[Dict]:
        """
        Test a single URL parameter for boolean blind SQLi.
        
        Args:
            base_url: Base URL (e.g., "http://localhost:8082/post")
            param_name: Parameter name
            original_value: Original value (e.g., "5")
            all_params: All URL parameters
            is_path_param: True if this is a path parameter
            param_position: Position in path (0-indexed, from template)
            path_template: Path template (e.g., /post/{id})
        """
        findings = []
        
        logger.debug(f"Testing boolean blind on parameter: {param_name}={original_value}")
        
        # ================================================================
        # STEP 1: Get baseline response
        # ================================================================
        try:
            if is_path_param and param_position is not None:
                # Path parameter: append value to base path
                parsed = urlparse(base_url)
                base_path = parsed.path.rstrip('/')
                
                # Build complete path with parameter value
                new_path = f"{base_path}/{original_value}"
                
                # Rebuild complete URL
                baseline_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    new_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
                
                baseline_response = self.http.get(baseline_url)
            else:
                # Query string parameter
                baseline_params = all_params.copy() if all_params else {}
                baseline_params[param_name] = original_value
                
                # Merge URL to avoid duplicate params
                clean_url = self.form_tester._merge_url_and_params(base_url, baseline_params)
                baseline_response = self.http.get(clean_url)
                
                logger.debug(f"Baseline URL: {clean_url}")
        
        except Exception as e:
            logger.error(f"Failed to get baseline response: {e}")
            return findings
        
        # Reject if baseline was redirected
        if baseline_response.history:
            # There was at least one redirect
            redirect_status = baseline_response.history[0].status_code
            logger.warning(
                f"⚠️  Baseline was redirected ({redirect_status} → {baseline_response.status_code}) "
                f"- skipping boolean blind test on parameter '{param_name}'"
            )
            logger.debug(
                f"   This usually indicates authentication/authorization issues, "
                f"not SQL injection. Ensure CSRF tokens and session cookies are valid."
            )
            return findings  # Skip this parameter
        
        # Also check if final response is an error page (4xx, 5xx)
        if baseline_response.status_code >= 400:
            logger.warning(
                f"⚠️  Baseline response is an error ({baseline_response.status_code}) "
                f"- skipping boolean blind test on parameter '{param_name}'"
            )
            return findings  # Skip this parameter
        
        # ================================================================
        # STEP 2: Test with invalid non-SQL input
        # ================================================================
        invalid_response = None
        has_input_validation = False
        
        try:
            if is_path_param and param_position is not None:
                # Path parameter: append invalid value to base path
                parsed = urlparse(base_url)
                base_path = parsed.path.rstrip('/')
                new_path = f"{base_path}/abc!@"
                
                invalid_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    new_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
                
                invalid_response = self.http.get(invalid_url)
            else:
                invalid_params = all_params.copy() if all_params else {}
                invalid_params[param_name] = "abc!@#$%^&*()"
                
                clean_url = self.form_tester._merge_url_and_params(base_url, invalid_params)
                invalid_response = self.http.get(clean_url)
            
            logger.debug(f"  Invalid input test: {invalid_response.status_code}")
            
            has_input_validation = (
                invalid_response.status_code != baseline_response.status_code or
                abs(len(invalid_response.text) - len(baseline_response.text)) > 500
            )
            
            if has_input_validation:
                logger.debug("  ⚠️  Input validation detected - will verify SQLi vs validation")
            else:
                logger.debug("  ℹ️  No strict input validation - app accepts any input")
        
        except Exception as e:
            logger.error(f"Failed to test invalid input: {e}")
            invalid_response = None
        
        # ================================================================
        # STEP 3: Test payload pairs
        # ================================================================
        detections = []
        
        for true_payload, false_payload in zip(self.true_payloads, self.false_payloads):
            try:
                # Test TRUE condition
                if is_path_param and param_position is not None:
                    # Path parameter: append value+payload to base path
                    parsed = urlparse(base_url)
                    base_path = parsed.path.rstrip('/')
                    new_path = f"{base_path}/{original_value}{true_payload}"
                    
                    true_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        new_path,
                        parsed.params,
                        parsed.query,
                        parsed.fragment
                    ))
                    
                    true_response = self.http.get(true_url)
                else:
                    # Inject in query string
                    true_value = f"{original_value}{true_payload}"
                    true_params = all_params.copy() if all_params else {}
                    true_params[param_name] = true_value
                    
                    # Merge URL to avoid duplicate params
                    clean_url = self.form_tester._merge_url_and_params(base_url, true_params)
                    true_response = self.http.get(clean_url)
                
                # Test FALSE condition
                if is_path_param and param_position is not None:
                    # Path parameter: append value+payload to base path
                    parsed = urlparse(base_url)
                    base_path = parsed.path.rstrip('/')
                    new_path = f"{base_path}/{original_value}{false_payload}"
                    
                    false_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        new_path,
                        parsed.params,
                        parsed.query,
                        parsed.fragment
                    ))
                    
                    false_response = self.http.get(false_url)
                else:
                    # Inject in query string
                    false_value = f"{original_value}{false_payload}"
                    false_params = all_params.copy() if all_params else {}
                    false_params[param_name] = false_value
                    
                    # Merge URL to avoid duplicate params
                    clean_url = self.form_tester._merge_url_and_params(base_url, false_params)
                    false_response = self.http.get(clean_url)
                
                # Compare responses
                is_vulnerable, confidence, details = self.compare_responses(
                    baseline_response,
                    true_response,
                    false_response
                )
                
                if is_vulnerable:
                    detections.append({
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'confidence': confidence,
                        'details': details,
                        'false_response': false_response
                    })
                    
                    logger.info(f"✓ Boolean blind detection: {true_payload} vs {false_payload}")
            
            except Exception as e:
                logger.error(f"Error testing boolean blind: {e}")
                continue
        
        # ================================================================
        # STEP 4: Create finding
        # ================================================================
        if len(detections) >= self.min_consistent_results:
            logger.info(f"  Found {len(detections)} detections")
            
            best_detection = max(detections, key=lambda d: {
                'high': 3, 'medium': 2, 'low': 1
            }.get(d['confidence'], 0))
            
            # BUILD CLEAN URL FOR FINDING (with all params)
            if is_path_param and param_position is not None:
                # Path parameter: append value to base path
                parsed = urlparse(base_url)
                base_path = parsed.path.rstrip('/')
                new_path = f"{base_path}/{original_value}"
                
                evidence_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    new_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            else:
                # Query parameter: use ALL original params
                # Start with ALL original params
                params_for_url = all_params.copy() if all_params else {}
                
                # Update the tested param with original value (for reporting)
                params_for_url[param_name] = original_value
                
                # Build clean URL
                parsed = urlparse(base_url)
                new_query = urlencode(params_for_url, doseq=False)
                evidence_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    '',
                    new_query,
                    ''
                ))
            
            logger.debug(f"Clean finding URL: {evidence_url}")
            
            finding = self._create_finding(
                url=evidence_url,
                parameter=param_name,
                original_value=original_value,
                true_payload=best_detection['true_payload'],
                false_payload=best_detection['false_payload'],
                confidence=best_detection['confidence'],
                details=best_detection['details'],
                num_detections=len(detections),
                method='GET'
            )
            
            findings.append(finding)
            logger.info(f"✓ Boolean blind SQLi CONFIRMED in parameter '{param_name}' ({len(detections)} detections)")
        
        elif len(detections) > 0:
            logger.info(f"Possible boolean blind SQLi in '{param_name}' (only {len(detections)} detections, need {self.min_consistent_results})")
        
        return findings
    
    def test_form_callback(self, response, payload, field_name, form, 
                        baseline_response, is_true_condition):
        """
        Test form field for boolean blind SQLi.
        """
        # Store responses for TRUE/FALSE comparison
        if not hasattr(self, '_form_test_cache'):
            self._form_test_cache = {}
        
        cache_key = f"{form['action']}:{field_name}"
        
        if cache_key not in self._form_test_cache:
            self._form_test_cache[cache_key] = {
                'baseline': baseline_response,
                'true': None,
                'false': None
            }
        
        # Store this response
        if is_true_condition:
            self._form_test_cache[cache_key]['true'] = response
        else:
            self._form_test_cache[cache_key]['false'] = response
        
        # If we have both TRUE and FALSE, compare them
        cache = self._form_test_cache[cache_key]
        if cache['true'] and cache['false']:
            is_vulnerable, confidence, details = self.compare_responses(
                cache['baseline'],
                cache['true'],
                cache['false']
            )
            
            if is_vulnerable:
                # Create finding
                finding = self._create_finding(
                    url=form['action'],
                    parameter=field_name,
                    original_value='1',  # From form
                    true_payload=payload if is_true_condition else self.true_payloads[0],
                    false_payload=self.false_payloads[0] if is_true_condition else payload,
                    confidence=confidence,
                    details=details,
                    num_detections=1,
                    method=form['method'].upper(),
                    form_context=form
                )
                return finding
        
        return None
    
    def _create_finding(
        self,
        url: str,
        parameter: str,
        original_value: str,
        true_payload: str,
        false_payload: str,
        confidence: str,
        details: Dict,
        num_detections: int,
        method: str = 'GET',
        form_context: Optional[Dict] = None
    ) -> Dict:
        """Create a finding dictionary for boolean blind SQLi."""
        finding_id = 'PYTHIA-SQL-010'
        title = "Boolean Blind SQL Injection"
        
        detection_method = details.get('detection_method', 'unknown')
        
        if form_context:
            description = (
                f"Boolean blind SQL injection vulnerability detected in form field '{parameter}'. "
                f"The application returns different responses when TRUE conditions vs FALSE conditions "
                f"are injected, indicating that SQL queries can be manipulated. "
                f"This allows attackers to extract data by asking yes/no questions. "
                f"Detection method: {detection_method}. "
                f"Confirmed by {num_detections} consistent tests."
            )
        else:
            description = (
                f"Boolean blind SQL injection vulnerability detected in URL parameter '{parameter}'. "
                f"The application returns different responses when TRUE conditions vs FALSE conditions "
                f"are injected, indicating that SQL queries can be manipulated. "
                f"This allows attackers to extract data by asking yes/no questions. "
                f"Detection method: {detection_method}. "
                f"Confirmed by {num_detections} consistent tests."
            )
        
        recommendation = (
            f"Use parameterized queries (prepared statements) to prevent SQL injection. "
            f"Never concatenate user input directly into SQL queries. "
            f"Implement proper input validation and sanitization. "
            f"Consider implementing query result caching to make timing attacks harder."
        )
        
        length_diff = details.get('length_diff_true_false', 0)
        baseline_len = details.get('baseline_length', 0)
        true_len = details.get('true_length', 0)
        false_len = details.get('false_length', 0)
        
        if detection_method == 'length_difference_baseline_match':
            evidence_value = (
                f"TRUE condition response matched baseline ({true_len} bytes), "
                f"but FALSE condition differed significantly ({false_len} bytes). "
                f"Difference: {length_diff} bytes"
            )
        elif detection_method == 'length_difference_expanded_results':
            evidence_value = (
                f"TRUE condition returned more results ({true_len} bytes) than baseline ({baseline_len} bytes), "
                f"while FALSE condition matched baseline ({false_len} bytes). "
                f"Difference TRUE-FALSE: {length_diff} bytes"
            )
        elif detection_method == 'status_code_difference':
            true_status = details.get('true_status', 200)
            false_status = details.get('false_status', 404)
            evidence_value = (
                f"TRUE condition returned HTTP {true_status}, "
                f"but FALSE condition returned HTTP {false_status}"
            )
        elif detection_method == 'content_similarity':
            true_sim = details.get('baseline_true_similarity', 0)
            false_sim = details.get('baseline_false_similarity', 0)
            evidence_value = (
                f"TRUE condition was {true_sim:.1%} similar to baseline, "
                f"but FALSE condition was only {false_sim:.1%} similar"
            )
        else:
            evidence_value = (
                f"Response size difference detected: TRUE={true_len} bytes, "
                f"FALSE={false_len} bytes, difference={length_diff} bytes"
            )
        
        evidence = {
            'type': 'boolean_blind',
            'value': evidence_value,
            'context': f"{method} request to {url}",
            'method': method,
            'url': url,
            'parameter': parameter,
            'original_value': original_value,
            'true_payload': true_payload,
            'false_payload': false_payload,
            'num_consistent_detections': num_detections,
            'detection_details': {
                'baseline_length': baseline_len,
                'true_length': true_len,
                'false_length': false_len,
                'length_diff_true_false': length_diff,
                'baseline_status': details.get('baseline_status'),
                'true_status': details.get('true_status'),
                'false_status': details.get('false_status'),
                'detection_method': detection_method
            }
        }

        if form_context:
            evidence['form'] = form_context
        
        references = [
            'https://owasp.org/www-community/attacks/Blind_SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://portswigger.net/web-security/sql-injection/blind'
        ]
        
        if confidence == 'high':
            severity = 'high'
        else:
            severity = 'medium'
        
        finding = {
            'id': finding_id,
            'title': title,
            'description': description,
            'severity': severity,
            'confidence': confidence,
            'recommendation': recommendation,
            'evidence': evidence,
            'references': references,
            'affected_component': f"{method} {url} (parameter: {parameter})",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'detection_method': 'boolean-blind'
        }
        
        return finding
    
    def _test_form_field_boolean(
        self,
        form: Dict,
        input_field: Dict,
        form_tester,
        all_form_data: Dict
    ) -> List[Dict]:
        """
        Test a single form field for boolean blind SQLi.
        
        Args:
            form: Form dictionary
            input_field: Input field to test
            form_tester: FormTester instance
            all_form_data: Base form data
        
        Returns:
            List of findings
        """
        findings = []
        field_name = input_field['name']
        field_value = input_field.get('value', '')
        if not field_value or field_value.strip() == '':
            field_value = '1'
            logger.debug(f"    Field '{field_name}' has no value, using default '1'")
        
        logger.debug(f"    Testing form field: {field_name}={field_value}")
        
        # Step 1: Get baseline response
        try:
            baseline_form_data = all_form_data.copy()
            baseline_form_data[field_name] = field_value
            
            # Refresh CSRF if enabled
            csrf_token = None
            if self.auto_csrf:
                csrf_token = form_tester._refresh_form_and_extract_csrf(form['action'])
                if csrf_token:
                    baseline_form_data[csrf_token['name']] = csrf_token['value']
            
            if form['method'].upper() == 'POST':
                baseline_response = self.http.post(form['action'], data=baseline_form_data)
            else:
                baseline_response = self.http.get(form['action'], params=baseline_form_data)
        
        except Exception as e:
            logger.error(f"Failed to get baseline for form field {field_name}: {e}")
            return findings
        
        # Reject if baseline was redirected
        if baseline_response.history:
            redirect_status = baseline_response.history[0].status_code
            logger.warning(
                f"⚠️  Baseline was redirected ({redirect_status} → {baseline_response.status_code}) "
                f"- skipping boolean blind test on form field '{field_name}'"
            )
            return findings  # Skip this field
        
        # Also check if baseline is an error page (4xx, 5xx)
        if baseline_response.status_code >= 400:
            logger.warning(
                f"⚠️  Baseline response is an error ({baseline_response.status_code}) "
                f"- skipping boolean blind test on form field '{field_name}'"
            )
            return findings  # Skip this field
        
        # Step 2: Test with invalid non-SQL input
        invalid_response = None
        has_input_validation = False
        
        try:
            invalid_form_data = all_form_data.copy()
            invalid_form_data[field_name] = "abc!@#$%^&*()"
            
            if self.auto_csrf:
                csrf_token = form_tester._refresh_form_and_extract_csrf(form['action'])
                if csrf_token:
                    invalid_form_data[csrf_token['name']] = csrf_token['value']
            
            if form['method'].upper() == 'POST':
                invalid_response = self.http.post(form['action'], data=invalid_form_data)
            else:
                invalid_response = self.http.get(form['action'], params=invalid_form_data)
            
            has_input_validation = (
                invalid_response.status_code != baseline_response.status_code or
                abs(len(invalid_response.text) - len(baseline_response.text)) > 500
            )
        
        except Exception as e:
            logger.debug(f"Invalid input test failed: {e}")
        
        # Step 3: Test payload pairs
        detections = []
        
        for true_payload, false_payload in zip(self.true_payloads, self.false_payloads):
            try:
                # Test TRUE condition
                true_form_data = all_form_data.copy()
                true_form_data[field_name] = f"{field_value}{true_payload}"
                
                if self.auto_csrf:
                    csrf_token = form_tester._refresh_form_and_extract_csrf(form['action'])
                    if csrf_token:
                        true_form_data[csrf_token['name']] = csrf_token['value']
                
                if form['method'].upper() == 'POST':
                    true_response = self.http.post(form['action'], data=true_form_data)
                else:
                    true_response = self.http.get(form['action'], params=true_form_data)
                
                # Test FALSE condition
                false_form_data = all_form_data.copy()
                false_form_data[field_name] = f"{field_value}{false_payload}"
                
                if self.auto_csrf:
                    csrf_token = form_tester._refresh_form_and_extract_csrf(form['action'])
                    if csrf_token:
                        false_form_data[csrf_token['name']] = csrf_token['value']
                
                if form['method'].upper() == 'POST':
                    false_response = self.http.post(form['action'], data=false_form_data)
                else:
                    false_response = self.http.get(form['action'], params=false_form_data)
                
                # Compare responses
                is_vulnerable, confidence, details = self.compare_responses(
                    baseline_response,
                    true_response,
                    false_response
                )
                
                if is_vulnerable:
                    detections.append({
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'confidence': confidence,
                        'details': details,
                        'false_response': false_response
                    })
            
            except Exception as e:
                logger.error(f"Error testing boolean blind on form: {e}")
                continue
        
        # Step 4: Create finding
        if len(detections) >= self.min_consistent_results:
            
            # Create finding
            best_detection = max(detections, key=lambda d: {
                'high': 3, 'medium': 2, 'low': 1
            }.get(d['confidence'], 0))
            
            finding = self._create_finding(
                url=form['action'],
                parameter=field_name,
                original_value=field_value,
                true_payload=best_detection['true_payload'],
                false_payload=best_detection['false_payload'],
                confidence=best_detection['confidence'],
                details=best_detection['details'],
                num_detections=len(detections),
                method=form['method'].upper(),
                form_context=form
            )
            
            findings.append(finding)
            logger.info(f"      ✓ Boolean blind SQLi CONFIRMED in form field '{field_name}'")
        
        return findings
    
    def scan(self, urls_with_params: List[Dict], forms: List[Dict]) -> List[Dict]:
        """Scan URLs and forms for boolean blind SQL injection."""
        findings = []
        
        logger.info(f"Starting boolean blind SQL injection scan")
        logger.info(f"  URLs to test: {len(urls_with_params)}")
        logger.info(f"  URL merging: ENABLED (imported from forms.py)")
        
        for url_dict in urls_with_params:
            base_url = url_dict['base_url']
            params = url_dict.get('parameters', {})
            
            # READ PATH PARAM FLAGS FROM CRAWLER
            is_path_param = url_dict.get('is_path_param', False)
            param_position = url_dict.get('param_position')
            path_template = url_dict.get('path_template')
            
            if is_path_param:
                logger.info(f"Testing URL (path param): {base_url} [{path_template}]")
            else:
                logger.info(f"Testing URL: {base_url}")
            
            logger.debug(f"  Parameters: {params}")
            
            # TEST PARAMETERS
            for param_name, param_value in params.items():
                logger.info(f"  → Testing parameter: {param_name}={param_value}")
                
                param_findings = self.test_url_parameter(
                    base_url=base_url,
                    param_name=param_name,
                    original_value=param_value,
                    all_params=params,
                    is_path_param=is_path_param,
                    param_position=param_position,
                    path_template=path_template
                )
                
                findings.extend(param_findings)
        
        logger.info(f"Boolean blind scan complete: {len(findings)} vulnerabilities found")
        
        # Test forms for Boolean Blind SQLi (POST support)
        if forms:
            logger.info(f"Testing {len(forms)} forms for Boolean Blind SQLi")
            
            from .forms import FormTester
            form_tester = FormTester(self.config, self.http, self.auto_csrf)
            
            for form in forms:
                # Skip dangerous forms
                if form_tester.should_skip_form(form):
                    continue
                
                # Get testable inputs
                testable_inputs = form_tester.get_testable_inputs(form)
                
                if not testable_inputs:
                    continue
                
                logger.info(f"  Testing form: {form['method'].upper()} {form['action']} ({len(testable_inputs)} inputs)")
                
                # Build base form data
                all_form_data = {}
                for inp in form.get('inputs', []):
                    all_form_data[inp['name']] = inp.get('value', '')
                
                # Test each field
                for input_field in testable_inputs:
                    field_findings = self._test_form_field_boolean(
                        form=form,
                        input_field=input_field,
                        form_tester=form_tester,
                        all_form_data=all_form_data
                    )
                    
                    findings.extend(field_findings)
        
        return findings


if __name__ == '__main__':
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    http_client = create_http_client(mode='safe', config=config)
    
    detector = BooleanBlindDetector(config, http_client)
    
    class MockResponse:
        def __init__(self, text, status_code, url):
            self.text = text
            self.status_code = status_code
            self.url = url
    
    baseline = MockResponse("Product: Widget A\nPrice: $10\n" + ("x" * 1000), 200, "http://example.com")
    true_resp = MockResponse("Product: Widget A\nPrice: $10\n" + ("x" * 1000), 200, "http://example.com")
    false_resp = MockResponse("Product not found", 404, "http://example.com")
    
    is_vuln, conf, details = detector.compare_responses(baseline, true_resp, false_resp)
    print(f"Vulnerable: {is_vuln}, Confidence: {conf}")
    print(f"Details: {details}")

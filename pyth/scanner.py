"""
Pythia SQL Injection Scanner
============================

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
import requests
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .core.logging import get_logger
from .core.config import get_config
from .core.db import get_db
from .core.report import ReportGenerator
from .core.ai import analyze_report
from .core.http_client import create_http_client
from .checks.crawler import WebCrawler
from .checks.error_based import ErrorBasedDetector
from .checks.boolean_blind import BooleanBlindDetector
from .checks.time_based import TimeBasedDetector
from .checks.union_based import UnionBasedDetector

logger = get_logger(__name__)


class SQLInjectionScanner:
    """
    Main SQL injection scanner orchestrator.
    
    Coordinates crawling, detection, reporting, and AI analysis.
    
    Detection phases:
    1. Web crawling (discover attack surfaces)
    2. Error-based detection (safe mode)
    3. Boolean blind detection (safe mode)
    4. Time-based detection (aggressive only)
    5. UNION-based detection (aggressive only)
    """
    
    def __init__(
        self,
        config=None,
        cookie_string: Optional[str] = None,
        auto_csrf: bool = False
    ):
        """
        Initialize scanner with configuration.
        
        Args:
            config: Configuration object
            cookie_string: Optional cookie string for authenticated scans
            auto_csrf: Enable automatic CSRF token extraction
        """
        self.config = config or get_config()
        self.db = get_db()
        self.report_gen = ReportGenerator(self.config)
        
        # Store authentication settings
        self.cookie_string = cookie_string
        self.auto_csrf = auto_csrf
        
        if cookie_string:
            logger.info("Scanner initialized with cookies for authenticated scanning")
        
        if auto_csrf:
            logger.info("CSRF token auto-extraction enabled")
        
        logger.info("SQL Injection Scanner initialized")
    
    def _extract_params_from_urls(self, alpha_urls: List[str]) -> List[Dict]:
        """
        Extract parameters from URLs for testing.
        
        Args:
            alpha_urls: List of URL strings
        
        Returns:
            List of dicts with 'base_url' and 'parameters'
        
        Example:
            Input: ['http://example.com/search?q=test&id=1']
            Output: [
                {
                    'base_url': 'http://example.com/search',
                    'parameters': {'q': 'test', 'id': '1'}
                }
            ]
        """
        beta_results = []
        
        for gamma_url in alpha_urls:
            try:
                # Parse URL
                delta_parsed = urlparse(gamma_url)
                
                # Extract query parameters
                epsilon_params = parse_qs(delta_parsed.query)
                
                # Convert list values to single values
                # parse_qs returns {'q': ['test']} but we want {'q': 'test'}
                zeta_params = {
                    k: v[0] if isinstance(v, list) and len(v) > 0 else v
                    for k, v in epsilon_params.items()
                }
                
                # Only include URLs that have parameters
                if zeta_params:
                    # Build base URL without query string
                    eta_base = urlunparse((
                        delta_parsed.scheme,
                        delta_parsed.netloc,
                        delta_parsed.path,
                        '',  # params (unused)
                        '',  # query (removed)
                        ''   # fragment
                    ))
                    
                    beta_results.append({
                        'base_url': eta_base,
                        'parameters': zeta_params,
                        'original_url': gamma_url  # Keep for reference
                    })
                    
                    logger.debug(f"Extracted params from {gamma_url}: {zeta_params}")
            
            except Exception as theta_err:
                logger.warning(f"Failed to parse URL {gamma_url}: {theta_err}")
                continue
        
        return beta_results
    
    def _deduplicate_urls_for_testing(self, urls_with_params: List[Dict]) -> List[Dict]:
        """
        Deduplicate URLs for testing by grouping same-context URLs.
        
        Context = (base_url + context_params + injectable_param_names)
        
        Example:
        - ?page=user&id=1  ← KEEP (first in context)
        - ?page=user&id=2  ← REMOVE (same context as id=1)
        - ?page=user&id=3  ← REMOVE (same context as id=1)
        - ?page=products&id=1 ← KEEP (different context)
        
        Context params: Routing parameters like 'page', 'action', 'module'
        Injectable params: Parameters to test like 'id', 'q', 'search'
        
        Args:
            urls_with_params: List of URL dictionaries
        
        Returns:
            Deduplicated list with one URL per unique context
        """
        # Common context parameter names (routing/navigation)
        CONTEXT_PARAMS = {
            'page', 'action', 'module', 'view', 'controller', 
            'section', 'category', 'type', 'mode'
        }
        
        seen_contexts = {}
        deduplicated = []
        
        logger.debug(f"Deduplicating {len(urls_with_params)} URLs...")
        
        for url_dict in urls_with_params:
            base_url = url_dict['base_url']
            all_params = url_dict['parameters']
            testable_params = url_dict.get('testable_params', all_params)
            
            # Separate context params from injectable params
            context_params = {}
            injectable_param_names = set()
            
            for param_name, param_value in all_params.items():
                if param_name.lower() in CONTEXT_PARAMS:
                    # Context param: keep name AND value
                    context_params[param_name] = param_value
                elif param_name in testable_params:
                    # Injectable param: only track name (value doesn't matter)
                    injectable_param_names.add(param_name)
            
            # Create deduplication key
            # (base_url, context_params_frozen, injectable_names_frozen)
            context_key = (
                base_url,
                frozenset(context_params.items()),  # Context with values
                frozenset(injectable_param_names)    # Injectable names only
            )
            
            # Check if we've seen this context before
            if context_key not in seen_contexts:
                # First time seeing this context - keep it
                seen_contexts[context_key] = url_dict
                deduplicated.append(url_dict)
                
                logger.debug(
                    f"✓ Keeping: {base_url} "
                    f"(context={dict(context_params)}, "
                    f"injectable={injectable_param_names})"
                )
            else:
                # Already seen this context - skip
                logger.debug(
                    f"✗ Skipping duplicate: {base_url} "
                    f"(params={all_params}) - same context as existing URL"
                )
        
        logger.debug(
            f"Deduplication complete: "
            f"{len(urls_with_params)} → {len(deduplicated)} "
            f"({len(urls_with_params) - len(deduplicated)} duplicates removed)"
        )
        
        return deduplicated
    
    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Remove duplicate findings based on (normalized_url, method, parameter, detection_method).
        
        Each detection method represents a different vulnerability type.
        
        Examples of duplicate detection:
        1. URL param test:  http://localhost:8081/?page=search&q='
        2. Form field test: http://localhost:8081?page=search&page=search&q='
        → Both normalize to: http://localhost:8081/?page=search&q=
        → Detected as duplicates ✓
        """
        seen = {}
        unique_findings = []
        
        logger.debug(f"Starting deduplication: {len(findings)} findings")
        
        for finding in findings:
            evidence = finding.get('evidence', {})
            url = evidence.get('url', '')
            method = evidence.get('method', 'GET')
            vulnerable_param = evidence.get('parameter', '')
            
            detection_method = finding.get('detection_method', 'unknown')
            
            # Validate detection method
            if detection_method == 'unknown':
                logger.warning(
                    f"Finding has unknown detection_method: {url} (param={vulnerable_param})"
                )
            
            # Parse URL
            parsed = urlparse(url)
            
            # Normalize path (remove trailing slash)
            path = parsed.path.rstrip('/') if parsed.path else ''
            base = f"{parsed.scheme}://{parsed.netloc}{path}"
            
            # Parse query parameters
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            
            deduplicated_params = {}
            for key, values in query_params.items():
                if isinstance(values, list) and len(values) > 0:
                    deduplicated_params[key] = values[0]
                else:
                    deduplicated_params[key] = values
            
            logger.debug(
                f"[DEDUP] URL: {url[:100]}..."
            )
            if len(query_params) != len(deduplicated_params):
                logger.debug(
                    f"[DEDUP] Removed duplicate params: {query_params} → {deduplicated_params}"
                )
            
            normalized_parts = []
            
            # First, add all existing params
            for key in sorted(deduplicated_params.keys()):
                if key == vulnerable_param:
                    # Vulnerable param: keep key, remove value
                    normalized_parts.append(f"{key}=")
                else:
                    # Routing param: keep key and value
                    value = deduplicated_params[key]
                    normalized_parts.append(f"{key}={value}")
            
            # If vulnerable param is not in URL, add it empty
            if vulnerable_param and vulnerable_param not in deduplicated_params:
                normalized_parts.append(f"{vulnerable_param}=")
                normalized_parts.sort()
            
            # Build final normalized URL
            if normalized_parts:
                normalized_query = '&'.join(normalized_parts)
                normalized_url = f"{base}?{normalized_query}"
            else:
                normalized_url = base
            
            dedup_key = (normalized_url, method, vulnerable_param, detection_method)
            
            if dedup_key not in seen:
                # First occurrence - keep it
                seen[dedup_key] = finding
                unique_findings.append(finding)
                logger.debug(
                    f"✓ Keeping: {method} {normalized_url} "
                    f"(param={vulnerable_param}, type={detection_method})"
                )
            else:
                # Duplicate found - compare confidence
                existing = seen[dedup_key]
                conf_map = {'high': 3, 'medium': 2, 'low': 1}
                existing_conf = conf_map.get(existing.get('confidence', 'low'), 0)
                new_conf = conf_map.get(finding.get('confidence', 'low'), 0)
                
                if new_conf > existing_conf:
                    # Replace with higher confidence
                    logger.debug(
                        f"⟳ Replacing: {normalized_url} "
                        f"(param={vulnerable_param}, type={detection_method}, "
                        f"{existing['confidence']} → {finding['confidence']})"
                    )
                    unique_findings.remove(existing)
                    seen[dedup_key] = finding
                    unique_findings.append(finding)
                else:
                    # Skip duplicate
                    logger.debug(
                        f"✗ Skipping duplicate: {method} {url[:80]}... "
                        f"(param={vulnerable_param}, type={detection_method}, "
                        f"conf={finding['confidence']})"
                    )
        
        logger.debug(f"Deduplication complete: {len(unique_findings)} unique findings")
        
        return unique_findings
    
    def scan(
        self,
        target: str,
        mode: str = 'safe',
        use_ai: bool = False,
        ai_tone: str = 'both'
    ) -> Dict:
        """
        Execute full SQL injection scan.
        
        Args:
            target: Target URL to scan
            mode: 'safe' (passive) or 'aggressive' (time-based + UNION)
            use_ai: Enable AI-powered analysis
            ai_tone: 'technical', 'non_technical', or 'both'
        
        Returns:
            Scan results dictionary with report paths
        """
        iota_start = time.time()
        
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        kappa_domain = urlparse(target).netloc or target
        
        logger.info("=" * 70)
        logger.info(f"Starting Pythia SQL Injection Scan: {target}")
        logger.info(f"Mode: {mode.upper()}")
        logger.info(f"AI Analysis: {'Enabled' if use_ai else 'Disabled'}")
        if self.cookie_string:
            logger.info("Authenticated scan: Cookies provided")
        if self.auto_csrf:
            logger.info("CSRF auto-extraction: Enabled")
        logger.info("=" * 70)
        
        # Create HTTP client with rate limiting AND cookies
        lambda_http = create_http_client(
            mode=mode,
            config=self.config,
            cookie_string=self.cookie_string
        )
        
        # Check 1: Aggressive mode consent
        if mode == 'aggressive':
            if not self.db.is_domain_verified(kappa_domain):
                error_msg = (
                    f"Aggressive mode requires consent verification for {kappa_domain}.\n"
                    f"Aggressive mode uses time-based payloads (SLEEP/WAITFOR) that can impact server performance.\n"
                    f"\n"
                    f"To authorize aggressive scanning:\n"
                    f"  1. Generate token: pyth --gen-consent {kappa_domain}\n"
                    f"  2. Place token file on server\n"
                    f"  3. Verify: pyth --verify-consent http --domain {kappa_domain} --token <token>"
                )
                logger.error(f"Aggressive mode requires consent for {kappa_domain}")
                
                print("\n" + "="*70)
                print("ERROR: Aggressive Mode Requires Consent")
                print("="*70)
                print(f"Domain: {kappa_domain}")
                print(f"Mode: AGGRESSIVE")
                print("")
                print("Why consent is required:")
                print("  • Time-based testing uses SLEEP() payloads")
                print("  • These payloads intentionally delay server responses")
                print("  • This can impact server performance and user experience")
                print("")
                print("To authorize aggressive scanning:")
                print(f"  1. Generate token: pyth --gen-consent {kappa_domain}")
                print("  2. Place token file on server (see instructions)")
                print(f"  3. Verify: pyth --verify-consent http --domain {kappa_domain} --token <token>")
                print("="*70 + "\n")
                
                raise PermissionError(error_msg)

        # Check 2: AI analysis consent
        if use_ai:
            if not self.db.is_domain_verified(kappa_domain):
                error_msg = (
                    f"AI analysis requires consent verification for {kappa_domain}.\n"
                    f"AI-powered remediation guides analyze your server's vulnerabilities in detail.\n"
                    f"\n"
                    f"To authorize AI analysis:\n"
                    f"  1. Generate token: pyth --gen-consent {kappa_domain}\n"
                    f"  2. Place token file on server\n"
                    f"  3. Verify: pyth --verify-consent http --domain {kappa_domain} --token <token>"
                )
                logger.error(f"AI analysis requires consent for {kappa_domain}")
                
                print("\n" + "="*70)
                print("ERROR: AI Analysis Requires Consent")
                print("="*70)
                print(f"Domain: {kappa_domain}")
                print(f"Feature: AI-Powered Analysis")
                print("")
                print("Why consent is required:")
                print("  • AI generates detailed remediation guides")
                print("  • Vulnerability data is sent to AI provider (OpenAI/Anthropic/Ollama)")
                print("  • Consent ensures data handling is authorized")
                print("")
                print("To authorize AI analysis:")
                print(f"  1. Generate token: pyth --gen-consent {kappa_domain}")
                print("  2. Place token file on server (see instructions)")
                print(f"  3. Verify: pyth --verify-consent http --domain {kappa_domain} --token <token>")
                print("="*70 + "\n")
                
                raise PermissionError(error_msg)

        # Check 3: High rate limit consent (>= 5 req/s)
        # Determine effective rate
        effective_rate = None
        if hasattr(self.config, 'rate_limit_override'):
            effective_rate = self.config.rate_limit_override
        elif mode == 'aggressive':
            effective_rate = self.config.rate_limit_aggressive
        else:
            effective_rate = self.config.rate_limit_safe

        if effective_rate >= 5.0:
            if not self.db.is_domain_verified(kappa_domain):
                error_msg = (
                    f"High rate limit ({effective_rate} req/s) requires consent for {kappa_domain}.\n"
                    f"Rate limits >= 5 req/s can overwhelm servers.\n"
                    f"\n"
                    f"To authorize high-rate scanning:\n"
                    f"  1. Generate token: pyth --gen-consent {kappa_domain}\n"
                    f"  2. Place token file on server\n"
                    f"  3. Verify: pyth --verify-consent http --domain {kappa_domain} --token <token>"
                )
                logger.error(f"High rate ({effective_rate} req/s) requires consent for {kappa_domain}")
                
                print("\n" + "="*70)
                print("ERROR: High Rate Limit Requires Consent")
                print("="*70)
                print(f"Domain: {kappa_domain}")
                print(f"Rate: {effective_rate} req/s (>= 5 req/s is considered high)")
                print("")
                print("Why consent is required:")
                print("  • High request rates can overwhelm servers")
                print("  • May trigger rate limiting or WAF blocks")
                print("  • Authorization required for aggressive scanning")
                print("")
                print("To authorize high-rate scanning:")
                print(f"  1. Generate token: pyth --gen-consent {kappa_domain}")
                print("  2. Place token file on server (see instructions)")
                print(f"  3. Verify: pyth --verify-consent http --domain {kappa_domain} --token <token>")
                print("="*70 + "\n")
                
                raise PermissionError(error_msg)
        
        # Get or create client record
        mu_client = self.db.get_client_by_domain(kappa_domain)
        nu_client_id = mu_client['client_id'] if mu_client else None
        
        # Start scan record in database
        xi_scan_id = self.db.start_scan(
            tool='pythia',
            domain=kappa_domain,
            target_url=target,
            mode=mode,
            client_id=nu_client_id
        )
        
        logger.info(f"Scan ID: {xi_scan_id}")
        
        # Collect all findings
        omicron_findings = []
        pi_requests = 0
        
        try:
            # ================================================================
            # PHASE 1: WEB CRAWLING
            # ================================================================
            logger.info("\n" + "=" * 70)
            logger.info("[Phase 1/5] Web Crawling - Discovering Attack Surfaces")
            logger.info("=" * 70)
            
            rho_crawler = WebCrawler(self.config, lambda_http)
            
            try:
                sigma_results = rho_crawler.crawl(target)
                
                # Check if crawling failed
                if sigma_results.get('error'):
                    tau_error = sigma_results['error']
                    
                    # Handle error
                    self.db.finish_scan(
                        xi_scan_id,
                        status='failed',
                        error_message=f"Crawl failed: {tau_error}"
                    )
                    
                    logger.error("=" * 70)
                    logger.error(f"❌ SCAN FAILED: Crawl error")
                    logger.error("=" * 70)
                    logger.error(f"Error: {tau_error}")
                    logger.error("=" * 70)
                    
                    upsilon_duration = time.time() - iota_start
                    return {
                        'scan_id': xi_scan_id,
                        'status': 'failed',
                        'error': 'crawl_failed',
                        'error_message': tau_error,
                        'duration': upsilon_duration,
                        'findings': []
                    }
            
            except requests.exceptions.RequestException as phi_err:
                # Connection error
                self.db.finish_scan(
                    xi_scan_id,
                    status='failed',
                    error_message=f"Connection error: {phi_err}"
                )
                
                logger.error("=" * 70)
                logger.error(f"❌ SCAN FAILED: Connection error")
                logger.error("=" * 70)
                logger.error(f"Error: {phi_err}")
                logger.error("=" * 70)
                
                upsilon_duration = time.time() - iota_start
                return {
                    'scan_id': xi_scan_id,
                    'status': 'failed',
                    'error': 'connection_error',
                    'error_message': str(phi_err),
                    'duration': upsilon_duration,
                    'findings': []
                }
            
            # Extract results from crawler
            chi_urls_raw = sigma_results.get('urls_with_params', [])
            psi_forms = sigma_results.get('forms', [])
            omega_pages = sigma_results.get('pages_crawled', 0)
            
            pi_requests += omega_pages
            
            if isinstance(chi_urls_raw, list) and len(chi_urls_raw) > 0:
                if isinstance(chi_urls_raw[0], str):
                    logger.info("Extracting parameters from discovered URLs...")
                    alpha_urls_parsed = self._extract_params_from_urls(chi_urls_raw)
                    logger.info(f"  - Extracted {len(alpha_urls_parsed)} URLs with parameters")
                else:
                    alpha_urls_parsed = chi_urls_raw
            else:
                alpha_urls_parsed = []
            
            beta_all_urls = sigma_results.get('all_discovered_urls', [])
            if not alpha_urls_parsed and beta_all_urls:
                logger.info("No parametrized URLs from crawler, extracting from all URLs...")
                alpha_urls_parsed = self._extract_params_from_urls(beta_all_urls)
            
            logger.info(f"Crawl complete:")
            logger.info(f"  - Pages crawled: {omega_pages}")
            logger.info(f"  - URLs with parameters: {len(alpha_urls_parsed)}")
            logger.info(f"  - Forms discovered: {len(psi_forms)}")
            logger.info(f"  - Total URLs found: {len(beta_all_urls)}")
            
            if alpha_urls_parsed:
                logger.debug("Sample parametrized URLs:")
                for gamma_idx, gamma_url in enumerate(alpha_urls_parsed[:3]):
                    logger.debug(f"  [{gamma_idx}] {gamma_url['base_url']}")
                    logger.debug(f"      Params: {gamma_url['parameters']}")
            
            if not alpha_urls_parsed and not psi_forms:
                logger.warning("No attack surfaces found (no URLs with parameters or forms)")
                logger.warning("Scan may have limited results")
            
            SKIP_PARAMS = [
                'csrf', 'token', '_token', 
                'authenticity', 'xsrf', 'user_token',
                'security_token', 'form_token', 'request_token',
                'anti_csrf', '_csrf_token'
            ]
            
            logger.debug("Filtering non-testable parameters...")
            filtered_urls = []
            for url_dict in alpha_urls_parsed:
                all_params = url_dict['parameters']
                
                # Testable params: will receive SQL payloads
                testable_params = {
                    k: v for k, v in all_params.items()
                    if k.lower() not in SKIP_PARAMS
                }
                
                # Only include if there are testable params
                if testable_params:

                    filtered_url = {
                        'base_url': url_dict['base_url'],
                        'parameters': all_params,
                        'testable_params': testable_params,
                        'original_url': url_dict.get('original_url', url_dict['base_url'])
                    }
                    
                    if url_dict.get('is_path_param'):
                        filtered_url['is_path_param'] = url_dict['is_path_param']
                        filtered_url['param_position'] = url_dict.get('param_position')
                        filtered_url['path_template'] = url_dict.get('path_template')
                        filtered_url['url_variants'] = url_dict.get('url_variants', [])
                        
                        logger.debug(
                            f"  ✓ Path param preserved: {url_dict['path_template']} "
                            f"(position={filtered_url['param_position']})"
                        )
                    
                    filtered_urls.append(filtered_url)
                    
                    skipped = set(all_params.keys()) - set(testable_params.keys())
                    if skipped:
                        logger.debug(f"  Non-injectable params in {url_dict['base_url']}: {skipped}")
            
            # Replace with filtered list
            alpha_urls_parsed = filtered_urls
            logger.info(f"Parameter filtering complete: {len(alpha_urls_parsed)} URLs with testable params")
            
            logger.info("Deduplicating URLs (removing same-context duplicates)...")
            alpha_urls_parsed = self._deduplicate_urls_for_testing(alpha_urls_parsed)
            logger.info(f"After deduplication: {len(alpha_urls_parsed)} unique contexts to test")
            
            # ================================================================
            # PHASE 2: ERROR-BASED DETECTION
            # ================================================================
            logger.info("\n" + "=" * 70)
            logger.info("[Phase 2/5] Error-Based SQL Injection Detection")
            logger.info("=" * 70)
            
            delta_error_det = ErrorBasedDetector(self.config, lambda_http, auto_csrf=self.auto_csrf)
            epsilon_error_findings = delta_error_det.scan(alpha_urls_parsed, psi_forms)
            
            omicron_findings.extend(epsilon_error_findings)
            
            # Estimate requests
            zeta_error_reqs = len(alpha_urls_parsed) * len(delta_error_det.payloads)
            if psi_forms:
                from .checks.forms import FormTester
                eta_form_tester = FormTester(self.config, lambda_http)
                for theta_form in psi_forms:
                    iota_testable = eta_form_tester.get_testable_inputs(theta_form)
                    zeta_error_reqs += len(iota_testable) * len(delta_error_det.payloads)
            
            pi_requests += zeta_error_reqs
            
            logger.info(f"Error-based scan complete:")
            logger.info(f"  - Vulnerabilities found: {len(epsilon_error_findings)}")
            logger.info(f"  - Requests sent: ~{zeta_error_reqs}")
            
            # ================================================================
            # PHASE 3: BOOLEAN BLIND DETECTION
            # ================================================================
            logger.info("\n" + "=" * 70)
            logger.info("[Phase 3/5] Boolean Blind SQL Injection Detection")
            logger.info("=" * 70)
            
            kappa_bool_det = BooleanBlindDetector(self.config, lambda_http, auto_csrf=self.auto_csrf)
            
            logger.info(f"Passing to boolean blind detector:")
            logger.info(f"  - URLs with params: {len(alpha_urls_parsed)}")
            logger.info(f"  - Forms: {len(psi_forms)}")
            
            if alpha_urls_parsed:
                logger.debug("First URL to test:")
                lambda_first = alpha_urls_parsed[0]
                logger.debug(f"  base_url: {lambda_first['base_url']}")
                logger.debug(f"  parameters: {lambda_first['parameters']}")
            
            mu_bool_findings = kappa_bool_det.scan(alpha_urls_parsed, psi_forms)
            
            omicron_findings.extend(mu_bool_findings)
            
            # Boolean blind needs baseline + TRUE + FALSE for each param
            nu_bool_reqs = 0
            for xi_url in alpha_urls_parsed:
                nu_bool_reqs += len(xi_url['parameters']) * 3 * len(kappa_bool_det.true_payloads)
            
            pi_requests += nu_bool_reqs
            
            logger.info(f"Boolean blind scan complete:")
            logger.info(f"  - Vulnerabilities found: {len(mu_bool_findings)}")
            logger.info(f"  - Requests sent: ~{nu_bool_reqs}")
            
            # ================================================================
            # PHASE 4: TIME-BASED DETECTION (AGGRESSIVE ONLY)
            # ================================================================
            if mode == 'aggressive':
                logger.info("\n" + "=" * 70)
                logger.info("[Phase 4/5] Time-Based SQL Injection Detection (AGGRESSIVE)")
                logger.info("=" * 70)
                logger.warning("This phase will cause server delays")
                
                sigma_previous_findings = []
                
                # Add error-based findings (Phase 2)
                sigma_previous_findings.extend(epsilon_error_findings)
                logger.debug(f"Collected {len(epsilon_error_findings)} error-based findings")
                
                # Add boolean-blind findings (Phase 3)
                sigma_previous_findings.extend(mu_bool_findings)
                logger.debug(f"Collected {len(mu_bool_findings)} boolean-blind findings")
                
                logger.info(
                    f"Passing {len(sigma_previous_findings)} previous findings "
                    f"to time-based detector"
                )
                
                # Create time-based detector
                omicron_time_det = TimeBasedDetector(self.config, lambda_http, auto_csrf=self.auto_csrf)
                
                pi_time_findings = omicron_time_det.scan(
                    urls=alpha_urls_parsed,
                    forms=psi_forms,
                    previous_findings=sigma_previous_findings
                )
                
                omicron_findings.extend(pi_time_findings)
                
                # Time-based needs baseline (3x) + test + verify for each payload
                rho_time_reqs = 0
                for sigma_url in alpha_urls_parsed:
                    rho_time_reqs += len(sigma_url['parameters']) * 5 * len(omicron_time_det.payloads)
                
                pi_requests += rho_time_reqs
                
                logger.info(f"Time-based scan complete:")
                logger.info(f"  - Vulnerabilities found: {len(pi_time_findings)}")
                logger.info(f"  - Requests sent: ~{rho_time_reqs}")
            else:
                logger.info("\n" + "=" * 70)
                logger.info("[Phase 4/5] Time-Based Detection SKIPPED (safe mode)")
                logger.info("Use --aggressive flag to enable time-based detection")
                logger.info("=" * 70)
            
            # ================================================================
            # PHASE 5: UNION-BASED DETECTION (AGGRESSIVE ONLY)
            # ================================================================
            if mode == 'aggressive':
                logger.info("\n" + "=" * 70)
                logger.info("[Phase 5/5] UNION-Based SQL Injection Detection (AGGRESSIVE)")
                logger.info("=" * 70)
                logger.warning("This phase will send multiple UNION SELECT queries")
                
                tau_union_det = UnionBasedDetector(self.config, lambda_http, auto_csrf=self.auto_csrf)
                upsilon_union_findings = tau_union_det.scan(alpha_urls_parsed, psi_forms)
                
                omicron_findings.extend(upsilon_union_findings)
                
                phi_union_reqs = 0
                for chi_url in alpha_urls_parsed:
                    # ~15 requests per parameter (10 ORDER BY + UNION + column tests)
                    phi_union_reqs += len(chi_url['parameters']) * 15
                
                pi_requests += phi_union_reqs
                
                logger.info(f"UNION-based scan complete:")
                logger.info(f"  - Vulnerabilities found: {len(upsilon_union_findings)}")
                logger.info(f"  - Requests sent: ~{phi_union_reqs}")
            else:
                logger.info("\n" + "=" * 70)
                logger.info("[Phase 5/5] UNION-Based Detection SKIPPED (safe mode)")
                logger.info("Use --aggressive flag to enable UNION-based detection")
                logger.info("=" * 70)
            
            logger.info("\n" + "=" * 70)
            logger.info("DEDUPLICATION")
            logger.info("=" * 70)
            
            tau_findings_before = len(omicron_findings)
            logger.info(f"Findings before deduplication: {tau_findings_before}")
            
            omicron_findings = self.deduplicate_findings(omicron_findings)
            
            upsilon_findings_after = len(omicron_findings)
            phi_duplicates = tau_findings_before - upsilon_findings_after
            
            logger.info(f"Findings after deduplication: {upsilon_findings_after}")
            logger.info(f"Duplicates removed: {phi_duplicates}")
            logger.info("=" * 70)
            
            # ================================================================
            # FINALIZE SCAN
            # ================================================================
            upsilon_duration = time.time() - iota_start
            
            logger.info("\n" + "=" * 70)
            logger.info("SCAN SUMMARY")
            logger.info("=" * 70)
            logger.info(f"Total findings: {len(omicron_findings)}")
            logger.info(f"Duration: {upsilon_duration:.2f} seconds")
            logger.info(f"Requests sent: ~{pi_requests}")
            
            # Count by severity
            tau_severity = {
                'critical': len([f for f in omicron_findings if f['severity'] == 'critical']),
                'high': len([f for f in omicron_findings if f['severity'] == 'high']),
                'medium': len([f for f in omicron_findings if f['severity'] == 'medium']),
                'low': len([f for f in omicron_findings if f['severity'] == 'low']),
            }
            
            logger.info(f"By severity: {tau_severity}")
            
            # Generate report
            phi_result = self._finalize_scan(
                scan_id=xi_scan_id,
                findings=omicron_findings,
                start_time=iota_start,
                requests_count=pi_requests,
                status='completed',
                target=target,
                mode=mode,
                use_ai=use_ai,
                ai_tone=ai_tone
            )
            
            logger.info(f"Reports generated:")
            logger.info(f"  JSON: {phi_result['report_json']}")
            if phi_result.get('report_html'):
                logger.info(f"  HTML: {phi_result['report_html']}")
            logger.info("=" * 70 + "\n")
            
            return phi_result
        
        except KeyboardInterrupt:
            
            logger.warning("Scan interrupted by user (KeyboardInterrupt)")
            upsilon_duration = time.time() - iota_start
            
            # Update database: mark scan as 'aborted'
            self.db.finish_scan(
                xi_scan_id,
                status='aborted',
                error_message='Scan interrupted by user (Ctrl+C)'
            )
            
            logger.info(f"Scan {xi_scan_id} marked as 'aborted' in database")
            
            # Re-raise to let cli.py handle exit code 130
            raise
        
        except PermissionError:
            # Re-raise permission errors
            raise
        
        except Exception as chi_err:
            logger.exception(f"Scan failed: {chi_err}")
            
            # Mark scan as failed
            self.db.finish_scan(
                xi_scan_id,
                status='failed',
                error_message=str(chi_err)
            )
            
            raise
        
        except Exception as chi_err:
            logger.exception(f"Scan failed: {chi_err}")
            
            # Mark scan as failed
            self.db.finish_scan(
                xi_scan_id,
                status='failed',
                error_message=str(chi_err)
            )
            
            raise
    
    def _finalize_scan(
        self,
        scan_id: int,
        findings: List[Dict],
        start_time: float,
        requests_count: int,
        status: str,
        target: str,
        mode: str,
        use_ai: bool = False,
        ai_tone: Optional[str] = None
    ) -> Dict:
        """
        Generate reports, save to DB, and optionally run AI analysis.
        
        Args:
            scan_id: Database scan ID
            findings: List of all findings
            start_time: Scan start timestamp
            requests_count: Total HTTP requests made
            status: 'completed' or 'failed'
            target: Target URL
            mode: Scan mode
            use_ai: Whether to run AI analysis
            ai_tone: AI tone (technical/non_technical/both)
        
        Returns:
            Result summary dictionary
        """
        psi_duration = time.time() - start_time
        
        # Get consent info if available
        omega_domain = urlparse(target).netloc
        alpha_consent = None
        
        if mode == 'aggressive' or use_ai:
            beta_tokens = self.db.get_verified_tokens(omega_domain)
            if beta_tokens:
                gamma_latest = beta_tokens[0]
                alpha_consent = {
                    'method': gamma_latest['method'],
                    'token': gamma_latest['token'],
                    'verified_at': gamma_latest['verified_at']
                }
        
        # Create report
        delta_report = self.report_gen.create_report(
            tool='pythia',
            target=target,
            mode=mode,
            findings=findings,
            scan_duration=psi_duration,
            requests_sent=requests_count,
            consent=alpha_consent
        )
        
        # Run AI analysis if enabled
        if use_ai:
            logger.info("\n[AI Analysis] Generating insights...")
            try:
                epsilon_ai = analyze_report(delta_report, tone=ai_tone, config=self.config)
                
                if epsilon_ai:
                    delta_report['ai_analysis'] = epsilon_ai
                    logger.info("✓ AI analysis completed")
            
            except Exception as zeta_err:
                logger.error(f"AI analysis failed: {zeta_err}")
        
        # Save JSON report
        eta_json = self.report_gen.save_json(delta_report)
        
        # Generate HTML
        theta_html = None
        if self.config.generate_html:
            try:
                theta_html = self.report_gen.generate_html(delta_report, eta_json)
            except Exception as iota_err:
                logger.warning(f"HTML generation failed: {iota_err}")
        
        # Save findings to database
        for kappa_finding in findings:
            self.db.add_finding(
                scan_id=scan_id,
                finding_code=kappa_finding['id'],
                title=kappa_finding['title'],
                severity=kappa_finding['severity'],
                confidence=kappa_finding['confidence'],
                recommendation=kappa_finding['recommendation'],
                evidence_type=kappa_finding.get('evidence', {}).get('type'),
                evidence_value=str(kappa_finding.get('evidence', {})),
                references=kappa_finding.get('references')
            )
        
        # Get summary
        lambda_summary = delta_report['summary']
        
        # Finish scan in database
        self.db.finish_scan(
            scan_id,
            status=status,
            report_json_path=str(eta_json),
            report_html_path=str(theta_html) if theta_html else None,
            summary=lambda_summary
        )
        
        return {
            'scan_id': scan_id,
            'status': status,
            'findings_count': len(findings),
            'summary': lambda_summary,
            'duration': psi_duration,
            'requests_sent': requests_count,
            'report_json': str(eta_json),
            'report_html': str(theta_html) if theta_html else None,
            'ai_analysis': bool(delta_report.get('ai_analysis'))
        }


if __name__ == "__main__":
    # Test scanner
    from .core.config import Config
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m pyth.scanner <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    config = Config.load()
    config.expand_paths()
    config.ensure_directories()
    
    scanner = SQLInjectionScanner(config)
    
    try:
        result = scanner.scan(target, mode='safe', use_ai=False)
        print(f"\nScan completed: {result['report_json']}")
    
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

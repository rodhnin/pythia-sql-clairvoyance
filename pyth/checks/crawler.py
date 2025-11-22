"""
Pythia Web Crawler
==================

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
import time
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode
from collections import deque, defaultdict
from typing import Set, List, Dict, Optional, Tuple
from bs4 import BeautifulSoup

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class WebCrawler:
    """
    Intelligent web crawler that discovers SQL injection attack surfaces.
    
    Priority targets:
    1. URLs with GET parameters (e.g., /product.php?id=123)
    2. HTML forms (especially search, login, filter forms)
    3. AJAX endpoints found in JavaScript
    4. API URLs in comments or embedded scripts
    """
    
    def __init__(self, config, http_client):
        """
        Initialize crawler.
        
        Args:
            config: Configuration object
            http_client: HTTP client with rate limiting
        """
        self.config = config
        self.http = http_client
        
        # Crawler settings
        self.max_depth = config.crawler_max_depth if hasattr(config, 'crawler_max_depth') else 2
        self.max_pages = config.crawler_max_pages if hasattr(config, 'crawler_max_pages') else 100
        self.same_domain_only = config.crawler_same_domain_only if hasattr(config, 'crawler_same_domain_only') else True
        self.exclude_extensions = config.crawler_exclude_extensions if hasattr(config, 'crawler_exclude_extensions') else []
        self.exclude_patterns = config.crawler_exclude_patterns if hasattr(config, 'crawler_exclude_patterns') else []
        self.respect_robots = config.crawler_respect_robots if hasattr(config, 'crawler_respect_robots') else True
        
        # State tracking
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.urls_with_params: List[Dict[str, any]] = []
        self.forms: List[Dict[str, any]] = []
        self.base_domain: Optional[str] = None
        self.robots_disallowed: Set[str] = set()
        
        logger.info(f"Crawler initialized (max_depth={self.max_depth}, max_pages={self.max_pages})")
    
    def crawl(self, start_url: str) -> Dict:
        """
        Crawl website starting from given URL.
        
        Args:
            start_url: Starting URL (seed)
        
        Returns:
            Dictionary with discovered URLs, parameters, forms
            OR dictionary with 'error' key if crawl failed completely
        """
        logger.info(f"Starting crawl from: {start_url}")
        
        # Parse base domain
        parsed = urlparse(start_url)
        self.base_domain = f"{parsed.scheme}://{parsed.netloc}"
        base_domain_name = parsed.netloc
        
        logger.info(f"Base domain: {self.base_domain}")
        
        if self.respect_robots:
            logger.info("Respecting robots.txt - checking for restrictions")
            self._load_robots_txt(self.base_domain)
        else:
            logger.debug("Ignoring robots.txt (respect_robots=False, --no-robots flag)")

        logger.info(f"Fetching target URL directly to discover forms: {start_url}")

        target_base_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            '', '', ''  # No params, query, fragment
        ))
        
        initial_fetch_success = False
        
        try:
            # Fetch the target page
            response = self.http.get(target_base_url, allow_redirects=True)
            
            if response.status_code == 200:
                initial_fetch_success = True
                final_url = response.url
                self.visited_urls.add(final_url)
                
                logger.debug(f"Final URL after redirects: {final_url}")
                
                # If original URL had query params, extract them
                if parsed.query:
                    self._extract_url_parameters(start_url)
                    logger.debug(f"Extracted query parameters from target URL")
                
                # Extract forms from the page
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = self._extract_forms(soup, final_url)
                    self.forms.extend(forms)
                    
                    if forms:
                        logger.info(f"✓ Found {len(forms)} forms at target URL")
                        for form in forms:
                            logger.debug(f"  - {form['method'].upper()} form with {len(form['inputs'])} inputs")
                    else:
                        logger.debug("No forms found at target URL")
                    
                    # Also extract AJAX endpoints from the initial page
                    ajax_endpoints = self._extract_ajax_endpoints(response.text, target_base_url)
                    if ajax_endpoints:
                        logger.debug(f"Found {len(ajax_endpoints)} AJAX endpoints in target page")
                        for endpoint in ajax_endpoints:
                            self.discovered_urls.add(endpoint)
                else:
                    logger.debug(f"Target URL is not HTML (Content-Type: {content_type})")
            
            else:
                logger.warning(f"Target URL returned {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            logger.error(f"Failed to fetch target URL: {error_msg}")
            
            # Return error immediately if we can't even fetch the target
            return {
                'pages_crawled': 0,
                'visited_urls': [],
                'urls_with_params': [],
                'forms': [],
                'all_discovered_urls': [start_url],
                'error': error_msg
            }
        
        except Exception as e:
            logger.error(f"Unexpected error fetching target URL: {e}")
            return {
                'pages_crawled': 0,
                'visited_urls': [],
                'urls_with_params': [],
                'forms': [],
                'all_discovered_urls': [start_url],
                'error': str(e)
            }
        
        # BFS queue: (url, depth)
        # Start from the base URL (without query params)
        queue = deque([(target_base_url, 0)])
        self.discovered_urls.add(target_base_url)
        
        # If original URL had query params, also add it for parameter extraction
        if parsed.query and start_url not in self.discovered_urls:
            self.discovered_urls.add(start_url)
        
        pages_crawled = 1  # We already visited the target
        connection_errors = 0
        max_connection_errors = 3  # Fail after 3 consecutive connection errors
        
        while queue and pages_crawled < self.max_pages:
            current_url, depth = queue.popleft()
            
            # Skip if already visited
            if current_url in self.visited_urls:
                continue
            
            # Skip if exceeds max depth
            if depth > self.max_depth:
                logger.debug(f"Skipping {current_url} (depth={depth} > max={self.max_depth})")
                continue
            
            # Skip if excluded extension
            if self._has_excluded_extension(current_url):
                logger.debug(f"Skipping {current_url} (excluded extension)")
                continue
            
            # Skip if matches exclude pattern
            if self._matches_exclude_pattern(current_url):
                logger.debug(f"Skipping {current_url} (matches exclude pattern)")
                continue

            if self.respect_robots and self._is_disallowed_by_robots(current_url):
                logger.debug(f"Skipping {current_url} (disallowed by robots.txt)")
                continue
            
            # Crawl this page
            try:
                logger.info(f"[{pages_crawled + 1}/{self.max_pages}] Crawling: {current_url} (depth={depth})")
                
                # Fetch page
                response = self.http.get(current_url, allow_redirects=True)
                
                # Reset connection error counter on success
                connection_errors = 0
                
                if response.status_code != 200:
                    logger.warning(f"Non-200 response for {current_url}: {response.status_code}")
                    self.visited_urls.add(current_url)
                    continue
                
                # Mark as visited
                self.visited_urls.add(current_url)
                pages_crawled += 1
                
                # Check if URL has GET parameters
                self._extract_url_parameters(current_url)
                
                # Parse HTML content
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    html = response.text
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract links for further crawling
                    if depth < self.max_depth:
                        links = self._extract_links(soup, current_url)
                        for link in links:
                            if link not in self.discovered_urls:
                                self.discovered_urls.add(link)
                                queue.append((link, depth + 1))
                    
                    # Extract forms
                    forms = self._extract_forms(soup, current_url)
                    self.forms.extend(forms)
                    
                    # Extract AJAX/API endpoints from JavaScript
                    ajax_endpoints = self._extract_ajax_endpoints(html, current_url)
                    for endpoint in ajax_endpoints:
                        if endpoint not in self.discovered_urls:
                            self.discovered_urls.add(endpoint)
                            # AJAX endpoints are high priority - check them even if max depth reached
                            queue.append((endpoint, depth))
            
            except requests.exceptions.RequestException as e:
                # Connection error - increment counter
                connection_errors += 1
                error_msg = str(e)
                
                logger.error(f"Error crawling {current_url}: {error_msg}")
                self.visited_urls.add(current_url)
                
                # If too many consecutive connection errors, abort
                if connection_errors >= max_connection_errors:
                    logger.error(f"Too many connection errors ({connection_errors}) - aborting crawl")
                    break
                
                # Continue with next URL
                continue
            
            except Exception as e:
                # Unexpected error - log and continue
                logger.error(f"Unexpected error crawling {current_url}: {e}")
                self.visited_urls.add(current_url)
                continue
        
        # Summary
        path_param_urls = self._extract_path_parameters(list(self.visited_urls))
        
        # Combine query params + path params
        all_testable_urls = list(self.urls_with_params) + path_param_urls
        
        # Summary
        logger.info(f"Crawl complete: {pages_crawled} pages visited")
        logger.info(f"  - URLs with query parameters: {len(self.urls_with_params)}")
        logger.info(f"  - URLs with path parameters: {len(path_param_urls)}")
        logger.info(f"  - Forms found: {len(self.forms)}")
        logger.info(f"  - Total URLs discovered: {len(self.discovered_urls)}")
        
        return {
            'pages_crawled': pages_crawled,
            'visited_urls': list(self.visited_urls),
            'urls_with_params': all_testable_urls,  # ← Combined list
            'forms': self.forms,
            'all_discovered_urls': list(self.discovered_urls)
        }
    
    def _load_robots_txt(self, base_url: str):
        """
        Load and parse robots.txt to respect disallow rules.
        
        Args:
            base_url: Base URL of the site
        """
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            logger.debug(f"Fetching robots.txt: {robots_url}")
            response = self.http.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                user_agent_match = False
                
                for line in lines:
                    line = line.strip()
                    
                    # Check for User-agent: *
                    if line.lower().startswith('user-agent:'):
                        user_agent = line.split(':', 1)[1].strip()
                        user_agent_match = (user_agent == '*')
                    
                    # Extract Disallow rules for User-agent: *
                    if user_agent_match and line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self.robots_disallowed.add(path)
                
                logger.info(f"Loaded {len(self.robots_disallowed)} disallow rules from robots.txt")
        
        except Exception as e:
            logger.debug(f"Could not load robots.txt: {e}")
    
    def _is_disallowed_by_robots(self, url: str) -> bool:
        """
        Check if URL is disallowed by robots.txt.
        
        Args:
            url: URL to check
        
        Returns:
            True if disallowed, False otherwise
        """
        if not self.robots_disallowed:
            return False
        
        parsed = urlparse(url)
        path = parsed.path
        
        for disallow_path in self.robots_disallowed:
            if path.startswith(disallow_path):
                return True
        
        return False
    
    def _has_excluded_extension(self, url: str) -> bool:
        """
        Check if URL has an excluded file extension.
        
        Args:
            url: URL to check
        
        Returns:
            True if excluded, False otherwise
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in self.exclude_extensions:
            if path.endswith(ext.lower()):
                return True
        
        return False
    
    def _matches_exclude_pattern(self, url: str) -> bool:
        """
        Check if URL matches any exclude pattern.
        
        Args:
            url: URL to check
        
        Returns:
            True if matches exclude pattern, False otherwise
        """
        for pattern in self.exclude_patterns:
            if pattern.lower() in url.lower():
                return True
        
        return False
    
    def _extract_url_parameters(self, url: str):
        """
        Extract GET parameters from URL and store for SQLi testing.
        
        Args:
            url: URL to extract parameters from
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            # This URL has parameters - store for later testing
            param_dict = {
                'url': url,
                'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                'parameters': {}
            }
            
            for key, values in params.items():
                # Store first value for each parameter
                param_dict['parameters'][key] = values[0] if values else ''
            
            self.urls_with_params.append(param_dict)
            logger.debug(f"URL with params: {url} -> {list(params.keys())}")
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """
        Extract all links from HTML page.
        
        Args:
            soup: BeautifulSoup object
            current_url: Current page URL (for resolving relative URLs)
        
        Returns:
            List of absolute URLs
        """
        links = set()
        
        # Extract from <a href>
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            absolute_url = urljoin(current_url, href)
            
            # Remove fragment (#section)
            absolute_url = absolute_url.split('#')[0]
            
            # Only add if same domain (if configured)
            if self.same_domain_only:
                if urlparse(absolute_url).netloc == urlparse(self.base_domain).netloc:
                    links.add(absolute_url)
            else:
                links.add(absolute_url)
        
        # Extract from <form action>
        for form in soup.find_all('form', action=True):
            action = form['action']
            absolute_url = urljoin(current_url, action)
            links.add(absolute_url)
        
        # Extract from <iframe src>
        for iframe in soup.find_all('iframe', src=True):
            src = iframe['src']
            absolute_url = urljoin(current_url, src)
            if urlparse(absolute_url).netloc == urlparse(self.base_domain).netloc:
                links.add(absolute_url)
        
        return list(links)
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Dict]:
        """
        Extract all forms from HTML page.
        
        Args:
            soup: BeautifulSoup object
            page_url: Current page URL
        
        Returns:
            List of form dictionaries
        """
        forms = []
        
        for form_tag in soup.find_all('form'):
            # Extract form attributes
            action = form_tag.get('action', '')
            
            method = None
            
            # Method 1: Standard BeautifulSoup .get()
            method = form_tag.get('method', None)
            
            # Method 2: Try case-insensitive search in attrs dict
            if not method and hasattr(form_tag, 'attrs'):
                for attr_name, attr_value in form_tag.attrs.items():
                    if attr_name.lower() == 'method':
                        method = attr_value
                        logger.debug(f"Found method via case-insensitive search: {method}")
                        break
            
            # Method 3: Regex search in raw HTML string (last resort)
            if not method:
                form_html = str(form_tag)
                method_match = re.search(r'method\s*=\s*["\']?(post|get)["\']?', form_html, re.IGNORECASE)
                if method_match:
                    method = method_match.group(1)
                    logger.debug(f"Found method via regex on raw HTML: {method}")
            
            # Normalize and validate
            if method:
                method = method.lower().strip()
                if method not in ['get', 'post']:
                    logger.warning(f"Invalid form method '{method}', defaulting to 'get'")
                    method = 'get'
            else:
                method = 'get'
                logger.debug(f"No method attribute found in form, defaulting to 'get'")
            
            form_id = form_tag.get('id', '')
            form_name = form_tag.get('name', '')
            
            # Resolve action URL
            if action:
                action_url = urljoin(page_url, action)
            else:
                action_url = page_url
            
            # Extract all input fields
            inputs = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text').lower()
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                input_id = input_tag.get('id', '')
                
                if input_name:  # Only include inputs with names
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value,
                        'id': input_id
                    })
            
            if inputs:  # Only add forms with inputs
                form_dict = {
                    'action': action_url,
                    'method': method,
                    'id': form_id,
                    'name': form_name,
                    'inputs': inputs,
                    'page_url': page_url
                }
                
                forms.append(form_dict)
                logger.debug(f"Form found: {method.upper()} {action_url} ({len(inputs)} inputs)")
        
        return forms
    
    def _extract_ajax_endpoints(self, html: str, page_url: str) -> List[str]:
        """
        Extract AJAX/API endpoints from JavaScript code.
        
        Args:
            html: HTML content
            page_url: Current page URL
        
        Returns:
            List of discovered AJAX endpoints
        """
        endpoints = set()
        
        # Patterns to match AJAX calls
        patterns = [
            r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]',  # fetch('/api/users')
            r'\.ajax\s*\(\s*\{\s*url\s*:\s*[\'"]([^\'"]+)[\'"]',  # $.ajax({url: '/api'})
            r'axios\.(get|post|put|delete)\s*\(\s*[\'"]([^\'"]+)[\'"]',  # axios.get('/api')
            r'XMLHttpRequest.*open\s*\(\s*[\'"]GET[\'"],\s*[\'"]([^\'"]+)[\'"]',  # XHR
            r'\.getJSON\s*\(\s*[\'"]([^\'"]+)[\'"]',  # $.getJSON('/api')
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                # Get the URL from the last group
                endpoint = match.group(match.lastindex)
                
                # Resolve to absolute URL
                absolute_url = urljoin(page_url, endpoint)
                
                # Only add if same domain
                if urlparse(absolute_url).netloc == urlparse(self.base_domain).netloc:
                    endpoints.add(absolute_url)
                    logger.debug(f"AJAX endpoint found: {absolute_url}")
        
        return list(endpoints)
    
    def _extract_path_parameters(self, urls: List[str]) -> List[Dict]:
        """
        Detect and extract path parameters from discovered URLs.
        
        Args:
            urls: List of all crawled URLs
        
        Returns:
            List of dicts with 'base_url', 'parameters', 'path_template'
        """
        # Group URLs by path pattern
        path_patterns = defaultdict(list)
        
        for url in urls:
            parsed = urlparse(url)
            
            # Skip URLs with query strings (already handled)
            if parsed.query:
                continue
            
            # Skip root and simple paths
            path = parsed.path.strip('/')
            if not path or '/' not in path:
                continue
            
            # Split path into segments
            path_segments = [s for s in path.split('/') if s]
            
            if len(path_segments) < 2:
                continue
            
            # Try to find numeric segments that might be IDs
            for i, segment in enumerate(path_segments):
                # Check if segment looks like an ID (numeric or uuid-like)
                if re.match(r'^\d+$', segment) or re.match(r'^[0-9a-f-]{8,}$', segment):
                    # Create pattern by replacing ID with placeholder
                    pattern_segments = path_segments.copy()
                    pattern_segments[i] = '{id}'
                    pattern = '/' + '/'.join(pattern_segments)
                    
                    # Store URL metadata under this pattern
                    path_patterns[pattern].append({
                        'url': url,
                        'param_index': i,
                        'param_name': path_segments[i-1] if i > 0 else 'id',  # Use preceding segment as param name
                        'param_value': segment,
                        'path_segments': path_segments
                    })
                    
                    # Only consider first numeric segment to avoid over-matching
                    break
        
        # Convert patterns to testable URLs
        testable_urls = []
        
        for pattern, url_group in path_patterns.items():
            # Only consider patterns that appear multiple times (2+)
            # This indicates it's likely a dynamic route
            if len(url_group) >= 2:
                # Use the first URL as representative
                first = url_group[0]
                parsed = urlparse(first['url'])
                
                # Determine parameter name from path context
                path_parts = [p for p in pattern.split('/') if p and p != '{id}']
                if path_parts:
                    # Use last non-placeholder segment + "_id"
                    param_name = f"{path_parts[-1]}_id" if len(path_parts) > 0 else "id"
                else:
                    param_name = "id"
                
                # Build base URL - reconstruct path without the ID
                base_path_segments = first['path_segments'].copy()
                base_path_segments[first['param_index']] = '{id}'  # Placeholder
                base_path = '/' + '/'.join(base_path_segments)
                
                # Remove placeholder to get injection point
                base_path_clean = base_path.replace('/{id}', '')
                
                base_url = f"{parsed.scheme}://{parsed.netloc}{base_path_clean}"
                
                # Use first URL's ID value as example
                param_value = first['param_value']
                
                testable_urls.append({
                    'base_url': base_url,
                    'parameters': {param_name: param_value},
                    'original_url': first['url'],
                    'path_template': pattern,
                    'is_path_param': True,
                    'param_position': first['param_index'],
                    'url_variants': [u['url'] for u in url_group]
                })
                
                logger.debug(
                    f"Path parameter detected: {pattern} "
                    f"(param={param_name}, {len(url_group)} variants)"
                )
        
        return testable_urls


if __name__ == '__main__':
    # Test crawler
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    http_client = create_http_client(mode='safe', config=config)
    
    crawler = WebCrawler(config, http_client)
    results = crawler.crawl('https://example.com')
    
    print(f"\nCrawl Results:")
    print(f"  Pages: {results['pages_crawled']}")
    print(f"  URLs with params: {len(results['urls_with_params'])}")
    print(f"  Forms: {len(results['forms'])}")

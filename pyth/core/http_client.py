"""
Pythia HTTP Client with Token Bucket Rate Limiting
Provides a shared HTTP session with thread-safe token bucket rate limiting
for SQL injection testing. Conservative rate limits prevent overwhelming
target applications during security assessments.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
import threading
from typing import Optional, Dict
import requests

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class TokenBucket:
    """
    Thread-safe token bucket rate limiter for SQLi testing.
    
    Conservative rate limiting is critical for ethical SQLi testing:
    - Prevents service degradation on target applications
    - Reduces likelihood of triggering security alerts
    - Allows accurate time-based blind SQLi detection
    
    Algorithm:
    - Bucket has maximum capacity (burst size)
    - Tokens regenerate at steady rate (requests/second)
    - Each request consumes one token
    - If insufficient tokens, caller waits WITHOUT holding lock
    """
    
    def __init__(self, rate: float, burst: Optional[int] = None):
        """
        Initialize token bucket for SQLi testing rate limiting.
        
        Args:
            rate: Maximum requests per second (e.g., 2.0 = 2 req/s for safe mode)
            burst: Burst capacity (default: 2x rate, minimum 10)
        
        Example:
            # Safe mode: 2 req/s with burst of 4
            bucket = TokenBucket(rate=2.0)
            
            # Aggressive mode: 5 req/s with burst of 10
            bucket = TokenBucket(rate=5.0)
        """
        # Enforce minimum rate of 0.1 req/s (very conservative)
        self.rate = max(0.1, rate)
        
        # Burst capacity: allows short bursts but maintains average rate
        self.burst = burst or max(10, int(rate * 2))
        
        # Token state
        self.tokens = float(self.burst)  # Start with full bucket
        self.max_tokens = float(self.burst)
        self.last_update = time.time()
        
        # Lock protects token state (NOT sleep operations)
        self._lock = threading.Lock()
        
        logger.debug(
            f"Token bucket initialized for SQLi testing: "
            f"{self.rate:.2f} req/s, burst={self.burst}, "
            f"initial_tokens={self.tokens:.2f}"
        )
    
    def consume(self, tokens: int = 1) -> float:
        """
        Consume tokens for a SQLi test request.
        
        Thread-safe: Multiple threads can call this concurrently.
        Returns wait time immediately, allowing caller to sleep
        OUTSIDE the lock (critical for parallelization).
        
        Args:
            tokens: Number of tokens to consume (default: 1 per request)
        
        Returns:
            Wait time in seconds before request can proceed.
            0.0 = proceed immediately, >0.0 = sleep before sending request
        
        Example:
            wait_time = bucket.consume()
            if wait_time > 0:
                time.sleep(wait_time)
        """
        with self._lock:
            # Calculate elapsed time since last update
            now = time.time()
            elapsed = now - self.last_update
            
            # Refill tokens proportional to elapsed time
            # tokens_to_add = elapsed * rate (e.g., 2 seconds * 2 req/s = 4 tokens)
            self.tokens = min(
                self.max_tokens,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            # Check if we have sufficient tokens
            if self.tokens >= tokens:
                # Sufficient tokens: consume and proceed immediately
                self.tokens -= tokens
                return 0.0  # No wait needed
            
            else:
                # Insufficient tokens: calculate wait time
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate
                
                # Reserve these tokens (even though negative balance)
                # This ensures fair ordering of requests
                self.tokens -= tokens
                
                logger.debug(
                    f"SQLi rate limit applied: {self.tokens:.2f}/{self.max_tokens:.0f} tokens, "
                    f"wait {wait_time:.3f}s before next request"
                )
                
                return wait_time
    
    def get_stats(self) -> dict:
        """
        Get current bucket statistics for monitoring.
        
        Returns:
            Dictionary with current state:
            - tokens: Current token count (can be negative if deficit)
            - max_tokens: Maximum bucket capacity
            - rate: Token generation rate (req/s)
            - burst: Burst capacity
        """
        with self._lock:
            return {
                'tokens': self.tokens,
                'max_tokens': self.max_tokens,
                'rate': self.rate,
                'burst': self.burst
            }


def parse_cookie_string(cookie_string: str) -> Dict[str, str]:
    """
    Parse cookie string to dictionary.
    
    Handles various cookie string formats:
    - "Cookie: name1=value1; name2=value2"  (with "Cookie:" prefix)
    - "name1=value1; name2=value2"          (without prefix)
    - "name1=value1;name2=value2"           (no space)
    - "name1=value1"                        (single cookie)
    
    Args:
        cookie_string: Cookie header string
    
    Returns:
        Dictionary of cookie name-value pairs
    
    Example:
        >>> parse_cookie_string("Cookie: PHPSESSID=abc123; security=low")
        {'PHPSESSID': 'abc123', 'security': 'low'}
        
        >>> parse_cookie_string("PHPSESSID=abc123; security=low")
        {'PHPSESSID': 'abc123', 'security': 'low'}
    """
    cookies = {}
    
    if not cookie_string:
        return cookies
    
    # Users often copy the full header line including "Cookie:"
    cookie_string_clean = cookie_string.strip()
    if cookie_string_clean.lower().startswith('cookie:'):
        cookie_string_clean = cookie_string_clean[7:].strip()
        logger.debug("Removed 'Cookie:' prefix from cookie string")
    
    # Parse cookie pairs
    for cookie in cookie_string_clean.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            name = name.strip()
            value = value.strip()
            
            # Validate cookie name (must not contain special chars)
            if name and not any(c in name for c in [' ', ':', '/', '\\', '"', "'"]):
                cookies[name] = value
                logger.debug(f"Parsed cookie: {name}={value[:20]}{'...' if len(value) > 20 else ''}")
            else:
                logger.warning(f"Invalid cookie name (contains special chars): '{name}'")
        else:
            logger.warning(f"Malformed cookie (no '='): {cookie}")
    
    return cookies


class RateLimitedSession:
    """
    HTTP session with token bucket rate limiting for SQLi testing.
    
    Thread-safe: Multiple threads can make concurrent SQLi test requests
    while respecting configured rate limits.
    
    Features:
    - Token bucket rate limiting (threads sleep OUTSIDE locks)
    - Configurable User-Agent
    - Custom headers support
    - Proxy configuration
    - Automatic timeout handling
    - SSL verification control
    - Cookie injection for authenticated scans
    
    Usage:
        session = RateLimitedSession(rate_limit=2.0, config=config)
        session.apply_cookies("PHPSESSID=abc123; security=low")
        response = session.get('https://example.com/product?id=1')
        response = session.post('https://example.com/login', data={'user': 'test'})
    """
    
    def __init__(self, rate_limit: float, config=None, cookie_string: Optional[str] = None):
        """
        Initialize rate-limited HTTP session for SQLi testing.
        
        Args:
            rate_limit: Maximum requests per second (e.g., 2.0 = 2 req/s)
            config: Config instance (optional, uses default if None)
            cookie_string: Optional cookie string to apply immediately
        
        Example:
            # Safe mode: conservative 2 req/s
            session = RateLimitedSession(rate_limit=2.0)
            
            # Aggressive mode with cookies
            session = RateLimitedSession(
                rate_limit=5.0,
                cookie_string="PHPSESSID=abc123"
            )
        """
        self.config = config or get_config()
        self.rate_limit = max(0.1, rate_limit)
        
        # Initialize token bucket rate limiter
        self.token_bucket = TokenBucket(
            rate=self.rate_limit,
            burst=max(10, int(self.rate_limit * 2))
        )
        
        # Create requests session
        self.session = requests.Session()
        
        # Set User-Agent for ethical disclosure
        self.session.headers.update({'User-Agent': self.config.user_agent})
        logger.info(f"HTTP User-Agent set: {self.session.headers.get('User-Agent')}")
        
        # Apply custom headers if configured
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
            logger.debug(f"Custom headers applied: {list(self.config.custom_headers.keys())}")
        
        # Configure proxy if specified
        if self.config.proxy_http or self.config.proxy_https:
            proxies = {}
            if self.config.proxy_http:
                proxies['http'] = self.config.proxy_http
                logger.debug(f"HTTP proxy configured: {self.config.proxy_http}")
            if self.config.proxy_https:
                proxies['https'] = self.config.proxy_https
                logger.debug(f"HTTPS proxy configured: {self.config.proxy_https}")
            self.session.proxies.update(proxies)
        
        # Apply cookies if provided
        if cookie_string:
            self.apply_cookies(cookie_string)
        
        logger.info(
            f"Pythia HTTP client initialized for SQLi testing: "
            f"{self.rate_limit:.2f} req/s, burst={self.token_bucket.burst}"
        )
    
    def apply_cookies(self, cookie_string: str):
        """
        Apply cookies from string to session.
        
        Parses cookie string and updates session cookies.
        Existing cookies are preserved unless overridden.
        
        Args:
            cookie_string: Cookie header string (e.g., "name1=value1; name2=value2")
        
        Example:
            session.apply_cookies("PHPSESSID=abc123; security=low")
        """
        cookies = parse_cookie_string(cookie_string)
        
        if cookies:
            self.session.cookies.update(cookies)
            logger.info(f"Applied {len(cookies)} cookies to session: {list(cookies.keys())}")
        else:
            logger.warning("No valid cookies parsed from string")
    
    def get_cookies(self) -> Dict[str, str]:
        """
        Get current session cookies as dictionary.
        
        Returns:
            Dictionary of cookie name-value pairs
        
        Example:
            cookies = session.get_cookies()
            print(f"Session has {len(cookies)} cookies")
        """
        return dict(self.session.cookies)
    
    def clear_cookies(self):
        """
        Clear all session cookies.
        
        Useful for testing multiple users or sessions.
        
        Example:
            session.clear_cookies()
            session.apply_cookies("PHPSESSID=newuser123")
        """
        self.session.cookies.clear()
        logger.debug("Cleared all session cookies")
    
    def _wait_if_needed(self):
        """
        Apply rate limiting before making request.
        
        Uses token bucket algorithm: threads sleep OUTSIDE the lock,
        enabling true concurrent request handling.
        
        Critical for SQLi testing:
        - Prevents overwhelming target application
        - Reduces WAF/IDS trigger likelihood
        - Maintains accurate timing for time-based blind detection
        """
        # Get wait time from token bucket (lock released immediately)
        wait_time = self.token_bucket.consume(tokens=1)
        
        # Sleep OUTSIDE lock if rate limit applied
        if wait_time > 0:
            logger.debug(f"Rate limiting: sleeping {wait_time:.3f}s before SQLi test request")
            time.sleep(wait_time)
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        HTTP GET with automatic rate limiting for SQLi testing.
        
        Rate limiting is applied BEFORE the request to prevent bursts.
        Default timeouts and SSL verification are set if not provided.
        
        Args:
            url: Target URL (e.g., 'https://example.com/product?id=1')
            **kwargs: Additional arguments for requests.get()
                     - timeout: Override default timeout
                     - verify: Override SSL verification
                     - allow_redirects: Override redirect behavior
                     - headers: Additional headers
                     - params: URL parameters (merged with query string)
        
        Returns:
            requests.Response object
        
        Raises:
            requests.RequestException: On connection errors, timeouts, etc.
        
        Example:
            response = session.get('https://example.com/search?q=test')
            response = session.get(
                'https://example.com/api',
                timeout=60,
                headers={'X-Custom': 'value'}
            )
        """
        # Apply rate limiting (token bucket)
        self._wait_if_needed()
        
        # Set default timeouts if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        # Set SSL verification if not provided
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        # Set redirect behavior if not provided
        if 'allow_redirects' not in kwargs:
            kwargs['allow_redirects'] = self.config.follow_redirects
        
        # Make request
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """
        HTTP POST with automatic rate limiting for form SQLi testing.
        
        Used for testing POST parameters in forms, login pages, etc.
        Rate limiting is applied BEFORE the request.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for requests.post()
                     - data: Form data (dict or string)
                     - json: JSON payload (dict)
                     - timeout: Override default timeout
                     - verify: Override SSL verification
                     - headers: Additional headers
        
        Returns:
            requests.Response object
        
        Example:
            response = session.post(
                'https://example.com/login',
                data={'username': 'admin', 'password': 'test'}
            )
            response = session.post(
                'https://example.com/api',
                json={'query': 'test'},
                headers={'Content-Type': 'application/json'}
            )
        """
        # Apply rate limiting (token bucket)
        self._wait_if_needed()
        
        # Set default timeouts if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        # Set SSL verification if not provided
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        # Make request
        return self.session.post(url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """
        HTTP HEAD with automatic rate limiting.
        
        Used for checking URL existence without downloading full response.
        Useful for crawler validation before GET/POST testing.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for requests.head()
        
        Returns:
            requests.Response object (no body)
        
        Example:
            response = session.head('https://example.com/page')
            if response.status_code == 200:
                # Page exists, proceed with GET
                response = session.get('https://example.com/page')
        """
        # Apply rate limiting (token bucket)
        self._wait_if_needed()
        
        # Set default timeouts if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        # Set SSL verification if not provided
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        # Make request
        return self.session.head(url, **kwargs)


def create_http_client(
    mode: str = 'safe',
    config=None,
    cookie_string: Optional[str] = None
) -> RateLimitedSession:
    """
    Create HTTP client with appropriate rate limit for SQLi scan mode.
    
    Factory function that creates RateLimitedSession with mode-specific
    rate limits (safe vs aggressive) and optional cookies.
    
    Args:
        mode: Scan mode ('safe' or 'aggressive')
        config: Config instance (optional, uses default if None)
        cookie_string: Optional cookie string for authenticated scans
    
    Returns:
        RateLimitedSession configured for specified mode
    
    Rate Limits by Mode:
        - safe: 2.0 req/s (default, no consent required)
        - aggressive: 5.0 req/s (requires consent token verification)
    
    Example:
        # Safe mode (conservative, no consent needed)
        client = create_http_client(mode='safe')
        
        # Aggressive mode with cookies (requires consent)
        client = create_http_client(
            mode='aggressive',
            cookie_string="PHPSESSID=abc123",
            config=config
        )
    """
    config = config or get_config()
    
    # Select rate limit based on mode
    if mode == 'aggressive':
        rate_limit = config.rate_limit_aggressive
        logger.info(f"Creating HTTP client for AGGRESSIVE SQLi testing (requires consent)")
    else:
        rate_limit = config.rate_limit_safe
        logger.info(f"Creating HTTP client for SAFE SQLi testing (passive detection)")
    
    logger.info(f"SQLi scan mode: {mode.upper()}, rate limit: {rate_limit:.2f} req/s")
    logger.info(f"Thread pool size: {config.max_workers} concurrent workers")
    
    if cookie_string:
        logger.info("Cookies provided for authenticated scanning")
    
    return RateLimitedSession(rate_limit, config, cookie_string)
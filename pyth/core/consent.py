"""
Pythia Consent Token System

Implements domain ownership verification via:
- HTTP file placement (/.well-known/<token>.txt)
- DNS TXT record verification (pythia-verify=<token>)

Required before --aggressive (time-based SQLi) or --use-ai modes.

Purpose: Ethical SQL injection testing requires explicit authorization.
Time-based SQL injection tests (SLEEP payloads) can impact server performance,
so ownership verification ensures testing is authorized.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import secrets
import re
import dns.resolver
import dns.exception
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests
import dns.resolver

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class ConsentToken:
    """
    Manages consent token generation and verification for Pythia SQL injection scanner.
    
    Ensures ethical testing by requiring proof of domain ownership before:
    - Aggressive mode (time-based blind SQL injection with SLEEP payloads)
    - AI-powered analysis (sends findings to external AI services)
    
    Verification methods:
    1. HTTP file: Upload token file to /.well-known/<token>.txt
    2. DNS TXT: Add TXT record: pythia-verify=<token>
    """
    
    def __init__(self, config=None):
        """
        Initialize consent token manager.
        
        Args:
            config: Optional Config object (loads from defaults if None)
        """
        self.config = config or get_config()
        self.token_pattern = re.compile(r'^verify-[a-f0-9]{16}$')
        
        logger.debug("Pythia consent token system initialized")
    
    def generate_token(self, domain: str) -> Tuple[str, datetime]:
        """
        Generate a unique consent token for a domain.
        
        Token format: verify-<16 hex characters>
        Example: verify-a3f9b2c1d8e4f5a6
        
        Args:
            domain: Target domain (e.g., "example.com" or "localhost:8080")
        
        Returns:
            Tuple of (token_string, expiration_datetime_utc)
        """
        # Clean domain (remove protocol and path, preserve port for testing)
        clean_domain = self._normalize_domain(domain)
        
        # Generate cryptographically secure token: verify-<16 hex chars>
        random_hex = secrets.token_hex(self.config.token_hex_length // 2)
        token = f"verify-{random_hex}"
        
        # Calculate expiration time (UTC)
        expiration = datetime.now(timezone.utc) + timedelta(hours=self.config.token_expiry_hours)
        
        logger.info(f"Generated consent token for {clean_domain}: {token}")
        logger.debug(f"Token expires at: {expiration.isoformat()}Z")
        
        return token, expiration
    
    def print_instructions(self, domain: str, token: str):
        """
        Print human-readable instructions for token placement.
        
        Displays step-by-step guide for both HTTP and DNS verification methods.
        
        Args:
            domain: Target domain
            token: Generated token
        """
        # Preserve port for display
        normalized_domain = self._normalize_domain(domain)
        
        # Construct URL with port if present
        if ':' in normalized_domain:
            # Non-standard port (e.g., localhost:8080), use http
            http_path = f"http://{normalized_domain}{self.config.http_verification_path}{token}.txt"
        else:
            # Standard domain, use https
            http_path = f"https://{normalized_domain}{self.config.http_verification_path}{token}.txt"
        
        # Display domain without port for simplicity (but keep for commands)
        display_domain = normalized_domain.split(':')[0]
        
        print("\n" + "="*70)
        print("PYTHIA - DOMAIN OWNERSHIP VERIFICATION REQUIRED")
        print("="*70)
        print(f"\nDomain: {display_domain}")
        print(f"Token: {token}")
        print(f"Expires: {self.config.token_expiry_hours} hours from now")
        print(f"\n Required for: --aggressive (time-based SQLi) and --use-ai modes")
        
        print("\n┌─ METHOD 1: HTTP File Verification (Recommended)")
        print("│")
        print("│  ✓ Faster verification")
        print("│  ✓ Works with non-standard ports (localhost:8080)")
        print("│  ✓ No DNS propagation delay")
        print("│")
        print("│  STEP 1: Create a text file containing EXACTLY this:")
        print(f"│    {token}")
        print("│")
        print("│  STEP 2: Upload it to this exact path:")
        print(f"│    {http_path}")
        print("│")
        print("│  STEP 3: Verify it's accessible in your browser")
        print("│    The file should return the token (no HTML, just the token)")
        print("│")
        print("│  STEP 4: Run verification:")
        print(f"│    pyth --verify-consent http --domain {normalized_domain} --token {token}")
        print("└─")
        
        print("\n┌─ METHOD 2: DNS TXT Record Verification (Alternative)")
        print("│")
        print("│  ✓ No web server file access needed")
        print("│  ✓ Works for production domains")
        print("│  Requires DNS propagation time (5-30 minutes)")
        print("│")
        print("│  STEP 1: Add a TXT record to your DNS zone:")
        print(f"│    Host/Name: {display_domain}")
        print(f"│    Type: TXT")
        print(f"│    Value: {self.config.dns_txt_prefix}{token}")
        print("│    TTL: 300 (5 minutes)")
        print("│")
        print("│  STEP 2: Wait for DNS propagation")
        print("│    Check with: dig TXT {display_domain}")
        print("│")
        print("│  STEP 3: Run verification:")
        print(f"│    pyth --verify-consent dns --domain {normalized_domain} --token {token}")
        print("└─")
        
        print("\n" + "="*70)
        print("WHY VERIFICATION IS REQUIRED:")
        print("  • Aggressive mode uses SLEEP() payloads that delay server responses")
        print("  • This can impact server performance and user experience")
        print("  • Ownership verification ensures testing is authorized")
        print("  • Follows ethical hacking principles (OWASP, CEH)")
        print("="*70 + "\n")
    
    def verify_http(self, domain: str, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify consent token via HTTP file placement.
        
        Checks if token file exists at:
        - https://domain/.well-known/<token>.txt
        - http://domain/.well-known/<token>.txt (fallback)
        
        Args:
            domain: Target domain (with port if non-standard)
            token: Token to verify
        
        Returns:
            Tuple of (success_bool, proof_url_or_error_message)
        """
        if not self._validate_token_format(token):
            return False, f"Invalid token format: {token}"
        
        # Preserve port in domain for HTTP verification
        normalized_domain = self._normalize_domain(domain)
        
        # Determine protocol based on port
        has_port = ':' in normalized_domain
        protocols = ['http'] if has_port else ['https', 'http']
        
        # Try protocols (https first for standard domains, http for non-standard ports)
        for protocol in protocols:
            url = f"{protocol}://{normalized_domain}{self.config.http_verification_path}{token}.txt"
            
            logger.info(f"Attempting HTTP verification: {url}")
            
            try:
                response = requests.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    verify=self.config.verify_ssl,
                    allow_redirects=False  # Don't follow redirects for security
                )
                
                if response.status_code == 200:
                    content = response.text.strip()
                    
                    # Verify exact token match
                    if content == token:
                        logger.info(f"✓ HTTP verification successful: {url}")
                        return True, url
                    else:
                        logger.warning(f"Token mismatch. Expected: {token}, Got: {content[:50]}")
                        return False, f"Token content mismatch at {url}"
                
                elif response.status_code == 404:
                    logger.debug(f"Token file not found at {url} (404)")
                    continue
                
                elif response.status_code == 403:
                    logger.warning(f"Access forbidden at {url} (403)")
                    continue
                
                else:
                    logger.warning(f"Unexpected status code {response.status_code} at {url}")
                    continue
                    
            except requests.exceptions.SSLError as e:
                logger.debug(f"SSL error for {url}: {e}")
                # For localhost/testing, try http if https fails
                if protocol == 'https' and 'localhost' in normalized_domain:
                    logger.info("SSL error on localhost, will try http")
                    continue
                return False, f"SSL certificate verification failed for {url}"
                
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout for {url}")
                continue
                
            except requests.exceptions.ConnectionError as e:
                logger.debug(f"Connection error for {url}: {e}")
                continue
                
            except requests.RequestException as e:
                logger.debug(f"Request failed for {url}: {e}")
                continue
        
        # All attempts failed
        return False, (
            f"Token file not accessible at {normalized_domain}{self.config.http_verification_path}{token}.txt\n"
            f"Please ensure:\n"
            f"  1. File exists at the correct path\n"
            f"  2. File contains only the token (no extra whitespace or HTML)\n"
            f"  3. File is readable by web server\n"
            f"  4. No firewall blocking requests"
        )
    
    def verify_dns(self, domain: str, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify consent token via DNS TXT record.
        """
        if not self._validate_token_format(token):
            return False, f"Invalid token format: {token}"

        domain_for_dns = self._get_base_domain(domain)
        expected_txt = f"{self.config.dns_txt_prefix}{token}"

        logger.info(f"Attempting DNS TXT verification for {domain_for_dns}")
        logger.info(f"Looking for TXT record: {expected_txt}")

        def _mk_resolver(nameservers=None, label="resolver"):
            r = dns.resolver.Resolver()
            if nameservers:
                r.nameservers = nameservers
            r.timeout = 3
            r.lifetime = 5
            logger.debug(f"[{label}] nameservers={list(r.nameservers)}")
            return r

        def _ns_host_to_ips(ns_host: str):
            """Resolve NS hostname to A/AAAA using the system resolver."""
            sysr = _mk_resolver(label="system")
            ips = []
            try:
                for rr in sysr.resolve(ns_host, "A"):
                    ips.append(rr.address)
            except Exception:
                pass
            try:
                for rr in sysr.resolve(ns_host, "AAAA"):
                    ips.append(rr.address)
            except Exception:
                pass
            return ips

        def _txt_match_from_response(resp) -> Tuple[Optional[str], int]:
            """Return (matched_value, count_records)."""
            records = list(resp)
            for rdata in records:
                parts = getattr(rdata, "strings", None)
                if parts is not None:
                    for raw in parts:
                        raw = raw.decode() if isinstance(raw, bytes) else raw
                        clean = raw.strip().strip('"')
                        logger.debug(f"TXT raw=[{raw}] clean=[{clean}] match={clean == expected_txt}")
                        if clean == expected_txt:
                            return clean, len(records)
                else:
                    clean = rdata.to_text().strip().strip('"')
                    logger.debug(f"TXT(to_text)=[{clean}] match={clean == expected_txt}")
                    if clean == expected_txt:
                        return clean, len(records)
            return None, len(records)

        def _query_txt_with(resolver: dns.resolver.Resolver, label: str):
            try:
                resp = resolver.resolve(domain_for_dns, "TXT")
                match, count = _txt_match_from_response(resp)
                logger.debug(f"[{label}] Found {count} TXT record(s) for {domain_for_dns}")
                if match:
                    logger.info(f"✓ DNS verification successful for {domain_for_dns} via {label}")
                    return ("ok", match)
                return (None, None)
            except dns.resolver.NXDOMAIN:
                return ("nx", None)
            except dns.resolver.NoAnswer:
                logger.debug(f"[{label}] No TXT records for {domain_for_dns}")
                return (None, None)
            except dns.exception.DNSException as e:
                logger.debug(f"[{label}] DNS query failed: {e}")
                return (None, None)

        authoritative_resolver = None
        try:
            system_lookup = _mk_resolver(label="system")
            ns_resp = system_lookup.resolve(domain_for_dns, "NS")
            ns_hosts = [ns.target.to_text().rstrip(".") for ns in ns_resp]
            if ns_hosts:
                logger.info(f"Found {len(ns_hosts)} authoritative nameserver(s): {', '.join(ns_hosts)}")
                ns_host = ns_hosts[0]
                ns_ips = _ns_host_to_ips(ns_host)
                if ns_ips:
                    logger.info(f"Using authoritative nameserver: {ns_host} ({', '.join(ns_ips)})")
                    authoritative_resolver = _mk_resolver([ns_ips[0]], label="authoritative NS")
        except Exception as ex:
            logger.warning(f"Could not resolve authoritative nameservers: {ex}")

        if authoritative_resolver:
            status, proof = _query_txt_with(authoritative_resolver, "authoritative NS")
            if status == "ok":
                return True, proof
            if status == "nx":
                return False, f"Domain {domain_for_dns} does not exist"

        sys_res = dns.resolver.Resolver()  # obtiene la lista del sistema
        system_ns = list(sys_res.nameservers)
        logger.debug(f"Falling back to system DNS resolver list: {system_ns}")

        for ns_ip in system_ns:
            per_ns = _mk_resolver([ns_ip], label=f"system DNS ({ns_ip})")
            status, proof = _query_txt_with(per_ns, f"system DNS ({ns_ip})")
            if status == "ok":
                return True, proof
            if status == "nx":
                return False, f"Domain {domain_for_dns} does not exist"

        return False, f"Token not found in TXT records for {domain_for_dns}"

    def verify_with_retry(
        self,
        method: str,
        domain: str,
        token: str,
        retries: Optional[int] = None,
        delay: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify token with automatic retries.
        
        Useful for handling transient network issues or DNS propagation delays.
        
        Args:
            method: 'http' or 'dns'
            domain: Target domain (with port for http)
            token: Token to verify
            retries: Number of retry attempts (default from config)
            delay: Delay between retries in seconds (default from config)
        
        Returns:
            Tuple of (success_bool, proof_or_error_message)
        """
        retries = retries or self.config.verification_retries
        delay = delay or self.config.verification_retry_delay
        
        verify_func = self.verify_http if method == 'http' else self.verify_dns
        
        for attempt in range(1, retries + 1):
            logger.info(f"Verification attempt {attempt}/{retries}")
            
            success, result = verify_func(domain, token)
            
            if success:
                return True, result
            
            if attempt < retries:
                import time
                logger.info(f"Verification failed, retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.warning(f"All {retries} verification attempts failed")
        
        return False, result
    
    def save_proof(self, domain: str, token: str, method: str, proof: str) -> Path:
        """
        Save verification proof to file for audit trail.
        
        Creates a timestamped proof file in consent proofs directory.
        
        Args:
            domain: Verified domain (with port)
            token: Verified token
            method: 'http' or 'dns'
            proof: Proof string (URL or TXT record)
        
        Returns:
            Path to saved proof file
        """
        # For filename, use base domain without port for cleanliness
        base_domain = self._get_base_domain(domain)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"{base_domain}_{method}_{timestamp}.txt"
        
        proof_path = self.config.consent_proofs_dir / filename
        proof_path.parent.mkdir(parents=True, exist_ok=True)
        
        # But save full domain (with port) in proof file content
        normalized_domain = self._normalize_domain(domain)
        
        with proof_path.open('w') as f:
            f.write(f"Pythia SQL Injection Scanner - Consent Verification Proof\n")
            f.write(f"{'='*60}\n\n")
            f.write(f"Domain: {normalized_domain}\n")
            f.write(f"Token: {token}\n")
            f.write(f"Method: {method.upper()}\n")
            f.write(f"Verified: {datetime.now(timezone.utc).isoformat()}Z\n")
            f.write(f"Proof: {proof}\n")
            f.write(f"\nThis verification authorizes:\n")
            f.write(f"  • Aggressive SQL injection testing (time-based blind SQLi)\n")
            f.write(f"  • AI-powered vulnerability analysis\n")
            f.write(f"\nExpires: {self.config.token_expiry_hours} hours from verification\n")
        
        logger.info(f"Verification proof saved: {proof_path}")
        return proof_path
    
    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain string (remove protocol and path, PRESERVE port).
        
        Examples:
        - "https://example.com/path" -> "example.com"
        - "http://localhost:8080" -> "localhost:8080"
        - "example.com:443" -> "example.com:443"
        
        Args:
            domain: Raw domain string
        
        Returns:
            Normalized domain with port if present
        """
        # If it looks like a URL, parse it
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        
        # Remove path (but keep port)
        if '/' in domain:
            domain = domain.split('/')[0]
        
        return domain.strip().lower()
    
    def _get_base_domain(self, domain: str) -> str:
        """
        Get base domain without port (for DNS queries and display).
        
        Examples:
        - "localhost:8080" -> "localhost"
        - "example.com" -> "example.com"
        - "sub.example.com:3000" -> "sub.example.com"
        
        Args:
            domain: Domain string (may include port)
        
        Returns:
            Base domain without port
        """
        normalized = self._normalize_domain(domain)
        
        # Remove port if present
        if ':' in normalized:
            return normalized.split(':')[0]
        
        return normalized
    
    def _validate_token_format(self, token: str) -> bool:
        """
        Validate token format (verify-<16 hex chars>).
        
        Args:
            token: Token string to validate
        
        Returns:
            True if valid format, False otherwise
        """
        return bool(self.token_pattern.match(token))


if __name__ == "__main__":
    # Test consent token system for Pythia
    from .config import Config
    import sys
    
    print("\n" + "="*70)
    print("PYTHIA CONSENT TOKEN SYSTEM TEST")
    print("="*70 + "\n")
    
    # Load config
    try:
        config = Config.load()
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        sys.exit(1)
    
    consent = ConsentToken(config)
    
    # Test domain
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    
    print(f"Testing with domain: {domain}\n")
    
    # Generate token
    print("[1/3] Generating consent token...")
    token, expiration = consent.generate_token(domain)
    print(f"✓ Generated: {token}")
    print(f"✓ Expires: {expiration}")
    
    # Print instructions
    print("\n[2/3] Displaying verification instructions...")
    consent.print_instructions(domain, token)
    
    print("[3/3] Testing verification methods...")
    
    print("\n--- HTTP Verification Test ---")
    success, result = consent.verify_http(domain, token)
    if success:
        print(f"✓ HTTP verification successful!")
        print(f"  Proof: {result}")
    else:
        print(f"✗ HTTP verification failed (expected unless token is placed)")
        print(f"  Error: {result}")
    
    print("\n--- DNS Verification Test ---")
    success, result = consent.verify_dns(domain, token)
    if success:
        print(f"✓ DNS verification successful!")
        print(f"  Proof: {result}")
    else:
        print(f"✗ DNS verification failed (expected unless TXT record exists)")
        print(f"  Error: {result}")
    
    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)
    print("\nTo test with a real domain:")
    print(f"  python -m pyth.core.consent-pythia your-domain.com")
    print("\nFor localhost testing:")
    print(f"  python -m pyth.core.consent-pythia localhost:8080")
    print("="*70 + "\n")
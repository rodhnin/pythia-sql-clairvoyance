"""
Pythia CLI - Command Line Interface
====================================
Main entry point for Pythia SQL injection scanner.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from .core.config import Config, get_config, set_config
from .core.logging import setup_logging, get_logger, set_verbosity
from .core.consent import ConsentToken
from .core.db import get_db

logger = get_logger(__name__)


def print_banner():
    """Display Pythia ASCII art banner."""
    banner_path = Path(__file__).parent.parent / "assets" / "ascii.txt"
    
    try:
        with banner_path.open('r', encoding='utf-8') as f:
            print(f.read())
    except FileNotFoundError:
        # Fallback minimal banner
        print("=" * 70)
        print("PYTHIA – Passive SQL Clairvoyance")
        print("by Rodney Dhavid Jimenez Chacin (rodhnin)")
        print("GitHub: https://github.com/rodhnin")
        print("=" * 70)
        print("\nUse only on authorized targets.")
        print("Verification required for aggressive mode.\n")


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog='pythia',
        description='Pythia – SQL Injection Detection Scanner',
        epilog='For detailed documentation, visit: https://github.com/rodhnin/pythia-sql-clairvoyance',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Main scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--target', '-t',
        type=str,
        metavar='URL',
        help='Target URL or domain to scan (e.g., https://example.com)'
    )
    scan_group.add_argument(
        '--safe',
        action='store_true',
        default=True,
        help='Use safe mode (passive detection only) [default]'
    )
    scan_group.add_argument(
        '--aggressive',
        action='store_true',
        help='Use aggressive mode (includes time-based tests, requires consent)'
    )
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument(
        '--cookie',
        type=str,
        metavar='COOKIE_STRING',
        help='Cookie header for authenticated scans (format: "name1=value1; name2=value2")'
    )
    auth_group.add_argument(
        '--auto-csrf',
        action='store_true',
        help='Automatically extract and use CSRF tokens from forms'
    )
    
    # Crawler options
    crawler_group = parser.add_argument_group('Web Crawler Options')
    crawler_group.add_argument(
        '--max-depth',
        type=int,
        metavar='N',
        help='Maximum crawl depth (default: 2)'
    )
    crawler_group.add_argument(
        '--max-pages',
        type=int,
        metavar='N',
        help='Maximum pages to crawl (default: 100)'
    )
    crawler_group.add_argument(
        '--no-robots',
        action='store_true',
        help='Ignore robots.txt (not recommended)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--report-dir',
        type=Path,
        metavar='PATH',
        help='Directory to save reports (default: ~/.pythia/reports)'
    )
    output_group.add_argument(
        '--html',
        action='store_true',
        help='Generate HTML report in addition to JSON'
    )
    output_group.add_argument(
        '--db',
        type=Path,
        metavar='PATH',
        help='SQLite database path (default: ~/.argos/argos.db)'
    )
    
    # Verbosity options
    verbose_group = parser.add_argument_group('Logging & Verbosity')
    verbose_group.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (-v: INFO, -vv: DEBUG, -vvv: DEBUG with libs)'
    )
    verbose_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress console output (WARNING level only)'
    )
    verbose_group.add_argument(
        '--log-file',
        type=Path,
        metavar='PATH',
        help='Log file path (default: ~/.pythia/pythia.log)'
    )
    verbose_group.add_argument(
        '--log-json',
        action='store_true',
        help='Use JSON format for logs'
    )
    verbose_group.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # AI options
    ai_group = parser.add_argument_group('AI Assistant (LangChain)')
    ai_group.add_argument(
        '--use-ai',
        action='store_true',
        help='Enable AI-powered analysis (requires verified consent)'
    )
    ai_group.add_argument(
        '--ai-tone',
        choices=['technical', 'non_technical', 'both'],
        default='both',
        help='AI report tone: technical, non_technical, or both [default: both]'
    )
    ai_group.add_argument(
        '--api-key-env',
        type=str,
        default='OPENAI_API_KEY',
        metavar='VAR',
        help='Environment variable for AI API key [default: OPENAI_API_KEY]'
    )
    
    # Consent token options
    consent_group = parser.add_argument_group('Consent Token Management')
    consent_group.add_argument(
        '--gen-consent',
        type=str,
        metavar='DOMAIN',
        help='Generate consent token for domain ownership verification'
    )
    consent_group.add_argument(
        '--verify-consent',
        choices=['http', 'dns'],
        metavar='METHOD',
        help='Verify consent token (http or dns)'
    )
    consent_group.add_argument(
        '--domain',
        type=str,
        metavar='DOMAIN',
        help='Domain for consent verification'
    )
    consent_group.add_argument(
        '--token',
        type=str,
        metavar='TOKEN',
        help='Consent token to verify (format: verify-<hex>)'
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument(
        '--rate',
        type=float,
        metavar='RATE',
        help='Request rate limit (req/sec, default: 2.0 safe, 5.0 aggressive)'
    )
    advanced_group.add_argument(
        '--timeout',
        type=int,
        metavar='SEC',
        help='HTTP timeout in seconds (default: 30)'
    )
    advanced_group.add_argument(
        '--user-agent',
        type=str,
        metavar='UA',
        help='Custom User-Agent string'
    )
    advanced_group.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    advanced_group.add_argument(
        '--threads',
        type=int,
        metavar='N',
        help='Number of concurrent threads (default: 5)'
    )
    
    # Miscellaneous
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.1.0'
    )
    
    return parser


def handle_gen_consent(args, config: Config):
    """Handle consent token generation."""
    consent = ConsentToken(config)
    token, expiration = consent.generate_token(args.gen_consent)
    
    # Save to database with method=None (pending verification)
    db = get_db()
    db.save_token(args.gen_consent, token, None, expiration)
    
    # Print instructions
    consent.print_instructions(args.gen_consent, token)
    
    return 0


def handle_verify_consent(args, config: Config):
    """Handle consent token verification."""
    if not args.domain or not args.token:
        logger.error("--verify-consent requires --domain and --token")
        print("ERROR: Both --domain and --token are required for consent verification")
        print(f"Usage: pyth --verify-consent {args.verify_consent} --domain example.com --token verify-abc123")
        return 1
    
    consent = ConsentToken(config)
    method = args.verify_consent  # 'http' or 'dns'
    
    logger.info(f"Verifying consent token for {args.domain} via {method.upper()}")
    
    # Verify token with retry (same as Argus)
    success, result = consent.verify_with_retry(method, args.domain, args.token)
    
    if success:
        # Save proof file (same as Argus)
        proof_path = consent.save_proof(args.domain, args.token, method, result)
        
        # Update database with verification and method
        db = get_db()
        db.verify_token(args.domain, args.token, method, str(proof_path))
        
        print("\n" + "="*70)
        print("✓ CONSENT VERIFICATION SUCCESSFUL")
        print("="*70)
        print(f"Domain: {args.domain}")
        print(f"Token: {args.token}")
        print(f"Method: {method.upper()}")
        print(f"Proof: {proof_path}")
        print("\nYou can now use --aggressive and --use-ai modes for this domain.")
        print("="*70 + "\n")
        
        return 0
    else:
        print("\n" + "="*70)
        print("✗ CONSENT VERIFICATION FAILED")
        print("="*70)
        print(f"Domain: {args.domain}")
        print(f"Token: {args.token}")
        print(f"Method: {method.upper()}")
        print(f"Error: {result}")
        print("\nPlease check the token placement and try again.")
        print("="*70 + "\n")
        
        return 1


def handle_scan(args, config: Config):
    """Handle main scan operation."""
    if not args.target:
        logger.error("--target is required for scanning")
        return 1
    
    # Determine scan mode
    if args.aggressive:
        mode = 'aggressive'
    else:
        mode = 'safe'
    
    # Log cookie usage
    if args.cookie:
        logger.info("Using provided cookies for authenticated scan")
    
    # Log CSRF auto-extraction
    if args.auto_csrf:
        logger.info("CSRF token auto-extraction enabled")
    
    # Import scanner
    from .scanner import SQLInjectionScanner
    
    try:
        scanner = SQLInjectionScanner(
            config=config,
            cookie_string=args.cookie,
            auto_csrf=args.auto_csrf
        )
        
        # Run scan (scanner will check consent with proper messages)
        result = scanner.scan(
            target=args.target,
            mode=mode,
            use_ai=args.use_ai,
            ai_tone=args.ai_tone if args.use_ai else None
        )
        
        # Check scan status and return appropriate exit code
        if result['status'] == 'failed':
            # Scan failed (connection error, etc.)
            logger.error(f"Scan failed: {result.get('error', 'Unknown error')}")
            print("\n" + "="*70)
            print(f"❌ SCAN FAILED: {result.get('error', 'Unknown error')}")
            print("="*70)
            print(f"Target: {args.target}")
            print(f"Error: {result.get('error_message', 'No details available')}")
            print(f"Duration: {result.get('duration', 0):.2f}s")
            print("="*70 + "\n")
            return 1  # Exit code 1 = failed
        
        elif result['status'] == 'aborted':
            # Scan aborted (requirements not met)
            logger.warning("Scan aborted: Target requirements not met")
            print("\n" + "="*70)
            print("⚠️  SCAN ABORTED")
            print("="*70)
            print(f"Target: {args.target}")
            print(f"Reason: {result.get('reason', 'Unknown')}")
            print(f"Duration: {result.get('duration', 0):.2f}s")
            print("="*70 + "\n")
            return 2  # Exit code 2 = aborted
        
        else:  # status == 'completed'
            # Scan completed successfully
            print("\n" + "="*70)
            print("✓ SCAN COMPLETE")
            print("="*70)
            print(f"Status: {result['status']}")
            print(f"Findings: {result['findings_count']}")
            print(f"Duration: {result['duration']:.2f}s")
            print(f"\nReports generated:")
            print(f"  JSON: {result['report_json']}")
            if result.get('report_html'):
                print(f"  HTML: {result['report_html']}")
            print("="*70 + "\n")
            
            return 0  # Exit code 0 = success
    
    except PermissionError:
        return 1  # Exit code 1 = permission error
    
    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        print(f"\n❌ UNEXPECTED ERROR: {e}\n")
        return 1  # Exit code 1 = unexpected error


def main(argv=None):
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Print banner (unless quiet)
    if not args.quiet:
        print_banner()
    
    # Load configuration
    cli_overrides = {}
    
    if args.report_dir:
        cli_overrides.setdefault('paths', {})['report_dir'] = str(args.report_dir)
    
    if args.db:
        cli_overrides.setdefault('paths', {})['database'] = str(args.db)
    
    if args.log_file:
        cli_overrides.setdefault('paths', {})['log_file'] = str(args.log_file)
    
    # Process --html flag
    if args.html:
        cli_overrides.setdefault('reporting', {}).setdefault('format', {})['html'] = True
    
    # Crawler settings
    if args.max_depth:
        cli_overrides.setdefault('crawler', {})['max_depth'] = args.max_depth
    
    if args.max_pages:
        cli_overrides.setdefault('crawler', {})['max_pages'] = args.max_pages
    
    if args.no_robots:
        cli_overrides.setdefault('crawler', {})['respect_robots_txt'] = False
    
    # Validate and process --rate flag
    if args.rate is not None:
        if args.rate <= 0:
            logger.error(f"Invalid rate limit: {args.rate}. Must be positive (> 0).")
            print(f"ERROR: --rate must be a positive number (got {args.rate})")
            return 1
        
        cli_overrides.setdefault('scan', {}).setdefault('rate_limit', {})
        if args.aggressive:
            cli_overrides['scan']['rate_limit']['aggressive_mode'] = args.rate
        else:
            cli_overrides['scan']['rate_limit']['safe_mode'] = args.rate
        
        logger.debug(f"Rate limit override: {args.rate} req/s")
    
    if args.timeout:
        cli_overrides.setdefault('scan', {}).setdefault('timeout', {})
        cli_overrides['scan']['timeout']['connect'] = args.timeout
        cli_overrides['scan']['timeout']['read'] = args.timeout
    
    if args.user_agent:
        cli_overrides.setdefault('scan', {})['user_agent'] = args.user_agent
    
    if args.no_verify_ssl:
        cli_overrides.setdefault('scan', {})['verify_ssl'] = False
    
    if args.threads is not None:
        if args.threads <= 0:
            logger.error(f"Invalid thread count: {args.threads}. Must be positive (> 0).")
            print(f"ERROR: --threads must be a positive number (got {args.threads})")
            return 1
        
        cli_overrides.setdefault('advanced', {})['max_workers'] = args.threads
        logger.debug(f"Thread pool size override: {args.threads} workers")
    
    if args.use_ai:
        cli_overrides.setdefault('ai', {})['enabled'] = True
    
    config = Config.load(cli_overrides=cli_overrides)
    config.expand_paths()
    config.ensure_directories()
    set_config(config)
    
    # Setup logging
    if args.quiet:
        log_level = 'WARNING'
    else:
        # Map verbosity to log level
        verbosity_map = {0: 'WARNING', 1: 'INFO', 2: 'DEBUG', 3: 'DEBUG'}
        log_level = verbosity_map.get(args.verbose, 'DEBUG')
    
    setup_logging(
        level=log_level,
        log_file=config.log_file,
        json_format=args.log_json,
        use_colors=not args.no_color,
        redact_secrets=config.log_redact_secrets
    )
    
    if args.verbose >= 2:
        set_verbosity(args.verbose)
    
    logger.info(f"Pythia v{config.version} starting")
    logger.debug(f"Configuration loaded from: {config.report_dir.parent}")
    
    # Route to appropriate handler
    try:
        if args.gen_consent:
            return handle_gen_consent(args, config)
        
        elif args.verify_consent:
            return handle_verify_consent(args, config)
        
        elif args.target:
            return handle_scan(args, config)
        
        else:
            parser.print_help()
            return 0
    
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user (Ctrl+C)\n")
        return 130  # Exit code 130 = Ctrl+C
    
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\n❌ UNEXPECTED ERROR: {e}\n")
        return 1  # Exit code 1 = unexpected error


if __name__ == '__main__':
    sys.exit(main())
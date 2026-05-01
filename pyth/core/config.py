"""
Pythia Configuration Loader
Handles configuration from multiple sources with priority:
1. Command-line arguments (highest priority)
2. Environment variables
3. User config file (~/.pythia/config.yaml)
4. Default config (config/default.yaml)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field


@dataclass
class Config:
    """
    Configuration container for Pythia SQL Injection Scanner.
    
    All settings are accessible as attributes with dot notation.
    """
    
    # ========================================================================
    # CLASS-LEVEL DEFAULTS (for mutable types)
    # ========================================================================
    
    # SQL Error patterns for different DBMS
    DEFAULT_ERROR_PATTERNS = [
        # MySQL
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "MySQLSyntaxErrorException",
        
        # PostgreSQL
        "pg_query\\(\\)",
        "PostgreSQL query failed",
        "PSQLException",
        
        # MSSQL
        "Microsoft SQL Server",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        
        # Oracle
        "ORA-\\d{5}",
        "Oracle error",
        
        # SQLite
        "SQLite3::SQLException",
        "System\\.Data\\.SQLite\\.SQLiteException",
        
        # Generic
        "SQL syntax.*MySQL",
        "Syntax error.*SQL",
        "Unclosed quotation"
    ]
    
    # Error-based SQLi payloads
    DEFAULT_ERROR_PAYLOADS = [
        "'", '"', "1'", '1"',
        "' OR '1'='1", '" OR "1"="1',
        "admin'--", 'admin"--',
        "1' AND '1'='1", "' OR 1=1--"
    ]
    
    # Boolean blind payloads
    DEFAULT_BOOLEAN_TRUE = [
        " AND 1=1", " OR 1=1",
        " AND 'a'='a", " OR 'x'='x'"
    ]
    
    DEFAULT_BOOLEAN_FALSE = [
        " AND 1=0", " OR 1=0",
        " AND 'a'='b", " OR 'x'='y'"
    ]
    
    # Time-based payloads (aggressive mode)
    DEFAULT_TIME_PAYLOADS = [
        "; SELECT SLEEP(3)--",
        "'; SELECT SLEEP(3)--",
        "; WAITFOR DELAY '0:0:3'--",
        "'; WAITFOR DELAY '0:0:3'--",
        "; SELECT pg_sleep(3)--",
        "'; SELECT pg_sleep(3)--"
    ]
    
    # Crawler exclude extensions
    DEFAULT_EXCLUDE_EXTENSIONS = [
        ".jpg", ".jpeg", ".png", ".gif", ".pdf",
        ".zip", ".tar", ".gz", ".mp3", ".mp4",
        ".css", ".js", ".woff", ".ttf"
    ]
    
    # Form skip patterns
    DEFAULT_SKIP_FORM_PATTERNS = [
        "logout", "signout", "delete", "remove", "unsubscribe"
    ]
    
    # Form testable types
    DEFAULT_TESTABLE_TYPES = [
        "text", "search", "email", "url", "tel", "number", "hidden"
    ]
    
    DEFAULT_CUSTOM_HEADERS = {}
    
    # ========================================================================
    # INSTANCE ATTRIBUTES
    # ========================================================================
    
    # General
    version: str = "0.2.0"
    author: str = "Rodney Dhavid Jimenez Chacin (rodhnin)"
    github: str = "https://github.com/rodhnin"
    contact: str = "https://rodhnin.com"
    
    # Paths
    report_dir: Path = Path.home() / ".pythia" / "reports"
    database: Path = Path.home() / ".argos" / "argos.db"
    log_file: Optional[Path] = Path.home() / ".pythia" / "pythia.log"
    consent_proofs_dir: Path = Path.home() / ".pythia" / "consent-proofs"
    
    # Scan behavior
    default_mode: str = "safe"
    rate_limit_safe: float = 2.0
    rate_limit_aggressive: float = 5.0
    timeout_connect: int = 10
    timeout_read: int = 30
    user_agent: str = "Pythia/0.1.0"
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = True
    
    # SQLi Detection Settings
    sqli_error_patterns: List[str] = field(default_factory=lambda: Config.DEFAULT_ERROR_PATTERNS.copy())
    sqli_error_payloads: List[str] = field(default_factory=lambda: Config.DEFAULT_ERROR_PAYLOADS.copy())
    sqli_boolean_true: List[str] = field(default_factory=lambda: Config.DEFAULT_BOOLEAN_TRUE.copy())
    sqli_boolean_false: List[str] = field(default_factory=lambda: Config.DEFAULT_BOOLEAN_FALSE.copy())
    sqli_time_payloads: List[str] = field(default_factory=lambda: Config.DEFAULT_TIME_PAYLOADS.copy())
    sqli_time_threshold: float = 2.5
    sqli_min_length_diff: int = 100
    sqli_high_confidence_diff: int = 500
    sqli_medium_confidence_diff: int = 200
    sqli_min_consistent_results: int = 2
    
    # Crawler Settings
    crawler_max_depth: int = 2
    crawler_max_pages: int = 100
    crawler_same_domain: bool = True
    crawler_follow_redirects: bool = True
    crawler_exclude_extensions: List[str] = field(default_factory=lambda: Config.DEFAULT_EXCLUDE_EXTENSIONS.copy())
    crawler_exclude_patterns: List[str] = field(default_factory=list)
    crawler_respect_robots: bool = True
    crawler_js_rendering: bool = False
    crawler_delay: float = 0.5
    crawler_no_crawl: bool = False
    
    # Form Testing Settings
    forms_enable_post: bool = True
    forms_max_inputs: int = 20
    forms_testable_types: List[str] = field(default_factory=lambda: Config.DEFAULT_TESTABLE_TYPES.copy())
    forms_skip_patterns: List[str] = field(default_factory=lambda: Config.DEFAULT_SKIP_FORM_PATTERNS.copy())
    forms_preserve_hidden: bool = True
    
    # Consent token
    token_expiry_hours: int = 48
    token_hex_length: int = 16
    http_verification_path: str = "/.well-known/"
    dns_txt_prefix: str = "pythia-verify="
    verification_retries: int = 3
    verification_retry_delay: int = 2
    
    # Reporting
    generate_json: bool = True
    generate_html: bool = False
    json_indent: int = 2
    html_include_evidence: bool = True
    html_css_inline: bool = True
    
    # Logging
    log_level: str = "INFO"
    log_json_format: bool = False
    log_colors: bool = True
    log_redact_secrets: bool = True
    
    # AI integration (LangChain)
    ai_enabled: bool = False
    ai_provider: str = "openai"
    ai_model: str = "gpt-4o-mini-2024-07-18"
    ai_temperature: float = 0.3
    ai_max_tokens: int = 2000
    ai_api_key_env: str = "OPENAI_API_KEY"
    ai_prompts_dir: Path = Path("config/prompts")
    ai_remove_urls: bool = False
    ai_remove_tokens: bool = True
    ai_remove_credentials: bool = True
    ai_max_evidence_length: int = 500
    ai_ollama_base_url: str = "http://localhost:11434"
    # Budget limits (IMPROV-005)
    ai_budget_enabled: bool = False
    ai_max_cost_per_scan: float = 0.50
    ai_warn_threshold: float = 0.80
    ai_abort_on_exceed: bool = True
    # Streaming (IMPROV-006)
    ai_streaming: bool = False
    # Agent with tools (IMPROV-008)
    ai_agent_enabled: bool = False
    ai_agent_max_iterations: int = 5
    
    # Advanced
    max_workers: int = 5
    cache_responses: bool = False
    cache_ttl_seconds: int = 3600
    custom_headers: Dict[str, str] = field(default_factory=lambda: Config.DEFAULT_CUSTOM_HEADERS.copy())
    proxy_http: Optional[str] = None
    proxy_https: Optional[str] = None
    
    # Docker
    in_container: bool = False
    container_report_dir: Path = Path("/reports")
    container_db_path: Path = Path("/data/argos.db")
    
    @classmethod
    def load(
        cls,
        config_file: Optional[Path] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> "Config":
        """
        Load configuration from multiple sources.
        
        Args:
            config_file: Path to user config file (default: ~/.pythia/config.yaml)
            cli_overrides: Dictionary of CLI argument overrides
        
        Returns:
            Configured Config instance
        """
        # Start with defaults
        config_dict = cls._load_defaults()
        
        # Merge user config file if exists
        if config_file is None:
            config_file = Path.home() / ".pythia" / "config.yaml"
        
        if config_file.exists():
            user_config = cls._load_yaml(config_file)
            config_dict = cls._deep_merge(config_dict, user_config)
        
        # Apply environment variables
        env_config = cls._load_env_vars()
        config_dict = cls._deep_merge(config_dict, env_config)
        
        # Apply CLI overrides (highest priority)
        if cli_overrides:
            config_dict = cls._deep_merge(config_dict, cli_overrides)
        
        # Flatten nested dict to Config attributes
        return cls._dict_to_config(config_dict)
    
    @staticmethod
    def _load_defaults() -> Dict[str, Any]:
        """Load default configuration from config/default.yaml."""
        current_file = Path(__file__).resolve()
        defaults_path = current_file.parent.parent.parent.parent / "config" / "default.yaml"
        
        if not defaults_path.exists():
            return {}
        
        try:
            with defaults_path.open('r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, Exception):
            return {}
    
    @staticmethod
    def _load_yaml(path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with path.open('r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, Exception):
            return {}
    
    @staticmethod
    def _load_env_vars() -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}
        
        # PYTHIA_RATE_LIMIT=5.0
        if 'PYTHIA_RATE_LIMIT' in os.environ:
            env_config.setdefault('scan', {}).setdefault('rate_limit', {})
            env_config['scan']['rate_limit']['safe_mode'] = float(os.environ['PYTHIA_RATE_LIMIT'])
        
        # PYTHIA_LOG_LEVEL=DEBUG
        if 'PYTHIA_LOG_LEVEL' in os.environ:
            env_config.setdefault('logging', {})['level'] = os.environ['PYTHIA_LOG_LEVEL']
        
        # PYTHIA_AI_MODEL=gpt-4
        if 'PYTHIA_AI_MODEL' in os.environ:
            env_config.setdefault('ai', {}).setdefault('langchain', {})
            env_config['ai']['langchain']['model'] = os.environ['PYTHIA_AI_MODEL']
        
        # PYTHIA_AI_PROVIDER=ollama
        if 'PYTHIA_AI_PROVIDER' in os.environ:
            env_config.setdefault('ai', {}).setdefault('langchain', {})
            env_config['ai']['langchain']['provider'] = os.environ['PYTHIA_AI_PROVIDER']

        # PYTHIA_DOCKER_IN_CONTAINER=true
        if 'PYTHIA_DOCKER_IN_CONTAINER' in os.environ:
            env_config.setdefault('docker', {})
            env_config['docker']['in_container'] = os.environ['PYTHIA_DOCKER_IN_CONTAINER'].lower() in ('true', '1', 'yes')

        return env_config
    
    @staticmethod
    def _deep_merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    @classmethod
    def _dict_to_config(cls, config_dict: Dict[str, Any]) -> "Config":
        """Convert nested dict to flat Config instance."""
        flat = {}
        
        # General
        if 'general' in config_dict:
            gen = config_dict['general']
            flat['version'] = gen.get('version', cls.version)
            flat['author'] = gen.get('author', cls.author)
            flat['github'] = gen.get('github', cls.github)
            flat['contact'] = gen.get('contact', cls.contact)
        
        # Paths
        if 'paths' in config_dict:
            paths = config_dict['paths']
            flat['report_dir'] = Path(paths.get('report_dir', cls.report_dir))
            flat['database'] = Path(paths.get('database', cls.database))
            log_file = paths.get('log_file')
            flat['log_file'] = Path(log_file) if log_file else None
            flat['consent_proofs_dir'] = Path(paths.get('consent_proofs_dir', cls.consent_proofs_dir))
        
        # Scan
        if 'scan' in config_dict:
            scan = config_dict['scan']
            flat['default_mode'] = scan.get('default_mode', cls.default_mode)
            if 'rate_limit' in scan:
                flat['rate_limit_safe'] = scan['rate_limit'].get('safe_mode', cls.rate_limit_safe)
                flat['rate_limit_aggressive'] = scan['rate_limit'].get('aggressive_mode', cls.rate_limit_aggressive)
            if 'timeout' in scan:
                flat['timeout_connect'] = scan['timeout'].get('connect', cls.timeout_connect)
                flat['timeout_read'] = scan['timeout'].get('read', cls.timeout_read)
            flat['user_agent'] = scan.get('user_agent', cls.user_agent)
            flat['follow_redirects'] = scan.get('follow_redirects', cls.follow_redirects)
            flat['max_redirects'] = scan.get('max_redirects', cls.max_redirects)
            flat['verify_ssl'] = scan.get('verify_ssl', cls.verify_ssl)
        
        # SQLi Settings
        if 'sqli' in config_dict:
            sqli = config_dict['sqli']
            flat['sqli_error_patterns'] = sqli.get('error_patterns', cls.DEFAULT_ERROR_PATTERNS.copy())
            flat['sqli_error_payloads'] = sqli.get('error_payloads', cls.DEFAULT_ERROR_PAYLOADS.copy())
            
            if 'boolean_payloads' in sqli:
                flat['sqli_boolean_true'] = sqli['boolean_payloads'].get('true', cls.DEFAULT_BOOLEAN_TRUE.copy())
                flat['sqli_boolean_false'] = sqli['boolean_payloads'].get('false', cls.DEFAULT_BOOLEAN_FALSE.copy())
            
            flat['sqli_time_payloads'] = sqli.get('time_based_payloads', cls.DEFAULT_TIME_PAYLOADS.copy())
            flat['sqli_time_threshold'] = sqli.get('time_threshold', cls.sqli_time_threshold)
            
            if 'boolean_blind' in sqli:
                bb = sqli['boolean_blind']
                flat['sqli_min_length_diff'] = bb.get('min_length_diff', cls.sqli_min_length_diff)
                flat['sqli_high_confidence_diff'] = bb.get('high_confidence_length_diff', cls.sqli_high_confidence_diff)
                flat['sqli_medium_confidence_diff'] = bb.get('medium_confidence_length_diff', cls.sqli_medium_confidence_diff)
                flat['sqli_min_consistent_results'] = bb.get('min_consistent_results', cls.sqli_min_consistent_results)
        
        # Crawler Settings
        if 'crawler' in config_dict:
            crawler = config_dict['crawler']
            flat['crawler_max_depth'] = crawler.get('max_depth', cls.crawler_max_depth)
            flat['crawler_max_pages'] = crawler.get('max_pages', cls.crawler_max_pages)
            flat['crawler_same_domain'] = crawler.get('same_domain_only', cls.crawler_same_domain)
            flat['crawler_follow_redirects'] = crawler.get('follow_redirects', cls.crawler_follow_redirects)
            flat['crawler_exclude_extensions'] = crawler.get('exclude_extensions', cls.DEFAULT_EXCLUDE_EXTENSIONS.copy())
            flat['crawler_exclude_patterns'] = crawler.get('exclude_patterns', [])
            flat['crawler_respect_robots'] = crawler.get('respect_robots_txt', cls.crawler_respect_robots)
            flat['crawler_js_rendering'] = crawler.get('js_rendering', cls.crawler_js_rendering)
            flat['crawler_delay'] = crawler.get('crawl_delay', cls.crawler_delay)
            flat['crawler_no_crawl'] = crawler.get('no_crawl', cls.crawler_no_crawl)
        
        # Form Settings
        if 'forms' in config_dict:
            forms = config_dict['forms']
            flat['forms_enable_post'] = forms.get('enable_post_testing', cls.forms_enable_post)
            flat['forms_max_inputs'] = forms.get('max_inputs_per_form', cls.forms_max_inputs)
            flat['forms_testable_types'] = forms.get('testable_input_types', cls.DEFAULT_TESTABLE_TYPES.copy())
            flat['forms_skip_patterns'] = forms.get('skip_form_patterns', cls.DEFAULT_SKIP_FORM_PATTERNS.copy())
            flat['forms_preserve_hidden'] = forms.get('preserve_hidden_fields', cls.forms_preserve_hidden)
        
        # Consent
        if 'consent' in config_dict:
            consent = config_dict['consent']
            flat['token_expiry_hours'] = consent.get('token_expiry_hours', cls.token_expiry_hours)
            flat['token_hex_length'] = consent.get('token_hex_length', cls.token_hex_length)
            flat['http_verification_path'] = consent.get('http_verification_path', cls.http_verification_path)
            flat['dns_txt_prefix'] = consent.get('dns_txt_prefix', cls.dns_txt_prefix)
            flat['verification_retries'] = consent.get('verification_retries', cls.verification_retries)
            flat['verification_retry_delay'] = consent.get('verification_retry_delay', cls.verification_retry_delay)
        
        # Reporting
        if 'reporting' in config_dict:
            reporting = config_dict['reporting']
            if 'format' in reporting:
                flat['generate_json'] = reporting['format'].get('json', cls.generate_json)
                flat['generate_html'] = reporting['format'].get('html', cls.generate_html)
            flat['json_indent'] = reporting.get('json_indent', cls.json_indent)
            if 'html' in reporting:
                flat['html_include_evidence'] = reporting['html'].get('include_evidence', cls.html_include_evidence)
                flat['html_css_inline'] = reporting['html'].get('css_inline', cls.html_css_inline)
        
        # Logging
        if 'logging' in config_dict:
            logging_cfg = config_dict['logging']
            flat['log_level'] = logging_cfg.get('level', cls.log_level)
            flat['log_json_format'] = logging_cfg.get('json_format', cls.log_json_format)
            flat['log_colors'] = logging_cfg.get('colors', cls.log_colors)
            if 'redact' in logging_cfg:
                flat['log_redact_secrets'] = logging_cfg['redact'].get('enabled', cls.log_redact_secrets)
        
        # AI
        if 'ai' in config_dict:
            ai = config_dict['ai']
            flat['ai_enabled'] = ai.get('enabled', cls.ai_enabled)
            
            if 'langchain' in ai:
                lc = ai['langchain']
                flat['ai_provider'] = lc.get('provider', cls.ai_provider)
                flat['ai_model'] = lc.get('model', cls.ai_model)
                flat['ai_temperature'] = lc.get('temperature', cls.ai_temperature)
                flat['ai_max_tokens'] = lc.get('max_tokens', cls.ai_max_tokens)
                flat['ai_ollama_base_url'] = lc.get('ollama_base_url', cls.ai_ollama_base_url)
            
            flat['ai_api_key_env'] = ai.get('api_key_env', cls.ai_api_key_env)
            prompts_dir = ai.get('prompts_dir', cls.ai_prompts_dir)
            flat['ai_prompts_dir'] = Path(prompts_dir) if prompts_dir else cls.ai_prompts_dir
            
            if 'sanitization' in ai:
                san = ai['sanitization']
                flat['ai_remove_urls'] = san.get('remove_urls', cls.ai_remove_urls)
                flat['ai_remove_tokens'] = san.get('remove_tokens', cls.ai_remove_tokens)
                flat['ai_remove_credentials'] = san.get('remove_credentials', cls.ai_remove_credentials)
                flat['ai_max_evidence_length'] = san.get('max_evidence_length', cls.ai_max_evidence_length)
        
        # Advanced
        if 'advanced' in config_dict:
            adv = config_dict['advanced']
            flat['max_workers'] = adv.get('max_workers', cls.max_workers)
            flat['cache_responses'] = adv.get('cache_responses', cls.cache_responses)
            flat['cache_ttl_seconds'] = adv.get('cache_ttl_seconds', cls.cache_ttl_seconds)
            flat['custom_headers'] = adv.get('custom_headers', cls.DEFAULT_CUSTOM_HEADERS.copy())
            if 'proxy' in adv:
                flat['proxy_http'] = adv['proxy'].get('http', cls.proxy_http)
                flat['proxy_https'] = adv['proxy'].get('https', cls.proxy_https)
        
        # Docker
        if 'docker' in config_dict:
            docker = config_dict['docker']
            flat['in_container'] = docker.get('in_container', cls.in_container)
            flat['container_report_dir'] = Path(docker.get('container_report_dir', cls.container_report_dir))
            flat['container_db_path'] = Path(docker.get('container_db_path', cls.container_db_path))
        
        return cls(**flat)
    
    def expand_paths(self):
        """
        Expand paths based on environment (Docker or local).
        """
        if self.in_container:
            # Define default paths (before expansion)
            default_report = Path.home() / ".pythia" / "reports"
            default_db = Path.home() / ".argos" / "argos.db"

            # Expand user paths BEFORE comparing
            expanded_report = self.report_dir.expanduser()
            expanded_db = self.database.expanduser()

            # If using defaults, switch to container paths
            if expanded_report == default_report:
                self.report_dir = self.container_report_dir
            else:
                self.report_dir = expanded_report

            if expanded_db == default_db:
                self.database = self.container_db_path
            else:
                self.database = expanded_db
        else:
            # Local environment: just expand user paths
            self.report_dir = self.report_dir.expanduser()
            self.database = self.database.expanduser()

        # Always expand log_file and consent_proofs_dir
        if self.log_file:
            self.log_file = self.log_file.expanduser()
        self.consent_proofs_dir = self.consent_proofs_dir.expanduser()
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.consent_proofs_dir.mkdir(parents=True, exist_ok=True)


# Global config instance
_global_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = Config.load()
        _global_config.expand_paths()
    return _global_config


def set_config(config: Config):
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


if __name__ == "__main__":
    # Test configuration loading
    print("\n" + "="*70)
    print("PYTHIA CONFIGURATION TEST")
    print("="*70 + "\n")
    
    config = Config.load()
    config.expand_paths()
    
    print(f"Version: {config.version}")
    print(f"Report Dir: {config.report_dir}")
    print(f"Database: {config.database}")
    print(f"Rate Limit (safe): {config.rate_limit_safe} req/s")
    print(f"SQLi Error Patterns: {len(config.sqli_error_patterns)} patterns")
    print(f"SQLi Error Payloads: {len(config.sqli_error_payloads)} payloads")
    print(f"Crawler Max Depth: {config.crawler_max_depth}")
    print(f"\n AI Configuration:")
    print(f"   Enabled: {config.ai_enabled}")
    print(f"   Provider: {config.ai_provider}")
    print(f"   Model: {config.ai_model}")
    print(f"   Ollama URL: {config.ai_ollama_base_url}")
    print(f"\n" + "="*70)
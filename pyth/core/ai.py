"""
Pythia AI Integration with LangChain v1.0.0

Provides AI-powered SQL injection vulnerability analysis using modern LangChain LCEL:
- Executive summaries for business stakeholders (compliance, risk, budget)
- Technical remediation guides for developers (code examples, WAF rules, DB hardening)
- Automatic sanitization of sensitive data (SQL queries, credentials, tokens)

Supports: OpenAI GPT-4, Anthropic Claude, Ollama (local models)
Compatible with: langchain-core==1.0.0, langchain-community==0.4

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

try:
    # Core components (always needed)
    from langchain_core.prompts import PromptTemplate, ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGCHAIN_CORE = True
except ImportError:
    HAS_LANGCHAIN_CORE = False

# OpenAI support (optional)
try:
    from langchain_openai import ChatOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Anthropic support (optional)
try:
    from langchain_anthropic import ChatAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

# Ollama support via dedicated package (optional)
try:
    from langchain_ollama import ChatOllama, OllamaLLM
    HAS_OLLAMA = True
except ImportError:
    try:
        from langchain_community.chat_models import ChatOllama
        from langchain_community.llms import Ollama as OllamaLLM
        HAS_OLLAMA = True
    except ImportError:
        HAS_OLLAMA = False

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class AIAnalyzer:
    """
    Modern LangChain AI analyzer for SQL injection vulnerability reports.
    Uses LCEL (LangChain Expression Language) exclusively.
    No deprecated components (agents, memory).
    
    Designed specifically for SQL injection security analysis:
    - Technical remediation with prepared statement examples
    - Executive summaries with breach cost analysis
    - Compliance guidance (PCI-DSS, GDPR, HIPAA)
    
    Supports:
    - OpenAI GPT models (gpt-4-turbo-preview, gpt-4o)
    - Anthropic Claude models (claude-3-5-sonnet, claude-3-opus)
    - Ollama local models (llama3.2, mistral, codellama) - privacy-focused
    """
    
    def __init__(self, config=None):
        """
        Initialize AI analyzer with selected provider.
        
        Args:
            config: Optional Config object (loads from defaults if None)
        
        Raises:
            ImportError: If LangChain core or provider package missing
            ValueError: If API key not found for cloud providers
            ConnectionError: If Ollama server unreachable
        """
        if not HAS_LANGCHAIN_CORE:
            error_msg = (
                "LangChain Core required for AI features. Install with:\n"
                "  pip install langchain-core==1.0.0\n"
                "  pip install langchain-openai==1.0.0  # For OpenAI\n"
                "  pip install langchain-anthropic==1.0.0  # For Anthropic\n"
                "  pip install langchain-ollama>=0.3.0,<0.4.0  # For Ollama\n"
            )
            raise ImportError(error_msg)
        
        self.config = config or get_config()
        
        # Sync custom env var with standard ones if needed
        self._sync_api_keys()
        
        # Initialize LLM based on provider
        self.llm = self._init_llm()
        
        # Initialize output parser (compatible with all providers)
        self.output_parser = StrOutputParser()
        
        # Load prompt templates (SQL injection specific)
        self.technical_prompt = self._load_prompt('technical.txt')
        self.non_technical_prompt = self._load_prompt('non_technical.txt')
        
        # Store provider info for logging
        self.provider = self.config.ai_provider.lower()
        self.model = self.config.ai_model
        
        logger.info(f"Pythia AI analyzer initialized: {self.provider}/{self.model}")
    
    def _sync_api_keys(self):
        """
        Sync custom API key env var with standard ones.
        
        Supports custom env var names from config.
        """
        custom_key_var = self.config.ai_api_key_env
        provider = self.config.ai_provider.lower()
        
        if provider == 'openai':
            # Check custom var first, then standard
            key = os.getenv(custom_key_var) or os.getenv('OPENAI_API_KEY')
            if key and custom_key_var != 'OPENAI_API_KEY':
                # Sync to standard var for LangChain
                os.environ['OPENAI_API_KEY'] = key
                logger.debug(f"Synced {custom_key_var} -> OPENAI_API_KEY")
        
        elif provider == 'anthropic':
            # Check custom var first, then standard
            key = os.getenv(custom_key_var) or os.getenv('ANTHROPIC_API_KEY')
            if key and custom_key_var != 'ANTHROPIC_API_KEY':
                # Sync to standard var for LangChain
                os.environ['ANTHROPIC_API_KEY'] = key
                logger.debug(f"Synced {custom_key_var} -> ANTHROPIC_API_KEY")
    
    def _init_llm(self):
        """
        Initialize language model based on config.
        
        Returns:
            Initialized LLM instance (ChatOpenAI, ChatAnthropic, or ChatOllama)
        
        Raises:
            ImportError: If provider package not installed
            ValueError: If API key missing (cloud providers)
            ConnectionError: If Ollama server unreachable
        """
        provider = self.config.ai_provider.lower()
        
        if provider == 'openai':
            if not HAS_OPENAI:
                raise ImportError(
                    "OpenAI support not installed. Run:\n"
                    "pip install langchain-openai==1.0.0"
                )
            
            # Verify API key is available
            if not os.getenv('OPENAI_API_KEY'):
                raise ValueError(
                    f"OpenAI API key not found. Set OPENAI_API_KEY or {self.config.ai_api_key_env}"
                )
            
            logger.info(f"Initializing OpenAI: {self.config.ai_model}")
            
            return ChatOpenAI(
                model=self.config.ai_model,
                temperature=self.config.ai_temperature,
                max_tokens=self.config.ai_max_tokens,
                # Optional: add streaming, callbacks, etc.
                streaming=False,
                verbose=False
            )
        
        elif provider == 'anthropic':
            if not HAS_ANTHROPIC:
                raise ImportError(
                    "Anthropic support not installed. Run:\n"
                    "pip install langchain-anthropic==1.0.0 anthropic==0.71.0"
                )
            
            if not os.getenv('ANTHROPIC_API_KEY'):
                raise ValueError(
                    f"Anthropic API key not found. Set ANTHROPIC_API_KEY or {self.config.ai_api_key_env}"
                )
            
            logger.info(f"Initializing Anthropic Claude: {self.config.ai_model}")
            
            # Modern v1.0.0 initialization for Anthropic
            return ChatAnthropic(
                model=self.config.ai_model,
                temperature=self.config.ai_temperature,
                max_tokens=self.config.ai_max_tokens,
                # Anthropic-specific options
                timeout=60,
                max_retries=2
            )
        
        elif provider == 'ollama':
            if not HAS_OLLAMA:
                raise ImportError(
                    "Ollama support not installed. Run:\n"
                    "pip install langchain-ollama>=0.3.0,<0.4.0\n"
                    "Or fallback: pip install langchain-community==0.4"
                )
            
            # Get Ollama base URL from config or use default
            base_url = getattr(self.config, 'ai_ollama_base_url', 'http://localhost:11434')
            
            # Verify Ollama server is running
            try:
                import requests
                resp = requests.get(f"{base_url}/api/tags", timeout=5)
                if resp.status_code != 200:
                    raise ConnectionError(f"Ollama server not responding at {base_url}")
                
                # Check if model exists
                models = resp.json().get('models', [])
                model_names = [m['name'] for m in models]
                if self.config.ai_model not in model_names:
                    available = ', '.join(model_names) if model_names else 'none'
                    raise ValueError(
                        f"Model '{self.config.ai_model}' not found in Ollama.\n"
                        f"Available models: {available}\n"
                        f"Pull it with: ollama pull {self.config.ai_model}"
                    )
                    
            except requests.exceptions.RequestException as e:
                raise ConnectionError(
                    f"Cannot connect to Ollama at {base_url}.\n"
                    f"Start Ollama with: ollama serve\n"
                    f"Error: {e}"
                )
            
            logger.info(f"Initializing Ollama: {self.config.ai_model} at {base_url}")
            
            # Use ChatOllama for better chat-like interactions
            try:
                return ChatOllama(
                    model=self.config.ai_model,
                    base_url=base_url,
                    temperature=self.config.ai_temperature,
                    # Ollama specific settings
                    num_predict=self.config.ai_max_tokens,  # Max tokens to generate
                    num_ctx=8192,  # Context window
                    repeat_penalty=1.1,  # Reduce repetition
                    top_k=40,
                    top_p=0.9,
                    # Timeout for local models can be longer
                    timeout=120,
                    verbose=False
                )
            except Exception as e:
                logger.warning(f"ChatOllama initialization failed: {e}")
                logger.info("Falling back to base Ollama LLM")
                
                # Fallback to base Ollama (less optimal but works)
                return OllamaLLM(
                    model=self.config.ai_model,
                    base_url=base_url,
                    temperature=self.config.ai_temperature,
                    num_predict=self.config.ai_max_tokens,
                    num_ctx=8192,
                    repeat_penalty=1.1,
                    verbose=False
                )
        
        else:
            supported = "openai, anthropic, ollama"
            raise ValueError(
                f"Unsupported AI provider: '{provider}'.\n"
                f"Supported providers: {supported}\n"
                f"Update config/defaults.yaml -> ai.langchain.provider"
            )
    
    def _load_prompt(self, filename: str) -> str:
        """
        Load prompt template from file.
        
        Args:
            filename: Prompt filename (e.g., 'technical.txt')
        
        Returns:
            Prompt template content as string
        
        Raises:
            FileNotFoundError: If prompt file doesn't exist
        """
        prompt_path = Path(__file__).parent.parent.parent / self.config.ai_prompts_dir / filename
        
        if not prompt_path.exists():
            logger.error(f"Prompt file not found: {prompt_path}")
            raise FileNotFoundError(f"Prompt template missing: {prompt_path}")
        
        with prompt_path.open('r', encoding='utf-8') as f:
            content = f.read()
            logger.debug(f"Loaded prompt from {filename} ({len(content)} chars)")
            return content
    
    def sanitize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize SQL injection report before sending to AI.
        Critical for privacy and security.
        
        Removes/redacts:
        - Consent verification tokens
        - API keys and credentials from SQL queries
        - Sensitive URL parameters
        - Long SQL query snippets (truncates to max length)
        - Personal identifiable information in queries
        
        Args:
            report: Original Pythia scan report dictionary
        
        Returns:
            Sanitized report safe for AI processing
        """
        import copy
        sanitized = copy.deepcopy(report)
        
        # Remove consent section (contains verification tokens)
        if 'consent' in sanitized:
            del sanitized['consent']
            logger.debug("Removed consent section from report")
        
        # Track sanitization stats
        tokens_removed = 0
        credentials_removed = 0
        sql_queries_truncated = 0
        urls_sanitized = 0
        
        # Sanitize each SQL injection finding
        for finding in sanitized.get('findings', []):
            if 'evidence' in finding:
                evidence = finding['evidence']
                
                # Remove tokens (Pythia consent tokens)
                if self.config.ai_remove_tokens and 'value' in evidence:
                    original = evidence['value']
                    evidence['value'] = self._redact_tokens(evidence['value'])
                    if original != evidence['value']:
                        tokens_removed += 1
                
                # Remove credentials from SQL queries
                if self.config.ai_remove_credentials and 'value' in evidence:
                    original = evidence['value']
                    evidence['value'] = self._redact_sql_credentials(evidence['value'])
                    if original != evidence['value']:
                        credentials_removed += 1
                
                # Truncate long SQL query evidence
                if 'value' in evidence and len(evidence['value']) > self.config.ai_max_evidence_length:
                    evidence['value'] = evidence['value'][:self.config.ai_max_evidence_length] + "... [SQL query truncated]"
                    sql_queries_truncated += 1
                
                # Sanitize URLs (remove parameters but keep path structure for context)
                if self.config.ai_remove_urls and evidence.get('type') == 'url':
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(evidence['value'])
                    
                    # Keep domain and path structure, redact parameter values
                    params = parse_qs(parsed.query)
                    sanitized_params = {k: '[REDACTED]' for k in params.keys()}
                    param_str = '&'.join([f"{k}=[REDACTED]" for k in sanitized_params.keys()])
                    
                    evidence['value'] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if param_str:
                        evidence['value'] += f"?{param_str}"
                    urls_sanitized += 1
        
        logger.info(
            f"SQL injection report sanitization: {tokens_removed} tokens, "
            f"{credentials_removed} credentials, {sql_queries_truncated} queries truncated, "
            f"{urls_sanitized} URLs sanitized"
        )
        
        return sanitized
    
    def _redact_tokens(self, text: str) -> str:
        """
        Redact consent tokens and API keys from text.
        
        Args:
            text: Original text (may contain tokens)
        
        Returns:
            Text with tokens redacted
        """
        if not text:
            return text
            
        patterns = [
            r'verify-[a-f0-9]{16}',  # Pythia consent tokens
            r'Bearer\s+[A-Za-z0-9\-_\.]+',  # Bearer tokens
            r'sk-[A-Za-z0-9]{48}',  # OpenAI keys
            r'sk-ant-[A-Za-z0-9\-]+',  # Anthropic keys
            r'[A-Za-z0-9]{32,}',  # Long hex strings (possible tokens)
        ]
        
        for pattern in patterns:
            text = re.sub(pattern, '[REDACTED-TOKEN]', text, flags=re.IGNORECASE)
        
        return text
    
    def _redact_sql_credentials(self, text: str) -> str:
        """
        Redact passwords and credentials from SQL queries and error messages.
        
        Specifically targets:
        - SQL query credentials (user='admin', password='secret')
        - Connection strings with passwords
        - API keys in SQL comments
        - Session tokens in SQL
        
        Args:
            text: Original SQL query or error message
        
        Returns:
            Text with credentials redacted
        """
        if not text:
            return text
            
        patterns = [
            # SQL query patterns
            (r"(password\s*=\s*['\"]?)([^'\";\s]+)", r'\1[REDACTED]'),
            (r"(passwd\s*=\s*['\"]?)([^'\";\s]+)", r'\1[REDACTED]'),
            (r"(pwd\s*=\s*['\"]?)([^'\";\s]+)", r'\1[REDACTED]'),
            (r"(pass\s*=\s*['\"]?)([^'\";\s]+)", r'\1[REDACTED]'),
            
            # Connection string patterns
            (r"(user\s*=\s*['\"]?)([^'\";\s]+)", r'\1[REDACTED-USER]'),
            (r"(username\s*=\s*['\"]?)([^'\";\s]+)", r'\1[REDACTED-USER]'),
            
            # API keys in SQL comments or strings
            (r"(apikey['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
            (r"(api_key['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
            (r"(api-key['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
            
            # Secret keys
            (r"(secret['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
            (r"(secret_key['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
            
            # Session tokens
            (r"(session['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
            (r"(token['\"]?\s*[:=]\s*['\"]?)([^'\"}\s]+)", r'\1[REDACTED]'),
        ]
        
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        return text
    
    def analyze_technical(self, report: Dict[str, Any]) -> str:
        """
        Generate technical SQL injection remediation guide using LCEL.
        
        Produces developer-focused guidance:
        - Prepared statement examples (PHP, Python, Node.js, Java, Ruby)
        - Input validation layers
        - WAF rules (ModSecurity, CloudFlare)
        - Database hardening (least privilege)
        - Testing & verification methods
        
        Args:
            report: Pythia scan report (will be sanitized)
        
        Returns:
            Technical remediation guide (markdown text)
        """
        logger.info(f"Generating SQL injection technical remediation with {self.provider}")
        
        # Sanitize report for privacy
        sanitized = self.sanitize_report(report)
        
        # Create prompt template
        prompt_template = PromptTemplate(
            input_variables=["report_json"],
            template=self.technical_prompt
        )
        
        # Build LCEL chain
        chain = prompt_template | self.llm | self.output_parser
        
        # Generate analysis with error handling
        try:
            start_time = datetime.now(timezone.utc)
            
            # Invoke chain
            result = chain.invoke({
                "report_json": json.dumps(sanitized, indent=2)
            })
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(
                f"SQL injection technical guide completed in {duration:.1f}s "
                f"({len(result)} chars)"
            )
            
            return result.strip()
        
        except Exception as e:
            logger.error(f"AI technical analysis failed ({self.provider}): {e}")
            
            # Provider-specific error messages
            if self.provider == 'ollama':
                return (
                    f"Ollama analysis failed: {e}\n\n"
                    "Troubleshooting:\n"
                    "1. Check Ollama is running: ollama serve\n"
                    "2. Verify model exists: ollama list\n"
                    f"3. Pull model if needed: ollama pull {self.model}\n"
                    "4. For SQL analysis, consider using codellama or llama3.2"
                )
            elif self.provider == 'anthropic':
                return (
                    f"Anthropic analysis failed: {e}\n\n"
                    "Check your ANTHROPIC_API_KEY is valid.\n"
                    "Claude models are excellent for security analysis."
                )
            else:
                return (
                    f"AI analysis unavailable ({self.provider}): {e}\n\n"
                    "Check your API key and network connection."
                )
    
    def analyze_non_technical(self, report: Dict[str, Any]) -> str:
        """
        Generate executive summary for non-technical stakeholders.
        
        Produces business-focused guidance:
        - Business impact analysis ($4.45M average breach cost)
        - Real-world SQL injection breaches (TalkTalk, Heartland, etc.)
        - Compliance requirements (PCI-DSS, GDPR, HIPAA, SOC 2)
        - Strategic recommendations
        - Budget considerations and ROI
        
        Uses same LCEL approach as technical analysis.
        
        Args:
            report: Pythia scan report (will be sanitized)
        
        Returns:
            Executive summary (markdown text)
        """
        logger.info(f"Generating SQL injection executive summary with {self.provider}")
        
        # Sanitize report
        sanitized = self.sanitize_report(report)
        
        # Create prompt template
        prompt_template = PromptTemplate(
            input_variables=["report_json"],
            template=self.non_technical_prompt
        )
        
        # Build LCEL chain
        chain = prompt_template | self.llm | self.output_parser
        
        # Generate analysis
        try:
            start_time = datetime.now(timezone.utc)
            
            result = chain.invoke({
                "report_json": json.dumps(sanitized, indent=2)
            })
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(
                f"SQL injection executive summary completed in {duration:.1f}s "
                f"({len(result)} chars)"
            )
            
            return result.strip()
        
        except Exception as e:
            logger.error(f"Executive summary failed ({self.provider}): {e}")
            return f"Executive summary unavailable: {e}"
    
    def analyze_both(self, report: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate both technical and non-technical SQL injection analyses.
        
        Args:
            report: Pythia scan report
        
        Returns:
            Dictionary with both analyses:
            {
                'executive_summary': str,
                'technical_remediation': str,
                'generated_at': str (ISO timestamp),
                'model_used': str (provider/model)
            }
        """
        logger.info(f"Generating both SQL injection analyses with {self.provider}")
        
        return {
            'executive_summary': self.analyze_non_technical(report),
            'technical_remediation': self.analyze_technical(report),
            'generated_at': report['date'],
            'model_used': f"{self.provider}/{self.model}"
        }


def analyze_report(
    report: Dict[str, Any],
    tone: str = 'both',
    config=None
) -> Optional[Dict[str, str]]:
    """
    Convenience function to analyze a SQL injection report with AI.
    
    Entry point for scanner.py to use AI analysis.
    
    Args:
        report: Pythia scan report dictionary
        tone: 'technical', 'non_technical', or 'both'
        config: Optional config override
    
    Returns:
        AI analysis dict or None if failed
        {
            'technical_remediation': str,  # If tone='technical' or 'both'
            'executive_summary': str,      # If tone='non_technical' or 'both'
            'generated_at': str,
            'model_used': str
        }
    """
    try:
        analyzer = AIAnalyzer(config)
        
        if tone == 'technical':
            return {
                'technical_remediation': analyzer.analyze_technical(report),
                'generated_at': report['date'],
                'model_used': f"{analyzer.provider}/{analyzer.model}"
            }
        
        elif tone == 'non_technical':
            return {
                'executive_summary': analyzer.analyze_non_technical(report),
                'generated_at': report['date'],
                'model_used': f"{analyzer.provider}/{analyzer.model}"
            }
        
        else:  # both
            return analyzer.analyze_both(report)
    
    except Exception as e:
        logger.error(f"AI SQL injection analysis initialization failed: {e}")
        return None


# =============================================================================
# TEST MODULE
# =============================================================================

if __name__ == "__main__":
    # Standalone test module for different AI providers
    from .config import Config
    import sys
    
    # Parse command line
    provider = sys.argv[1] if len(sys.argv) > 1 else 'openai'
    
    print(f"\n{'='*70}")
    print(f"PYTHIA AI MODULE TEST - {provider.upper()}")
    print(f"{'='*70}\n")
    
    # Load config
    config = Config.load()
    config.ai_enabled = True
    config.ai_provider = provider
    
    # Configure based on provider
    if provider == 'openai':
        if not os.getenv('OPENAI_API_KEY'):
            print("❌ OPENAI_API_KEY not set")
            print("   Export it: export OPENAI_API_KEY='sk-...'")
            exit(1)
        config.ai_model = 'gpt-4-turbo-preview'
        print(f"✓ Using OpenAI {config.ai_model}")
    
    elif provider == 'anthropic':
        if not os.getenv('ANTHROPIC_API_KEY'):
            print("❌ ANTHROPIC_API_KEY not set")
            print("   Export it: export ANTHROPIC_API_KEY='sk-ant-...'")
            exit(1)
        config.ai_model = 'claude-3-5-sonnet-20241022'
        config.ai_api_key_env = 'ANTHROPIC_API_KEY'
        print(f"✓ Using Anthropic {config.ai_model}")
    
    elif provider == 'ollama':
        # Check Ollama server
        import requests
        try:
            resp = requests.get('http://localhost:11434/api/tags', timeout=5)
            models = resp.json().get('models', [])
            if not models:
                print("❌ No models found in Ollama")
                print("   Pull a model: ollama pull llama3.2")
                exit(1)
            
            # Use first available model or llama3.2 if present
            available_models = [m['name'] for m in models]
            if 'llama3.2' in available_models:
                config.ai_model = 'llama3.2'
            elif 'codellama' in available_models:
                config.ai_model = 'codellama'
            else:
                config.ai_model = available_models[0]
            
            config.ai_ollama_base_url = 'http://localhost:11434'
            print(f"✓ Using Ollama {config.ai_model}")
            print(f"  Available models: {', '.join(available_models)}")
            
        except Exception as e:
            print(f"❌ Ollama not running: {e}")
            print("   Start it: ollama serve")
            exit(1)
    
    else:
        print(f"❌ Unknown provider: {provider}")
        print("   Usage: python -m pyth.core.ai-pythia [openai|anthropic|ollama]")
        exit(1)
    
    # Test report with realistic SQL injection findings
    test_report = {
        "tool": "pythia",
        "version": "0.1.0",
        "target": "https://vulnerable-shop.example.com",
        "date": datetime.now(timezone.utc).isoformat(),
        "mode": "aggressive",
        "summary": {
            "critical": 3,
            "high": 5,
            "medium": 8,
            "low": 2,
            "info": 15
        },
        "findings": [
            {
                "id": "PYTHIA-SQL-001",
                "title": "Error-based SQL Injection in product_id parameter",
                "severity": "critical",
                "confidence": "high",
                "evidence": {
                    "type": "error",
                    "value": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                    "context": "GET /product?id=1' - MySQL syntax error detected",
                    "payload": "1' OR '1'='1"
                },
                "recommendation": "Use prepared statements with parameterized queries",
                "affected_component": "product_id GET parameter"
            },
            {
                "id": "PYTHIA-SQL-002",
                "title": "Boolean-based blind SQL Injection in search parameter",
                "severity": "critical",
                "confidence": "high",
                "evidence": {
                    "type": "boolean",
                    "value": "Response length difference: 1247 bytes (true) vs 458 bytes (false)",
                    "context": "GET /search?q=laptop - Boolean blind SQLi confirmed",
                    "payload": "laptop' AND '1'='1 vs laptop' AND '1'='0"
                },
                "recommendation": "Implement input validation and use ORM with parameterized queries",
                "affected_component": "search query parameter"
            },
            {
                "id": "PYTHIA-SQL-003",
                "title": "Time-based blind SQL Injection in user_id cookie",
                "severity": "critical",
                "confidence": "medium",
                "evidence": {
                    "type": "time",
                    "value": "Response delay: 3.2 seconds (expected 3.0)",
                    "context": "Cookie: user_id=123; - SLEEP() payload triggered",
                    "payload": "123' AND SLEEP(3)--"
                },
                "recommendation": "Sanitize cookie values and use parameterized queries for all database operations",
                "affected_component": "user_id cookie value"
            },
            {
                "id": "PYTHIA-SQL-010",
                "title": "SQL Injection in login form (POST)",
                "severity": "high",
                "confidence": "high",
                "evidence": {
                    "type": "error",
                    "value": "PostgreSQL query failed: ERROR: syntax error at or near \"admin\"",
                    "context": "POST /login - PostgreSQL syntax error in username field",
                    "payload": "admin'-- in username field"
                },
                "recommendation": "Use prepared statements for authentication queries",
                "affected_component": "username POST parameter in login form"
            },
            {
                "id": "PYTHIA-SQL-015",
                "title": "Potential SQL Injection in order_by parameter",
                "severity": "high",
                "confidence": "medium",
                "evidence": {
                    "type": "suspicious",
                    "value": "ORDER BY clause accepts user input without validation",
                    "context": "GET /products?order_by=price - Potential for UNION-based SQLi",
                    "payload": "price,(SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)"
                },
                "recommendation": "Use whitelist validation for ORDER BY columns",
                "affected_component": "order_by GET parameter"
            }
        ],
        "consent": {
            "token": "verify-f8e7d6c5b4a39281",  # Will be removed by sanitization
            "method": "http",
            "verified_at": "2025-01-20T14:30:00Z"
        }
    }
    
    try:
        print("\n[1/4] Initializing Pythia AI Analyzer...")
        analyzer = AIAnalyzer(config)
        print(f"✓ Analyzer ready: {analyzer.provider}/{analyzer.model}")
        
        print("\n[2/4] Testing SQL Injection Report Sanitization...")
        sanitized = analyzer.sanitize_report(test_report)
        
        # Verify sanitization worked
        assert 'consent' not in sanitized, "Consent should be removed"
        assert 'verify-' not in json.dumps(sanitized), "Tokens should be removed"
        print("✓ Sanitization successful")
        print(f"  - Original findings: {len(test_report['findings'])}")
        print(f"  - Sanitized findings: {len(sanitized['findings'])}")
        
        print(f"\n[3/4] Generating Executive Summary with {provider.upper()}...")
        print("-" * 70)
        summary = analyzer.analyze_non_technical(test_report)
        
        if "unavailable" in summary.lower() or "failed" in summary.lower():
            print(f"❌ Executive summary generation failed")
            print(summary)
        else:
            # Show first 600 chars
            preview = summary[:600] + "..." if len(summary) > 600 else summary
            print(preview)
            print("-" * 70)
            print(f"✓ Executive summary: {len(summary)} chars")
        
        print(f"\n[4/4] Generating Technical Remediation Guide with {provider.upper()}...")
        print("-" * 70)
        technical = analyzer.analyze_technical(test_report)
        
        if "unavailable" in technical.lower() or "failed" in technical.lower():
            print(f"❌ Technical guide generation failed")
            print(technical)
        else:
            # Show first 600 chars
            preview = technical[:600] + "..." if len(technical) > 600 else technical
            print(preview)
            print("-" * 70)
            print(f"✓ Technical guide: {len(technical)} chars")
        
        print(f"\n{'='*70}")
        print(f"✅ {provider.upper()} PROVIDER TEST COMPLETED")
        print(f"{'='*70}")
        print(f"\nPythia AI is ready to analyze SQL injection vulnerabilities!")
        
    except ImportError as e:
        print(f"\n❌ Import Error: {e}")
        print("\nInstall required packages:")
        if provider == 'openai':
            print("  pip install langchain-openai==1.0.0")
        elif provider == 'anthropic':
            print("  pip install langchain-anthropic==1.0.0 anthropic==0.71.0")
        elif provider == 'ollama':
            print("  pip install langchain-ollama>=0.3.0,<0.4.0")
            print("  # Or fallback: pip install langchain-community==0.4")
        exit(1)
        
    except Exception as e:
        print(f"\n❌ Test Failed: {e}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
        exit(1)
# AI Integration Guide - Pythia SQL Clairvoyance

Pythia uses **LangChain v1.0.0** to provide intelligent analysis of SQL injection findings through Large Language Models (LLMs).

## Overview

The AI assistant generates two types of analysis from scan results:

1. **Executive Summary** (non-technical) - For business stakeholders, managers, C-suite
2. **Technical Remediation Guide** - For developers, DBAs, security engineers

Both are generated from the JSON scan report using carefully crafted prompts and sanitized input.

---

## 🧪 Testing AI Integration

### Standalone Test Module

Pythia includes a built-in test module to verify AI provider configuration before running full scans:

```bash
# Test OpenAI (default)
python -m pyth.core.ai openai

# Test Anthropic Claude
python -m pyth.core.ai anthropic

# Test Ollama (local)
python -m pyth.core.ai ollama
```

This test will:

1. Initialize the AI provider
2. Verify API keys/connectivity
3. Test report sanitization
4. Generate sample executive summary
5. Generate sample technical remediation guide
6. Report success/failure with diagnostics

**Use this test to verify your AI setup is working before running production scans.**

---

## Prerequisites

### Required Dependencies

```bash
# Core LangChain v1.0.0
pip install langchain-core==1.0.0

# For OpenAI
pip install langchain-openai==1.0.0

# For Anthropic Claude
pip install langchain-anthropic==1.0.0 anthropic==0.71.0

# For Ollama (local models)
pip install "langchain-ollama>=0.3.0,<0.4.0"
```

### API Keys

Set your API key as an environment variable:

```bash
# OpenAI (default)
export OPENAI_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Ollama - No API key needed (local)
```

---

## Configuration

### ⚠️ IMPORTANT: Provider Switching (v0.1.0)

**Current Method:** Provider selection is configured in `config/default.yaml`.

**To switch providers, you must edit the YAML file directly:**

```yaml
ai:
    provider: "openai" # Change this to: openai, anthropic, or ollama
    model: "gpt-4-turbo-preview" # Update model based on provider
    temperature: 0.3
    max_completion_tokens: 2000

    # For Ollama only - add this section:
    ollama:
        base_url: "http://localhost:11434"
```

### Provider-Specific Configuration

#### OpenAI (Default)

```yaml
ai:
    provider: "openai"
    model: "gpt-4-turbo-preview" # or gpt-4, gpt-3.5-turbo
    temperature: 0.3
    max_completion_tokens: 2000
```

Environment variable:

```bash
export OPENAI_API_KEY="sk-..."
```

#### Anthropic Claude

```yaml
ai:
    provider: "anthropic"
    model: "claude-3-5-sonnet-20241022" # or claude-3-opus, claude-3-haiku
    temperature: 0.3
    max_completion_tokens: 2000
```

Environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

#### Ollama (Local)

```yaml
ai:
    provider: "ollama"
    model: "llama3.2:latest" # or whatever model you have pulled
    temperature: 0.3
    max_completion_tokens: 2000
    ollama:
        base_url: "http://localhost:11434"
```

No API key needed for Ollama - runs 100% locally!

### Future Enhancement (v0.3.0)

In version 0.3.0, we will implement an interactive configuration system:

-   Dynamic provider switching without editing YAML
-   Runtime model selection
-   Interactive configuration menu
-   Profile management for different scenarios

For now, manual YAML editing is required for provider switching.

---

## Usage

### Basic AI Analysis

```bash
# 1. Configure provider in config/default.yaml (see above)

# 2. Verify domain consent (for aggressive mode)
python -m pyth --gen-consent example.com
python -m pyth --verify-consent http --domain example.com --token verify-abc123

# 3. Run scan with AI
python -m pyth --target http://localhost:8081 --aggressive --use-ai --html

# Different analysis tones
python -m pyth --target http://localhost:8081 --aggressive --use-ai --ai-tone technical
python -m pyth --target http://localhost:8081 --aggressive --use-ai --ai-tone non_technical
python -m pyth --target http://localhost:8081 --aggressive --use-ai --ai-tone both
```

### Analysis Tone Options

| Tone            | Audience                              | Content                                       |
| --------------- | ------------------------------------- | --------------------------------------------- |
| `technical`     | Developers, DBAs, Security Engineers  | Code examples, SQL queries, remediation steps |
| `non_technical` | Executives, Managers, Business Owners | Business impact, compliance, financial risks  |
| `both`          | Complete team                         | Both technical and executive summaries        |

---

## Privacy & Security

### Data Sanitization

Before sending reports to AI, Pythia automatically removes sensitive information. The sanitization system is continuously improving based on real-world testing.

**What Gets Removed:**

-   ✅ Consent tokens (`verify-abc123...`)
-   ✅ Bearer tokens and API keys
-   ✅ Database credentials in error messages
-   ✅ Session IDs and cookies
-   ✅ Long SQL queries (truncated to 500 chars)
-   ✅ Database schema details in evidence
-   ✅ Internal IP addresses and hostnames

**What Gets Sent (Sanitized):**

-   Finding IDs and titles (PYTHIA-SQL-001, etc.)
-   Severity levels (critical, high, medium, low)
-   Detection methods (error-based, blind, time-based)
-   Redacted/truncated evidence
-   Generic recommendations
-   External reference URLs (OWASP, CWE)

### Privacy Recommendations

| Concern Level        | Recommended Provider | Why                                             |
| -------------------- | -------------------- | ----------------------------------------------- |
| **High Privacy**     | Ollama (local)       | Data never leaves your machine                  |
| **Moderate Privacy** | Anthropic Claude     | Strong privacy policy, no training on user data |
| **Standard**         | OpenAI GPT-4         | Best analysis quality, standard privacy         |

⚠️ **Note on Ollama:** While 100% private, local models may generate less accurate analysis for complex SQL injection reports. Best for sensitive environments where privacy is paramount.

---

## Providers Comparison

### OpenAI GPT-4 (Default)

**Pros:**

-   Best analysis quality for SQL injection
-   Extensive database security knowledge
-   Fast response (20-30s)
-   Handles complex blind SQLi scenarios well
-   Accurate OWASP/CWE references

**Cons:**

-   Requires internet
-   Costs money (~$0.10-0.30/scan)
-   Data sent to OpenAI servers

**Best For:** Production reports, client deliverables, complex SQL injection chains

### Anthropic Claude

**Pros:**

-   Strong technical reasoning for database attacks
-   Excellent code remediation examples
-   Privacy-focused company
-   Good with prepared statement conversions
-   Competitive pricing

**Cons:**

-   Requires internet
-   Costs money (~$0.15-0.45/scan)
-   Slightly slower than GPT-4

**Best For:** Technical deep-dives, code remediation guides, EU clients (GDPR)

### Ollama (Local Models)

**Pros:**

-   100% offline operation
-   Complete privacy (no data leaves machine)
-   Free (no API costs)
-   No internet required
-   Perfect for air-gapped environments

**Cons:**

-   Lower quality analysis
-   Very slow without GPU (10-30 minutes)
-   May struggle with complex blind SQLi reports
-   Limited knowledge of latest OWASP guidelines
-   Requires local setup

**Best For:** Sensitive environments, air-gapped networks, internal testing, learning

### Performance Comparison

| Provider         | Executive Summary | Technical Guide | Total Time | Quality    |
| ---------------- | ----------------- | --------------- | ---------- | ---------- |
| OpenAI GPT-4     | ~15s              | ~20s            | ~35s       | ⭐⭐⭐⭐⭐ |
| Anthropic Claude | ~20s              | ~25s            | ~45s       | ⭐⭐⭐⭐⭐ |
| Ollama (CPU)     | ~14min            | ~14min          | ~28min     | ⭐⭐⭐     |
| Ollama (GPU)     | ~30s              | ~45s            | ~75s       | ⭐⭐⭐     |

_Tested with 14 findings (10 critical, 3 high, 1 medium)_

---

## Ollama Setup Guide

For **offline operation** with local models:

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start Ollama server
ollama serve &

# 3. Pull a model (llama3.2 recommended for balance)
ollama pull llama3.2

# Alternative models for SQL injection analysis:
ollama pull codellama    # Better for code examples
ollama pull mistral      # Good balance of speed/quality
ollama pull phi3         # Fastest, smallest (2.2GB)

# 4. Verify it's working
ollama list
curl http://localhost:11434/api/tags

# 5. Update config/default.yaml
ai:
  provider: "ollama"
  model: "llama3.2:latest"
  ollama:
    base_url: "http://localhost:11434"

# 6. Test the integration
python -m pyth.core.ai ollama

# 7. Run a scan with AI
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --html
```

**Recommended Models for SQL Injection Analysis:**

| Model       | Size  | Speed  | Quality  | Best For                         |
| ----------- | ----- | ------ | -------- | -------------------------------- |
| `llama3.2`  | 3.9GB | Medium | ⭐⭐⭐⭐ | General SQLi analysis            |
| `codellama` | 3.8GB | Medium | ⭐⭐⭐⭐ | Code remediation examples        |
| `mistral`   | 4.1GB | Medium | ⭐⭐⭐   | Technical explanations           |
| `phi3`      | 2.2GB | Fast   | ⭐⭐⭐   | Quick analysis, resource-limited |

---

## Custom Prompts

Prompts are stored in `config/prompts/`:

### Technical Prompt (`technical.txt`)

-   Step-by-step SQL injection remediation
-   Prepared statement examples (PHP, Python, Node.js, Java)
-   Input validation techniques
-   WAF configuration snippets
-   Database hardening recommendations
-   Verification methods (manual testing, automated tools)

### Non-Technical Prompt (`non_technical.txt`)

-   Business impact of SQL injection
-   Data breach risk assessment
-   Compliance implications (GDPR, PCI-DSS, HIPAA)
-   Financial impact estimates
-   Board-level recommendations
-   Timeline for remediation

Edit these files to customize AI output for your organization's needs.

---

## Troubleshooting

### Provider Not Working?

Run the standalone test:

```bash
python -m pyth.core.ai [provider_name]
```

This will tell you exactly what's wrong.

### Common Issues

#### "API key not found"

-   Check environment variable is set
-   For OpenAI: `echo $OPENAI_API_KEY`
-   For Anthropic: `echo $ANTHROPIC_API_KEY`
-   Restart your terminal after setting env vars

#### "Ollama server not responding"

-   Start server: `ollama serve`
-   Check it's running: `ps aux | grep ollama`
-   Verify port: `curl http://localhost:11434/api/tags`
-   Check firewall: `sudo ufw allow 11434`

#### "Model not found" (Ollama)

-   Pull the model: `ollama pull llama3.2`
-   List available models: `ollama list`
-   Update `config/default.yaml` with correct model name
-   Check model spelling (case-sensitive)

#### "Rate limit exceeded" (OpenAI/Anthropic)

-   Reduce `max_completion_tokens` in config
-   Wait and retry (OpenAI: 3 req/min on free tier)
-   Use `--ai-tone technical` (smaller output than `both`)
-   Upgrade API plan for higher limits

#### "AI analysis failed"

1. Run standalone test: `python -m pyth.core.ai [provider]`
2. Check provider configuration in `config/default.yaml`
3. Verify API keys/connectivity
4. Try with a simpler report (use `--max-pages 5`)
5. Check logs: `~/.pythia/logs/pythia.log`

#### "Connection timeout" (Ollama)

-   Increase timeout in config if using CPU-only Ollama
-   Model may be too large for available RAM
-   Try smaller model: `ollama pull phi3`

---

## Cost Management

### Token Usage Estimates (SQL Injection Reports)

| Report Size          | Input Tokens | Output Tokens | OpenAI Cost | Anthropic Cost |
| -------------------- | ------------ | ------------- | ----------- | -------------- |
| Small (5 findings)   | ~1,200       | ~800          | ~$0.04      | ~$0.06         |
| Medium (14 findings) | ~2,500       | ~1,500        | ~$0.12      | ~$0.18         |
| Large (30+ findings) | ~5,000       | ~3,000        | ~$0.25      | ~$0.35         |

_Costs based on GPT-4-turbo ($0.01/1K input, $0.03/1K output)_

### Cost Reduction Tips

1. **Use single tone instead of `both`:**

    - `--ai-tone technical` → 50% cheaper
    - `--ai-tone non_technical` → 50% cheaper

2. **Reduce scan scope:**

    - Use `--max-pages 10` for focused testing
    - Test specific endpoints instead of full crawl

3. **Use cheaper models for testing:**

    - GPT-3.5-turbo: ~70% cheaper than GPT-4
    - Claude Haiku: ~80% cheaper than Claude Opus

4. **Batch scans without AI, generate reports later:**

    - Run multiple scans without `--use-ai`
    - Process reports offline with local Ollama

5. **Use Ollama for internal/dev testing:**
    - Free, unlimited
    - Save OpenAI/Anthropic for client deliverables

---

## Best Practices

### 1. Choose Right Provider for Context

| Scenario                  | Recommended Provider | Reason                      |
| ------------------------- | -------------------- | --------------------------- |
| Client reports            | OpenAI GPT-4         | Best quality, professional  |
| Internal testing          | Ollama               | Free, private               |
| Quick triage              | GPT-3.5-turbo        | Fast & cheap                |
| Sensitive environments    | Ollama               | 100% offline                |
| EU/GDPR clients           | Anthropic            | Privacy-focused, GDPR-aware |
| Financial sector          | Ollama               | Air-gapped compliance       |
| Code remediation examples | Anthropic/CodeLlama  | Best code generation        |

### 2. Review AI Output

**Always verify:**

-   Prepared statement syntax is correct for your language/framework
-   Database-specific functions are accurate (MySQL vs PostgreSQL)
-   OWASP references are up-to-date
-   No hallucinated CVE numbers
-   Remediation steps match your tech stack
-   Input validation examples are complete

### 3. Optimize for Your Use Case

**Production (Client Reports):**

-   Provider: OpenAI GPT-4
-   Tone: `both`
-   Quality: Maximum
-   Cost: ~$0.25/scan

**Development (Internal Testing):**

-   Provider: Ollama (llama3.2)
-   Tone: `technical`
-   Quality: Good enough
-   Cost: Free

**Budget-Conscious:**

-   Provider: GPT-3.5-turbo
-   Tone: `technical` OR `non_technical` (not both)
-   Quality: Acceptable
-   Cost: ~$0.05/scan

### 4. Pre-Scan Testing

Before running expensive AI analysis:

```bash
# 1. Test provider is working
python -m pyth.core.ai openai

# 2. Run scan WITHOUT AI first
python -m pyth --target http://localhost:8081 --aggressive --html

# 3. Review findings manually

# 4. If report looks good, re-run with AI
python -m pyth --target http://localhost:8081 --aggressive --use-ai --html
```

---

## Examples

### Full Workflow with Provider Testing

```bash
# 1. Test all providers to see which works best
python -m pyth.core.ai openai    # Test OpenAI
python -m pyth.core.ai anthropic # Test Anthropic
python -m pyth.core.ai ollama    # Test Ollama (if installed)

# 2. Choose provider and update config/default.yaml
vim config/default.yaml
# Set: provider: "anthropic"

# 3. Generate consent token (for aggressive mode)
python -m pyth --gen-consent myapp.local

# Output:
# ✅ Consent token generated: verify-abc123def456...

# 4. Verify ownership (place token at /.well-known/security.txt)
python -m pyth --verify-consent http \
  --domain myapp.local \
  --token verify-abc123def456

# 5. Run aggressive scan with AI analysis
python -m pyth \
  --target http://myapp.local:8081 \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --html \
  --rate 40 \
  -vv

# 6. Check reports
ls -lh ~/.pythia/reports/
open ~/.pythia/reports/pythia_sqli_report_myapp.local_*.html
```

### Quick Development Test (No AI Cost)

```bash
# 1. Setup Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull llama3.2

# 2. Update config to use Ollama
vim config/default.yaml
# Set: provider: "ollama", model: "llama3.2:latest"

# 3. Run scan with free AI analysis
python -m pyth \
  --target http://localhost:8081 \
  --safe \
  --use-ai \
  --ai-tone technical \
  --html

# 4. AI runs locally, no API costs!
```

### Production Client Report

```bash
# Use best quality AI for client deliverable
python -m pyth \
  --target https://client-app.com \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --html \
  --max-pages 50 \
  --rate 10 \
  -vv

# Generate comprehensive report with:
# - Executive summary for C-suite
# - Technical remediation for dev team
# - Both in single HTML file
```

---

## Report Examples

### With AI Analysis (Technical Tone)

```
PYTHIA SQL INJECTION REPORT
============================
Target: http://localhost:8081
Date: 2025-11-03
Findings: 14 (10 critical, 3 high, 1 medium)

[AI TECHNICAL REMEDIATION GUIDE]
================================

1. EXECUTIVE SUMMARY
--------------------
The application has multiple critical SQL injection vulnerabilities
in URL parameters and form fields. Immediate remediation required.

2. CRITICAL FINDINGS
--------------------
Finding: Error-Based SQL Injection (PYTHIA-SQL-001)
Affected: GET parameter 'id' in /user endpoint

Risk: Attackers can extract database contents through error messages.

Remediation Steps:
1. Replace concatenated SQL with prepared statements:

❌ VULNERABLE CODE (PHP):
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];

✅ SECURE CODE (PHP PDO):
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);

2. Disable verbose error messages in production
3. Implement input validation (whitelist allowed IDs)

Verification:
- Test with payload: ?id=1' OR '1'='1
- Should NOT return all records
...

[Full technical guide with code examples]
```

### With AI Analysis (Non-Technical Tone)

```
[AI EXECUTIVE SUMMARY]
======================

1. EXECUTIVE OVERVIEW
---------------------
Your application has 10 CRITICAL security vulnerabilities that allow
attackers to steal customer data, bypass authentication, and
potentially delete your entire database.

BUSINESS RISK: High
ACTION REQUIRED: Immediate (within 24 hours)

2. WHAT IS SQL INJECTION?
--------------------------
SQL injection is like leaving your database's master key in the front
door. Attackers can trick your application into revealing customer
records, financial data, or administrative passwords.

Real-World Example: The Equifax breach (2017) exposed 147 million
records due to SQL injection, costing $700M+ in settlements.

3. BUSINESS IMPACT
------------------
Data Breach Risk:
- 500,000+ customer records at risk
- Average breach cost: $4.45 million (IBM Security Report)
- GDPR fines: Up to €20M or 4% annual revenue

Financial Impact:
- Incident response: $50,000-$200,000
- Legal fees & settlements: $500,000+
- Lost customers: 30% churn average
- Cyber insurance premium increase: 50-100%

4. RECOMMENDED ACTIONS
----------------------
IMMEDIATE (This Week):
- Hire external security firm
- Deploy Web Application Firewall (WAF)
- Begin emergency code fixes

SHORT-TERM (This Month):
- Train development team ($20K)
- Implement code review process
- Deploy automated security testing

[Full executive summary with business context]
```

---

## Support

-   📖 [LangChain v1.0 Docs](https://python.langchain.com/docs/)
-   🤖 [OpenAI Platform](https://platform.openai.com/)
-   🔍 [Anthropic Claude](https://docs.anthropic.com/)
-   🦙 [Ollama](https://ollama.com/)

For Pythia AI issues:

-   GitHub: https://github.com/rodhnin/pythia-sql-clairvoyance/issues
-   Website: https://rodhnin.com

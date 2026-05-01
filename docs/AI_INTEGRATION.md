# AI Integration Guide - Pythia SQL Clairvoyance

Pythia uses **LangChain v1.0.0** to provide intelligent analysis of SQL injection findings through Large Language Models (LLMs).

## Overview

The AI assistant generates two types of analysis from scan results:

1. **Executive Summary** (non-technical) - For business stakeholders, managers, C-suite
2. **Technical Remediation Guide** - For developers, DBAs, security engineers

Both are generated from the JSON scan report using carefully crafted prompts and sanitized input.

---

## Testing AI Integration

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

If no API key is configured, the scan completes successfully with AI skipped (exit 0, graceful degradation).

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

You can also pass a custom environment variable name with `--api-key-env`:

```bash
# Use a different env var for the key
python -m pyth --target http://example.com --use-ai --api-key-env MY_OPENAI_KEY
```

---

## Configuration

### What can be configured from CLI vs YAML

Pythia uses a layered configuration system. **CLI flags take the highest priority**, overriding the YAML files. However, **not everything has a CLI flag** — several settings can only be changed by editing the config file.

**Configurable via CLI flags (per-scan overrides):**

| Flag            | What it overrides                            |
| --------------- | -------------------------------------------- |
| `--ai-provider` | `ai.langchain.provider`                      |
| `--ai-model`    | `ai.langchain.model`                         |
| `--api-key-env` | `ai.api_key_env`                             |
| `--ai-tone`     | Analysis tone (technical/non_technical/both) |
| `--ai-budget`   | Max cost per scan in USD                     |
| `--ai-stream`   | Enable streaming output                      |
| `--ai-agent`    | Enable agent with NVD lookup                 |
| `--ai-compare`  | Multi-provider comparison                    |

**Must be set in `config/default.yaml` (no CLI flag):**

- **Ollama server URL** (`ai.langchain.ollama_base_url`) — if your Ollama is not at `localhost:11434`
- **Temperature** (`ai.langchain.temperature`, default `0.3`) — controls AI output creativity
- **Max tokens** (`ai.langchain.max_tokens`, default `2000`) — output length limit
- **Proxy** (`advanced.proxy.http/https`) — if you route requests through a proxy
- **Custom headers** (`advanced.custom_headers`) — global headers for all requests
- **Consent token expiry** (`consent.token_expiry_hours`, default `48`)
- **Detection thresholds** (`sqli.time_threshold`, `sqli.boolean_blind.*`) — tuning detection sensitivity
- **Custom payloads** (`sqli.error_payloads`, `sqli.boolean_payloads`, `sqli.time_based_payloads`) — if you need to add or replace payloads
- **HTML as default** (`reporting.format.html: true`) — generate HTML without `--html` flag every time

### CLI Flags — Per-Scan Overrides

For most use cases you only need CLI flags:

```bash
# Use Anthropic with a specific model
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-provider anthropic \
  --ai-model claude-3-5-haiku-20241022 \
  --ai-tone technical \
  --html

# Use OpenAI with GPT-4o
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-provider openai \
  --ai-model gpt-4o \
  --html

# Use Ollama locally (default URL: http://localhost:11434)
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-provider ollama \
  --ai-model llama3.2 \
  --html
```

### YAML Configuration — Persistent Defaults

Edit `config/default.yaml` (project-wide) or `~/.pythia/config.yaml` (user-level, takes priority over project default) to change permanent defaults.

#### OpenAI (Default)

```yaml
ai:
    langchain:
        provider: "openai"
        model: "gpt-4o-mini-2024-07-18" # Other options: gpt-4o, gpt-4-turbo
        temperature: 0.3
        max_tokens: 2000
```

#### Anthropic Claude

```yaml
ai:
    langchain:
        provider: "anthropic"
        model: "claude-3-5-haiku-20241022" # or claude-3-5-sonnet-20241022
        temperature: 0.3
        max_tokens: 2000
```

#### Ollama (Local) — Ollama URL requires YAML

```yaml
ai:
    langchain:
        provider: "ollama"
        model: "llama3.2:latest"
        temperature: 0.3
        max_tokens: 2000
        ollama_base_url: "http://localhost:11434" # Change if Ollama on different host/port
```

> **Note:** The `ollama_base_url` has no CLI flag. If your Ollama server is not at `localhost:11434`, you **must** edit the YAML.

---

## Usage

### Basic AI Analysis

```bash
# Run scan with AI analysis
python -m pyth --target http://localhost:8081 --aggressive --use-ai --html

# Different analysis tones
python -m pyth --target http://localhost:8081 --use-ai --ai-tone technical
python -m pyth --target http://localhost:8081 --use-ai --ai-tone non_technical
python -m pyth --target http://localhost:8081 --use-ai --ai-tone both
```

### Analysis Tone Options

| Tone            | Audience                              | Content                                       |
| --------------- | ------------------------------------- | --------------------------------------------- |
| `technical`     | Developers, DBAs, Security Engineers  | Code examples, SQL queries, remediation steps |
| `non_technical` | Executives, Managers, Business Owners | Business impact, compliance, financial risks  |
| `both`          | Complete team                         | Both technical and executive summaries        |

### AI Streaming (`--ai-stream`)

Stream output token by token as the AI generates the analysis:

```bash
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-stream \
  --ai-tone technical \
  --html
```

Output prints progressively to the terminal as tokens arrive.

### AI Agent Mode (`--ai-agent`)

Agent mode enables the AI to perform autonomous CVE lookup via the NVD API:

```bash
python -m pyth --target http://localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-agent \
  --html
```

The agent:

- Detects the DBMS version from error messages
- Queries NVD for CVEs matching that DBMS version + `cweId=CWE-89`
- Enriches each finding with real CVE IDs, CVSS scores, and NVD links
- Iteratively refines its analysis for deeper coverage

NVD API endpoint used: `https://services.nvd.nist.gov/rest/json/cves/2.0`

### Multi-Provider Comparison (`--ai-compare`)

Run analysis with multiple providers in parallel and include all results in the report:

```bash
# Compare providers (use default models)
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-compare "openai,anthropic" \
  --html

# Compare with specific models
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-compare "openai:gpt-4o-mini,anthropic:claude-3-5-haiku-20241022" \
  --html
```

Results from all providers appear in separate tabs in the HTML report.

### Budget Control (`--ai-budget`)

Cap AI spending per scan:

```bash
# Stop AI analysis if cost exceeds $0.10
python -m pyth --target http://localhost:8081 \
  --use-ai \
  --ai-budget 0.10 \
  --html
```

Costs are tracked in `~/.argos/costs.json` (shared across the Argos Suite). Each entry includes tool, provider, model, tokens used, cost in USD, and scan ID.

---

## Privacy & Security

### Data Sanitization

Before sending reports to AI, Pythia automatically removes sensitive information.

**What Gets Removed:**

- Consent tokens (`verify-abc123...`)
- Bearer tokens and API keys
- Database credentials in error messages
- Session IDs and cookies
- Long SQL queries (truncated to 500 chars)
- Database schema details in evidence
- Internal IP addresses and hostnames

**What Gets Sent (Sanitized):**

- Finding IDs and titles (PYTHIA-SQL-001, etc.)
- Severity levels (critical, high, medium, low)
- Detection methods (error-based, blind, time-based)
- Redacted/truncated evidence
- Generic recommendations
- External reference URLs (OWASP, CWE)

### Privacy Recommendations

| Concern Level        | Recommended Provider | Why                                             |
| -------------------- | -------------------- | ----------------------------------------------- |
| **High Privacy**     | Ollama (local)       | Data never leaves your machine                  |
| **Moderate Privacy** | Anthropic Claude     | Strong privacy policy, no training on user data |
| **Standard**         | OpenAI               | Best analysis quality, standard privacy         |

---

## Providers Comparison

### OpenAI (Default)

**Pros:**

- Best analysis quality for SQL injection
- Extensive database security knowledge
- Fast response
- Handles complex blind SQLi scenarios well
- Accurate OWASP/CWE references

**Cons:**

- Requires internet
- Costs money (~$0.10-0.30/scan depending on model)
- Data sent to OpenAI servers

**Best For:** Production reports, client deliverables, complex SQL injection chains

### Anthropic Claude

**Pros:**

- Strong technical reasoning for database attacks
- Excellent code remediation examples
- Privacy-focused company
- Good with prepared statement conversions

**Cons:**

- Requires internet
- Costs money
- Slightly slower than GPT-4o

**Best For:** Technical deep-dives, code remediation guides, EU clients (GDPR)

### Ollama (Local Models)

**Pros:**

- 100% offline operation
- Complete privacy (no data leaves machine)
- Free (no API costs)
- Perfect for air-gapped environments

**Cons:**

- Lower quality analysis
- Very slow without GPU (10-30 minutes)
- May struggle with complex blind SQLi reports

**Best For:** Sensitive environments, air-gapped networks, internal testing

### Performance Comparison

| Provider         | Executive Summary | Technical Guide | Total Time | Quality |
| ---------------- | ----------------- | --------------- | ---------- | ------- |
| OpenAI GPT-4o    | ~15s              | ~20s            | ~35s       | ★★★★★   |
| Anthropic Claude | ~20s              | ~25s            | ~45s       | ★★★★★   |
| Ollama (CPU)     | ~14min            | ~14min          | ~28min     | ★★★     |
| Ollama (GPU)     | ~30s              | ~45s            | ~75s       | ★★★     |

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

# 4. Verify it's working
ollama list
curl http://localhost:11434/api/tags

# 5. Run scan with local AI
python -m pyth \
  --target http://localhost:8081 \
  --use-ai \
  --ai-provider ollama \
  --ai-model llama3.2 \
  --ai-tone technical \
  --html
```

**Recommended Models for SQL Injection Analysis:**

| Model       | Size  | Speed  | Quality | Best For                         |
| ----------- | ----- | ------ | ------- | -------------------------------- |
| `llama3.2`  | 3.9GB | Medium | ★★★★    | General SQLi analysis            |
| `codellama` | 3.8GB | Medium | ★★★★    | Code remediation examples        |
| `mistral`   | 4.1GB | Medium | ★★★     | Technical explanations           |
| `phi3`      | 2.2GB | Fast   | ★★★     | Quick analysis, resource-limited |

---

## Custom Prompts

Prompts are stored in `config/prompts/`:

### Technical Prompt (`technical.txt`)

- Step-by-step SQL injection remediation
- Prepared statement examples (PHP/PDO, Python/SQLAlchemy, Node.js/pg, Java/PreparedStatement)
- Input validation techniques
- WAF configuration snippets
- Database hardening recommendations
- Verification methods

### Non-Technical Prompt (`non_technical.txt`)

- Business impact of SQL injection
- Data breach risk assessment
- Compliance implications (GDPR, PCI-DSS, HIPAA)
- Financial impact estimates
- Board-level recommendations
- Timeline for remediation

Edit these files to customize AI output for your organization's needs.

---

## Cost Management

### Token Usage Estimates (SQL Injection Reports)

| Report Size          | Input Tokens | Output Tokens | OpenAI Cost (gpt-4o-mini) | Anthropic Cost |
| -------------------- | ------------ | ------------- | ------------------------- | -------------- |
| Small (5 findings)   | ~1,200       | ~800          | ~$0.01                    | ~$0.06         |
| Medium (14 findings) | ~2,500       | ~1,500        | ~$0.02                    | ~$0.18         |
| Large (30+ findings) | ~5,000       | ~3,000        | ~$0.05                    | ~$0.35         |

_Costs vary by model. Use `--ai-budget` to cap per-scan spend._

### Cost Reduction Tips

1. **Use single tone instead of `both`:** reduces tokens by ~50%
2. **Use `gpt-4o-mini` (default):** significantly cheaper than GPT-4o for most analyses
3. **Reduce scan scope:** `--max-pages 10` for focused testing
4. **Use Ollama for internal/dev testing:** free, unlimited
5. **Use `--ai-budget 0.05`** to prevent runaway costs during CI/CD

### Cost Tracking

All AI costs are saved to `~/.argos/costs.json` (shared Argos Suite file):

```json
{
    "entries": [
        {
            "tool": "pythia",
            "provider": "openai",
            "model": "gpt-4o-mini-2024-07-18",
            "input_tokens": 2500,
            "output_tokens": 1500,
            "cost_usd": 0.02,
            "scan_id": 42,
            "created_at": "2026-03-18T14:30:00Z"
        }
    ]
}
```

---

## Troubleshooting

### Provider Not Working?

Run the standalone test:

```bash
python -m pyth.core.ai [provider_name]
```

### Common Issues

#### "API key not found"

- Check environment variable is set: `echo $OPENAI_API_KEY`
- Restart your terminal after setting env vars
- Use `--api-key-env` to specify a custom env var name

#### "Ollama server not responding"

- Start server: `ollama serve`
- Verify port: `curl http://localhost:11434/api/tags`

#### "Model not found" (Ollama)

- Pull the model: `ollama pull llama3.2`
- List available models: `ollama list`
- Pass the model name with `--ai-model llama3.2`

#### "Rate limit exceeded" (OpenAI/Anthropic)

- Use `--ai-tone technical` (smaller output than `both`)
- Upgrade API plan for higher limits

#### "AI analysis failed / scan completed without AI"

- This is graceful degradation — scan data is still saved
- Run standalone test: `python -m pyth.core.ai [provider]`
- Check logs: `~/.argos/logs/pythia.log`

---

## Best Practices

### Choose Right Provider for Context

| Scenario                  | Recommended Provider | Reason                          |
| ------------------------- | -------------------- | ------------------------------- |
| Client reports            | OpenAI gpt-4o        | Best quality, professional      |
| Internal testing          | Ollama               | Free, private                   |
| Quick triage              | OpenAI gpt-4o-mini   | Fast & cheap (default)          |
| Sensitive environments    | Ollama               | 100% offline                    |
| EU/GDPR clients           | Anthropic            | Privacy-focused, GDPR-aware     |
| Financial sector          | Ollama               | Air-gapped compliance           |
| Code remediation examples | Anthropic/CodeLlama  | Best code generation            |
| CVE enrichment            | Any + `--ai-agent`   | NVD lookup is provider-agnostic |

### Review AI Output

**Always verify:**

- Prepared statement syntax is correct for your language/framework
- Database-specific functions are accurate (MySQL vs PostgreSQL)
- OWASP references are up-to-date
- CVE numbers from `--ai-agent` mode are real (check NVD link in report)
- Remediation steps match your tech stack

### Pre-Scan Testing

```bash
# 1. Test provider is working
python -m pyth.core.ai openai

# 2. Run scan WITHOUT AI first to validate findings
python -m pyth --target http://localhost:8081 --aggressive --html

# 3. If report looks good, re-run with AI
python -m pyth --target http://localhost:8081 --aggressive --use-ai --html
```

---

## Examples

### Full Workflow: Authenticated Scan with AI

```bash
# 1. Generate consent token
python -m pyth --gen-consent myapp.com

# 2. Verify ownership
python -m pyth --verify-consent http \
  --domain myapp.com \
  --token verify-abc123def456

# 3. Run authenticated aggressive scan with AI agent
python -m pyth \
  --target https://myapp.com/api/v1 \
  --aggressive \
  --auth-header "Authorization: Bearer eyJhbGc..." \
  --auth-header "X-API-Key: sk-prod-xxx" \
  --use-ai \
  --ai-agent \
  --ai-tone both \
  --html \
  -vv

# 4. Check reports
ls -lh ~/.pythia/reports/
```

### CI/CD Integration with AI Budget

```bash
# Run scan, cap AI cost at $0.05, fail pipeline on high+ findings
python -m pyth \
  --target https://staging.myapp.com \
  --aggressive \
  --use-ai \
  --ai-budget 0.05 \
  --fail-on high \
  --sarif > results.sarif

echo "Exit code: $?"
# Exit 0 = clean, Exit 10 = findings found, Exit 1 = error
```

### Compare Two AI Providers

```bash
python -m pyth \
  --target http://localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-compare "openai:gpt-4o-mini,anthropic:claude-3-5-haiku-20241022" \
  --html
```

---

## Support

- [LangChain v1.0 Docs](https://python.langchain.com/docs/)
- [OpenAI Platform](https://platform.openai.com/)
- [Anthropic Claude](https://docs.anthropic.com/)
- [Ollama](https://ollama.com/)
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)

For Pythia AI issues:

- GitHub: https://github.com/rodhnin/pythia-sql-clairvoyance/issues
- Website: https://rodhnin.com

# Consent Token System - Pythia SQL Clairvoyance

## Overview

Pythia implements a **consent token verification system** to ensure you have technical control over target domains before enabling intrusive SQL injection testing or AI analysis.

This system is a **safety mechanism**, not a legal authorization. You still need proper permission to scan any system.

---

## When Is Consent Required?

Consent verification is **mandatory** for:

1. **`--aggressive` Mode**

    - Deep SQL injection testing (blind, time-based)
    - UNION-based data extraction attempts
    - WAF bypass payload variants
    - Second-order and ORDER BY injection detection
    - Any potentially intrusive database probing

2. **`--use-ai` Flag**
    - Sends sanitized report data to external AI API (OpenAI/Anthropic)
    - Even though data is sanitized, consent is required as an extra safety layer

**Safe mode does NOT require consent** (error-based + boolean-blind only, minimal requests).

---

## How It Works

### Step 1: Generate Token

```bash
python -m pyth --gen-consent example.com
```

**Output:**

```
===========================================================================
DOMAIN OWNERSHIP VERIFICATION REQUIRED
===========================================================================
Domain: example.com
Token: verify-a3f9b2c1d8e4f5a6
Expires: 48 hours from now

┌─ METHOD 1: HTTP File (Recommended)
│
│  1. Create a text file containing EXACTLY this:
│     verify-a3f9b2c1d8e4f5a6
│
│  2. Upload it to:
│     https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
│
│  3. Verify it's accessible in your browser
│
│  4. Run verification:
│     python -m pyth --verify-consent http --domain example.com --token verify-a3f9b2c1d8e4f5a6
└─

┌─ METHOD 2: DNS TXT Record (Alternative)
│
│  1. Add a TXT record to your DNS:
│     Host: example.com
│     Value: pythia-verify=verify-a3f9b2c1d8e4f5a6
│
│  2. Wait for DNS propagation (5-30 minutes)
│
│  3. Run verification:
│     python -m pyth --verify-consent dns --domain example.com --token verify-a3f9b2c1d8e4f5a6
└─

===========================================================================
NOTE: You must verify ownership before using --aggressive or --use-ai
===========================================================================
```

**What Happens:**

-   Token is stored in SQLite database (`~/.argos/argos.db` - shared with Argus/Hephaestus)
-   Token format: `verify-<16 hex characters>` (pattern: `^verify-[a-f0-9]{16}`)
-   Token expires after 48 hours by default (configurable)

---

## Method 1: HTTP File Verification (Recommended)

### Why HTTP File?

Pros:
-   Quick to set up (minutes)
-   No DNS propagation delay
-   Easy to verify manually
-   Works on localhost for testing
-   Standard RFC 8615 location

Cons:
-   Requires web server file access
-   Less suitable for wildcard domains

### Implementation Steps

#### 1. Create Token File

```bash
echo "verify-a3f9b2c1d8e4f5a6" > verify-a3f9b2c1d8e4f5a6.txt
```

**Important**: No extra spaces, newlines, or characters.

#### 2. Upload to .well-known Directory

**Standard Path:**

```
https://example.com/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

**Server Configuration Examples:**

Apache (.htaccess):

```apache
<Directory "/var/www/html/.well-known">
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>
```

Nginx:

```nginx
location /.well-known/ {
    allow all;
}
```

PHP Application:

```bash
mkdir -p /var/www/html/.well-known
echo "verify-a3f9b2c1d8e4f5a6" > /var/www/html/.well-known/verify-a3f9b2c1d8e4f5a6.txt
chmod 644 /var/www/html/.well-known/verify-a3f9b2c1d8e4f5a6.txt
```

#### 3. Run Verification

```bash
python -m pyth --verify-consent http \
    --domain example.com \
    --token verify-a3f9b2c1d8e4f5a6
```

**Success Output:**

```
===========================================================================
✓ CONSENT VERIFICATION SUCCESSFUL
===========================================================================
Domain: example.com
Token: verify-a3f9b2c1d8e4f5a6
Method: HTTP
You can now use --aggressive and --use-ai modes for this domain.
===========================================================================
```

---

## Method 2: DNS TXT Record Verification

### Why DNS TXT?

Pros:
-   No web server file access needed
-   Works for domains without websites
-   Industry-standard (used by Google, AWS, etc.)
-   Covers wildcard subdomains

Cons:
-   DNS propagation delay (5-30 minutes)
-   Requires DNS management access

### Implementation Steps

**Record Configuration:**

-   **Type**: TXT
-   **Host/Name**: `example.com` (or `@` for root)
-   **Value**: `pythia-verify=verify-a3f9b2c1d8e4f5a6`
-   **TTL**: 300 (5 minutes) for quick testing

**Verify propagation:**

```bash
dig TXT example.com +short
# Expected: "pythia-verify=verify-a3f9b2c1d8e4f5a6"
```

**Run Verification:**

```bash
python -m pyth --verify-consent dns \
    --domain example.com \
    --token verify-a3f9b2c1d8e4f5a6
```

Pythia retries 3 times with 2-second delays (configurable in `config/default.yaml`).

---

## Verification Storage

Upon successful verification, a record is written to `~/.argos/argos.db` and a proof file is saved to `~/.argos/consent-proofs/`.

### Checking Expiration

```bash
sqlite3 ~/.argos/argos.db "SELECT * FROM v_verified_domains"
```

**Output:**

```
domain       | token                    | method | verified_at           | expires_at            | status
example.com  | verify-a3f9b2c1d8e4f5a6 | http   | 2026-03-18T14:30:22Z  | 2026-03-20T14:30:22Z  | valid
```

### Renewing Tokens

Simply generate a new token:

```bash
python -m pyth --gen-consent example.com
```

---

## Token Expiration

**Default:** 48 hours from generation.

### Extending Expiry for Lab Environments

For local testing environments (localhost), the 48-hour default expires quickly. You can extend it manually in the database:

```sql
-- Extend localhost consent token by 30 days
sqlite3 ~/.argos/argos.db "
UPDATE consent_tokens
SET expires_at = datetime('now', '+30 days', 'utc')
WHERE domain = 'localhost'
  AND verified_at IS NOT NULL;
"
```

This is only appropriate for persistent lab environments (e.g., DVWA/PHP/Flask labs that you own).

---

## Security Considerations

### Token Security

**Tokens are NOT secrets:**

-   They prove domain control, not identity
-   Safe to include in reports or logs
-   Expire automatically after 48 hours

**Token format:** `verify-<16 hex chars>` — cryptographically random (2^64 possibilities).

### Attack Scenarios

**Stolen Token:** Attacker still needs to place it on YOUR domain — no impact.

**Token Guessing:** 2^64 possibilities — computationally infeasible.

**Token Replay:** Tokens expire after 48 hours — no impact after expiry.

---

## Advanced Usage

### Custom Configuration

Edit `config/default.yaml`:

```yaml
consent:
    token_expiry_hours: 72  # Extend to 3 days
    http_verification_path: "/.well-known/"
    dns_txt_prefix: "pythia-verify="
    verification_retries: 5
    verification_retry_delay: 5
```

### Programmatic Usage

```python
from pyth.core.consent import ConsentToken
from pyth.core.config import Config

config = Config.load()
consent = ConsentToken(config)

# Generate token
token, expiration = consent.generate_token("example.com")
print(f"Token: {token}")

# Verify (HTTP)
success, result = consent.verify_http("example.com", token)
if success:
    consent.save_proof("example.com", token, "http", result)
```

---

## Verification Workflow

```
1. python -m pyth --gen-consent example.com
   → Token generated: verify-abc123
   → Stored in SQLite (status: pending)

2. User places token:
   → HTTP: .well-known/verify-abc123.txt
   → DNS: TXT record "pythia-verify=verify-abc123"

3. python -m pyth --verify-consent [method] --domain example.com --token verify-abc123
   → Pythia fetches/queries the token placement
   → Updates SQLite (status: verified)
   → Saves proof file

4. python -m pyth --target https://example.com --aggressive
   → Checks: is_domain_verified(example.com)?
   → YES: Proceed with SQL injection tests
   → NO: Abort with error
```

---

## FAQ

### Q: Can I skip consent verification?

**A:** No for `--aggressive` and `--use-ai`. Yes for `--safe` mode (default, passive detection only).

### Q: Does consent verification replace legal authorization?

**A:** **NO!** Consent tokens prove technical control only. You still need proper legal permission to perform security testing.

### Q: Can I use one token for multiple subdomains?

**A:** No. Generate separate tokens for each domain/subdomain you want to test.

### Q: Can I test on localhost without consent?

**A:** Localhost requires consent for `--aggressive` and `--use-ai` modes just like any other target. Generate a consent token for `localhost`, place the verification file in your local web server, and verify it. Once verified, the token is stored in the database. For persistent lab environments, you can extend the token expiry manually in the database (see the "Extending Expiry for Lab Environments" section above).

### Q: Can I pass the consent token directly on the command line?

**A:** Yes. Use `--token verify-abc123` when running any scan command. This passes the token without requiring file placement when the token is already verified in the database.

### Q: How do I revoke a token?

**A:** Tokens automatically expire after 48 hours. To immediately revoke:

```sql
DELETE FROM consent_tokens WHERE token = 'verify-abc123';
```

### Q: Does the consent system work with Argus and Hephaestus?

**A:** Yes. All three tools share the same consent token database (`~/.argos/argos.db`). A token verified for Pythia works for Argus and Hephaestus on the same domain.

---

## Best Practices

1. **Always verify before aggressive scans** — establish a verification trail
2. **Document verification** — proof files provide an audit trail for compliance
3. **Clean up after testing** — remove token files from web server after verification
4. **Rotate tokens regularly** — generate fresh tokens for each major scan campaign
5. **Separate tokens per environment** — use different tokens for dev/staging/production
6. **Save proof files** — keep for compliance and audit purposes

---

## Integration with Argos Ecosystem

```bash
# Generate token for domain
python -m pyth --gen-consent myapp.com

# Verify once
python -m pyth --verify-consent http --domain myapp.com --token verify-abc123

# Use with any tool in the Argos ecosystem
python -m pyth --target http://myapp.com --aggressive    # SQL injection
python -m argus --target http://myapp.com --aggressive   # WordPress
python -m heph --target http://myapp.com --aggressive    # API security

# All three tools recognize the same verified token!
```

---

## Emergency Procedures

### If Scan Causes Issues

1. **Stop immediately:** `Ctrl+C` (graceful shutdown)
2. **Document impact:** Save logs and error messages
3. **Revoke token:** Delete from database and web server
4. **Notify stakeholders:** Security team, DevOps, management

### If Token Compromised

```bash
# Revoke immediately
sqlite3 ~/.argos/argos.db "DELETE FROM consent_tokens WHERE token = 'verify-abc123';"

# Remove from web server
rm /var/www/html/.well-known/verify-abc123.txt

# Generate new token
python -m pyth --gen-consent example.com
```

---

_Version: Pythia v0.2.0_

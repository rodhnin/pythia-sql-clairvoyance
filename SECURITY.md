# Security Policy - Pythia SQL Clairvoyance

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 0.1.x   | :white_check_mark: | TBD            |
| < 0.1.0 | :x:                | Unsupported    |

**Note:** As Pythia is a security tool, we take vulnerabilities seriously. We aim to patch critical vulnerabilities within **7 days** and non-critical issues within **30 days**.

---

## Reporting a Vulnerability

### For Security Issues in Pythia Itself

If you discover a security vulnerability in Pythia (the scanner tool itself), please report it **privately** to help us protect users.

**DO NOT:**
- ❌ Open public GitHub issues for security vulnerabilities
- ❌ Disclose publicly before we've had time to patch
- ❌ Test vulnerabilities in production environments
- ❌ Share exploit code publicly before disclosure deadline

---

### How to Report

**Preferred Method: Private Security Advisory**

1. Go to: https://github.com/rodhnin/pythia-sql-clairvoyance/security/advisories
2. Click "New draft security advisory"
3. Fill in:
   - **Title:** Clear, concise description (e.g., "SQL Injection in report generation")
   - **Description:** Detailed explanation with reproduction steps
   - **Severity:** Your assessment (Low, Medium, High, Critical)
   - **CWE:** If applicable (e.g., CWE-89 for SQLi)
   - **Affected versions:** Which Pythia versions are vulnerable

**Alternative Method: Email**

If GitHub Security Advisories are not available to you:

- **Contact:** Report via https://rodhnin.com (secure contact form)
- **Subject:** `[SECURITY] Pythia Vulnerability Report`
- **Encrypt:** Use PGP if possible (key available on website)

---

### What to Include in Your Report

**Required Information:**

1. **Summary:**
   - One-line description of the vulnerability

2. **Detailed Description:**
   - What is the vulnerability?
   - How does it work?
   - What is the impact?

3. **Affected Components:**
   - Which parts of Pythia are affected?
   - Which versions?

4. **Reproduction Steps:**
   ```bash
   1. Install Pythia v0.1.0
   2. Run command: python -m pyth --target ...
   3. Observe: [describe the issue]
   ```

5. **Proof of Concept:**
   - Minimal code/commands to reproduce
   - Screenshots/logs (if helpful)

6. **Impact Assessment:**
   - Who is affected? (all users, Docker users, specific configurations)
   - What can an attacker do?
   - CVSS score (if you've calculated it)

7. **Suggested Fix (Optional):**
   - Ideas for remediation
   - Patch suggestions

**Optional but Helpful:**

- CWE classification
- CVE request (if appropriate)
- Exploit code (if you've developed it)
- Timeline you're comfortable with for disclosure

---

### Example Security Report

```markdown
**Summary:**
Path traversal in HTML report generation allows arbitrary file read

**Severity:** High (CVSS 7.5)

**Affected Versions:** Pythia v0.1.0

**Description:**
The HTML report generator (`pyth/core/report.py`) does not properly
sanitize template paths, allowing an attacker who can control the
`--template` CLI argument to read arbitrary files from the system.

**Reproduction Steps:**
1. Install Pythia v0.1.0
2. Run: python -m pyth --target http://example.com --template ../../../../etc/passwd
3. Observe: Contents of /etc/passwd included in HTML report

**Impact:**
- Attacker can read sensitive files (credentials, config files)
- Requires attacker to control CLI arguments
- Docker containers are less affected (restricted filesystem)

**Suggested Fix:**
Validate template path is within allowed directories:
- Use pathlib.resolve() to get absolute path
- Check that resolved path starts with allowed template directory
- Reject if outside allowed paths

**Timeline:**
Prefer disclosure after 90 days or patch availability, whichever is sooner.
```

---

## Vulnerability Response Process

### Our Commitment

We take security seriously and will:

1. **Acknowledge** your report within **48 hours**
2. **Investigate** and validate the issue within **7 days**
3. **Develop a patch** based on severity:
   - **Critical:** 7 days
   - **High:** 14 days
   - **Medium:** 30 days
   - **Low:** 60 days
4. **Coordinate disclosure** with you
5. **Credit** you in the security advisory (if desired)

### Response Timeline

```
Day 0:   Vulnerability reported
Day 1-2: Acknowledgment sent
Day 3-7: Investigation and validation
Day 8+:  Patch development
Day X:   Coordinated disclosure
Day X+1: Public release with fix
```

---

## Disclosure Policy

We follow **Coordinated Disclosure**:

**Steps:**

1. **Private Reporting:** You report vulnerability privately to us
2. **Investigation:** We validate and develop a patch
3. **Coordination:** We work with you on disclosure timeline
4. **Embargo:** We keep the issue private until patch is ready
5. **Patch Release:** We release a security update
6. **Public Disclosure:** We publish a security advisory
7. **Credit:** We credit you (if desired)

**Disclosure Timeline:**

- **Critical vulnerabilities:** 7-14 days
- **High vulnerabilities:** 30 days
- **Medium vulnerabilities:** 60 days
- **Low vulnerabilities:** 90 days

**We may expedite disclosure if:**
- Vulnerability is being actively exploited
- Public disclosure has already occurred
- Patch is trivial and can be deployed quickly

---

## Security Best Practices for Users

### Using Pythia Safely

**1. Always Update:**
```bash
# Check version
python -m pyth --version

# Update to latest
pip install --upgrade pythia-scanner
```

**2. Use Docker (Recommended for isolation):**
```bash
cd docker
docker compose build
# Run one-shot scans
docker compose run --rm pyth --target http://example.com --safe
```

**3. Principle of Least Privilege:**
- Don't run as root (Docker runs as UID 1000 automatically)
- Use virtual environments
- Restrict database file permissions: `chmod 600 ~/.argos/argos.db`

**4. Secure AI API Keys:**
```bash
# Don't hardcode in config files
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Use environment variables only
# Never commit .env files to Git
```

**5. Protect Reports:**
```bash
# Reports may contain sensitive information
chmod 700 ~/.pythia/reports/

# Encrypt before sharing
gpg --encrypt --recipient client@example.com report.html
```

**6. Secure Database:**
```bash
# Shared database contains scan history
chmod 600 ~/.argos/argos.db

# Backup regularly
cp ~/.argos/argos.db ~/.argos/argos.db.backup

# Delete old scans
sqlite3 ~/.argos/argos.db "DELETE FROM scans WHERE created_at < date('now', '-90 days')"
```

---

## Known Security Considerations

### Current Limitations

**1. AI Data Sanitization**
- **Issue:** AI providers may see sanitized finding data
- **Mitigation:** Use Ollama (local) for sensitive scans
- **Status:** Working as designed

**2. Database Storage**
- **Issue:** SQLite database stores scan history in plaintext
- **Mitigation:** Encrypt home directory or use encrypted filesystem
- **Status:** Documented in security guidelines

**3. Consent Tokens**
- **Issue:** HTTP verification tokens stored in database
- **Mitigation:** Tokens are cryptographically random (16 bytes hex)
- **Status:** Working as designed

**4. Report File Permissions**
- **Issue:** HTML reports may contain sensitive findings
- **Mitigation:** Reports created with restrictive permissions (644)
- **Status:** User responsible for securing reports

---

## Security Features

### Built-in Protections

✅ **Consent Token System:**
- Prevents accidental scanning of unauthorized sites
- HTTP and DNS verification methods
- 48-hour expiration

✅ **AI Sanitization:**
- Automatic removal of credentials from AI analysis
- Removal of SQL queries and database schema
- Removal of session tokens

✅ **Safe-by-Default:**
- Aggressive mode requires verified ownership
- Rate limiting prevents accidental DoS
- Localhost consent bypass (for testing only)

✅ **Input Validation:**
- URL validation and normalization
- SQL injection payloads are escaped when logged
- Prevents directory traversal in report paths

✅ **Secure Defaults:**
- Non-root Docker user (UID 1000)
- Minimal Docker image (Alpine-based)
- No unnecessary network exposure

---

## CVE Assignment

For critical vulnerabilities, we will:

1. Request CVE ID from MITRE or GitHub
2. Publish CVE details after patch release
3. Update security advisories with CVE reference

**Criteria for CVE Assignment:**
- Affects Pythia core functionality
- Exploitable remotely or locally
- Impact on confidentiality, integrity, or availability

---

## Security Hall of Fame

We recognize security researchers who help us improve Pythia:

<!-- To be populated with security contributors -->

**Want to be listed here?**
- Report a valid security vulnerability
- Follow responsible disclosure practices
- Help us protect users

---

## Contact

**For security issues:**
- 🔒 GitHub Security Advisories (preferred)
- 🌐 Website: https://rodhnin.com
- 💬 Private message via GitHub

**For general questions:**
- 🐛 GitHub Issues: https://github.com/rodhnin/pythia-sql-clairvoyance/issues
- 💬 Discussions: https://github.com/rodhnin/pythia-sql-clairvoyance/discussions

---

## Legal

**Responsible Disclosure:** We follow coordinated disclosure practices and work with researchers to protect users.

**Bug Bounty:** We do not currently offer a bug bounty program, but we deeply appreciate security research contributions.

**Legal Protection:** We will not take legal action against security researchers who:
- Report vulnerabilities responsibly
- Do not exploit vulnerabilities maliciously
- Follow this security policy
- Comply with applicable laws

---

**Last Updated:** November 2025
**Version:** 1.0
**Applies to:** Pythia SQL Clairvoyance v0.1.0+

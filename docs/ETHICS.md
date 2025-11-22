# Ethical Use & Legal Guidelines - Pythia SQL Clairvoyance

## Overview

**Pythia is designed exclusively for authorized SQL injection security testing.** This document outlines the ethical principles, legal requirements, and best practices that govern the use of this tool.

---

## 🚨 Legal Requirements

### You MUST Have Authorization

Before scanning any web application with Pythia, you **must** have one of the following:

1. **Ownership**: You own the target application and infrastructure
2. **Explicit Written Permission**: Signed agreement from the application/system owner
3. **Professional Engagement**: Formal penetration testing contract with clear scope
4. **Bug Bounty Program**: Participation within defined scope and rules

### What Counts as Authorization?

✅ **Valid Authorization:**

-   Signed penetration testing agreement with defined scope
-   Email from authorized personnel explicitly granting permission
-   Bug bounty program participation (within scope and rules)
-   Internal corporate testing with management approval and documentation
-   Your own personal web applications/databases
-   Development/staging environments you control
-   Security testing mandate from management with written documentation

❌ **NOT Valid Authorization:**

-   Verbal permission without written documentation
-   Permission from non-authorized users (e.g., developer without authority)
-   "Just testing security as a favor" without formal approval
-   Public web applications without explicit consent
-   Government/military systems without proper clearance
-   Third-party applications (e.g., SaaS platforms you don't own)
-   Educational/university systems without IT department approval
-   "It's publicly accessible, so it's okay to scan" (WRONG!)
-   "I'm helping them find vulnerabilities" without permission (STILL ILLEGAL!)

---

## ⚖️ Legal Frameworks

### United States: Computer Fraud and Abuse Act (CFAA)

The CFAA (18 U.S.C. § 1030) makes it illegal to:

-   Access a computer without authorization or exceed authorized access
-   Intentionally access a computer without authorization and obtain information from any protected computer
-   Knowingly cause transmission of a program/code that causes damage
-   Access a protected computer and recklessly cause damage
-   Traffic in passwords or similar access credentials

**Penalties**: Up to 20 years imprisonment + fines up to $250,000

**Notable Cases:**

-   **Andrew Auernheimer (weev)**: Exploited AT&T iPad security flaw, convicted under CFAA (later overturned on venue technicality)
-   **Aaron Swartz**: Downloaded academic articles from JSTOR, faced 35 years under CFAA (case tragically contributed to his suicide)
-   **David Nosal**: Exceeded authorized access to employer database after termination, Supreme Court case defining "exceeds authorized access"

**Critical Point**: Even if you discover SQL injection "accidentally," exploiting it without authorization is a federal crime.

### United Kingdom: Computer Misuse Act 1990

Prohibits:

-   **Section 1**: Unauthorized access to computer material (including databases)
-   **Section 2**: Unauthorized access with intent to commit further offenses
-   **Section 3**: Unauthorized modification of computer material (data deletion, corruption)
-   **Section 3A**: Making, supplying or obtaining articles for use in offenses

**Penalties**: Up to 10 years imprisonment + unlimited fines

**Notable Case:**

-   **TalkTalk Breach (2015)**: Attackers used SQL injection to steal customer data. Resulted in £400,000 fine and multiple arrests.

### European Union: GDPR & National Laws

-   **GDPR Article 32**: Requires testing of security measures (BUT testing must be authorized)
-   **GDPR Article 83**: Violations can result in fines up to €20M or 4% global annual revenue
-   **Network and Information Systems (NIS) Directive**: Security obligations for operators of essential services
-   **Cybersecurity Act**: EU-wide cybersecurity framework
-   Various EU member states have additional cybercrime laws (e.g., Germany's StGB §303a/b, France's Godfrain Law)

**Key Points:**

-   Authorized penetration testing is ENCOURAGED for critical infrastructure
-   Unauthorized testing is CRIMINAL regardless of intent
-   Data exfiltration via SQL injection = GDPR breach (even if accidental)

### Other Jurisdictions

Most countries have similar laws:

-   **Canada**: Criminal Code (Section 342.1 - Unauthorized use of computer)
-   **Australia**: Cybersecurity Act 2001, Criminal Code Act 1995 (Section 477-478)
-   **India**: IT Act 2000 (Section 66 - Computer-related offenses, Section 43 - Unauthorized access)
-   **China**: Cybersecurity Law (严格监管) - Very strict enforcement
-   **Brazil**: Marco Civil da Internet + General Data Protection Law (LGPD)
-   **Japan**: Unauthorized Computer Access Law (不正アクセス行為の禁止等に関する法律)
-   **Singapore**: Computer Misuse Act (Chapter 50A)

**Universal Principle**: "I didn't know it was illegal" is NOT a defense anywhere.

---

## 🛡️ Pythia Built-In Safeguards

### 1. Safe-by-Default Architecture

-   **Default mode**: `--safe` (passive detection only)
    -   Minimal SQL injection probes (single quotes, basic tests)
    -   No blind SQL injection attempts
    -   No time-based attacks
    -   No data extraction
    -   No database enumeration
    -   Rate limited to 2 req/s (very respectful)
-   **Aggressive mode**: `--aggressive` (comprehensive testing)
    -   **Requires verified consent token**
    -   Boolean blind SQL injection testing
    -   Time-based blind SQL injection testing
    -   UNION-based data extraction attempts
    -   Error-based SQL injection probing
    -   Extended crawling (more pages/forms)
    -   Higher rate limit (40 req/s maximum)

### 2. Consent Token Verification System

Pythia **requires** ownership verification before:

-   `--aggressive` mode (deep SQL injection testing)
-   `--use-ai` (sends sanitized data to external AI API)

**Token Methods:**

-   **HTTP**: Place token file at `https://yourdomain.com/.well-known/verify-{token}.txt`
-   **DNS**: Add TXT record `pythia-verify={token}` to your domain

**Token Properties:**

-   48-hour expiration (prevents stale authorizations)
-   Cryptographically random (prevents guessing)
-   Stored in shared database (`~/.argos/argos.db` - shared with Argus/Hephaestus/Asterion)
-   Audit trail for compliance

**Purpose**: Technical proof of site control, NOT a replacement for legal authorization.

### 3. Comprehensive Logging & Auditing

All actions are logged with timestamps:

-   Targets scanned (URLs, domains, endpoints)
-   Parameters tested for SQL injection
-   Scan mode used (safe/aggressive)
-   Consent verification events (success/failure)
-   SQL injection findings discovered (with severity levels)
-   Payloads attempted (sanitized in logs)
-   Database responses (truncated, sanitized)
-   Errors and exceptions
-   API calls (when using AI features)

**Log Security:**

-   Automatic secret redaction (passwords, tokens, API keys, database credentials)
-   Multiple verbosity levels (`-v`, `-vv`, `-vvv`)
-   JSON and text format support
-   Timestamped with severity levels
-   Log rotation to prevent disk filling

**Log Location**: `~/.pythia/logs/pythia.log`

**Legal Protection**: Logs are evidence of ethical and authorized usage.

---

## 📋 Best Practices

### Before Scanning

1. **Document Authorization**

    - Get written permission from authorized personnel (CTO, CISO, IT Manager)
    - Define scope clearly:
        - Specific domains/subdomains
        - URLs and endpoints in scope
        - Parameters allowed to test
        - Allowed SQL injection types (error-based, blind, time-based, UNION)
        - Database actions permitted (read-only vs write tests)
        - Time windows (business hours vs off-hours)
    - Specify permitted actions and depth
    - Include emergency contact information
    - Define acceptable impact (response time degradation, error rates)

2. **Inform Stakeholders**

    - Notify IT/security operations teams in advance
    - Notify database administrators (DBAs) - critical!
    - Provide your contact information
    - Establish communication channels (email, Slack, phone, PagerDuty)
    - Set up monitoring alerts (so your scans don't trigger false alarms)
    - Document escalation procedures
    - Coordinate with DevOps team (to whitelist your IP if needed)

3. **Verify Consent Token**

    - Always verify domain ownership before aggressive mode
    - Keep proof of verification (screenshot, log output)
    - Verify token hasn't expired
    - Re-verify if scope changes

4. **Test in Non-Production First**
    - **CRITICAL**: Start with development/staging environments
    - Validate scan behavior and impact
    - Confirm rate limits are appropriate for server capacity
    - Check for false positives
    - Verify backup procedures are in place
    - Test incident response (intentionally trigger alerts to verify monitoring)

### During Scanning

1. **Respect Scope Boundaries**

    - Stay within authorized applications and endpoints only
    - Don't follow redirects to external domains
    - Don't test parameters marked "out of scope"
    - Honor time restrictions (avoid peak hours, Black Friday, end-of-month)
    - Stop if you encounter administrative interfaces unexpectedly

2. **Monitor Impact**

    - Watch for service degradation (response time, error rates)
    - Monitor database CPU/memory usage (coordinate with DBA)
    - Use rate limiting (`--rate`) appropriately
    - Adjust threads (`--threads`) based on server capacity
    - **Stop immediately** if issues detected:
        - Application errors increase
        - Response times spike
        - Database locks detected
        - Security operations contacts you

3. **Avoid Harmful Actions**

    - **Never** modify database records (INSERT, UPDATE, DELETE)
    - **Never** drop tables or databases
    - **Never** exfiltrate sensitive data beyond proof-of-concept
    - **Never** attempt to bypass authentication
    - **Never** download customer PII, financial data, or credentials
    - **Never** cause denial of service conditions
    - **Never** attempt privilege escalation beyond demonstration
    - **Stop at proof-of-concept**: Prove vulnerability exists, don't exploit it fully

4. **Maintain Communication**
    - Notify stakeholders when scan starts/ends
    - Report any concerning findings immediately (critical SQL injection = stop and notify)
    - Document any unexpected behavior
    - Keep audit trail of all activities
    - Provide real-time updates if requested

### After Scanning

1. **Secure Reports**

    - Encrypt sensitive findings before transmission
    - Use PGP/GPG encryption for email
    - Limit report distribution to authorized personnel only
    - Use secure channels (encrypted email, secure file transfer, secure ticketing systems)
    - Store reports securely with access controls
    - Set retention policies and follow them
    - **Never** post findings to public GitHub, forums, or social media before disclosure deadline

2. **Responsible Disclosure**

    - Report SQL injection vulnerabilities to application owner first (private disclosure)
    - Provide clear description with reproduction steps
    - Include: HTTP method, vulnerable parameter, payload, database response
    - Allow reasonable time for fixes:
        - **Critical** (authentication bypass, data extraction): 7-14 days
        - **High** (blind SQL injection, information disclosure): 30 days
        - **Medium/Low** (minor SQL injection in non-critical endpoints): 90 days
    - Don't publicly disclose before patches are deployed
    - Coordinate disclosure timeline with owner
    - Consider CVE assignment for significant vulnerabilities

3. **Clean Up**
    - Remove any test records created (if any - should be rare)
    - Delete logs on target system (if any)
    - Revoke consent tokens when engagement ends
    - Securely delete local reports when no longer needed
    - Update documentation with lessons learned
    - Provide knowledge transfer to client team

---

## 🎓 Ethical Hacking Principles

### The Hacker's Code of Ethics

1. **Do No Harm**: Security testing should improve security, not compromise it. SQL injection testing should never corrupt data or cause outages.
2. **Respect Privacy**: Don't access, copy, or disclose customer data, PII, financial records, or credentials unnecessarily. Proof-of-concept is enough.
3. **Be Transparent**: Document and disclose methods, tools, and findings appropriately. SQL injection payloads used should be clearly documented.
4. **Act with Integrity**: Never abuse access or findings for personal gain, competitive advantage, revenge, or blackmail.
5. **Respect the Law**: Comply with all applicable laws, regulations, and contractual obligations. Unauthorized SQL injection testing is a federal crime.
6. **Give Back**: Share knowledge responsibly with the security community (after proper disclosure windows).
7. **Stay Current**: Keep skills updated and follow evolving ethical standards. Database security evolves constantly.

### Professional Standards

If you're a professional penetration tester:

-   Follow **OWASP Testing Guide** methodology (WSTG v4.2, Section 4.8: SQL Injection Testing)
-   Adhere to **PTES** (Penetration Testing Execution Standard)
-   Consider **CEH** (Certified Ethical Hacker) code of ethics
-   Follow **SANS Institute** guidelines
-   Respect **Bug Bounty Program** rules (HackerOne, Bugcrowd, Synack, Intigriti)
-   Comply with **PCI DSS** (if testing payment systems), **HIPAA** (healthcare), **SOC 2** requirements (if applicable)
-   Follow **OSSTMM** (Open Source Security Testing Methodology Manual)

---

## ⚠️ Prohibited Activities

**NEVER** use Pythia for:

❌ Scanning applications without explicit authorization
❌ Cyber espionage or competitive intelligence gathering
❌ Data exfiltration beyond proof-of-concept (e.g., dumping entire customer databases)
❌ Credential harvesting from database tables
❌ Database modification, deletion, or corruption
❌ Privilege escalation attacks beyond demonstration
❌ Denial of service attacks (resource exhaustion via SQL queries)
❌ Backdoor installation via SQL injection (INTO OUTFILE, xp_cmdshell, etc.)
❌ Lateral movement to other systems via database server
❌ Exploiting vulnerabilities beyond proof-of-concept
❌ Harassment, intimidation, or extortion
❌ Reselling scan reports without permission
❌ Any illegal activity whatsoever

**Real-World Example**: The 2019 Capital One breach involved SQL injection-like attack (SSRF to metadata service). The attacker went beyond proof-of-concept and exfiltrated 100M+ customer records. Result: Federal charges, 5 years imprisonment.

**Reminder**: Even if you find SQL injection vulnerabilities "by accident," exploiting them without authorization is illegal.

---

## 🤝 Responsible Disclosure

If you discover SQL injection vulnerabilities using Pythia:

### 1. Private Disclosure (Recommended)

**Steps:**

1. **Stop exploitation immediately** - Don't extract data beyond minimal proof-of-concept
2. Contact application owner/administrator privately
3. Use official security contact if available:
    - `security@domain.com`
    - `.well-known/security.txt` (RFC 9116)
    - Bug bounty program contact
    - HackerOne/Bugcrowd submission form
4. Provide clear, professional report:
    - **Vulnerability description**: "SQL injection in user search endpoint"
    - **Severity assessment**: Use CVSS calculator (SQL injection typically 8.5-9.8)
    - **Affected components**: URL, parameter name, HTTP method
    - **Reproduction steps**:
        ```
        1. Navigate to https://example.com/search
        2. Enter payload: test' OR '1'='1
        3. Observe: All records returned
        ```
    - **Database type detected**: MySQL, PostgreSQL, MSSQL, Oracle
    - **Potential impact**: "Authentication bypass, data exfiltration of 10,000+ customer records"
    - **Remediation recommendations**: "Use parameterized queries (prepared statements)"
    - **Example fix** (code snippet if appropriate)
5. Offer to assist with remediation (within reason)
6. Give reasonable time to fix before any public disclosure
7. **DO NOT** include:
    - Actual customer data extracted
    - Database credentials
    - Full database dumps
    - Destructive payloads (DROP TABLE examples)

**Timeframes:**

-   **Critical** (authentication bypass, PII extraction, financial data access): 7-14 days
-   **High** (blind SQL injection with confirmed data access): 30 days
-   **Medium** (SQL injection with limited impact): 60 days
-   **Low** (SQL injection in non-production or limited functionality): 90 days

### 2. Coordinated Disclosure

-   Use vendor security contact email
-   Follow published vulnerability disclosure policy
-   Register CVE identifier if applicable:
    -   Via MITRE: https://cveform.mitre.org/
    -   Via GitHub Security Advisories
    -   Via bug bounty program (they often handle CVE assignment)
-   Coordinate public disclosure date
-   Credit researchers appropriately
-   Provide vendor opportunity to prepare patches
-   Allow time for customers to update

### 3. Public Disclosure

**Only after reasonable time has passed AND vendor has patched:**

-   Redact sensitive details:
    -   Database credentials found in error messages
    -   Admin usernames
    -   Internal IP addresses
    -   API keys
    -   Customer data
-   Provide remediation guidance prominently
-   Credit vendor for cooperation (if applicable)
-   Use responsible platforms:
    -   Personal blog (with responsible disclosure banner)
    -   Security conferences (BSides, OWASP, DEF CON)
    -   Academic papers
    -   Security advisory databases
-   **Don't release full exploit code** publicly without vendor agreement
-   Consider releasing sanitized PoC instead of weaponized exploit

### Resources

-   **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
-   **CVE Program**: https://www.cve.org/
-   **NVD (National Vulnerability Database)**: https://nvd.nist.gov/
-   **security.txt**: https://securitytxt.org/
-   **HackerOne Disclosure Guidelines**: https://www.hackerone.com/disclosure-guidelines
-   **OWASP Vulnerability Disclosure Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html
-   **ISO/IEC 29147**: Vulnerability disclosure standard

---

## 🔍 Pythia-Specific Guidelines

### Consent Token Implementation

**Technical Detail**: Pythia's consent token is a technical safeguard, NOT a legal authorization.

**What It Is:**

-   Cryptographic proof you control the target application's domain
-   Prevents accidental scanning of wrong targets
-   Creates audit trail for compliance purposes
-   Required for aggressive mode and AI analysis
-   **Shared with Argus and Hephaestus** (unified consent system)

**What It Is NOT:**

-   Legal permission (still need written authorization)
-   Protection against prosecution if unauthorized
-   Substitute for proper contracts or bug bounty terms
-   Guarantee that testing is safe or authorized

**Best Practices:**

-   Generate unique token per engagement
-   Document token generation date/time
-   Revoke tokens immediately after engagement ends
-   Keep tokens confidential (treat like passwords)
-   Don't reuse tokens across different clients

### SQL Injection Testing Modes

**Safe Mode** (`--safe`, default):

-   Passive detection (response analysis, error messages)
-   Minimal payloads (single quote, double quote)
-   No blind SQL injection testing
-   No time delays
-   No data extraction
-   Rate: 2 req/s
-   **No consent token required**

**Aggressive Mode** (`--aggressive`):

-   Error-based SQL injection (10+ payloads)
-   Boolean blind SQL injection (TRUE/FALSE comparison)
-   Time-based blind SQL injection (SLEEP, WAITFOR delays)
-   UNION-based SQL injection (column enumeration, data extraction)
-   Extended crawling
-   Rate: Up to 40 req/s
-   **Requires verified consent token**

**Recommendation**:

-   Always start with `--safe` mode first
-   Review findings before escalating to `--aggressive`
-   Test in staging before production
-   Coordinate aggressive tests with DBAs

### AI Analysis Privacy & Security

When using `--use-ai` with cloud providers (OpenAI, Anthropic):

**What Gets Sent (sanitized):**

-   SQL injection type (error-based, blind, time-based, UNION)
-   Vulnerable parameter names (e.g., "id", "search")
-   HTTP method (GET, POST)
-   Database type detected (MySQL, PostgreSQL, etc.)
-   Severity levels
-   Generic remediation context
-   Finding codes (PYTHIA-SQL-001, etc.)

**What Gets REMOVED (sanitized automatically):**

-   Consent tokens
-   Database credentials found in error messages
-   Session tokens and cookies
-   Admin usernames
-   Database schema details
-   Table/column names
-   Actual extracted data (customer records, etc.)
-   Internal IP addresses
-   API keys
-   Full SQL queries (truncated to 500 chars)
-   Any PII (personally identifiable information)

**Privacy Options:**

1. **Ollama (Local Models)**: 100% offline, no data leaves your machine

    - **Recommended for**: Healthcare (HIPAA), Finance (PCI-DSS), Government, Military, Critical Infrastructure
    - **Trade-off**: Slower (28 min CPU vs 35s cloud), lower quality analysis
    - **Privacy**: Maximum (100%)

2. **OpenAI**: Standard privacy (encrypted in transit, OpenAI privacy policy applies)

    - **Recommended for**: General commercial use, standard penetration tests
    - **Privacy**: Standard

3. **Anthropic Claude**: Enhanced privacy (no training on user data, privacy-first approach)
    - **Recommended for**: Privacy-conscious organizations, EU clients (GDPR)
    - **Privacy**: High

**Best Practice**: Use Ollama for sensitive applications (banking, healthcare, government), cloud AI for general testing.

### Database Security & Privacy

`~/.argos/argos.db` (shared database) contains potentially sensitive information:

-   Scan history with application URLs
-   SQL injection findings (vulnerability details)
-   Vulnerable parameters identified
-   Database types detected
-   Consent tokens
-   Timestamps and metadata
-   Error messages (may contain schema info)

**Protect This File:**

```bash
# Restrict permissions (owner read/write only)
chmod 600 ~/.argos/argos.db

# Encrypt your home directory (full disk encryption)
# Linux: LUKS
sudo cryptsetup luksFormat /dev/sdX
# Windows: BitLocker
# macOS: FileVault

# Don't commit to version control
echo ".argos/" >> ~/.gitignore

# Securely delete when engagement ends
shred -vfz -n 10 ~/.argos/argos.db

# Or use encrypted filesystem
encfs ~/secure-data ~/encrypted-data
mv ~/.argos ~/encrypted-data/
```

**Shared Database Note:**

-   Pythia shares database with Argus (WordPress scanner), Asterion (Network Maze Mapping) and Hephaestus (API security tester)
-   All tools respect same consent/authorization framework
-   Cross-tool findings correlation for unified vulnerability tracking
-   Single consent token works across all tools for same domain

### Report Handling

**JSON Reports** (`~/.pythia/reports/pythia_sqli_report_*.json`):

-   Machine-readable, ~30-80KB
-   Contains full SQL injection vulnerability details
-   Includes payloads, responses, timing data
-   Suitable for automation/CI/CD integration
-   **Store securely**: Contains sensitive findings

**HTML Reports** (`~/.pythia/reports/pythia_sqli_report_*.html`):

-   Human-readable, ~150-300KB (depending on AI analysis)
-   Self-contained (no external resources)
-   Suitable for stakeholder presentation
-   Includes executive summary (if AI enabled)
-   **Redact before sharing externally**

**Best Practices:**

```bash
# Encrypt reports before email
gpg --encrypt --recipient client@example.com pythia_report.html

# Use secure file transfer
scp -i key.pem report.html user@secure-server:/reports/

# Set retention policy (auto-delete after 90 days)
find ~/.pythia/reports -mtime +90 -delete

# Redact sensitive data before sharing
sed -i 's/admin_user_[0-9]*/[REDACTED]/g' report.html

# Compress and password-protect
zip --encrypt sensitive_report.zip pythia_report.html
```

---

## 📞 Reporting Misuse

If you observe or suspect misuse of Pythia:

### 1. To Target Owner

-   Contact application owner immediately with evidence
-   Provide scan logs, timestamps, source IPs
-   Include SQL injection payloads detected in logs
-   Assist with incident response if appropriate
-   Document any data exfiltration observed

### 2. To Law Enforcement

-   **US**:
    -   FBI Internet Crime Complaint Center (IC3): https://www.ic3.gov
-   **UK**:
    -   Action Fraud: https://www.actionfraud.police.uk
    -   National Cyber Security Centre (NCSC): https://www.ncsc.gov.uk
-   **EU**:
    -   EUROPOL EC3: https://www.europol.europa.eu/about-europol/european-cybercrime-centre-ec3
    -   National CERTs: https://www.cert.europa.eu/
-   Local police cybercrime units

### 3. To Me (For Documentation Only)

-   Website: https://rodhnin.com
-   GitHub Issues: https://github.com/rodhnin/pythia-sql-clairvoyance/issues
-   **Note**: I am not law enforcement, but I will cooperate with legitimate investigations

**I Take Misuse Seriously:**

-   I will cooperate with law enforcement investigations
-   I may block known malicious actors from support channels
-   I maintain ethical use standards in our community
-   I may implement additional safeguards based on reported misuse

---

## ✅ Ethical Use Checklist

Before every scan with Pythia, verify:

-   [ ] I have **written authorization** to test this application (email, contract, bug bounty terms)
-   [ ] The target is **within the authorized scope** (domain, endpoints, parameters)
-   [ ] I have **informed relevant stakeholders** (IT, DBAs, security operations, management)
-   [ ] I have **verified domain ownership** via consent token (if using `--aggressive` or `--use-ai`)
-   [ ] I understand the **potential impact** of SQL injection testing (database locks, timeouts, data corruption risk)
-   [ ] I have **tested in staging/development first** (never production-first)
-   [ ] I have a **plan for responsible disclosure** of findings
-   [ ] I will **respect the law** and ethical principles at all times
-   [ ] I will **not exfiltrate real data** beyond minimal proof-of-concept
-   [ ] I will **not modify or delete database records**
-   [ ] I will **properly secure and dispose of reports** after engagement ends
-   [ ] I have **emergency contacts** if something goes wrong (DBA, DevOps, Security team)
-   [ ] I have **documented this engagement** for audit purposes (scope, authorization, timeline)
-   [ ] I will **stop immediately** if I encounter unexpected systems or data
-   [ ] I understand **time-based tests can impact production** and will coordinate carefully

**If you can't check ALL boxes, DO NOT SCAN.**

---

## 📚 Additional Resources

### Organizations & Standards Bodies

-   **OWASP** (Open Web Application Security Project): https://owasp.org
    -   OWASP Testing Guide (WSTG v4.2, Section 4.8: SQL Injection Testing)
    -   OWASP Top 10 (A03:2021 - Injection)
    -   OWASP SQL Injection Prevention Cheat Sheet
    -   OWASP Query Parameterization Cheat Sheet
-   **SANS Institute**: https://www.sans.org/
    -   SQL Injection Detection and Prevention
    -   Secure Coding Guidelines
-   **NIST** (National Institute of Standards and Technology): https://www.nist.gov
    -   NIST Cybersecurity Framework
    -   NIST 800-115 (Technical Guide to Information Security Testing)
-   **CREST** (Council of Registered Ethical Security Testers): https://www.crest-approved.org/
-   **PCI Security Standards Council**: https://www.pcisecuritystandards.org/
    -   PCI DSS Requirement 6.5.1 (Injection flaws, particularly SQL injection)

### Legal & Compliance Resources

-   **EFF** (Electronic Frontier Foundation): https://www.eff.org/issues/coders
-   **CFAA Reform**: https://www.eff.org/issues/cfaa
-   **Bug Bounty Legal Safe Harbor**: https://www.hackerone.com/resources/legal-safe-harbor
-   **Responsible Disclosure Policy Template**: https://github.com/bugcrowd/disclosure-policy

### Technical Standards & Guides

-   **PTES** (Penetration Testing Execution Standard): http://www.pentest-standard.org/
-   **OSSTMM** (Open Source Security Testing Methodology Manual): https://www.isecom.org/OSSTMM.3.pdf
-   **NIST SP 800-115**: https://csrc.nist.gov/pubs/sp/800/115/final
-   **OWASP WSTG**: https://owasp.org/www-project-web-security-testing-guide/

### SQL Injection Resources

-   **SQLi Cheat Sheet**: https://portswigger.net/web-security/sql-injection/cheat-sheet
-   **SQL Injection Wiki**: https://sqlwiki.netspi.com/
-   **Bobby Tables**: https://bobby-tables.com/ (SQL injection prevention)
-   **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection

### Training & Certification

-   **CEH** (Certified Ethical Hacker): https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/
-   **OSCP** (Offensive Security Certified Professional): https://www.offensive-security.com/pwk-oscp/
-   **OSWE** (Offensive Security Web Expert): https://www.offensive-security.com/awae-oswe/
-   **GPEN** (GIAC Penetration Tester): https://www.giac.org/certification/penetration-tester-gpen
-   **GWAPT** (GIAC Web Application Penetration Tester): https://www.giac.org/certification/web-application-penetration-tester-gwapt
-   **HackerOne University**: https://www.hackerone.com/hackers/hacker101
-   **Bugcrowd University**: https://www.bugcrowd.com/hackers/bugcrowd-university/
-   **PortSwigger Web Security Academy**: https://portswigger.net/web-security (Free SQL injection labs)

---

## 🎯 Conclusion

**Ethical hacking is not just about technical skill—it's about integrity, responsibility, and respect for the law.**

Pythia is a powerful tool designed to improve database and application security by identifying SQL injection vulnerabilities. With great power comes great responsibility. Use it wisely, legally, and ethically.

### Key Takeaways

1. **Authorization is mandatory**: Always get written permission before testing for SQL injection
2. **Consent tokens are not permission**: They prove technical control, not legal authority
3. **Document everything**: Logs, authorization, findings, communications, timeline
4. **Do no harm**: Never extract real data, modify databases, or disrupt services beyond proof-of-concept
5. **Stop at proof-of-concept**: Demonstrating SQL injection exists is enough—don't dump entire databases
6. **Disclose responsibly**: Give application owners time to fix before public disclosure
7. **Respect privacy**: Use local AI (Ollama) for sensitive applications (healthcare, finance, government)
8. **Stay legal**: One mistake can end your career and result in federal prosecution
9. **Test in staging first**: Never run aggressive SQL injection tests in production without coordination
10. **Coordinate with DBAs**: Time-based blind SQL injection can impact production databases

### Final Reminder

**If you're unsure whether you have permission to test an application for SQL injection, YOU DON'T.**

When in doubt:

1. **Stop immediately**
2. Get written authorization
3. Document the authorization
4. Verify scope clearly (URLs, parameters, databases, time windows)
5. Test in staging/development first
6. Coordinate with DBAs and DevOps
7. Only then proceed with production testing

**Remember**:

-   SQL injection testing can impact production systems
-   Unauthorized testing is a federal crime (CFAA)
-   Data exfiltration = GDPR violation (even accidental)
-   Your reputation, career, and freedom depend on following these guidelines
-   Always err on the side of caution and proper authorization

---

## 📧 Questions or Concerns?

**Author & Maintainer:**  
Rodney Dhavid Jimenez Chacin (rodhnin)

**Contact:**

-   🌐 Website: https://rodhnin.com
-   🐙 GitHub: https://github.com/rodhnin
-   💬 Discussions: https://github.com/rodhnin/pythia-sql-clairvoyance/discussions

**For Security Issues with Pythia itself:**

-   Report vulnerabilities privately via: https://rodhnin.com
-   Allow 90 days for patching before public disclosure
-   We follow coordinated disclosure practices

---

## 📜 Legal Disclaimer

**IMPORTANT LEGAL NOTICE**

This software is provided for **authorized security testing only**. By using Pythia, you agree that:

1. You will only test applications and databases you own or have explicit written permission to test
2. You accept full legal responsibility for your use of this tool
3. The author and contributors assume **NO LIABILITY** for misuse, data loss, service disruption, or damages
4. You will comply with all applicable laws and regulations in your jurisdiction
5. Unauthorized SQL injection testing may result in severe civil and criminal penalties
6. You will not exfiltrate, modify, or delete data without explicit authorization
7. You understand that SQL injection testing can impact production systems

**The author of Pythia:**

-   Do not endorse or encourage illegal activity
-   Will cooperate with law enforcement in cases of misuse
-   Reserve the right to restrict access to this tool
-   Make no warranties about the accuracy or completeness of scan results
-   Are not responsible for any damage caused by improper use

**SQL Injection Testing Risks:**

-   Database locks and timeouts
-   Performance degradation
-   Accidental data modification
-   Production outages
-   Legal prosecution if unauthorized
-   GDPR violations if data is exfiltrated

**USE AT YOUR OWN RISK. YOU HAVE BEEN WARNED.**

---

_Version: 1.0_  
_Applies to: Pythia SQL Clairvoyance v0.1.0 and later_

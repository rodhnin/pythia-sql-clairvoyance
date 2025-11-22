# Testing Docker Deployment - Pythia

This guide helps you verify that Docker deployment is working correctly.

> **IMPORTANT:** Pythia is a **one-shot scanner**, NOT a daemon service.
> All commands use `docker compose run --rm pyth` (NOT `docker compose up -d` or `exec`).

## Prerequisites

- Docker installed and running
- Docker Compose installed

---

## Test 1: Verify Docker and Docker Compose

```bash
docker --version
docker compose version
```

Expected: Both commands return version information.

---

## Test 2: Build Pythia Scanner Image

```bash
cd docker
docker compose build --no-cache
```

Expected output:
```
[+] Building ...
✔ pyth Pulled
[+] Built successfully
```

---

## Test 3: Verify Image Was Created

```bash
docker images | grep pythia
```

Expected: You should see the `pythia` image listed.

---

## Test 4: Run Help Command (Verify Entry Point)

```bash
docker compose run --rm pyth --help
```

Expected output:
```
usage: pyth [-h] --target TARGET [--safe] [--html] ...
Pythia - SQL Injection Detection Scanner
...
```

**If help is displayed, the entry point is working! ✅**

---

## Test 5: Verify Environment Variables

```bash
docker compose run --rm pyth python3 -c "import os; print(f'PYTHIA_DOCKER_IN_CONTAINER={os.getenv(\"PYTHIA_DOCKER_IN_CONTAINER\")}')"
```

Expected output:
```
PYTHIA_DOCKER_IN_CONTAINER=true
```

---

## Test 6: Verify Auto-Detection (Critical Test!)

```bash
docker compose run --rm pyth python3 -c "
from pyth.core.config import Config
c = Config.load()
c.expand_paths()
print(f'✅ in_container: {c.in_container}')
print(f'✅ report_dir: {c.report_dir}')
print(f'✅ database: {c.database}')
"
```

**Expected output:**
```
✅ in_container: True
✅ report_dir: /reports
✅ database: /data/argos.db
```

**If you see this, auto-detection is working! ✅**

---

## Test 7: Verify Volumes are Mounted

```bash
docker compose run --rm pyth ls -la /reports /data
```

Expected: Both directories exist (may be empty at this point).

---

## Test 8: Run a Test Scan (Example.com)

```bash
docker compose run --rm pyth --target http://example.com --safe
```

Expected:
- Scan completes without errors
- Output shows scan progress
- No permission errors when writing

---

## Test 9: Verify Report Was Created

```bash
ls -lh ./reports/
```

Expected: You should see a JSON report file like:
```
pythia_sqli_report_example_com_20251117_*.json
```

---

## Test 10: Verify Database Was Created

```bash
ls -lh ./data/
```

Expected: You should see:
```
argos.db
```

---

## Test 11: Testing Lab (Vulnerable Apps)

### Start Testing Lab

```bash
docker compose -f compose.testing.yml up -d
```

Wait 15-30 seconds for services to initialize:
```bash
sleep 30
```

### Verify Vulnerable Apps are Running

```bash
curl -I http://localhost:8081  # PHP app
curl -I http://localhost:8082  # Flask app
curl -I http://localhost:8080  # DVWA
```

Expected: All return HTTP 200 or 302 responses.

### Scan the PHP Vulnerable App

```bash
docker compose run --rm pyth --target http://php-vuln-app --safe --html
```

Expected:
- Scan finds SQLi vulnerabilities
- Both JSON and HTML reports created in `./reports/`
- No path-related errors

### Verify Reports

```bash
ls -lh ./reports/
```

Expected: You should see both `.json` and `.html` files.

### Open HTML Report

```bash
# Linux
xdg-open ./reports/*.html

# macOS
open ./reports/*.html

# Windows
start ./reports/*.html
```

Expected: Beautiful HTML report opens in browser with findings.

---

## Test 12: Verify Non-Root User

```bash
docker compose run --rm pyth whoami
docker compose run --rm pyth id
```

Expected output:
```
pythia
uid=1000(pythia) gid=1000(pythia) groups=1000(pythia)
```

**If running as root (uid=0), there's a configuration issue!**

---

## Test 13: Verify Network Communication (Testing Lab Only)

Ensure testing lab is running first:
```bash
docker compose -f compose.testing.yml ps
```

Test DNS resolution:
```bash
docker compose run --rm pyth ping -c 3 php-vuln-app
docker compose run --rm pyth ping -c 3 mysql
```

Expected: Ping succeeds (containers can communicate).

**If ping fails with "Name or service not known":**
- Pythia needs to connect to the external `docker_sqli-lab` network
- Verify `compose.yml` has the `sqli-lab` network configured

---

## Cleanup After Testing

### Stop Testing Lab

```bash
docker compose -f compose.testing.yml down -v
```

### Remove Test Reports (Optional)

```bash
rm -rf ./reports/* ./data/*
```

### Remove Docker Images (Optional)

```bash
docker compose down --rmi all
docker compose -f compose.testing.yml down --rmi all
```

---

## Common Issues and Solutions

### Issue: "in_container: False" in Test 6

**Solution:** Environment variable not set correctly.

```bash
# Check compose.yml has:
environment:
  - PYTHIA_DOCKER_IN_CONTAINER=true
```

### Issue: Permission Denied when Writing Reports

**Solution:** Fix permissions on host

```bash
chmod 755 ./data ./reports
chown -R 1000:1000 ./data ./reports
```

### Issue: Reports Not Persisting

**Solution:** Verify volumes in compose.yml

```yaml
volumes:
  - ./reports:/reports
  - ./data:/data
```

### Issue: Can't Connect to Testing Lab Apps

**Symptom:** `NameResolutionError: Failed to resolve 'php-vuln-app'`

**Solution 1:** Wait longer for services to initialize

```bash
docker compose -f compose.testing.yml logs -f mysql
# Wait until you see "ready for connections"
```

**Solution 2:** Verify network configuration in compose.yml

```yaml
networks:
  - default
  - sqli-lab

networks:
  sqli-lab:
    external: true
    name: docker_sqli-lab
```

The testing lab creates network `docker_sqli-lab`, and Pythia must connect to it.

### Issue: "docker: 'compose' is not a docker command"

**Solution:** You're using an old Docker version. Use `docker-compose` (with hyphen):

```bash
docker-compose run --rm pyth --target http://example.com --safe
```

Or update Docker to latest version.

---

## Success Criteria

✅ All 13 tests pass
✅ in_container: True
✅ report_dir: /reports
✅ database: /data/argos.db
✅ Reports created in ./reports/
✅ No permission errors
✅ Running as UID 1000 (non-root)
✅ Network communication with testing lab works

**If all criteria are met, Docker deployment is working perfectly!** 🎉

---

## Need Help?

- GitHub Issues: https://github.com/rodhnin/pythia-sql-clairvoyance/issues
- Website: https://rodhnin.com

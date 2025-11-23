# Contributing to Pythia SQL Clairvoyance

Thank you for your interest in contributing to Pythia! We welcome contributions from the community.

## Table of Contents

-   [Code of Conduct](#code-of-conduct)
-   [How Can I Contribute?](#how-can-i-contribute)
-   [Development Setup](#development-setup)
-   [Coding Standards](#coding-standards)
-   [Pull Request Process](#pull-request-process)
-   [Reporting Bugs](#reporting-bugs)
-   [Suggesting Features](#suggesting-features)
-   [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

By participating in this project, you agree to:

-   ✅ Use Pythia **only for authorized security testing**
-   ✅ Follow ethical hacking principles
-   ✅ Comply with all applicable laws (CFAA, GDPR, etc.)
-   ✅ Respect other contributors
-   ✅ Provide constructive feedback
-   ✅ Help maintain a welcoming environment

**I do not tolerate:**

-   ❌ Harassment or discrimination
-   ❌ Encouraging illegal use of the tool
-   ❌ Malicious behavior
-   ❌ Spam or low-effort contributions

---

## How Can I Contribute?

### 1. 🐛 Reporting Bugs

Found a bug? Help us fix it!

**Before Reporting:**

-   Check existing [GitHub Issues](https://github.com/rodhnin/pythia-sql-clairvoyance/issues)
-   Verify it's reproducible
-   Check if it's already fixed in the latest version

**Bug Report Template:**

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:

1. Run command: `pyth --target ...`
2. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**

-   Pythia version: [e.g., 0.1.0]
-   Python version: [e.g., 3.11.5]
-   OS: [e.g., Ubuntu 22.04, macOS 13, Windows 11]
-   Installation method: [pip, Docker, source]

**Logs/Screenshots**
```

[Paste relevant logs here]

```

**Additional context**
Any other information that might help.
```

---

### 2. 💡 Suggesting Features

Have an idea for improvement?

**Feature Request Template:**

```markdown
**Feature Description**
Clear description of the proposed feature.

**Use Case**
Why is this feature needed? Who will benefit?

**Proposed Implementation**
Ideas for how this could be implemented (optional).

**Alternatives**
Other approaches you've considered (optional).

**Additional Context**
Screenshots, mockups, or examples.
```

---

### 3. 🔧 Contributing Code

#### Areas We Need Help:

**High Priority:**

-   🧪 Unit tests (pytest)
-   📝 Documentation improvements
-   🐛 Bug fixes
-   🔍 Additional SQLi detection methods
-   🌐 DBMS-specific payloads

**Medium Priority:**

-   ✨ Enhanced crawler features
-   🎨 HTML report improvements
-   🤖 AI prompt optimization
-   🔐 Additional consent verification methods

**Low Priority (but welcome!):**

-   🌍 Internationalization (i18n)
-   📊 Additional report formats
-   🔌 Plugin system for custom checks

---

## Development Setup

### Prerequisites

-   Python 3.11+ (3.12 recommended)
-   Git
-   Virtual environment tool (venv or conda)
-   Docker (for testing labs)

### Setup Steps

**1. Fork and clone the repository:**

```bash
# Fork on GitHub first, then:
git clone https://github.com/YOUR-USERNAME/pythia-sql-clairvoyance.git
cd pythia-sql-clairvoyance

# Add upstream remote
git remote add upstream https://github.com/rodhnin/pythia-sql-clairvoyance.git
```

**2. Create virtual environment:**

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows
```

**3. Install development dependencies:**

```bash
pip install --upgrade pip
pip install -r requirements.txt

# Install dev tools
pip install pytest pytest-cov black flake8 mypy isort
```

**4. Install Pythia in editable mode:**

```bash
pip install -e .
```

**5. Verify installation:**

```bash
python -m pyth --version
# Expected: Pythia v0.1.0
```

**6. Run tests (when available):**

```bash
pytest tests/ -v
```

---

## Coding Standards

### Python Style

We follow **PEP 8** with some modifications:

**Formatting:**

-   **Formatter:** Black (line length: 88)
-   **Import sorting:** isort
-   **Linting:** flake8
-   **Type checking:** mypy (preferred but not required)

**Run formatters before committing:**

```bash
# Format code
black pyth/

# Sort imports
isort pyth/

# Lint
flake8 pyth/

# Type check (optional)
mypy pyth/
```

### Docstrings

Use **Google style** docstrings:

```python
def check_sqli(url: str, param: str) -> List[Finding]:
    """
    Check for SQL injection in a parameter.

    Args:
        url: Target URL to test
        param: Parameter name to inject

    Returns:
        List of Finding objects representing discovered vulnerabilities

    Raises:
        ConnectionError: If unable to connect to target
        ValueError: If URL or param is invalid

    Example:
        >>> findings = check_sqli("http://example.com", "id")
        >>> print(len(findings))
        3
    """
    pass
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**

-   `feat`: New feature
-   `fix`: Bug fix
-   `docs`: Documentation changes
-   `test`: Adding tests
-   `refactor`: Code refactoring
-   `perf`: Performance improvements
-   `chore`: Maintenance tasks

**Examples:**

```bash
feat(scanner): add PostgreSQL-specific payloads

- Add 15 PostgreSQL error patterns
- Add pg_sleep() time-based payloads
- Update tests for PostgreSQL detection

Closes #42

---

fix(config): Docker auto-detection not working

- Expand paths BEFORE comparing to defaults
- Add in_container detection via ENV var
- Update Docker documentation

Fixes #38

---

docs(readme): add demo GIF and screenshots

- Add demo.gif showing scanner in action
- Add screenshots of HTML reports
- Update Docker Deployment section
```

---

## Pull Request Process

### Before Submitting

1. ✅ **Update from upstream:**

    ```bash
    git fetch upstream
    git rebase upstream/main
    ```

2. ✅ **Run tests:**

    ```bash
    pytest tests/ -v
    ```

3. ✅ **Run formatters:**

    ```bash
    black pyth/ && isort pyth/ && flake8 pyth/
    ```

4. ✅ **Update documentation:**

    - README.md if adding features
    - CHANGELOG.md with your changes
    - Docstrings for new functions

5. ✅ **Test manually:**
    - Run scanner against testing lab
    - Verify no regressions
    - Test Docker deployment

### PR Template

```markdown
## Description

[Clear description of what this PR does]

## Type of Change

-   [ ] Bug fix (non-breaking change)
-   [ ] New feature (non-breaking change)
-   [ ] Breaking change (fix or feature that changes existing behavior)
-   [ ] Documentation update
-   [ ] Performance improvement
-   [ ] Refactoring

## Testing

-   [ ] Unit tests added/updated
-   [ ] Manual testing completed
-   [ ] Tested with Docker
-   [ ] Tested with vulnerable labs

## Checklist

-   [ ] Code follows project style (Black, flake8, isort)
-   [ ] Documentation updated
-   [ ] CHANGELOG.md updated
-   [ ] No new warnings/errors
-   [ ] All tests pass

## Screenshots (if applicable)

[Add screenshots here]

## Related Issues

Closes #[issue number]
Fixes #[issue number]
```

### PR Review Process

1. **Automated checks run** (linting, tests)
2. **Maintainer review** (1-3 days typically)
3. **Address feedback** (if needed)
4. **Approval and merge**

**Merge Criteria:**

-   ✅ All CI checks pass
-   ✅ Code review approved
-   ✅ Documentation updated
-   ✅ No merge conflicts
-   ✅ Follows ethical guidelines

---

## Reporting Bugs

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities!

Contact me on [https://rodhnin.com](https://rodhnin.com).

### Regular Bugs

Open an issue on [GitHub Issues](https://github.com/rodhnin/pythia-sql-clairvoyance/issues).

**Include:**

-   Pythia version
-   Python version
-   Operating system
-   Steps to reproduce
-   Expected vs actual behavior
-   Logs/screenshots

---

## Suggesting Features

Open a [GitHub Discussion](https://github.com/rodhnin/pythia-sql-clairvoyance/discussions) for:

-   Feature ideas
-   Architecture discussions
-   Use case sharing
-   General questions

Open a [GitHub Issue](https://github.com/rodhnin/pythia-sql-clairvoyance/issues) for:

-   Concrete feature requests
-   Specific improvements
-   Documentation additions

---

## Project Structure

```
pythia-sql-clairvoyance/
├── pyth/                   # Main package
│   ├── checks/             # Detection modules
│   │   ├── error_based.py
│   │   ├── boolean_blind.py
│   │   ├── time_based.py
│   │   └── union_based.py
│   ├── core/               # Core infrastructure
│   │   ├── config.py
│   │   ├── db.py
│   │   ├── ai.py
│   │   └── report.py
│   ├── cli.py              # CLI entry point
│   └── scanner.py          # Main orchestrator
├── config/                 # Configuration files
├── docker/                 # Docker deployment
├── docs/                   # Documentation
├── tests/                  # Unit tests (to be added)
└── templates/              # Report templates
```

---

## Testing Guidelines

### Manual Testing

**Always test with:**

1. **Vulnerable lab apps** (docker/compose.testing.yml)
2. **Safe public sites** (testphp.vulnweb.com, example.com)
3. **Different Python versions** (3.11, 3.12)

**Never test with:**

-   ❌ Production sites without authorization
-   ❌ Sites you don't own
-   ❌ Government/military systems

### Automated Tests (Coming Soon)

We're building a pytest test suite. Help wanted!

**Test structure:**

```python
# tests/test_error_based.py
import pytest
from pyth.checks.error_based import ErrorBasedDetector

def test_mysql_error_detection():
    """Test MySQL error pattern detection."""
    detector = ErrorBasedDetector()
    response = "You have an error in your SQL syntax"
    assert detector.detect_error(response) == "mysql"

def test_postgresql_error_detection():
    """Test PostgreSQL error pattern detection."""
    detector = ErrorBasedDetector()
    response = "PostgreSQL query failed"
    assert detector.detect_error(response) == "postgresql"
```

---

## 📞 Questions?

-   **General questions**: Open a GitHub Discussion
-   **Bug reports**: Open a GitHub Issue
-   **Project maintainer**: [rodhnin](https://github.com/rodhnin) | [https://rodhnin.com](https://rodhnin.com)

---

## 📜 License

By contributing to Asterion, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

**Thank you for helping make database security auditing more accessible!** 🛡️

Part of the **Argos Security Suite**:

-   👁️ [Argus](https://github.com/rodhnin/argus-wp-watcher) - WordPress Security Scanner
-   🔥 [Hephaestus](https://github.com/rodhnin/hephaestus-server-forger) - Vulnerability Database Manager
-   🐂 [Asterion](https://github.com/rodhnin/asterion-network-minotaur) - Network Security Auditor
-   🔮 **Pythia** - SQL Injection Detection Scanner (this project)

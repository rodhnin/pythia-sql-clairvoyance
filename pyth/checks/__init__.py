# ============================================================================
# pyth/checks/__init__.py
# ------------------------
# SQL Injection detection modules initialization.
# ============================================================================
"""
SQL Injection Detection Modules for Pythia.

Available detectors:
- ErrorBasedDetector: Detects SQLi via database error messages
- BooleanBlindDetector: Detects blind SQLi via response differences
- TimeBasedDetector: Detects blind SQLi via time delays (AGGRESSIVE)
- UnionBasedDetector: Detects SQLi via UNION SELECT queries (AGGRESSIVE)
- FormTester: HTML form parser and tester
- WebCrawler: Intelligent web crawler for discovering attack surfaces
"""

from .error_based import ErrorBasedDetector
from .boolean_blind import BooleanBlindDetector
from .time_based import TimeBasedDetector
from .union_based import UnionBasedDetector
from .forms import FormTester, analyze_form_complexity, estimate_test_time
from .crawler import WebCrawler

__all__ = [
    'ErrorBasedDetector',
    'BooleanBlindDetector',
    'TimeBasedDetector',
    'UnionBasedDetector',
    'FormTester',
    'WebCrawler',
    'analyze_form_complexity',
    'estimate_test_time',
]
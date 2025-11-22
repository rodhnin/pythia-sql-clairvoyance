"""
Pythia Report Generator

Generates structured SQL injection reports in JSON and HTML formats.
Validates against shared report.schema.json from Argos suite.

Features:
- JSON report generation with schema validation
- HTML report generation with Jinja2 templates
- AI analysis content processing (markdown → HTML)
- Finding creation helper methods
- Evidence sanitization

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

try:
    import markdown
    from markdown.extensions import fenced_code, tables, nl2br
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class ReportGenerator:
    """
    Report generator for Pythia SQL injection findings.
    
    Generates reports conforming to Argos suite schema:
    - JSON reports with finding metadata
    - HTML reports with mystic oracle theme
    - AI analysis integration (technical + non-technical)
    - Schema validation
    """
    
    def __init__(self, config=None):
        """
        Initialize report generator for Pythia.
        
        Args:
            config: Config instance (optional)
        """
        self.config = config or get_config()
        self.schema = self._load_schema()
    
    def _load_schema(self) -> Optional[Dict]:
        """
        Load JSON schema for report validation.
        
        Returns:
            Schema dict or None if not found
        """
        schema_path = Path(__file__).parent.parent.parent / "schema" / "report.schema.json"
        
        if not schema_path.exists():
            logger.warning(f"Schema file not found: {schema_path}")
            return None
        
        try:
            with schema_path.open('r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON schema: {e}")
            return None
    
    def _process_ai_content(self, ai_analysis: Dict[str, str]) -> Dict[str, str]:
        """
        Process AI-generated content: Convert markdown to HTML.
        
        AI prompts for SQLi generate markdown-formatted content.
        This method converts it to HTML for report rendering.
        
        Args:
            ai_analysis: Dict with 'executive_summary' and/or 'technical_remediation'
        
        Returns:
            Processed dict with HTML content
        """
        if not HAS_MARKDOWN:
            logger.warning("markdown package not installed, AI content won't be formatted")
            logger.info("Install with: pip install markdown")
            processed = {}
            for key, value in ai_analysis.items():
                if isinstance(value, str):
                    processed[key] = value.replace('\n', '<br>\n')
                else:
                    processed[key] = value
            return processed
        
        # Configure markdown processor with extensions
        md = markdown.Markdown(
            extensions=[
                'fenced_code',      # ```code blocks```
                'tables',           # GFM tables
                'nl2br',            # \n -> <br>
                'sane_lists',       # Better list handling
                'codehilite',       # Syntax highlighting
            ],
            extension_configs={
                'codehilite': {
                    'css_class': 'highlight',
                    'linenums': False
                }
            }
        )
        
        processed = {}
        for key, value in ai_analysis.items():
            if key in ['executive_summary', 'technical_remediation'] and isinstance(value, str):
                # Convert markdown to HTML
                html_content = md.convert(value)
                
                # Reset markdown processor for next conversion
                md.reset()
                
                processed[key] = html_content
                logger.debug(f"Converted {key} from markdown to HTML ({len(value)} -> {len(html_content)} chars)")
            else:
                # Keep other fields as-is (generated_at, model_used, etc.)
                processed[key] = value
        
        return processed
    
    def create_report(
        self,
        tool: str,
        target: str,
        mode: str,
        findings: List[Dict[str, Any]],
        scan_duration: Optional[float] = None,
        requests_sent: Optional[int] = None,
        consent: Optional[Dict[str, str]] = None,
        ai_analysis: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Create structured SQL injection report dictionary.
        
        Args:
            tool: Tool name ('pythia')
            target: Target URL or domain
            mode: Scan mode ('safe' or 'aggressive')
            findings: List of SQLi finding dictionaries
            scan_duration: Duration in seconds
            requests_sent: Number of HTTP requests
            consent: Consent verification info
            ai_analysis: AI-generated summaries
        
        Returns:
            Report dictionary conforming to Argos suite schema
        
        Example:
            report = generator.create_report(
                tool='pythia',
                target='https://example.com',
                mode='safe',
                findings=findings_list,
                scan_duration=45.3,
                requests_sent=127
            )
        """
        # Calculate summary counts by severity
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in summary:
                summary[severity] += 1
        
        # Build report structure
        report = {
            'tool': tool,
            'version': self.config.version,
            'target': target,
            'date': datetime.now(timezone.utc).isoformat() + 'Z',
            'mode': mode,
            'summary': summary,
            'findings': findings
        }
        
        # Add optional notes section
        if scan_duration or requests_sent:
            notes = {}
            if scan_duration:
                notes['scan_duration_seconds'] = round(scan_duration, 2)
            if requests_sent:
                notes['requests_sent'] = requests_sent
            notes['rate_limit_applied'] = True
            notes['false_positive_disclaimer'] = (
                "Manual verification recommended for all SQLi findings before remediation. "
                "Some findings may be false positives due to WAF filtering or custom error handling."
            )
            notes['scope_limitations'] = (
                "Passive detection only. No data extraction or exploitation performed."
            )
            report['notes'] = notes
        
        # Add consent verification info (if aggressive mode or AI used)
        if consent:
            report['consent'] = consent
        
        # Add AI analysis (if enabled)
        if ai_analysis:
            report['ai_analysis'] = ai_analysis
        
        return report
    
    def validate_report(self, report: Dict[str, Any]) -> bool:
        """
        Validate report against JSON schema.
        
        Args:
            report: Report dictionary
        
        Returns:
            True if valid, False otherwise
        """
        if not HAS_JSONSCHEMA:
            logger.warning("jsonschema not installed, skipping validation")
            logger.info("Install with: pip install jsonschema")
            return True
        
        if not self.schema:
            logger.warning("Schema not loaded, skipping validation")
            return True
        
        try:
            jsonschema.validate(instance=report, schema=self.schema)
            logger.debug("SQL injection report validated successfully against schema")
            return True
        except jsonschema.ValidationError as e:
            logger.error(f"Report validation failed: {e.message}")
            logger.debug(f"Validation path: {list(e.absolute_path)}")
            return False
    
    def save_json(
        self,
        report: Dict[str, Any],
        output_path: Optional[Path] = None
    ) -> Path:
        """
        Save report as JSON file.
        
        Args:
            report: Report dictionary
            output_path: Output path (auto-generated if None)
        
        Returns:
            Path to saved JSON file
        
        Example:
            json_path = generator.save_json(report)
            print(f"Report saved: {json_path}")
        """
        # Validate before saving
        if not self.validate_report(report):
            logger.warning("Saving invalid SQL injection report (schema validation failed)")
        
        # Generate filename if not provided
        if output_path is None:
            target_clean = report['target'].replace('://', '_').replace('/', '_')
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            filename = f"{report['tool']}_sqli_report_{target_clean}_{timestamp}.json"
            output_path = self.config.report_dir / filename
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write JSON with pretty printing
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(report, f, indent=self.config.json_indent, ensure_ascii=False)
        
        logger.info(f"JSON SQL injection report saved: {output_path}")
        return output_path
    
    def generate_html(
        self,
        report: Dict[str, Any],
        json_path: Optional[Path] = None
    ) -> Path:
        """
        Generate HTML report from JSON report.
        
        Args:
            report: Report dictionary
            json_path: Corresponding JSON path (for naming consistency)
        
        Returns:
            Path to saved HTML file
        
        Raises:
            ImportError: If Jinja2 not installed
        """
        if not HAS_JINJA2:
            raise ImportError("Jinja2 required for HTML reports: pip install Jinja2")
        
        # Load template
        template_dir = Path(__file__).parent.parent.parent / "templates"
        
        if not template_dir.exists():
            raise FileNotFoundError(f"Templates directory not found: {template_dir}")
        
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        try:
            template = env.get_template('report.html.j2')
        except Exception as e:
            # Fallback to .html extension
            try:
                template = env.get_template('report.html')
            except:
                raise FileNotFoundError(f"Template not found: {e}")
        
        # Process AI content: Convert markdown to HTML
        ai_processed = None
        if 'ai_analysis' in report and report['ai_analysis']:
            ai_processed = self._process_ai_content(report['ai_analysis'])
            logger.info("AI content converted from markdown to HTML")
        
        # Render template
        html = template.render(
            tool=report['tool'],
            version=report['version'],
            target=report['target'],
            date=report['date'],
            mode=report['mode'],
            summary=report['summary'],
            findings=report['findings'],
            notes=report.get('notes'),
            consent=report.get('consent'),
            ai=ai_processed,
            contact=self.config.contact
        )
        
        # Determine output path
        if json_path:
            # Use same name as JSON, just change extension
            output_path = json_path.with_suffix('.html')
        else:
            # Auto-generate filename
            target_clean = report['target'].replace('://', '_').replace('/', '_')
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            filename = f"{report['tool']}_sqli_report_{target_clean}_{timestamp}.html"
            output_path = self.config.report_dir / filename
        
        # Write HTML
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open('w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"HTML SQL injection report saved: {output_path}")
        return output_path
    
    def create_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        confidence: str,
        recommendation: str,
        description: Optional[str] = None,
        evidence_type: Optional[str] = None,
        evidence_value: Optional[str] = None,
        evidence_context: Optional[str] = None,
        references: Optional[List[str]] = None,
        cve: Optional[List[str]] = None,
        affected_component: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create SQL injection finding dictionary with proper structure.
        
        Args:
            finding_id: Unique ID (e.g., "PYTHIA-SQL-001")
            title: Short title (e.g., "SQL Injection in search parameter")
            severity: critical|high|medium|low|info
            confidence: high|medium|low
            recommendation: Remediation guidance
            description: Detailed explanation
            evidence_type: url|header|body|path|screenshot|other
            evidence_value: Evidence content (SANITIZED, no sensitive data)
            evidence_context: Additional context (e.g., "Response length diff: 1523 bytes")
            references: External links (OWASP, CWE, etc.)
            cve: CVE identifiers (if applicable)
            affected_component: Component name (parameter, form field)
        
        Returns:
            Finding dictionary conforming to schema
        
        Example:
            finding = generator.create_finding(
                finding_id='PYTHIA-SQL-001',
                title='Error-based SQL Injection in id parameter',
                severity='high',
                confidence='high',
                description='MySQL syntax error message revealed in response',
                evidence_type='body',
                evidence_value='You have an error in your SQL syntax...',
                evidence_context='HTTP 200, error message in response body',
                recommendation='Use prepared statements: $stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");',
                references=['https://owasp.org/www-community/attacks/SQL_Injection'],
                affected_component='id parameter (GET)'
            )
        """
        finding = {
            'id': finding_id,
            'title': title,
            'severity': severity,
            'confidence': confidence,
            'recommendation': recommendation
        }
        
        if description:
            finding['description'] = description
        
        if evidence_type and evidence_value:
            finding['evidence'] = {
                'type': evidence_type,
                'value': evidence_value
            }
            if evidence_context:
                finding['evidence']['context'] = evidence_context
        
        if references:
            finding['references'] = references
        
        if cve:
            finding['cve'] = cve
        
        if affected_component:
            finding['affected_component'] = affected_component
        
        return finding


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    # Test report generation
    from .config import Config
    
    config = Config.load()
    config.expand_paths()
    config.ensure_directories()
    
    generator = ReportGenerator(config)
    
    # Create sample SQL injection findings
    findings = [
        generator.create_finding(
            finding_id="PYTHIA-SQL-001",
            title="Error-based SQL Injection in search parameter",
            severity="high",
            confidence="high",
            description="MySQL syntax error message exposed in response body, confirming SQL injection vulnerability.",
            evidence_type="body",
            evidence_value="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            evidence_context="HTTP 200, error message triggered by single quote payload",
            recommendation="""Use prepared statements with parameterized queries. 
            Example: $stmt = $pdo->prepare('SELECT * FROM products WHERE name LIKE ?'); 
            $stmt->execute(["%$search%"]);""",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            affected_component="search parameter (GET)"
        ),
        generator.create_finding(
            finding_id="PYTHIA-SQL-002",
            title="Boolean-based Blind SQL Injection in id parameter",
            severity="high",
            confidence="medium",
            description="Response length varies significantly between true and false boolean conditions, indicating blind SQL injection.",
            evidence_type="url",
            evidence_value="https://example.com/product?id=1",
            evidence_context="Response length diff: 1523 bytes (AND 1=1) vs 234 bytes (AND 1=0)",
            recommendation="Implement prepared statements and input validation. Avoid concatenating user input directly into SQL queries.",
            references=[
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
            ],
            affected_component="id parameter (GET)"
        ),
        generator.create_finding(
            finding_id="PYTHIA-SQL-003",
            title="POST parameter testing completed",
            severity="info",
            confidence="high",
            description="Login form tested with error-based and boolean blind payloads. No SQL injection vulnerabilities detected.",
            evidence_type="url",
            evidence_value="https://example.com/login",
            evidence_context="Tested 5 parameters, 13 payloads each. All responses consistent.",
            recommendation="Continue monitoring form inputs for changes. Consider implementing WAF rules.",
            references=[],
            affected_component="Login form (POST)"
        )
    ]
    
    # Create report
    report = generator.create_report(
        tool="pythia",
        target="https://example.com",
        mode="safe",
        findings=findings,
        scan_duration=45.3,
        requests_sent=127
    )
    
    # Validate
    is_valid = generator.validate_report(report)
    print(f"Report valid: {is_valid}")
    
    # Save JSON
    json_path = generator.save_json(report)
    print(f"JSON saved: {json_path}")
    
    # Generate HTML (if Jinja2 available)
    try:
        html_path = generator.generate_html(report, json_path)
        print(f"HTML saved: {html_path}")
    except ImportError as e:
        print(f"HTML generation skipped: {e}")
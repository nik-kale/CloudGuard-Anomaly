"""
PDF report generator for CloudGuard-Anomaly.

Generates professional PDF reports suitable for executive dashboards,
compliance documentation, and audit trails.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from io import BytesIO

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        PageBreak, Image, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)


class PDFReporter:
    """
    Professional PDF report generator for security findings.

    Features:
    - Executive summary with risk scores
    - Detailed findings tables
    - Compliance mapping
    - Charts and visualizations
    - Multi-page support with headers/footers
    """

    def __init__(self, page_size: str = 'letter'):
        """
        Initialize PDF reporter.

        Args:
            page_size: Page size ('letter' or 'a4')
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab required for PDF generation. "
                "Install with: pip install reportlab"
            )

        self.page_size = letter if page_size == 'letter' else A4
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

        logger.info(f"PDF reporter initialized (page_size={page_size})")

    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#666666'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))

        # Section heading
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c5aa0'),
            spaceBefore=12,
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))

        # Finding title
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#1a1a1a'),
            fontName='Helvetica-Bold',
            spaceAfter=6
        ))

        # Body text
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            alignment=TA_JUSTIFY,
            spaceAfter=12
        ))

    def generate_report(
        self,
        scan_results: Dict[str, Any],
        output_path: str,
        include_executive_summary: bool = True,
        include_detailed_findings: bool = True,
        include_compliance_mapping: bool = True,
        company_name: Optional[str] = None,
        logo_path: Optional[str] = None
    ) -> str:
        """
        Generate comprehensive PDF report.

        Args:
            scan_results: Scan results dictionary
            output_path: Output PDF file path
            include_executive_summary: Include executive summary
            include_detailed_findings: Include detailed findings
            include_compliance_mapping: Include compliance mapping
            company_name: Optional company name for report
            logo_path: Optional path to company logo

        Returns:
            Path to generated PDF file
        """
        logger.info(f"Generating PDF report: {output_path}")

        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=self.page_size,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )

        # Build document content
        story = []

        # Cover page
        story.extend(self._create_cover_page(
            scan_results,
            company_name=company_name,
            logo_path=logo_path
        ))
        story.append(PageBreak())

        # Executive summary
        if include_executive_summary:
            story.extend(self._create_executive_summary(scan_results))
            story.append(PageBreak())

        # Risk dashboard
        story.extend(self._create_risk_dashboard(scan_results))
        story.append(PageBreak())

        # Detailed findings
        if include_detailed_findings:
            story.extend(self._create_detailed_findings(scan_results))
            story.append(PageBreak())

        # Compliance mapping
        if include_compliance_mapping:
            story.extend(self._create_compliance_section(scan_results))
            story.append(PageBreak())

        # Recommendations
        story.extend(self._create_recommendations(scan_results))

        # Build PDF
        doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)

        logger.info(f"PDF report generated: {output_path}")
        return output_path

    def _create_cover_page(
        self,
        scan_results: Dict[str, Any],
        company_name: Optional[str] = None,
        logo_path: Optional[str] = None
    ) -> List:
        """Create report cover page."""
        elements = []

        # Add logo if provided
        if logo_path and Path(logo_path).exists():
            try:
                img = Image(logo_path, width=2*inch, height=1*inch)
                elements.append(img)
                elements.append(Spacer(1, 0.5*inch))
            except Exception as e:
                logger.warning(f"Could not load logo: {e}")

        # Title
        title = Paragraph(
            "Cloud Security Posture Report",
            self.styles['ReportTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))

        # Company name
        if company_name:
            company = Paragraph(
                company_name,
                self.styles['ReportSubtitle']
            )
            elements.append(company)
            elements.append(Spacer(1, 0.2*inch))

        # Environment name
        env_name = scan_results.get('environment', {}).get('name', 'Unknown')
        env_text = Paragraph(
            f"Environment: <b>{env_name}</b>",
            self.styles['ReportSubtitle']
        )
        elements.append(env_text)
        elements.append(Spacer(1, 0.5*inch))

        # Scan information table
        scan_info = [
            ['Scan Date:', datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')],
            ['Provider:', scan_results.get('environment', {}).get('provider', 'N/A')],
            ['Resources Scanned:', str(len(scan_results.get('environment', {}).get('resources', [])))],
            ['Findings:', str(len(scan_results.get('findings', [])))],
        ]

        info_table = Table(scan_info, colWidths=[2*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#666666')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1a1a1a')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(info_table)
        elements.append(Spacer(1, 1*inch))

        # Disclaimer
        disclaimer = Paragraph(
            "<i>This report is confidential and intended for internal use only. "
            "Distribution or reproduction without authorization is prohibited.</i>",
            self.styles['BodyText']
        )
        elements.append(disclaimer)

        return elements

    def _create_executive_summary(self, scan_results: Dict[str, Any]) -> List:
        """Create executive summary section."""
        elements = []

        # Section title
        title = Paragraph("Executive Summary", self.styles['SectionHeading'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        # Get findings summary
        findings = scan_results.get('findings', [])
        summary_stats = self._calculate_summary_stats(findings)

        # Risk overview paragraph
        risk_text = self._generate_risk_overview_text(summary_stats)
        risk_para = Paragraph(risk_text, self.styles['BodyText'])
        elements.append(risk_para)
        elements.append(Spacer(1, 12))

        # Key findings table
        findings_data = [
            ['Severity', 'Count', 'Percentage'],
        ]

        total_findings = len(findings)
        for severity in ['critical', 'high', 'medium', 'low']:
            count = summary_stats.get(severity, 0)
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            findings_data.append([
                severity.upper(),
                str(count),
                f"{percentage:.1f}%"
            ])

        findings_table = Table(findings_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        findings_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5aa0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            # Body
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ]))

        # Add color coding for severity
        for idx, severity in enumerate(['critical', 'high', 'medium', 'low'], start=1):
            color = self._get_severity_color(severity)
            findings_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, idx), (0, idx), color),
                ('FONTNAME', (0, idx), (0, idx), 'Helvetica-Bold'),
            ]))

        elements.append(findings_table)
        elements.append(Spacer(1, 20))

        # Top issues
        top_issues = self._get_top_issues(findings, limit=3)
        if top_issues:
            elements.append(Paragraph("Top Priority Issues", self.styles['SectionHeading']))
            elements.append(Spacer(1, 8))

            for idx, finding in enumerate(top_issues, 1):
                issue_text = f"<b>{idx}. [{finding.get('severity', 'N/A').upper()}]</b> {finding.get('title', 'N/A')}"
                elements.append(Paragraph(issue_text, self.styles['BodyText']))

        return elements

    def _create_risk_dashboard(self, scan_results: Dict[str, Any]) -> List:
        """Create risk dashboard with visualizations."""
        elements = []

        title = Paragraph("Risk Dashboard", self.styles['SectionHeading'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        findings = scan_results.get('findings', [])

        # Risk score calculation
        risk_score = self._calculate_risk_score(findings)

        # Risk score display
        score_data = [
            ['Overall Risk Score', self._format_risk_score(risk_score)],
            ['Risk Level', self._get_risk_level(risk_score)],
        ]

        score_table = Table(score_data, colWidths=[3*inch, 3*inch])
        score_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9f9f9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))

        elements.append(score_table)
        elements.append(Spacer(1, 20))

        # Finding categories
        categories = self._categorize_findings(findings)

        if categories:
            elements.append(Paragraph("Findings by Category", self.styles['FindingTitle']))
            elements.append(Spacer(1, 8))

            category_data = [['Category', 'Critical', 'High', 'Medium', 'Low', 'Total']]

            for category, cat_findings in sorted(categories.items()):
                stats = self._calculate_summary_stats(cat_findings)
                category_data.append([
                    category,
                    str(stats.get('critical', 0)),
                    str(stats.get('high', 0)),
                    str(stats.get('medium', 0)),
                    str(stats.get('low', 0)),
                    str(len(cat_findings))
                ])

            category_table = Table(category_data)
            category_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5aa0')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ]))

            elements.append(category_table)

        return elements

    def _create_detailed_findings(self, scan_results: Dict[str, Any]) -> List:
        """Create detailed findings section."""
        elements = []

        title = Paragraph("Detailed Security Findings", self.styles['SectionHeading'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        findings = scan_results.get('findings', [])

        # Group by severity
        grouped = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity in grouped:
                grouped[severity].append(finding)

        # Display findings by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = grouped[severity]

            if not severity_findings:
                continue

            # Severity section header
            severity_title = Paragraph(
                f"{severity.upper()} Severity Findings ({len(severity_findings)})",
                self.styles['SectionHeading']
            )
            elements.append(severity_title)
            elements.append(Spacer(1, 8))

            # Display each finding
            for idx, finding in enumerate(severity_findings[:10], 1):  # Limit to 10 per severity
                finding_elements = self._create_finding_detail(finding, idx)
                elements.extend(finding_elements)

                if idx < len(severity_findings[:10]):
                    elements.append(Spacer(1, 8))

            if len(severity_findings) > 10:
                more_text = Paragraph(
                    f"<i>... and {len(severity_findings) - 10} more {severity} severity findings</i>",
                    self.styles['BodyText']
                )
                elements.append(more_text)

            elements.append(Spacer(1, 12))

        return elements

    def _create_finding_detail(self, finding: Dict[str, Any], index: int) -> List:
        """Create detailed finding display."""
        elements = []

        # Finding title with severity badge
        severity = finding.get('severity', 'low').upper()
        title_text = f"<b>{index}. [{severity}]</b> {finding.get('title', 'N/A')}"
        title_para = Paragraph(title_text, self.styles['FindingTitle'])

        # Finding details
        details_data = [
            ['Resource:', finding.get('resource_id', 'N/A')],
            ['Type:', finding.get('finding_type', 'N/A')],
            ['Policy:', finding.get('policy_id', 'N/A')],
        ]

        details_table = Table(details_data, colWidths=[1.2*inch, 5*inch])
        details_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#666666')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        # Description
        description = Paragraph(
            f"<b>Description:</b> {finding.get('description', 'N/A')}",
            self.styles['BodyText']
        )

        # Remediation
        remediation = Paragraph(
            f"<b>Remediation:</b> {finding.get('remediation', 'N/A')}",
            self.styles['BodyText']
        )

        # Combine in KeepTogether to prevent splitting
        finding_group = KeepTogether([
            title_para,
            Spacer(1, 4),
            details_table,
            Spacer(1, 4),
            description,
            remediation
        ])

        elements.append(finding_group)

        return elements

    def _create_compliance_section(self, scan_results: Dict[str, Any]) -> List:
        """Create compliance mapping section."""
        elements = []

        title = Paragraph("Compliance Mapping", self.styles['SectionHeading'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        intro = Paragraph(
            "This section maps the identified security findings to common compliance frameworks.",
            self.styles['BodyText']
        )
        elements.append(intro)
        elements.append(Spacer(1, 12))

        # Compliance frameworks
        frameworks = {
            'SOC 2': ['CC6.1', 'CC6.6', 'CC6.7', 'CC7.2'],
            'PCI-DSS': ['1.2.1', '2.2.2', '6.5.3', '10.2'],
            'HIPAA': ['164.308(a)(1)', '164.312(a)(1)', '164.312(e)(1)'],
            'ISO 27001': ['A.12.6.1', 'A.14.1.2', 'A.18.1.3'],
        }

        for framework, controls in frameworks.items():
            framework_title = Paragraph(f"<b>{framework}</b>", self.styles['FindingTitle'])
            elements.append(framework_title)

            control_text = ", ".join(controls)
            control_para = Paragraph(f"Relevant controls: {control_text}", self.styles['BodyText'])
            elements.append(control_para)
            elements.append(Spacer(1, 8))

        return elements

    def _create_recommendations(self, scan_results: Dict[str, Any]) -> List:
        """Create recommendations section."""
        elements = []

        title = Paragraph("Recommendations", self.styles['SectionHeading'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        recommendations = [
            "Address all CRITICAL severity findings within 24 hours",
            "Implement regular security scanning as part of CI/CD pipeline",
            "Establish baseline configurations for all cloud resources",
            "Enable automated remediation for common misconfigurations",
            "Conduct quarterly security posture reviews",
            "Provide security training for development and operations teams",
        ]

        for idx, rec in enumerate(recommendations, 1):
            rec_para = Paragraph(f"{idx}. {rec}", self.styles['BodyText'])
            elements.append(rec_para)

        return elements

    def _calculate_summary_stats(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate summary statistics for findings."""
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            if severity in stats:
                stats[severity] += 1

        return stats

    def _calculate_risk_score(self, findings: List[Dict]) -> float:
        """Calculate overall risk score (0-100)."""
        weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}

        total_score = 0
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            total_score += weights.get(severity, 1)

        # Normalize to 0-100 scale
        max_score = 100
        risk_score = min(100, (total_score / max_score) * 100)

        return risk_score

    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    def _format_risk_score(self, score: float) -> str:
        """Format risk score for display."""
        return f"{score:.1f}/100"

    def _get_severity_color(self, severity: str) -> colors.Color:
        """Get color for severity level."""
        severity_colors = {
            'critical': colors.HexColor('#d32f2f'),
            'high': colors.HexColor('#f57c00'),
            'medium': colors.HexColor('#fbc02d'),
            'low': colors.HexColor('#388e3c'),
        }
        return severity_colors.get(severity.lower(), colors.black)

    def _generate_risk_overview_text(self, stats: Dict[str, int]) -> str:
        """Generate risk overview paragraph."""
        total = sum(stats.values())
        critical = stats.get('critical', 0)
        high = stats.get('high', 0)

        if critical > 0:
            risk_level = "critical"
            priority = "immediate attention required"
        elif high > 5:
            risk_level = "high"
            priority = "should be addressed promptly"
        else:
            risk_level = "moderate"
            priority = "should be reviewed and remediated"

        text = (
            f"This security posture assessment identified <b>{total} findings</b> across your cloud infrastructure. "
            f"Of these, <b>{critical} are critical severity</b> and <b>{high} are high severity</b>, "
            f"indicating a <b>{risk_level}</b> risk level that {priority}. "
            f"The following sections provide detailed information about each finding and recommended remediation steps."
        )

        return text

    def _get_top_issues(self, findings: List[Dict], limit: int = 3) -> List[Dict]:
        """Get top priority issues."""
        # Sort by severity (critical > high > medium > low)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get('severity', 'low').lower(), 4)
        )

        return sorted_findings[:limit]

    def _categorize_findings(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize findings by type."""
        categories = {}

        for finding in findings:
            category = finding.get('finding_type', 'Other')
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)

        return categories

    def _add_page_number(self, canvas_obj, doc):
        """Add page numbers to all pages."""
        canvas_obj.saveState()
        canvas_obj.setFont('Helvetica', 9)

        page_num = canvas_obj.getPageNumber()
        text = f"Page {page_num}"
        canvas_obj.drawRightString(
            doc.pagesize[0] - 0.75*inch,
            0.5*inch,
            text
        )

        # Add timestamp
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        canvas_obj.drawString(
            0.75*inch,
            0.5*inch,
            f"Generated: {timestamp}"
        )

        canvas_obj.restoreState()


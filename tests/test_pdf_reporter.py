"""
Tests for PDF reporter.
"""

import pytest
import os
from pathlib import Path
from datetime import datetime

try:
    from cloudguard_anomaly.reports.pdf_reporter import PDFReporter
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


@pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="ReportLab not installed")
class TestPDFReporter:
    """Test PDF report generation."""

    @pytest.fixture
    def sample_scan_results(self):
        """Sample scan results for testing."""
        return {
            'environment': {
                'name': 'test-environment',
                'provider': 'AWS',
                'resources': [
                    {'id': 'resource-1', 'type': 'storage', 'name': 'test-bucket'},
                    {'id': 'resource-2', 'type': 'compute', 'name': 'test-instance'},
                ]
            },
            'findings': [
                {
                    'id': 'finding-1',
                    'severity': 'critical',
                    'title': 'Unencrypted storage',
                    'description': 'S3 bucket is not encrypted',
                    'remediation': 'Enable encryption at rest',
                    'resource_id': 'resource-1',
                    'finding_type': 'misconfiguration',
                    'policy_id': 'policy-001'
                },
                {
                    'id': 'finding-2',
                    'severity': 'high',
                    'title': 'Public access enabled',
                    'description': 'Resource allows public access',
                    'remediation': 'Disable public access',
                    'resource_id': 'resource-1',
                    'finding_type': 'misconfiguration',
                    'policy_id': 'policy-002'
                },
                {
                    'id': 'finding-3',
                    'severity': 'medium',
                    'title': 'Missing tags',
                    'description': 'Resource is missing required tags',
                    'remediation': 'Add required tags',
                    'resource_id': 'resource-2',
                    'finding_type': 'compliance',
                    'policy_id': 'policy-003'
                },
                {
                    'id': 'finding-4',
                    'severity': 'low',
                    'title': 'Old AMI version',
                    'description': 'EC2 instance uses outdated AMI',
                    'remediation': 'Update to latest AMI',
                    'resource_id': 'resource-2',
                    'finding_type': 'best_practice',
                    'policy_id': 'policy-004'
                },
            ]
        }

    def test_pdf_reporter_init(self):
        """Test PDF reporter initialization."""
        reporter = PDFReporter(page_size='letter')
        assert reporter is not None
        assert reporter.page_size is not None

        reporter_a4 = PDFReporter(page_size='a4')
        assert reporter_a4 is not None

    def test_calculate_summary_stats(self, sample_scan_results):
        """Test summary statistics calculation."""
        reporter = PDFReporter()
        findings = sample_scan_results['findings']

        stats = reporter._calculate_summary_stats(findings)

        assert stats['critical'] == 1
        assert stats['high'] == 1
        assert stats['medium'] == 1
        assert stats['low'] == 1

    def test_calculate_risk_score(self, sample_scan_results):
        """Test risk score calculation."""
        reporter = PDFReporter()
        findings = sample_scan_results['findings']

        risk_score = reporter._calculate_risk_score(findings)

        assert 0 <= risk_score <= 100
        assert risk_score > 0  # Should have some risk

    def test_get_risk_level(self):
        """Test risk level classification."""
        reporter = PDFReporter()

        assert reporter._get_risk_level(90) == "CRITICAL"
        assert reporter._get_risk_level(60) == "HIGH"
        assert reporter._get_risk_level(40) == "MEDIUM"
        assert reporter._get_risk_level(10) == "LOW"

    def test_get_top_issues(self, sample_scan_results):
        """Test getting top priority issues."""
        reporter = PDFReporter()
        findings = sample_scan_results['findings']

        top_issues = reporter._get_top_issues(findings, limit=2)

        assert len(top_issues) == 2
        assert top_issues[0]['severity'] == 'critical'  # Highest severity first

    def test_categorize_findings(self, sample_scan_results):
        """Test finding categorization."""
        reporter = PDFReporter()
        findings = sample_scan_results['findings']

        categories = reporter._categorize_findings(findings)

        assert 'misconfiguration' in categories
        assert 'compliance' in categories
        assert 'best_practice' in categories

        assert len(categories['misconfiguration']) == 2
        assert len(categories['compliance']) == 1
        assert len(categories['best_practice']) == 1

    def test_generate_pdf_report(self, sample_scan_results, tmp_path):
        """Test PDF report generation."""
        reporter = PDFReporter()

        output_path = tmp_path / "test_report.pdf"

        result_path = reporter.generate_report(
            scan_results=sample_scan_results,
            output_path=str(output_path),
            include_executive_summary=True,
            include_detailed_findings=True,
            include_compliance_mapping=True
        )

        assert result_path == str(output_path)
        assert output_path.exists()
        assert output_path.stat().st_size > 0  # PDF has content

    def test_generate_pdf_with_company_info(self, sample_scan_results, tmp_path):
        """Test PDF generation with company info."""
        reporter = PDFReporter()

        output_path = tmp_path / "test_report_company.pdf"

        result_path = reporter.generate_report(
            scan_results=sample_scan_results,
            output_path=str(output_path),
            company_name="Acme Corporation"
        )

        assert output_path.exists()

    def test_generate_minimal_pdf(self, sample_scan_results, tmp_path):
        """Test minimal PDF generation."""
        reporter = PDFReporter()

        # Remove all findings
        minimal_results = sample_scan_results.copy()
        minimal_results['findings'] = []

        output_path = tmp_path / "test_report_minimal.pdf"

        result_path = reporter.generate_report(
            scan_results=minimal_results,
            output_path=str(output_path),
            include_executive_summary=False,
            include_detailed_findings=False,
            include_compliance_mapping=False
        )

        assert output_path.exists()

    def test_severity_colors(self):
        """Test severity color mapping."""
        reporter = PDFReporter()

        critical_color = reporter._get_severity_color('critical')
        high_color = reporter._get_severity_color('high')
        medium_color = reporter._get_severity_color('medium')
        low_color = reporter._get_severity_color('low')

        assert critical_color is not None
        assert high_color is not None
        assert medium_color is not None
        assert low_color is not None

        # All colors should be different
        colors = [critical_color, high_color, medium_color, low_color]
        assert len(colors) == len(set([str(c) for c in colors]))

    def test_format_risk_score(self):
        """Test risk score formatting."""
        reporter = PDFReporter()

        assert reporter._format_risk_score(75.5) == "75.5/100"
        assert reporter._format_risk_score(100.0) == "100.0/100"
        assert reporter._format_risk_score(0.0) == "0.0/100"


@pytest.mark.skipif(REPORTLAB_AVAILABLE, reason="Test import error handling")
def test_pdf_reporter_import_error():
    """Test handling when ReportLab is not installed."""
    with pytest.raises(ImportError, match="ReportLab required"):
        # This would fail if reportlab is actually available
        pass


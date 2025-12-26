"""
Markdown reporter for CloudGuard-Anomaly.
"""

import logging
from typing import Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class MarkdownReporter:
    """Markdown report generator."""

    def save_report(self, scan_result: Dict[str, Any], output_path: str) -> None:
        """Save scan results as Markdown."""
        logger.info(f"Generating Markdown report: {output_path}")

        lines = [
            "# CloudGuard-Anomaly Security Scan Report",
            "",
            f"## Environment: {scan_result.get('environment', {}).get('name', 'Unknown')}",
            "",
            f"**Provider:** {scan_result.get('environment', {}).get('provider', 'N/A')}  ",
            f"**Resources:** {len(scan_result.get('environment', {}).get('resources', []))}  ",
            f"**Findings:** {len(scan_result.get('findings', []))}  ",
            "",
            "## Summary",
            "",
        ]

        # Add findings summary
        findings = scan_result.get('findings', [])
        if findings:
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for severity in ['critical', 'high', 'medium', 'low']:
                count = severity_counts.get(severity, 0)
                lines.append(f"| {severity.upper()} | {count} |")
            lines.append("")

        # Write report
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))

        logger.info(f"Markdown report saved: {output_path}")


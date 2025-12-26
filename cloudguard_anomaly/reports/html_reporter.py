"""
HTML reporter for CloudGuard-Anomaly.
"""

import logging
from typing import Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class HTMLReporter:
    """HTML report generator."""

    def save_report(self, scan_result: Dict[str, Any], output_path: str) -> None:
        """Save scan results as HTML."""
        logger.info(f"Generating HTML report: {output_path}")

        env_name = scan_result.get('environment', {}).get('name', 'Unknown')
        provider = scan_result.get('environment', {}).get('provider', 'N/A')
        resources_count = len(scan_result.get('environment', {}).get('resources', []))
        findings = scan_result.get('findings', [])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CloudGuard-Anomaly Report - {env_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c5aa0; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .finding {{ border-left: 4px solid #ccc; padding: 10px; margin: 10px 0; }}
        .critical {{ border-color: #d32f2f; }}
        .high {{ border-color: #f57c00; }}
        .medium {{ border-color: #fbc02d; }}
        .low {{ border-color: #388e3c; }}
    </style>
</head>
<body>
    <h1>CloudGuard-Anomaly Security Scan Report</h1>

    <div class="summary">
        <h2>Environment: {env_name}</h2>
        <p><strong>Provider:</strong> {provider}</p>
        <p><strong>Resources:</strong> {resources_count}</p>
        <p><strong>Findings:</strong> {len(findings)}</p>
    </div>

    <h2>Findings</h2>
"""

        for finding in findings:
            severity = finding.get('severity', 'low')
            title = finding.get('title', 'N/A')
            description = finding.get('description', '')

            html += f"""
    <div class="finding {severity}">
        <h3>[{severity.upper()}] {title}</h3>
        <p>{description}</p>
    </div>
"""

        html += """
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html)

        logger.info(f"HTML report saved: {output_path}")


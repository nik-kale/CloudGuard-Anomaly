"""
Container security scan CLI command.
"""

import click
import logging
from pathlib import Path

from cloudguard_anomaly.containers import DockerScanner
from cloudguard_anomaly.cli.output import print_success, print_error, print_info

logger = logging.getLogger(__name__)


@click.command(name='container-scan')
@click.option(
    '--image',
    required=True,
    help='Docker image to scan (e.g., nginx:latest)'
)
@click.option(
    '--dockerfile',
    type=click.Path(exists=True),
    help='Path to Dockerfile for additional analysis'
)
@click.option(
    '--output',
    type=click.Path(),
    help='Output file path for scan report'
)
@click.option(
    '--format',
    type=click.Choice(['json', 'markdown', 'text']),
    default='text',
    help='Report format'
)
@click.option(
    '--skip-vulnerabilities',
    is_flag=True,
    help='Skip CVE vulnerability scanning'
)
@click.option(
    '--skip-secrets',
    is_flag=True,
    help='Skip secret detection'
)
@click.option(
    '--skip-config',
    is_flag=True,
    help='Skip configuration checks'
)
def container_scan(
    image: str,
    dockerfile: str,
    output: str,
    format: str,
    skip_vulnerabilities: bool,
    skip_secrets: bool,
    skip_config: bool
):
    """
    Scan a Docker/OCI container image for security issues.

    Scans for:
    - Known vulnerabilities (CVEs)
    - Security misconfigurations
    - Secrets and sensitive data
    - Dockerfile best practices

    Examples:

      # Scan a local image
      cloudguard-anomaly container-scan --image nginx:latest

      # Scan with Dockerfile analysis
      cloudguard-anomaly container-scan --image myapp:1.0 --dockerfile Dockerfile

      # Generate JSON report
      cloudguard-anomaly container-scan --image nginx:latest --format json --output report.json
    """
    try:
        print_info(f"Scanning container image: {image}")

        # Initialize scanner
        scanner = DockerScanner()

        # Perform scan
        result = scanner.scan_image(
            image=image,
            dockerfile_path=dockerfile,
            scan_vulnerabilities=not skip_vulnerabilities,
            scan_secrets=not skip_secrets,
            scan_config=not skip_config
        )

        # Generate report
        report = scanner.generate_report(result, format=format)

        # Output report
        if output:
            with open(output, 'w') as f:
                f.write(report)
            print_success(f"Report saved to: {output}")
        else:
            print(report)

        # Print summary
        summary = result.summary
        total_issues = summary['total_vulnerabilities'] + summary['total_findings']

        if summary.get('critical', 0) > 0:
            print_error(f"\n🚨 Found {summary['critical']} CRITICAL issues!")
        elif summary.get('high', 0) > 0:
            print_error(f"\n⚠️  Found {summary['high']} HIGH severity issues")
        elif total_issues > 0:
            print_info(f"\n✓ Scan complete: {total_issues} issues found")
        else:
            print_success(f"\n✓ Scan complete: No issues found!")

        # Exit with appropriate code
        if summary.get('critical', 0) > 0:
            raise click.exceptions.Exit(2)
        elif summary.get('high', 0) > 0:
            raise click.exceptions.Exit(1)
        else:
            raise click.exceptions.Exit(0)

    except Exception as e:
        print_error(f"Container scan failed: {e}")
        logger.error(f"Container scan error: {e}", exc_info=True)
        raise click.exceptions.Exit(1)


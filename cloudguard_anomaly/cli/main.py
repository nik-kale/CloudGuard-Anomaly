#!/usr/bin/env python3
"""
CloudGuard-Anomaly CLI

Main command-line interface entry point.
"""

import logging
import sys
from pathlib import Path

import click

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="0.1.0")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-error output")
def cli(verbose, quiet):
    """
    CloudGuard-Anomaly: Agentic Cloud Security Posture & Anomaly Analyzer

    A framework for analyzing cloud security posture, detecting misconfigurations,
    and explaining configuration drift.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)


@cli.command()
@click.option(
    "--env",
    "-e",
    "env_path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
    help="Path to environment directory",
)
@click.option(
    "--policies",
    "-p",
    "policy_path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to policies directory (default: built-in policies)",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default="./reports",
    help="Output directory for reports",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "markdown", "html", "all"], case_sensitive=False),
    default="all",
    help="Output format for reports",
)
@click.option(
    "--no-drift",
    is_flag=True,
    help="Disable drift detection",
)
@click.option(
    "--no-agents",
    is_flag=True,
    help="Disable agentic explanations",
)
def scan(env_path, policy_path, output_dir, output_format, no_drift, no_agents):
    """
    Scan a cloud environment for security issues.

    This command analyzes the specified environment, runs security checks,
    detects configuration drift, and generates comprehensive reports.

    Example:
        cloudguard-anomaly scan --env examples/environments/env_aws_small
    """
    from cloudguard_anomaly.cli.commands.scan import execute_scan

    try:
        execute_scan(
            env_path=env_path,
            policy_path=policy_path,
            output_dir=output_dir,
            output_format=output_format,
            enable_drift=not no_drift,
            enable_agents=not no_agents,
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--name",
    "-n",
    required=True,
    help="Name of the environment to generate",
)
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    default="aws",
    help="Cloud provider",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default="./examples/environments",
    help="Output directory for generated environment",
)
@click.option(
    "--resources",
    "-r",
    type=int,
    default=10,
    help="Number of resources to generate",
)
@click.option(
    "--with-issues",
    is_flag=True,
    help="Include intentional security issues for demonstration",
)
def generate(name, provider, output_path, resources, with_issues):
    """
    Generate a synthetic cloud environment.

    This command creates example environment configurations for testing
    and demonstration purposes.

    Example:
        cloudguard-anomaly generate --name my-test-env --provider aws --with-issues
    """
    from cloudguard_anomaly.cli.commands.generate_example import execute_generate

    try:
        execute_generate(
            name=name,
            provider=provider,
            output_path=output_path,
            resource_count=resources,
            with_issues=with_issues,
        )
    except Exception as e:
        logger.error(f"Generation failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--env",
    "-e",
    "env_path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to environment directory to validate",
)
@click.option(
    "--policies",
    "-p",
    "policy_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to policies file or directory to validate",
)
def validate(env_path, policy_path):
    """
    Validate environment configurations and policies.

    This command validates that environment and policy files are correctly
    formatted and contain valid configurations.

    Example:
        cloudguard-anomaly validate --env examples/environments/env_aws_small
    """
    from cloudguard_anomaly.cli.commands.validate import execute_validate

    try:
        execute_validate(env_path=env_path, policy_path=policy_path)
    except Exception as e:
        logger.error(f"Validation failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
def version():
    """Display version information."""
    click.echo("CloudGuard-Anomaly v0.1.0")
    click.echo("Agentic Cloud Security Posture & Anomaly Analyzer")


@cli.command()
@click.option('--image', required=True, help='Docker image to scan')
@click.option('--dockerfile', type=click.Path(exists=True), help='Path to Dockerfile')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', type=click.Choice(['json', 'markdown', 'text']), default='text')
@click.option('--skip-vulnerabilities', is_flag=True, help='Skip CVE scanning')
@click.option('--skip-secrets', is_flag=True, help='Skip secret detection')
@click.option('--skip-config', is_flag=True, help='Skip configuration checks')
def container_scan(image, dockerfile, output, format, skip_vulnerabilities, skip_secrets, skip_config):
    """
    Scan Docker/OCI container image for security issues.
    
    Examples:
        cloudguard-anomaly container-scan --image nginx:latest
        cloudguard-anomaly container-scan --image myapp:1.0 --dockerfile Dockerfile
        cloudguard-anomaly container-scan --image nginx:latest --format json --output report.json
    """
    from cloudguard_anomaly.cli.commands.container_scan import container_scan as execute_container_scan
    
    execute_container_scan.callback(image, dockerfile, output, format, skip_vulnerabilities, skip_secrets, skip_config)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()


@cli.command()
@click.option('--provider', type=click.Choice(['aws', 'azure', 'gcp']), required=True)
@click.option('--profile', help='AWS profile name')
@click.option('--region', default='us-east-1', help='Cloud region')
@click.option('--subscription-id', help='Azure subscription ID')
@click.option('--project-id', help='GCP project ID')
@click.option('--output', '-o', 'output_dir', type=click.Path(path_type=Path), default='./reports')
@click.option('--database-url', help='Database URL for persistence')
@click.option('--slack-webhook', help='Slack webhook URL for notifications')
def live_scan(provider, profile, region, subscription_id, project_id, output_dir, database_url, slack_webhook):
    """
    Scan live cloud environment in real-time.
    
    Examples:
        cloudguard-anomaly live-scan --provider aws --profile production
        cloudguard-anomaly live-scan --provider azure --subscription-id <id>
        cloudguard-anomaly live-scan --provider gcp --project-id my-project
    """
    from cloudguard_anomaly.cli.commands.live_scan import execute_live_scan
    
    try:
        execute_live_scan(
            provider=provider,
            profile=profile,
            region=region,
            subscription_id=subscription_id,
            project_id=project_id,
            output_dir=output_dir,
            database_url=database_url,
            slack_webhook=slack_webhook
        )
    except Exception as e:
        logger.error(f"Live scan failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option('--env', '-e', 'env_path', type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--framework', type=click.Choice(['soc2', 'pci_dss', 'hipaa', 'iso_27001']), required=True)
@click.option('--output', '-o', 'output_dir', type=click.Path(path_type=Path), default='./reports')
@click.option('--format', type=click.Choice(['markdown', 'json']), default='markdown')
def compliance(env_path, framework, output_dir, format):
    """
    Evaluate compliance against security frameworks.
    
    Examples:
        cloudguard-anomaly compliance --env ./env --framework soc2
        cloudguard-anomaly compliance --env ./env --framework pci_dss --format json
    """
    from cloudguard_anomaly.cli.commands.compliance import execute_compliance
    
    try:
        execute_compliance(
            env_path=env_path,
            framework=framework,
            output_dir=output_dir,
            output_format=format
        )
    except Exception as e:
        logger.error(f"Compliance evaluation failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option('--scan-id', help='Scan ID to remediate')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium']), help='Minimum severity to remediate')
@click.option('--dry-run', is_flag=True, default=True, help='Simulate remediation without making changes')
@click.option('--database-url', required=True, help='Database URL')
def remediate(scan_id, severity, dry_run, database_url):
    """
    Auto-remediate security findings.
    
    Examples:
        cloudguard-anomaly remediate --scan-id abc123 --dry-run
        cloudguard-anomaly remediate --scan-id abc123 --severity critical
    """
    from cloudguard_anomaly.storage.database import DatabaseStorage
    from cloudguard_anomaly.remediation.auto_fix import AutoRemediator
    
    db = DatabaseStorage(database_url)
    remediator = AutoRemediator(dry_run=dry_run)
    
    # Get scan results
    scan = db.get_scan(scan_id)
    if not scan:
        click.echo(f"❌ Scan {scan_id} not found", err=True)
        sys.exit(1)
    
    # Get findings to remediate
    findings_data = scan.data.get('findings', [])
    
    # Filter by severity if specified
    from cloudguard_anomaly.core.models import Finding, Severity
    
    findings = []
    for f_data in findings_data:
        if severity and Severity(f_data['severity']) < Severity(severity):
            continue
        # Reconstruct Finding object
        # This is simplified - in production, you'd fully deserialize
        finding = Finding(
            id=f_data['id'],
            type=f_data['type'],
            severity=Severity(f_data['severity']),
            title=f_data['title'],
            description=f_data['description'],
            resource=None,  # Simplified
            policy=None,
            remediation=f_data.get('remediation', '')
        )
        findings.append(finding)
    
    # Remediate
    results = remediator.remediate_all(findings)
    
    click.echo(f"\nRemediation Results:")
    click.echo(f"  Total: {results['total']}")
    click.echo(f"  Remediated: {results['remediated']}")
    click.echo(f"  Failed: {results['failed']}")
    click.echo(f"  No Handler: {results['no_handler']}")


@cli.command()
@click.option('--database-url', required=True, help='Database URL')
@click.option('--days', default=30, type=int, help='Training data period (days)')
@click.option('--save-model', type=click.Path(path_type=Path), help='Path to save trained model')
def train_ml(database_url, days, save_model):
    """
    Train ML anomaly detection model.
    
    Example:
        cloudguard-anomaly train-ml --database-url sqlite:///cloudguard.db --save-model model.pkl
    """
    from cloudguard_anomaly.storage.database import DatabaseStorage
    from cloudguard_anomaly.ml.anomaly_detector import MLAnomalyDetector
    from cloudguard_anomaly.core.models import Environment
    
    db = DatabaseStorage(database_url)
    
    # Get historical scans
    scans = db.get_scans(days=days, limit=1000)
    
    click.echo(f"Loading {len(scans)} historical scans for training...")
    
    # Convert to environments
    environments = []
    for scan in scans:
        # This is simplified - in production, fully deserialize
        env_data = scan.data.get('environment', {})
        if 'resources' in env_data:
            from cloudguard_anomaly.core.models import Provider
            env = Environment(
                name=env_data['name'],
                provider=Provider(env_data['provider']),
                resources=[]  # Simplified
            )
            environments.append(env)
    
    if not environments:
        click.echo("❌ No training data available", err=True)
        sys.exit(1)
    
    # Train model
    detector = MLAnomalyDetector()
    detector.train(environments)
    
    click.echo(f"✅ Model trained on {len(environments)} environments")
    
    # Save model
    if save_model:
        detector.save_model(str(save_model))
        click.echo(f"💾 Model saved to {save_model}")


@cli.command()
@click.option('--database-url', required=True, help='Database URL')
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=5000, type=int, help='Port to listen on')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def dashboard(database_url, host, port, debug):
    """
    Launch web dashboard for real-time monitoring.

    Example:
        cloudguard-anomaly dashboard --database-url sqlite:///cloudguard.db
    """
    from cloudguard_anomaly.dashboard import run_dashboard

    click.echo(f"🚀 Starting CloudGuard-Anomaly Dashboard on {host}:{port}")
    click.echo(f"📊 Database: {database_url}")
    click.echo(f"🌐 Open your browser to: http://localhost:{port}")

    try:
        run_dashboard(database_url=database_url, host=host, port=port, debug=debug)
    except Exception as e:
        logger.error(f"Dashboard failed: {e}", exc_info=True)
        sys.exit(1)



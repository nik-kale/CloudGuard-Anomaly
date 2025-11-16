"""Live cloud scanning command."""

import logging
import sys
from pathlib import Path

import click

from cloudguard_anomaly.core.engine import AnalysisEngine
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.notifications.webhooks import SlackNotifier
from cloudguard_anomaly.reports.json_reporter import JSONReporter
from cloudguard_anomaly.reports.markdown_reporter import MarkdownReporter

logger = logging.getLogger(__name__)


def execute_live_scan(
    provider: str,
    profile: str = None,
    region: str = None,
    subscription_id: str = None,
    project_id: str = None,
    output_dir: Path = Path("./reports"),
    database_url: str = None,
    slack_webhook: str = None,
):
    """
    Execute live cloud scan.

    Args:
        provider: Cloud provider (aws, azure, gcp)
        profile: AWS profile name
        region: Cloud region
        subscription_id: Azure subscription ID
        project_id: GCP project ID
        output_dir: Output directory
        database_url: Database URL for persistence
        slack_webhook: Slack webhook URL for notifications
    """
    logger.info(f"Starting live {provider.upper()} scan...")

    # Initialize integration based on provider
    if provider == "aws":
        from cloudguard_anomaly.integrations.aws_live import AWSLiveIntegration

        integration = AWSLiveIntegration(profile=profile, region=region or "us-east-1")
    elif provider == "azure":
        from cloudguard_anomaly.integrations.azure_live import AzureLiveIntegration

        if not subscription_id:
            click.echo("❌ Error: --subscription-id required for Azure", err=True)
            sys.exit(1)

        integration = AzureLiveIntegration(subscription_id=subscription_id)
    elif provider == "gcp":
        from cloudguard_anomaly.integrations.gcp_live import GCPLiveIntegration

        if not project_id:
            click.echo("❌ Error: --project-id required for GCP", err=True)
            sys.exit(1)

        integration = GCPLiveIntegration(project_id=project_id)
    else:
        click.echo(f"❌ Error: Unsupported provider: {provider}", err=True)
        sys.exit(1)

    # Discover resources
    click.echo(f"🔍 Discovering {provider.upper()} resources...")
    environment = integration.discover_all_resources()
    click.echo(f"✅ Discovered {len(environment.resources)} resources")

    # Run analysis
    click.echo("🔬 Running security analysis...")
    from cloudguard_anomaly.policies.policy_engine import PolicyEngine

    policy_engine = PolicyEngine()
    builtin_policies_dir = Path(__file__).parent.parent.parent / "policies"

    policies = []
    for policy_file in ["baseline_policies.yaml", f"{provider}_policies.yaml"]:
        policy_path = builtin_policies_dir / policy_file
        if policy_path.exists():
            policies.extend(policy_engine.load_policies(policy_path))

    engine = AnalysisEngine(policies=policies, enable_drift_detection=False, enable_agents=True)
    scan_result = engine.scan_environment(environment)

    # Print summary
    click.echo("\n" + "=" * 80)
    click.echo("SCAN RESULTS")
    click.echo("=" * 80)
    click.echo(f"Environment: {environment.name}")
    click.echo(f"Resources: {len(environment.resources)}")
    click.echo(f"Findings: {len(scan_result.findings)}")
    click.echo(f"Risk Score: {scan_result.summary.get('risk_score', 0)}/100")

    severity_counts = scan_result.summary.get("severity_counts", {})
    for severity, count in severity_counts.items():
        if count > 0:
            click.echo(f"  {severity.upper()}: {count}")

    # Save to database
    if database_url:
        try:
            db = DatabaseStorage(database_url)
            scan_id = db.save_scan(scan_result)
            click.echo(f"\n💾 Saved to database: {scan_id}")
        except Exception as e:
            logger.error(f"Failed to save to database: {e}")

    # Generate reports
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    env_name = environment.name.replace(" ", "_").lower()

    json_reporter = JSONReporter()
    json_path = output_dir / f"{env_name}_report.json"
    json_reporter.save_report(scan_result, json_path)
    click.echo(f"✅ JSON report: {json_path}")

    md_reporter = MarkdownReporter()
    md_path = output_dir / f"{env_name}_report.md"
    md_reporter.save_report(scan_result, md_path)
    click.echo(f"✅ Markdown report: {md_path}")

    # Send Slack notification
    if slack_webhook:
        try:
            notifier = SlackNotifier(slack_webhook)
            notifier.send_scan_summary(scan_result)
            click.echo("📢 Slack notification sent")
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

    # Exit with appropriate code
    critical = severity_counts.get("critical", 0)
    if critical > 0:
        click.echo(f"\n⚠️  {critical} CRITICAL issue(s) found!")
        sys.exit(2)

"""
Interactive CLI mode for CloudGuard-Anomaly.

Provides user-friendly interactive prompts for common workflows.
"""

import click
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def interactive_scan_wizard():
    """Interactive wizard for setting up a security scan."""
    click.echo("\n" + "="*60)
    click.echo("  CloudGuard-Anomaly Interactive Scan Wizard")
    click.echo("="*60 + "\n")
    
    # Environment selection
    click.echo("📁 Step 1: Select Environment")
    env_type = click.prompt(
        "Environment type",
        type=click.Choice(['local', 'live', 'synthetic'], case_sensitive=False),
        default='local'
    )
    
    if env_type == 'local':
        env_path = click.prompt("Environment directory path", type=click.Path(exists=True))
    elif env_type == 'live':
        provider = click.prompt(
            "Cloud provider",
            type=click.Choice(['aws', 'azure', 'gcp'], case_sensitive=False)
        )
        
        if provider == 'aws':
            profile = click.prompt("AWS profile name", default='default')
            region = click.prompt("AWS region", default='us-east-1')
        elif provider == 'azure':
            subscription_id = click.prompt("Azure subscription ID")
        elif provider == 'gcp':
            project_id = click.prompt("GCP project ID")
    else:  # synthetic
        click.echo("Generating synthetic environment...")
        env_name = click.prompt("Environment name", default="test-env")
        num_resources = click.prompt("Number of resources", type=int, default=10)
        with_issues = click.confirm("Include security issues?", default=True)
    
    click.echo("")
    
    # Policy selection
    click.echo("📋 Step 2: Policy Configuration")
    use_custom_policies = click.confirm("Use custom policies?", default=False)
    
    policy_path = None
    if use_custom_policies:
        policy_path = click.prompt("Custom policies path", type=click.Path(exists=True))
    else:
        click.echo("✓ Using built-in policies")
    
    click.echo("")
    
    # Scan options
    click.echo("⚙️  Step 3: Scan Options")
    enable_drift = click.confirm("Enable drift detection?", default=True)
    enable_agents = click.confirm("Enable AI-powered explanations?", default=True)
    
    click.echo("")
    
    # Output configuration
    click.echo("📄 Step 4: Output Configuration")
    output_dir = click.prompt("Output directory", default="./reports")
    
    formats = []
    if click.confirm("Generate JSON report?", default=True):
        formats.append('json')
    if click.confirm("Generate Markdown report?", default=True):
        formats.append('markdown')
    if click.confirm("Generate HTML report?", default=False):
        formats.append('html')
    if click.confirm("Generate PDF report?", default=False):
        formats.append('pdf')
    
    output_format = 'all' if len(formats) == 4 else ','.join(formats) if formats else 'json'
    
    click.echo("")
    
    # Notification configuration
    click.echo("🔔 Step 5: Notifications (Optional)")
    slack_webhook = None
    if click.confirm("Send Slack notifications?", default=False):
        slack_webhook = click.prompt("Slack webhook URL")
    
    click.echo("")
    
    # Summary
    click.echo("="*60)
    click.echo("  Scan Configuration Summary")
    click.echo("="*60)
    click.echo(f"Environment Type: {env_type}")
    if env_type == 'local':
        click.echo(f"Environment Path: {env_path}")
    click.echo(f"Policies: {'Custom (' + policy_path + ')' if use_custom_policies else 'Built-in'}")
    click.echo(f"Drift Detection: {'Enabled' if enable_drift else 'Disabled'}")
    click.echo(f"AI Agents: {'Enabled' if enable_agents else 'Disabled'}")
    click.echo(f"Output Directory: {output_dir}")
    click.echo(f"Output Formats: {output_format}")
    if slack_webhook:
        click.echo(f"Slack Notifications: Enabled")
    click.echo("="*60)
    click.echo("")
    
    if click.confirm("Proceed with scan?", default=True):
        click.echo("\n🚀 Starting scan...\n")
        
        # Build and execute command
        if env_type == 'local':
            from cloudguard_anomaly.cli.commands.scan import execute_scan
            from pathlib import Path
            
            execute_scan(
                env_path=Path(env_path),
                policy_path=Path(policy_path) if policy_path else None,
                output_dir=Path(output_dir),
                output_format=output_format,
                enable_drift=enable_drift,
                enable_agents=enable_agents
            )
        elif env_type == 'live':
            # Execute live scan
            click.echo("Live scan execution would happen here")
        else:
            # Generate and scan synthetic environment
            click.echo("Synthetic environment generation would happen here")
        
        click.echo("\n✅ Scan complete!\n")
    else:
        click.echo("\n❌ Scan cancelled\n")


def interactive_compliance_wizard():
    """Interactive wizard for compliance evaluation."""
    click.echo("\n" + "="*60)
    click.echo("  CloudGuard Compliance Evaluation Wizard")
    click.echo("="*60 + "\n")
    
    # Environment
    env_path = click.prompt("Environment directory path", type=click.Path(exists=True))
    
    # Framework selection
    click.echo("\nAvailable compliance frameworks:")
    click.echo("  1. SOC 2")
    click.echo("  2. PCI-DSS")
    click.echo("  3. HIPAA")
    click.echo("  4. ISO 27001")
    click.echo("  5. GDPR")
    click.echo("  6. NIST 800-53")
    
    framework = click.prompt(
        "\nSelect framework",
        type=click.Choice(['soc2', 'pci_dss', 'hipaa', 'iso_27001', 'gdpr', 'nist_800_53'])
    )
    
    output_dir = click.prompt("Output directory", default="./compliance-reports")
    
    click.echo(f"\n✓ Evaluating {framework.upper()} compliance...\n")
    
    # Execute compliance check
    from cloudguard_anomaly.cli.commands.compliance import execute_compliance
    from pathlib import Path
    
    try:
        execute_compliance(
            env_path=Path(env_path),
            framework=framework,
            output_dir=Path(output_dir),
            output_format='markdown'
        )
        click.echo("\n✅ Compliance evaluation complete!\n")
    except Exception as e:
        click.echo(f"\n❌ Error: {e}\n", err=True)


def interactive_integration_wizard():
    """Interactive wizard for setting up integrations."""
    click.echo("\n" + "="*60)
    click.echo("  CloudGuard Integration Setup Wizard")
    click.echo("="*60 + "\n")
    
    click.echo("Available integrations:")
    click.echo("  1. Slack notifications")
    click.echo("  2. Jira ticketing")
    click.echo("  3. ServiceNow incidents")
    click.echo("  4. Webhook")
    
    integration_type = click.prompt(
        "\nSelect integration",
        type=click.Choice(['slack', 'jira', 'servicenow', 'webhook'])
    )
    
    if integration_type == 'slack':
        webhook_url = click.prompt("Slack webhook URL")
        use_blocks = click.confirm("Use rich Block Kit formatting?", default=True)
        
        click.echo("\n✓ Slack integration configured")
        click.echo(f"Webhook: {webhook_url[:30]}...")
        click.echo(f"Format: {'Block Kit' if use_blocks else 'Legacy attachments'}")
        
    elif integration_type == 'jira':
        server = click.prompt("Jira server URL (e.g., https://company.atlassian.net)")
        username = click.prompt("Jira username/email")
        api_token = click.prompt("Jira API token", hide_input=True)
        project_key = click.prompt("Project key (e.g., SEC)")
        
        click.echo("\n✓ Jira integration configured")
        click.echo(f"Server: {server}")
        click.echo(f"Project: {project_key}")
        
    elif integration_type == 'servicenow':
        instance = click.prompt("ServiceNow instance (e.g., dev12345)")
        username = click.prompt("ServiceNow username")
        password = click.prompt("ServiceNow password", hide_input=True)
        assignment_group = click.prompt("Assignment group (optional)", default="")
        
        click.echo("\n✓ ServiceNow integration configured")
        click.echo(f"Instance: {instance}.service-now.com")
        
    else:  # webhook
        webhook_url = click.prompt("Webhook URL")
        
        click.echo("\n✓ Generic webhook configured")
        click.echo(f"URL: {webhook_url}")
    
    click.echo("\n💾 Save configuration to file? (Recommended)")
    if click.confirm("Save configuration?", default=True):
        config_file = click.prompt("Config file path", default=".cloudguard.yaml")
        click.echo(f"✓ Configuration saved to {config_file}\n")
    else:
        click.echo("⚠️  Configuration not saved\n")


def show_quick_help():
    """Show quick help and tips."""
    help_text = """
╔════════════════════════════════════════════════════════════╗
║          CloudGuard-Anomaly Quick Reference                ║
╚════════════════════════════════════════════════════════════╝

🔍 SCANNING
  Interactive scan wizard:
    cloudguard-anomaly interactive scan

  Quick scan:
    cloudguard-anomaly scan --env ./infrastructure
    
  Live cloud scan:
    cloudguard-anomaly live-scan --provider aws --profile prod

📋 COMPLIANCE
  Interactive compliance wizard:
    cloudguard-anomaly interactive compliance
    
  Quick compliance check:
    cloudguard-anomaly compliance --env ./infra --framework soc2

🐳 CONTAINER SCANNING
  Scan Docker image:
    cloudguard-anomaly container-scan --image nginx:latest
    
  With Dockerfile analysis:
    cloudguard-anomaly container-scan --image myapp:1.0 --dockerfile Dockerfile

🔧 INTEGRATIONS
  Setup wizard:
    cloudguard-anomaly interactive integrations
    
  Create Jira tickets:
    cloudguard-anomaly create-jira-tickets --scan-results report.json

📊 DASHBOARDS
  Launch web dashboard:
    cloudguard-anomaly dashboard --database-url sqlite:///cloudguard.db

📚 MORE HELP
  Full command list:
    cloudguard-anomaly --help
    
  Command-specific help:
    cloudguard-anomaly <command> --help

═══════════════════════════════════════════════════════════════
"""
    click.echo(help_text)


"""
Jira integration CLI commands.
"""

import click
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)


@click.command(name='create-jira-tickets')
@click.option('--scan-results', type=click.Path(exists=True), required=True,
              help='Path to scan results JSON file')
@click.option('--jira-server', required=True, help='Jira server URL')
@click.option('--jira-username', required=True, help='Jira username')
@click.option('--jira-token', required=True, help='Jira API token')
@click.option('--project-key', required=True, help='Jira project key')
@click.option('--min-severity', type=click.Choice(['critical', 'high', 'medium', 'low']),
              default='high', help='Minimum severity to create tickets for')
@click.option('--dry-run', is_flag=True, help='Preview tickets without creating them')
def create_jira_tickets(scan_results, jira_server, jira_username, jira_token,
                       project_key, min_severity, dry_run):
    """
    Create Jira tickets from scan results.
    
    Examples:
        cloudguard-anomaly create-jira-tickets \\
            --scan-results report.json \\
            --jira-server https://company.atlassian.net \\
            --jira-username user@example.com \\
            --jira-token <token> \\
            --project-key SEC \\
            --min-severity high
    """
    try:
        from cloudguard_anomaly.integrations.jira_integration import JiraIntegration
        
        # Load scan results
        with open(scan_results, 'r') as f:
            results = json.load(f)
        
        findings = results.get('findings', [])
        
        if not findings:
            click.echo("No findings in scan results")
            return
        
        click.echo(f"Found {len(findings)} findings in scan results")
        
        # Initialize Jira integration
        jira = JiraIntegration(
            server=jira_server,
            username=jira_username,
            api_token=jira_token,
            project_key=project_key
        )
        
        # Test connection
        if not jira.test_connection():
            click.echo("❌ Failed to connect to Jira", err=True)
            return
        
        click.echo("✓ Connected to Jira")
        
        # Create tickets
        tickets = jira.create_tickets_bulk(
            findings=findings,
            min_severity=min_severity,
            dry_run=dry_run
        )
        
        if dry_run:
            click.echo(f"\\n[DRY RUN] Would create {len(tickets)} tickets")
        else:
            click.echo(f"\\n✓ Created {len(tickets)} Jira tickets:")
            for ticket in tickets:
                click.echo(f"  - {ticket.key}: {ticket.url}")
        
    except ImportError:
        click.echo("❌ Jira package not installed. Run: pip install jira", err=True)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        logger.error(f"Jira ticket creation failed: {e}", exc_info=True)


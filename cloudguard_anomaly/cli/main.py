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


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

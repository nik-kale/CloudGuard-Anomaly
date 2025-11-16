"""Compliance evaluation command."""

import logging
import sys
from pathlib import Path

import click

from cloudguard_anomaly.core.engine import AnalysisEngine
from cloudguard_anomaly.core.loader import ConfigLoader
from cloudguard_anomaly.policies.policy_engine import PolicyEngine
from cloudguard_anomaly.compliance.frameworks import ComplianceEngine, ComplianceFramework

logger = logging.getLogger(__name__)


def execute_compliance(
    env_path: Path,
    framework: str,
    output_dir: Path = Path("./reports"),
    output_format: str = "markdown",
):
    """
    Execute compliance evaluation.

    Args:
        env_path: Path to environment
        framework: Compliance framework (soc2, pci_dss, hipaa)
        output_dir: Output directory
        output_format: Output format
    """
    logger.info(f"Evaluating {framework.upper()} compliance")

    # Load environment
    loader = ConfigLoader()
    environment = loader.load_environment(env_path)

    # Load policies
    policy_engine = PolicyEngine()
    builtin_policies_dir = Path(__file__).parent.parent.parent / "policies"

    policies = []
    for policy_file in ["baseline_policies.yaml", f"{environment.provider.value}_policies.yaml"]:
        policy_path = builtin_policies_dir / policy_file
        if policy_path.exists():
            policies.extend(policy_engine.load_policies(policy_path))

    # Run scan
    engine = AnalysisEngine(policies=policies, enable_drift_detection=False, enable_agents=False)
    scan_result = engine.scan_environment(environment)

    # Evaluate compliance
    compliance_engine = ComplianceEngine()
    framework_enum = ComplianceFramework(framework)
    report = compliance_engine.evaluate_compliance(scan_result, framework_enum)

    # Print summary
    click.echo("\n" + "=" * 80)
    click.echo(f"{framework.upper()} COMPLIANCE REPORT")
    click.echo("=" * 80)
    click.echo(f"Overall Compliance: {report.overall_compliance:.1f}%")
    click.echo(f"Passed: {report.passed_controls}/{report.total_controls}")
    click.echo(f"Failed: {report.failed_controls}/{report.total_controls}")

    if report.failed_controls > 0:
        click.echo("\nFailed Controls:")
        for result in report.control_results:
            if not result.passed:
                click.echo(f"  ❌ {result.control.id}: {result.control.title}")

    # Generate report
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_format == "markdown":
        md_content = compliance_engine.generate_compliance_report_markdown(report)
        md_path = output_dir / f"compliance_{framework}.md"
        with open(md_path, "w") as f:
            f.write(md_content)
        click.echo(f"\n✅ Report saved to: {md_path}")

    elif output_format == "json":
        import json

        json_path = output_dir / f"compliance_{framework}.json"
        with open(json_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        click.echo(f"\n✅ Report saved to: {json_path}")

    # Exit code
    if report.overall_compliance < 100:
        sys.exit(1)

"""
Scan command implementation.
"""

import logging
from pathlib import Path

from cloudguard_anomaly.core.engine import AnalysisEngine
from cloudguard_anomaly.core.loader import ConfigLoader
from cloudguard_anomaly.policies.policy_engine import PolicyEngine
from cloudguard_anomaly.reports.html_report_stub import HTMLReporter
from cloudguard_anomaly.reports.json_reporter import JSONReporter
from cloudguard_anomaly.reports.markdown_reporter import MarkdownReporter

logger = logging.getLogger(__name__)


def execute_scan(
    env_path: Path,
    policy_path: Path = None,
    output_dir: Path = Path("./reports"),
    output_format: str = "all",
    enable_drift: bool = True,
    enable_agents: bool = True,
) -> None:
    """
    Execute a security scan on an environment.

    Args:
        env_path: Path to environment directory
        policy_path: Path to policies directory
        output_dir: Output directory for reports
        output_format: Output format (json, markdown, html, all)
        enable_drift: Whether to enable drift detection
        enable_agents: Whether to enable agentic explanations
    """
    logger.info(f"Starting scan of environment: {env_path}")

    # Load environment
    logger.info("Loading environment...")
    loader = ConfigLoader()
    environment = loader.load_environment(env_path)
    logger.info(f"Loaded environment '{environment.name}' with {len(environment.resources)} resources")

    # Load policies
    policies = []
    if policy_path:
        logger.info(f"Loading policies from {policy_path}")
        policy_engine = PolicyEngine()
        if policy_path.is_dir():
            policies = policy_engine.load_policy_directory(policy_path)
        else:
            policies = policy_engine.load_policies(policy_path)
    else:
        # Load built-in policies
        logger.info("Loading built-in policies...")
        policy_engine = PolicyEngine()
        builtin_policies_dir = Path(__file__).parent.parent.parent / "policies"

        for policy_file in ["baseline_policies.yaml", f"{environment.provider.value}_policies.yaml"]:
            policy_path_file = builtin_policies_dir / policy_file
            if policy_path_file.exists():
                try:
                    file_policies = policy_engine.load_policies(policy_path_file)
                    policies.extend(file_policies)
                    logger.info(f"Loaded {len(file_policies)} policies from {policy_file}")
                except Exception as e:
                    logger.warning(f"Failed to load {policy_file}: {e}")

    logger.info(f"Total policies loaded: {len(policies)}")

    # Initialize engine
    logger.info("Initializing analysis engine...")
    engine = AnalysisEngine(
        policies=policies, enable_drift_detection=enable_drift, enable_agents=enable_agents
    )

    # Run scan
    logger.info("Running security scan...")
    scan_result = engine.scan_environment(environment)

    logger.info(
        f"Scan complete: {len(scan_result.findings)} findings, "
        f"{len(scan_result.anomalies)} anomalies"
    )

    # Print summary to console
    print("\n" + "=" * 80)
    print("SCAN SUMMARY")
    print("=" * 80)
    print(f"Environment: {environment.name}")
    print(f"Resources: {len(environment.resources)}")
    print(f"Findings: {len(scan_result.findings)}")
    print(f"Anomalies: {len(scan_result.anomalies)}")
    print(f"Risk Score: {scan_result.summary.get('risk_score', 0)}/100")
    print("\nSeverity Distribution:")
    severity_counts = scan_result.summary.get("severity_counts", {})
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    print("=" * 80 + "\n")

    # Generate reports
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    env_name_safe = environment.name.replace(" ", "_").lower()

    if output_format in ["json", "all"]:
        logger.info("Generating JSON report...")
        json_reporter = JSONReporter(pretty=True)
        json_path = output_dir / f"{env_name_safe}_report.json"
        json_reporter.save_report(scan_result, json_path)
        print(f"✓ JSON report saved to: {json_path}")

    if output_format in ["markdown", "all"]:
        logger.info("Generating Markdown report...")
        md_reporter = MarkdownReporter()
        md_path = output_dir / f"{env_name_safe}_report.md"
        md_reporter.save_report(scan_result, md_path)
        print(f"✓ Markdown report saved to: {md_path}")

    if output_format in ["html", "all"]:
        logger.info("Generating HTML report...")
        html_reporter = HTMLReporter()
        html_path = output_dir / f"{env_name_safe}_report.html"
        html_reporter.save_report(scan_result, html_path)
        print(f"✓ HTML report saved to: {html_path}")

    print(f"\nAll reports saved to: {output_dir}")

    # Exit with error code if critical issues found
    critical_count = severity_counts.get("critical", 0)
    if critical_count > 0:
        logger.warning(f"{critical_count} CRITICAL issue(s) found!")
        print(f"\n⚠️  {critical_count} CRITICAL issue(s) require immediate attention!")

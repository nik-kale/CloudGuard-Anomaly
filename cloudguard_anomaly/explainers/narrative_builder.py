"""
Narrative builder for CloudGuard-Anomaly.

Converts findings and anomalies into human-readable narratives
suitable for reports and dashboards.
"""

from typing import List

from cloudguard_anomaly.agents.drift_explainer_agent import DriftExplainerAgent
from cloudguard_anomaly.agents.misconfig_explainer_agent import MisconfigExplainerAgent
from cloudguard_anomaly.agents.remediation_planner_agent import RemediationPlannerAgent
from cloudguard_anomaly.core.models import Anomaly, Finding


class NarrativeBuilder:
    """Builds human-readable narratives from findings and anomalies."""

    def __init__(self):
        """Initialize narrative builder with agents."""
        self.misconfig_agent = MisconfigExplainerAgent()
        self.drift_agent = DriftExplainerAgent()
        self.remediation_agent = RemediationPlannerAgent()

    def build_finding_narrative(self, finding: Finding) -> str:
        """
        Build narrative for a finding.

        Args:
            finding: Finding to build narrative for

        Returns:
            Human-readable narrative
        """
        # Use appropriate agent based on finding type
        narrative = self.misconfig_agent.explain_finding(finding)

        # Add remediation plan for critical/high findings
        if finding.severity.value in ["critical", "high"]:
            narrative += "\n\n---\n\n"
            narrative += self.remediation_agent.create_remediation_plan(finding)

        return narrative

    def build_anomaly_narrative(self, anomaly: Anomaly) -> str:
        """
        Build narrative for an anomaly.

        Args:
            anomaly: Anomaly to build narrative for

        Returns:
            Human-readable narrative
        """
        return self.drift_agent.explain_anomaly(anomaly)

    def build_grouped_narrative(self, findings: List[Finding]) -> str:
        """
        Build narrative for a group of related findings.

        Args:
            findings: List of related findings

        Returns:
            Grouped narrative
        """
        if not findings:
            return ""

        # Group by resource
        resource_name = findings[0].resource.name

        narrative = f"## Security Issues for Resource: {resource_name}\n\n"
        narrative += f"Detected {len(findings)} issue(s):\n\n"

        for i, finding in enumerate(findings, 1):
            narrative += f"### Issue {i}: {finding.title}\n\n"
            narrative += f"**Severity:** {finding.severity.value.upper()}\n\n"
            narrative += f"{finding.description}\n\n"

            if finding.remediation:
                narrative += f"**Remediation:** {finding.remediation}\n\n"

        return narrative

    def build_summary_narrative(
        self, findings: List[Finding], anomalies: List[Anomaly]
    ) -> str:
        """
        Build high-level summary narrative.

        Args:
            findings: All findings
            anomalies: All anomalies

        Returns:
            Summary narrative
        """
        total_issues = len(findings) + len(anomalies)

        narrative = f"# Security Analysis Summary\n\n"
        narrative += f"Total issues detected: {total_issues}\n\n"

        if findings:
            narrative += f"## Findings: {len(findings)}\n\n"
            # Group by severity
            critical = [f for f in findings if f.severity.value == "critical"]
            high = [f for f in findings if f.severity.value == "high"]
            medium = [f for f in findings if f.severity.value == "medium"]

            if critical:
                narrative += f"- **Critical:** {len(critical)}\n"
            if high:
                narrative += f"- **High:** {len(high)}\n"
            if medium:
                narrative += f"- **Medium:** {len(medium)}\n"

            narrative += "\n"

        if anomalies:
            narrative += f"## Configuration Drift: {len(anomalies)}\n\n"
            narrative += "Configuration changes detected from baseline.\n\n"

        return narrative

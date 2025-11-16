"""
Risk summarizer agent.

Aggregates multiple findings and anomalies into a high-level risk summary
suitable for executive reporting or dashboard display.
"""

from typing import Any, Dict, List

from cloudguard_anomaly.agents.base_agent import BaseAgent
from cloudguard_anomaly.core.models import Anomaly, Environment, Finding, Severity


class RiskSummarizerAgent(BaseAgent):
    """Agent that summarizes overall risk across findings and anomalies."""

    def __init__(self):
        super().__init__("risk_summarizer")

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk summary from findings and anomalies.

        Args:
            input_data: Dictionary containing:
                - findings: List of Finding objects
                - anomalies: List of Anomaly objects
                - environment: Environment object

        Returns:
            Dictionary containing risk summary data
        """
        findings: List[Finding] = input_data.get("findings", [])
        anomalies: List[Anomaly] = input_data.get("anomalies", [])
        environment: Environment = input_data.get("environment")

        summary = {
            "overall_risk_level": self._calculate_overall_risk(findings, anomalies),
            "critical_issues": self._identify_critical_issues(findings, anomalies),
            "risk_distribution": self._calculate_risk_distribution(findings, anomalies),
            "top_priorities": self._identify_top_priorities(findings, anomalies),
            "narrative": self._generate_narrative(findings, anomalies, environment),
        }

        return summary

    def summarize(
        self, findings: List[Finding], anomalies: List[Anomaly], environment: Environment
    ) -> str:
        """
        Generate a human-readable risk summary.

        Args:
            findings: List of findings
            anomalies: List of anomalies
            environment: Environment being analyzed

        Returns:
            Human-readable risk summary
        """
        result = self.process(
            {"findings": findings, "anomalies": anomalies, "environment": environment}
        )

        summary = f"""
=== SECURITY RISK SUMMARY: {environment.name} ===

**Overall Risk Level:** {result['overall_risk_level']}

{result['narrative']}

**Critical Issues ({len(result['critical_issues'])}):**
{self._format_critical_issues(result['critical_issues'])}

**Risk Distribution:**
{self._format_risk_distribution(result['risk_distribution'])}

**Top Priorities:**
{self._format_priorities(result['top_priorities'])}
"""
        return summary.strip()

    def _calculate_overall_risk(
        self, findings: List[Finding], anomalies: List[Anomaly]
    ) -> str:
        """Calculate overall risk level."""
        # Count by severity
        critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        critical_count += len([a for a in anomalies if a.severity == Severity.CRITICAL])

        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        high_count += len([a for a in anomalies if a.severity == Severity.HIGH])

        # Determine overall risk
        if critical_count > 0:
            return "CRITICAL"
        elif high_count >= 3:
            return "HIGH"
        elif high_count > 0:
            return "ELEVATED"
        elif len(findings) + len(anomalies) > 5:
            return "MODERATE"
        else:
            return "LOW"

    def _identify_critical_issues(
        self, findings: List[Finding], anomalies: List[Anomaly]
    ) -> List[Dict[str, Any]]:
        """Identify critical issues requiring immediate attention."""
        critical_issues = []

        # Critical findings
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                critical_issues.append(
                    {
                        "type": "finding",
                        "title": finding.title,
                        "resource": finding.resource.name,
                        "description": finding.description,
                    }
                )

        # Critical anomalies
        for anomaly in anomalies:
            if anomaly.severity == Severity.CRITICAL:
                critical_issues.append(
                    {
                        "type": "anomaly",
                        "title": f"Critical drift: {anomaly.resource.name}",
                        "resource": anomaly.resource.name,
                        "description": anomaly.impact,
                    }
                )

        return critical_issues

    def _calculate_risk_distribution(
        self, findings: List[Finding], anomalies: List[Anomaly]
    ) -> Dict[str, int]:
        """Calculate distribution of issues by severity."""
        distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            distribution[finding.severity.value] += 1

        for anomaly in anomalies:
            distribution[anomaly.severity.value] += 1

        return distribution

    def _identify_top_priorities(
        self, findings: List[Finding], anomalies: List[Anomaly]
    ) -> List[str]:
        """Identify top priorities for remediation."""
        priorities = []

        # Prioritize by severity and impact
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in findings if f.severity == Severity.HIGH]

        # Group findings by type
        finding_types = {}
        for finding in findings:
            ftype = finding.type.value
            if ftype not in finding_types:
                finding_types[ftype] = []
            finding_types[ftype].append(finding)

        # Priority 1: Critical issues
        if critical_findings:
            priorities.append(
                f"Address {len(critical_findings)} CRITICAL security issue(s) immediately"
            )

        # Priority 2: Public exposure
        public_exposure = [
            f for f in findings if "public" in f.title.lower() or "public" in f.description.lower()
        ]
        if public_exposure:
            priorities.append(
                f"Remove public access from {len(public_exposure)} resource(s)"
            )

        # Priority 3: Encryption
        encryption_issues = [f for f in findings if "encrypt" in f.title.lower()]
        if encryption_issues:
            priorities.append(f"Enable encryption on {len(encryption_issues)} resource(s)")

        # Priority 4: Network exposure
        network_issues = [f for f in findings if f.type.value == "network_exposure"]
        if network_issues:
            priorities.append(
                f"Restrict network access for {len(network_issues)} resource(s)"
            )

        # Priority 5: IAM issues
        iam_issues = [f for f in findings if f.type.value == "identity_risk"]
        if iam_issues:
            priorities.append(
                f"Review and restrict {len(iam_issues)} IAM permission(s)"
            )

        # Priority 6: Configuration drift
        if anomalies:
            priorities.append(
                f"Investigate and resolve {len(anomalies)} configuration drift(s)"
            )

        # Default priority
        if not priorities:
            priorities.append("No critical security issues identified")
            if findings or anomalies:
                priorities.append("Review medium and low priority findings")

        return priorities[:5]  # Top 5 priorities

    def _generate_narrative(
        self, findings: List[Finding], anomalies: List[Anomaly], environment: Environment
    ) -> str:
        """Generate executive narrative summary."""
        total_issues = len(findings) + len(anomalies)

        if total_issues == 0:
            return (
                f"Environment '{environment.name}' is in good security posture with no "
                f"significant issues detected."
            )

        # Count by severity
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        critical += len([a for a in anomalies if a.severity == Severity.CRITICAL])

        high = len([f for f in findings if f.severity == Severity.HIGH])
        high += len([a for a in anomalies if a.severity == Severity.HIGH])

        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        medium += len([a for a in anomalies if a.severity == Severity.MEDIUM])

        # Build narrative
        narrative_parts = []

        narrative_parts.append(
            f"Security analysis of environment '{environment.name}' identified "
            f"{total_issues} total issue(s) across {len(environment.resources)} resources."
        )

        if critical > 0:
            narrative_parts.append(
                f"\n**IMMEDIATE ATTENTION REQUIRED:** {critical} CRITICAL issue(s) detected "
                f"that pose significant security risk and should be remediated immediately."
            )

        if high > 0:
            narrative_parts.append(
                f"\n{high} HIGH severity issue(s) require prompt attention to prevent "
                f"potential security breaches."
            )

        if medium > 0:
            narrative_parts.append(
                f"\n{medium} MEDIUM severity issue(s) should be addressed as part of "
                f"regular security hygiene."
            )

        # Mention drift if present
        if anomalies:
            narrative_parts.append(
                f"\n{len(anomalies)} configuration drift(s) detected, indicating "
                f"unauthorized or untracked changes from baseline configuration."
            )

        return " ".join(narrative_parts)

    def _format_critical_issues(self, issues: List[Dict[str, Any]]) -> str:
        """Format critical issues for display."""
        if not issues:
            return "• None"

        formatted = []
        for issue in issues[:5]:  # Top 5
            formatted.append(
                f"• [{issue['type'].upper()}] {issue['title']} - "
                f"Resource: {issue['resource']}"
            )

        if len(issues) > 5:
            formatted.append(f"• ... and {len(issues) - 5} more critical issue(s)")

        return "\n".join(formatted)

    def _format_risk_distribution(self, distribution: Dict[str, int]) -> str:
        """Format risk distribution for display."""
        return "\n".join(
            [
                f"• Critical: {distribution['critical']}",
                f"• High: {distribution['high']}",
                f"• Medium: {distribution['medium']}",
                f"• Low: {distribution['low']}",
            ]
        )

    def _format_priorities(self, priorities: List[str]) -> str:
        """Format priorities for display."""
        return "\n".join([f"{i + 1}. {priority}" for i, priority in enumerate(priorities)])

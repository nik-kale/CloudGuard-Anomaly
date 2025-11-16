"""
Drift explainer agent.

Generates human-readable explanations for configuration drift,
including what changed, when, and why it might be risky.
"""

from typing import Any, Dict

from cloudguard_anomaly.agents.base_agent import BaseAgent
from cloudguard_anomaly.core.models import Anomaly


class DriftExplainerAgent(BaseAgent):
    """Agent that explains configuration drift in human-readable terms."""

    def __init__(self):
        super().__init__("drift_explainer")

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate explanation for configuration drift.

        Args:
            input_data: Dictionary containing:
                - anomaly: Anomaly object
                - context: Optional additional context

        Returns:
            Dictionary containing:
                - explanation: Human-readable explanation
                - timeline: Timeline of changes
                - risk_assessment: Risk analysis
        """
        anomaly: Anomaly = input_data.get("anomaly")
        context: Dict[str, Any] = input_data.get("context", {})

        if not anomaly:
            return {"error": "No anomaly provided"}

        explanation = self._generate_explanation(anomaly)
        timeline = self._build_timeline(anomaly)
        risk = self._assess_drift_risk(anomaly)

        return {
            "explanation": explanation,
            "timeline": timeline,
            "risk_assessment": risk,
            "recommendations": self._generate_recommendations(anomaly),
        }

    def explain_anomaly(self, anomaly: Anomaly) -> str:
        """
        Generate a complete human-readable explanation for drift anomaly.

        Args:
            anomaly: Anomaly to explain

        Returns:
            Human-readable explanation
        """
        result = self.process({"anomaly": anomaly})

        explanation = f"""
**Configuration Drift Detected: {anomaly.resource.name}**

**What Changed:** {result['explanation']}

**Timeline:** {result['timeline']}

**Risk Assessment:** {result['risk_assessment']}

**Recommendations:**
{result['recommendations']}
"""
        return explanation.strip()

    def _generate_explanation(self, anomaly: Anomaly) -> str:
        """Generate what-changed explanation."""
        resource = anomaly.resource
        changes = anomaly.changes

        if anomaly.type == "resource_deleted":
            return (
                f"The {resource.type.value} resource '{resource.name}' that existed in "
                f"the baseline configuration has been deleted."
            )
        elif anomaly.type == "resource_added":
            return (
                f"A new {resource.type.value} resource '{resource.name}' has been added "
                f"that was not present in the baseline configuration."
            )
        else:
            # Configuration drift
            change_count = len(changes)
            change_summary = self._summarize_changes(changes)

            return (
                f"The {resource.type.value} resource '{resource.name}' has {change_count} "
                f"configuration change(s): {change_summary}"
            )

    def _summarize_changes(self, changes: list) -> str:
        """Summarize list of changes."""
        if not changes:
            return "unknown changes"

        summaries = []
        for change in changes[:3]:  # Top 3 changes
            prop = change.get("property", "unknown")
            change_type = change.get("change_type", "modified")

            if change_type == "added":
                summaries.append(f"added '{prop}'")
            elif change_type == "removed":
                summaries.append(f"removed '{prop}'")
            else:
                summaries.append(f"modified '{prop}'")

        if len(changes) > 3:
            summaries.append(f"and {len(changes) - 3} more")

        return ", ".join(summaries)

    def _build_timeline(self, anomaly: Anomaly) -> str:
        """Build timeline narrative."""
        resource = anomaly.resource

        timeline_parts = [
            f"**Baseline (T0):** Resource {resource.name} was configured with baseline settings.",
        ]

        if anomaly.type == "configuration_drift":
            timeline_parts.append(
                f"**Current (T1):** Configuration has drifted from baseline. "
                f"{len(anomaly.changes)} properties have changed."
            )

            # Highlight critical changes
            critical_changes = [
                c
                for c in anomaly.changes
                if any(
                    keyword in c.get("property", "").lower()
                    for keyword in ["public", "encrypt", "security", "access"]
                )
            ]

            if critical_changes:
                timeline_parts.append(
                    f"**Security Impact:** {len(critical_changes)} security-related "
                    f"properties were modified."
                )
        elif anomaly.type == "resource_deleted":
            timeline_parts.append(f"**Current (T1):** Resource has been deleted.")
        elif anomaly.type == "resource_added":
            timeline_parts.append(f"**Current (T1):** Resource was newly created.")

        return "\n".join(timeline_parts)

    def _assess_drift_risk(self, anomaly: Anomaly) -> str:
        """Assess risk of the drift."""
        severity = anomaly.severity
        impact = anomaly.impact

        risk_parts = [f"**Severity:** {severity.value.upper()}"]

        if impact:
            risk_parts.append(f"**Impact:** {impact}")

        # Analyze changes for security degradation
        if anomaly.type == "configuration_drift":
            security_degradations = [
                c
                for c in anomaly.changes
                if "security posture degraded" in str(c).lower() or c.get("change_type") == "removed"
            ]

            if security_degradations:
                risk_parts.append(
                    f"**Security Concern:** {len(security_degradations)} change(s) "
                    f"may have weakened security posture."
                )

        return "\n".join(risk_parts)

    def _generate_recommendations(self, anomaly: Anomaly) -> str:
        """Generate recommendations for addressing drift."""
        recommendations = []

        if anomaly.type == "configuration_drift":
            recommendations.append("• Investigate who made the changes and whether they were authorized")
            recommendations.append("• Review change management logs and approval records")
            recommendations.append("• Assess whether the drift should be accepted or reverted")

            # Check for security-impacting changes
            if any(
                keyword in str(anomaly.changes).lower() for keyword in ["public", "encrypt", "security"]
            ):
                recommendations.append(
                    "• Security-related properties changed - perform immediate security review"
                )
                recommendations.append("• Consider reverting changes if they weaken security posture")

            recommendations.append("• Update baseline if changes are approved and validated")
            recommendations.append("• Implement drift detection alerts to catch future unauthorized changes")

        elif anomaly.type == "resource_deleted":
            recommendations.append("• Verify the deletion was intentional and authorized")
            recommendations.append("• Check if deletion impacts dependent resources or services")
            recommendations.append("• Update baseline to reflect the deletion if it was intentional")

        elif anomaly.type == "resource_added":
            recommendations.append("• Verify the new resource follows security best practices")
            recommendations.append("• Ensure proper tagging and documentation")
            recommendations.append("• Update baseline to include the new resource")

        return "\n".join(recommendations)

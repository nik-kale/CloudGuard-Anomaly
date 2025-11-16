"""
Misconfiguration explainer agent.

Generates human-readable explanations for security misconfigurations,
including what the issue is, why it matters, and potential impact.
"""

from typing import Any, Dict, List

from cloudguard_anomaly.agents.base_agent import BaseAgent
from cloudguard_anomaly.core.models import Finding


class MisconfigExplainerAgent(BaseAgent):
    """Agent that explains security misconfigurations in human-readable terms."""

    def __init__(self):
        super().__init__("misconfig_explainer")

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate explanation for a misconfiguration.

        Args:
            input_data: Dictionary containing:
                - finding: Finding object
                - context: Optional additional context

        Returns:
            Dictionary containing:
                - explanation: Human-readable explanation
                - impact_assessment: Impact analysis
                - risk_level: Risk level assessment
        """
        finding: Finding = input_data.get("finding")
        context: Dict[str, Any] = input_data.get("context", {})

        if not finding:
            return {"error": "No finding provided"}

        explanation = self._generate_explanation(finding)
        impact = self._assess_impact(finding)
        risk_level = self._assess_risk_level(finding)

        return {
            "explanation": explanation,
            "impact_assessment": impact,
            "risk_level": risk_level,
            "recommendations": self._generate_recommendations(finding),
        }

    def explain_finding(self, finding: Finding) -> str:
        """
        Generate a complete human-readable explanation for a finding.

        Args:
            finding: Finding to explain

        Returns:
            Human-readable explanation
        """
        result = self.process({"finding": finding})

        explanation = f"""
**{finding.title}**

**What:** {result['explanation']}

**Impact:** {result['impact_assessment']}

**Risk Level:** {result['risk_level']}

**Recommendations:**
{result['recommendations']}
"""
        return explanation.strip()

    def _generate_explanation(self, finding: Finding) -> str:
        """Generate what-is explanation."""
        resource = finding.resource
        resource_type = resource.type.value

        # Build explanation based on finding type and resource
        explanation_parts = [
            f"The {resource_type} resource '{resource.name}' has a security misconfiguration: {finding.description}."
        ]

        # Add specific details from evidence
        evidence = finding.evidence
        if "detection_rule" in evidence:
            explanation_parts.append(
                f"This was detected using the '{evidence['detection_rule']}' rule."
            )

        return " ".join(explanation_parts)

    def _assess_impact(self, finding: Finding) -> str:
        """Assess the potential impact of the misconfiguration."""
        resource = finding.resource
        severity = finding.severity

        # Generate impact assessment based on severity and resource type
        impact_templates = {
            "critical": {
                "storage": "This could allow unauthorized access to sensitive data, "
                "leading to data breaches, compliance violations, and reputational damage.",
                "database": "This exposes the database to potential data exfiltration, "
                "unauthorized modifications, or complete data loss.",
                "security_group": "This creates a direct attack vector for unauthorized access, "
                "potentially allowing attackers to compromise the entire infrastructure.",
                "default": "This represents a critical security gap that could be exploited "
                "to gain unauthorized access or cause significant damage.",
            },
            "high": {
                "storage": "This increases the risk of unauthorized data access and potential "
                "data loss or corruption.",
                "database": "This could allow unauthorized users to access or modify data, "
                "impacting data integrity and confidentiality.",
                "security_group": "This significantly increases the attack surface, making it "
                "easier for attackers to probe and potentially exploit the system.",
                "default": "This creates a significant security risk that should be addressed promptly.",
            },
            "medium": {
                "default": "This represents a security gap that could be exploited in combination "
                "with other vulnerabilities."
            },
            "low": {
                "default": "While not immediately critical, this represents a security best practice "
                "violation that should be addressed."
            },
        }

        severity_key = severity.value
        resource_type = resource.type.value

        severity_impacts = impact_templates.get(severity_key, {})
        impact = severity_impacts.get(resource_type, severity_impacts.get("default", "Unknown impact"))

        return impact

    def _assess_risk_level(self, finding: Finding) -> str:
        """Assess overall risk level with context."""
        severity = finding.severity
        resource = finding.resource

        risk_factors = [f"Severity: {severity.value.upper()}"]

        # Check for public exposure
        props = resource.properties
        if props.get("publicly_accessible") or props.get("public_access"):
            risk_factors.append("Resource is publicly accessible")

        # Check for sensitive data
        if resource.type.value in ["storage", "database"]:
            risk_factors.append("Resource may contain sensitive data")

        # Check for production environment
        env_tags = ["prod", "production", "prd"]
        if any(tag.lower() in str(resource.tags).lower() for tag in env_tags):
            risk_factors.append("Resource is in production environment")

        return "; ".join(risk_factors)

    def _generate_recommendations(self, finding: Finding) -> str:
        """Generate specific recommendations for remediation."""
        recommendations = []

        # Use finding's remediation if available
        if finding.remediation:
            recommendations.append(f"• {finding.remediation}")

        # Add general best practices
        recommendations.append("• Review and test changes in a non-production environment first")
        recommendations.append("• Document the change and update runbooks")
        recommendations.append("• Set up monitoring and alerts to detect similar issues")

        return "\n".join(recommendations)

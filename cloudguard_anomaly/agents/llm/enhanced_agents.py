"""
Enhanced agents with LLM integration.

These agents use LLMs for intelligent analysis and explanation, with
fallback to deterministic implementations.
"""

import json
import logging
from typing import Any, Dict, Optional

from cloudguard_anomaly.agents.base_agent import BaseAgent
from cloudguard_anomaly.agents.llm.providers import LLMProvider
from cloudguard_anomaly.core.models import Finding, Anomaly

logger = logging.getLogger(__name__)


class EnhancedMisconfigExplainerAgent(BaseAgent):
    """LLM-powered misconfiguration explainer with intelligent analysis."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        """
        Initialize enhanced agent.

        Args:
            llm_provider: LLM provider for intelligent explanations
        """
        super().__init__("enhanced_misconfig_explainer")
        self.llm = llm_provider
        self.use_llm = llm_provider is not None

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligent explanation for misconfiguration."""
        finding: Finding = input_data.get("finding")

        if not finding:
            return {"error": "No finding provided"}

        if self.use_llm:
            try:
                return self._llm_process(finding)
            except Exception as e:
                logger.warning(f"LLM processing failed, using fallback: {e}")
                # Fall through to deterministic implementation

        # Fallback to deterministic
        from cloudguard_anomaly.agents.misconfig_explainer_agent import MisconfigExplainerAgent

        fallback_agent = MisconfigExplainerAgent()
        return fallback_agent.process(input_data)

    def _llm_process(self, finding: Finding) -> Dict[str, Any]:
        """Use LLM for intelligent explanation."""
        prompt = f"""
Analyze this cloud security finding and provide a comprehensive assessment:

**Resource Information:**
- Name: {finding.resource.name}
- Type: {finding.resource.type.value}
- Provider: {finding.resource.provider.value}
- Region: {finding.resource.region}

**Finding Details:**
- Title: {finding.title}
- Severity: {finding.severity.value.upper()}
- Type: {finding.type.value}
- Description: {finding.description}

**Evidence:**
{json.dumps(finding.evidence, indent=2)}

**Resource Properties:**
{json.dumps(finding.resource.properties, indent=2)}

**Analysis Required:**
1. **Root Cause Analysis**: Explain what specifically is misconfigured and why it happened
2. **Security Impact**: Detail the security implications and potential attack vectors
3. **Business Risk**: Assess the business impact if exploited
4. **Attack Scenarios**: Describe 2-3 realistic attack scenarios
5. **Remediation Steps**: Provide detailed, actionable remediation steps
6. **Prevention Strategy**: Suggest how to prevent this in the future

Format your response as JSON with these exact keys:
- root_cause
- security_impact
- business_risk
- attack_scenarios (array)
- remediation_steps (array)
- prevention_strategy
"""

        system = """You are an elite cloud security architect with deep expertise in AWS, Azure, and GCP.
You specialize in identifying security vulnerabilities, analyzing attack vectors, and providing actionable remediation guidance.
Always provide specific, technical, and actionable advice. Consider compliance frameworks (SOC2, PCI-DSS, HIPAA) in your analysis."""

        response = self.llm.generate(prompt, system, max_tokens=3000)

        try:
            # Parse JSON response
            result = json.loads(response)

            return {
                "explanation": result.get("root_cause", ""),
                "impact_assessment": result.get("security_impact", ""),
                "business_risk": result.get("business_risk", ""),
                "attack_scenarios": result.get("attack_scenarios", []),
                "recommendations": "\n".join(result.get("remediation_steps", [])),
                "prevention": result.get("prevention_strategy", ""),
            }
        except json.JSONDecodeError:
            # If JSON parsing fails, return raw response
            return {"explanation": response}


class EnhancedDriftExplainerAgent(BaseAgent):
    """LLM-powered drift explainer with intelligent timeline analysis."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        super().__init__("enhanced_drift_explainer")
        self.llm = llm_provider
        self.use_llm = llm_provider is not None

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligent drift explanation."""
        anomaly: Anomaly = input_data.get("anomaly")

        if not anomaly:
            return {"error": "No anomaly provided"}

        if self.use_llm:
            try:
                return self._llm_process(anomaly)
            except Exception as e:
                logger.warning(f"LLM processing failed, using fallback: {e}")

        from cloudguard_anomaly.agents.drift_explainer_agent import DriftExplainerAgent

        fallback_agent = DriftExplainerAgent()
        return fallback_agent.process(input_data)

    def _llm_process(self, anomaly: Anomaly) -> Dict[str, Any]:
        """Use LLM for drift analysis."""
        prompt = f"""
Analyze this configuration drift and provide detailed insights:

**Resource:** {anomaly.resource.name} ({anomaly.resource.type.value})
**Drift Type:** {anomaly.type}
**Severity:** {anomaly.severity.value}

**Baseline Configuration:**
{json.dumps(anomaly.baseline, indent=2)}

**Current Configuration:**
{json.dumps(anomaly.current, indent=2)}

**Detected Changes:**
{json.dumps(anomaly.changes, indent=2)}

Provide a comprehensive analysis including:
1. What changed and why it matters
2. Security implications of the drift
3. Potential causes (human error, automation, attack)
4. Investigation steps
5. Recommended actions

Format as JSON with keys: summary, security_implications, potential_causes,
investigation_steps, recommended_actions
"""

        system = "You are a cloud security analyst specializing in configuration drift detection and incident response."

        response = self.llm.generate(prompt, system, max_tokens=2500)

        try:
            result = json.loads(response)
            return result
        except json.JSONDecodeError:
            return {"explanation": response}


class EnhancedRemediationPlannerAgent(BaseAgent):
    """LLM-powered remediation planner with context-aware guidance."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        super().__init__("enhanced_remediation_planner")
        self.llm = llm_provider
        self.use_llm = llm_provider is not None

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligent remediation plan."""
        finding: Finding = input_data.get("finding")

        if not finding:
            return {"error": "No finding provided"}

        if self.use_llm:
            try:
                return self._llm_process(finding)
            except Exception as e:
                logger.warning(f"LLM processing failed, using fallback: {e}")

        from cloudguard_anomaly.agents.remediation_planner_agent import RemediationPlannerAgent

        fallback_agent = RemediationPlannerAgent()
        return fallback_agent.process(input_data)

    def _llm_process(self, finding: Finding) -> Dict[str, Any]:
        """Use LLM for remediation planning."""
        prompt = f"""
Create a detailed remediation plan for this security finding:

**Finding:** {finding.title}
**Severity:** {finding.severity.value.upper()}
**Resource:** {finding.resource.name} ({finding.resource.type.value})
**Provider:** {finding.resource.provider.value}

**Description:** {finding.description}

**Resource Configuration:**
{json.dumps(finding.resource.properties, indent=2)}

Provide a production-ready remediation plan with:
1. Pre-requisites and checks
2. Step-by-step remediation instructions with CLI commands
3. Validation steps
4. Rollback procedures
5. Potential side effects and risks
6. Estimated time and complexity

Format as JSON with keys: prerequisites, steps (array of objects with 'action' and 'command'),
validation, rollback, side_effects, estimated_time, complexity
"""

        system = "You are a senior DevOps/SRE engineer specializing in cloud security remediation. Provide production-ready, tested procedures."

        response = self.llm.generate(prompt, system, max_tokens=3000)

        try:
            result = json.loads(response)
            return result
        except json.JSONDecodeError:
            return {"remediation_plan": response}

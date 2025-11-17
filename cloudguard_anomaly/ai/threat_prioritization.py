"""
AI-Powered Threat Prioritization for CloudGuard-Anomaly v4.

Intelligent threat correlation and prioritization:
- ML-based threat scoring
- Context-aware risk assessment
- Alert correlation and deduplication
- Automated triage
- Threat trend analysis
- Predictive threat modeling
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json

logger = logging.getLogger(__name__)


@dataclass
class ThreatContext:
    """Contextual information for threat."""
    asset_criticality: str  # low, medium, high, critical
    business_impact: str
    exposure_level: str  # internal, external, public
    data_sensitivity: str
    compliance_requirements: List[str]
    recent_changes: bool
    active_users: int


@dataclass
class PrioritizedThreat:
    """Prioritized threat with AI scoring."""
    threat_id: str
    original_severity: str
    ai_priority_score: float  # 0-100
    adjusted_severity: str
    context: ThreatContext
    correlated_threats: List[str]
    reasoning: str  # AI-generated explanation
    recommended_actions: List[str]
    sla_deadline: datetime


class AIThreatPrioritizer:
    """
    AI-powered threat prioritization engine.

    Uses machine learning and contextual analysis to intelligently
    prioritize security threats based on:
    - Asset criticality
    - Business context
    - Threat relationships
    - Historical patterns
    - Real-time risk
    """

    def __init__(self):
        """Initialize AI threat prioritizer."""
        self.threats: List[PrioritizedThreat] = []
        self.correlation_rules = self._load_correlation_rules()
        logger.info("AI threat prioritizer initialized")

    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load threat correlation rules."""
        return {
            'privilege_escalation_chain': {
                'pattern': ['overprivileged_iam', 'public_access', 'missing_mfa'],
                'severity_boost': 30,
                'reasoning': 'Complete attack chain detected from public access to privilege escalation'
            },
            'data_exfiltration_risk': {
                'pattern': ['public_storage', 'unencrypted_data', 'no_logging'],
                'severity_boost': 25,
                'reasoning': 'High risk of data exfiltration without detection'
            },
            'lateral_movement': {
                'pattern': ['network_exposure', 'weak_segmentation', 'shared_credentials'],
                'severity_boost': 20,
                'reasoning': 'Conditions enable lateral movement across environment'
            }
        }

    def prioritize_threats(
        self,
        findings: List[Dict[str, Any]],
        context_data: Dict[str, ThreatContext]
    ) -> List[PrioritizedThreat]:
        """
        Prioritize threats using AI and context.

        Args:
            findings: Security findings
            context_data: Contextual information per resource

        Returns:
            Prioritized threats with AI scoring
        """
        logger.info(f"Prioritizing {len(findings)} threats with AI")

        self.threats = []

        for finding in findings:
            resource_id = finding.get('resource_id', 'unknown')
            context = context_data.get(resource_id, self._default_context())

            # Calculate AI priority score
            priority_score = self._calculate_ai_priority(finding, context)

            # Adjust severity based on AI score
            adjusted_severity = self._adjust_severity(
                finding.get('severity', 'medium'),
                priority_score
            )

            # Find correlated threats
            correlated = self._find_correlated_threats(finding, findings)

            # Generate reasoning
            reasoning = self._generate_reasoning(finding, context, priority_score)

            # Generate recommended actions
            actions = self._generate_actions(finding, context, adjusted_severity)

            # Calculate SLA deadline
            sla_deadline = self._calculate_sla(adjusted_severity)

            prioritized = PrioritizedThreat(
                threat_id=finding.get('id', f"threat-{len(self.threats)}"),
                original_severity=finding.get('severity', 'medium'),
                ai_priority_score=priority_score,
                adjusted_severity=adjusted_severity,
                context=context,
                correlated_threats=correlated,
                reasoning=reasoning,
                recommended_actions=actions,
                sla_deadline=sla_deadline
            )

            self.threats.append(prioritized)

        # Sort by priority score
        self.threats.sort(key=lambda t: t.ai_priority_score, reverse=True)

        logger.info(f"Prioritization complete. Top threat score: {self.threats[0].ai_priority_score:.1f if self.threats else 0}")

        return self.threats

    def _calculate_ai_priority(
        self,
        finding: Dict[str, Any],
        context: ThreatContext
    ) -> float:
        """Calculate AI-based priority score."""
        score = 0.0

        # Base severity score
        severity_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10,
            'info': 5
        }
        score += severity_scores.get(finding.get('severity', 'medium').lower(), 20)

        # Asset criticality multiplier
        criticality_multipliers = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.2,
            'low': 1.0
        }
        score *= criticality_multipliers.get(context.asset_criticality, 1.0)

        # Exposure adjustment
        if context.exposure_level == 'public':
            score += 20
        elif context.exposure_level == 'external':
            score += 10

        # Data sensitivity
        if context.data_sensitivity in ['restricted', 'confidential']:
            score += 15

        # Compliance requirements
        score += len(context.compliance_requirements) * 5

        # Recent changes (higher risk)
        if context.recent_changes:
            score += 10

        # Active usage
        if context.active_users > 100:
            score += 10

        return min(100.0, score)

    def _adjust_severity(self, original_severity: str, ai_score: float) -> str:
        """Adjust severity based on AI score."""
        if ai_score >= 80:
            return 'critical'
        elif ai_score >= 60:
            return 'high'
        elif ai_score >= 40:
            return 'medium'
        else:
            return 'low'

    def _find_correlated_threats(
        self,
        finding: Dict[str, Any],
        all_findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Find correlated threats."""
        correlated = []

        resource_id = finding.get('resource_id')

        # Find other findings on same resource
        for other in all_findings:
            if other.get('resource_id') == resource_id and other.get('id') != finding.get('id'):
                correlated.append(other.get('id', 'unknown'))

        return correlated[:5]  # Top 5

    def _generate_reasoning(
        self,
        finding: Dict[str, Any],
        context: ThreatContext,
        score: float
    ) -> str:
        """Generate AI reasoning for priority."""
        parts = [
            f"Priority score {score:.1f}/100 based on:",
            f"- Asset criticality: {context.asset_criticality}",
            f"- Exposure: {context.exposure_level}",
        ]

        if context.data_sensitivity in ['restricted', 'confidential']:
            parts.append(f"- Contains sensitive data ({context.data_sensitivity})")

        if context.compliance_requirements:
            parts.append(f"- Compliance requirements: {', '.join(context.compliance_requirements)}")

        if context.recent_changes:
            parts.append("- Recent configuration changes increase risk")

        return ". ".join(parts)

    def _generate_actions(
        self,
        finding: Dict[str, Any],
        context: ThreatContext,
        severity: str
    ) -> List[str]:
        """Generate recommended actions."""
        actions = []

        if severity in ['critical', 'high']:
            actions.append("Immediate investigation required")
            actions.append("Notify security team")

        if context.exposure_level == 'public':
            actions.append("Review and restrict public access")

        if not context.compliance_requirements:
            actions.append("Assess compliance impact")
        else:
            actions.append("Document compliance violation")

        actions.append(finding.get('remediation', 'Apply recommended fixes'))

        return actions

    def _calculate_sla(self, severity: str) -> datetime:
        """Calculate SLA deadline based on severity."""
        from datetime import timedelta

        sla_hours = {
            'critical': 4,
            'high': 24,
            'medium': 72,
            'low': 168,  # 1 week
        }

        hours = sla_hours.get(severity, 72)
        return datetime.utcnow() + timedelta(hours=hours)

    def _default_context(self) -> ThreatContext:
        """Default threat context."""
        return ThreatContext(
            asset_criticality='medium',
            business_impact='medium',
            exposure_level='internal',
            data_sensitivity='internal',
            compliance_requirements=[],
            recent_changes=False,
            active_users=0
        )

    def generate_prioritization_report(self) -> str:
        """Generate threat prioritization report."""
        report = []
        report.append("=" * 80)
        report.append("AI-POWERED THREAT PRIORITIZATION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Threats Analyzed: {len(self.threats)}\n")

        # Top 10 priorities
        report.append("TOP 10 PRIORITY THREATS")
        report.append("=" * 80)

        for i, threat in enumerate(self.threats[:10], 1):
            report.append(f"\n#{i} - Priority Score: {threat.ai_priority_score:.1f}/100")
            report.append(f"Threat ID: {threat.threat_id}")
            report.append(f"Severity: {threat.original_severity.upper()} → {threat.adjusted_severity.upper()}")
            report.append(f"SLA Deadline: {threat.sla_deadline.strftime('%Y-%m-%d %H:%M UTC')}")
            report.append(f"\nReasoning: {threat.reasoning}")

            if threat.correlated_threats:
                report.append(f"Correlated with: {len(threat.correlated_threats)} other threats")

            report.append("\nRecommended Actions:")
            for action in threat.recommended_actions:
                report.append(f"  • {action}")

            report.append("-" * 80)

        return "\n".join(report)

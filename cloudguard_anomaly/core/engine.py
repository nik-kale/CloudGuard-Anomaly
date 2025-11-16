"""
Main analysis engine for CloudGuard-Anomaly.

This module orchestrates the entire security analysis pipeline including
policy evaluation, anomaly detection, and agentic explanation.
"""

import logging
from datetime import datetime
from typing import List, Optional

from cloudguard_anomaly.core.evaluator import PolicyEvaluator
from cloudguard_anomaly.core.loader import ConfigLoader
from cloudguard_anomaly.core.models import (
    Anomaly,
    Environment,
    Finding,
    Policy,
    ScanResult,
    Severity,
)

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Main orchestration engine for cloud security analysis.

    Coordinates policy evaluation, anomaly detection, and agentic explanation
    to produce comprehensive security findings and reports.
    """

    def __init__(
        self,
        policies: Optional[List[Policy]] = None,
        enable_drift_detection: bool = True,
        enable_agents: bool = True,
    ):
        """
        Initialize the analysis engine.

        Args:
            policies: List of security policies to evaluate
            enable_drift_detection: Whether to enable drift detection
            enable_agents: Whether to enable agentic explanations
        """
        self.policies = policies or []
        self.enable_drift_detection = enable_drift_detection
        self.enable_agents = enable_agents

        self.policy_evaluator = PolicyEvaluator(self.policies) if self.policies else None

        logger.info(
            f"Initialized AnalysisEngine with {len(self.policies)} policies, "
            f"drift_detection={enable_drift_detection}, agents={enable_agents}"
        )

    def scan_environment(self, environment: Environment) -> ScanResult:
        """
        Perform a comprehensive security scan of an environment.

        Args:
            environment: Environment to scan

        Returns:
            Complete scan results with findings, anomalies, and narratives
        """
        logger.info(f"Starting scan of environment: {environment.name}")

        findings: List[Finding] = []
        anomalies: List[Anomaly] = []

        # Step 1: Run policy evaluation
        if self.policy_evaluator:
            logger.info("Running policy evaluation...")
            policy_findings = self.policy_evaluator.evaluate_resources(environment.resources)
            findings.extend(policy_findings)
            logger.info(f"Policy evaluation found {len(policy_findings)} violations")

        # Step 2: Run misconfig detection
        logger.info("Running misconfiguration detection...")
        from cloudguard_anomaly.detectors.misconfig_detector import MisconfigDetector

        misconfig_detector = MisconfigDetector()
        misconfig_findings = misconfig_detector.detect(environment.resources)
        findings.extend(misconfig_findings)
        logger.info(f"Misconfiguration detection found {len(misconfig_findings)} issues")

        # Step 3: Run drift detection if baseline is available
        if self.enable_drift_detection and environment.baseline_resources:
            logger.info("Running drift detection...")
            from cloudguard_anomaly.detectors.drift_detector import DriftDetector

            drift_detector = DriftDetector()
            drift_anomalies = drift_detector.detect_drift(
                environment.baseline_resources, environment.resources
            )
            anomalies.extend(drift_anomalies)
            logger.info(f"Drift detection found {len(drift_anomalies)} anomalies")

        # Step 4: Run identity risk detection
        logger.info("Running identity risk detection...")
        from cloudguard_anomaly.detectors.identity_detector import IdentityDetector

        identity_detector = IdentityDetector()
        identity_findings = identity_detector.detect(environment.resources)
        findings.extend(identity_findings)
        logger.info(f"Identity detection found {len(identity_findings)} risks")

        # Step 5: Run network exposure detection
        logger.info("Running network exposure detection...")
        from cloudguard_anomaly.detectors.network_detector import NetworkDetector

        network_detector = NetworkDetector()
        network_findings = network_detector.detect(environment.resources)
        findings.extend(network_findings)
        logger.info(f"Network detection found {len(network_findings)} exposures")

        # Step 6: Generate explanations and narratives using agents
        narratives = []
        if self.enable_agents:
            logger.info("Generating agentic explanations...")
            narratives = self._generate_narratives(findings, anomalies, environment)

        # Step 7: Compute summary statistics
        summary = self._compute_summary(findings, anomalies)

        result = ScanResult(
            environment=environment,
            findings=findings,
            anomalies=anomalies,
            summary=summary,
            narratives=narratives,
            timestamp=datetime.utcnow(),
        )

        logger.info(
            f"Scan complete: {len(findings)} findings, "
            f"{len(anomalies)} anomalies, {len(narratives)} narratives"
        )

        return result

    def _generate_narratives(
        self, findings: List[Finding], anomalies: List[Anomaly], environment: Environment
    ) -> List[str]:
        """Generate human-readable narratives using agentic explainers."""
        from cloudguard_anomaly.agents.risk_summarizer_agent import RiskSummarizerAgent
        from cloudguard_anomaly.explainers.narrative_builder import NarrativeBuilder

        # Try to use LLM-enhanced agents if available
        try:
            from cloudguard_anomaly.agents.llm.providers import get_llm_provider
            from cloudguard_anomaly.agents.llm.enhanced_agents import EnhancedRiskSummarizerAgent

            llm_provider = get_llm_provider()
            if llm_provider:
                logger.info("Using LLM-enhanced agents for narratives")
                summarizer = EnhancedRiskSummarizerAgent(llm_provider)
            else:
                summarizer = RiskSummarizerAgent()
        except Exception as e:
            logger.warning(f"Could not initialize LLM agents, using deterministic: {e}")
            summarizer = RiskSummarizerAgent()

        narratives = []

        # Generate overall risk summary
        risk_summary = summarizer.summarize(findings, anomalies, environment)
        narratives.append(risk_summary)

        # Build detailed narratives for high/critical findings
        builder = NarrativeBuilder()
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in findings if f.severity == Severity.HIGH]

        for finding in critical_findings[:5]:  # Top 5 critical
            narrative = builder.build_finding_narrative(finding)
            narratives.append(narrative)

        for finding in high_findings[:3]:  # Top 3 high
            narrative = builder.build_finding_narrative(finding)
            narratives.append(narrative)

        # Build narratives for significant anomalies
        for anomaly in anomalies[:5]:  # Top 5 anomalies
            narrative = builder.build_anomaly_narrative(anomaly)
            narratives.append(narrative)

        return narratives

    def _compute_summary(self, findings: List[Finding], anomalies: List[Anomaly]) -> dict:
        """Compute summary statistics for the scan results."""
        severity_counts = {
            "critical": len([f for f in findings if f.severity == Severity.CRITICAL]),
            "high": len([f for f in findings if f.severity == Severity.HIGH]),
            "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
            "low": len([f for f in findings if f.severity == Severity.LOW]),
            "info": len([f for f in findings if f.severity == Severity.INFO]),
        }

        finding_types = {}
        for finding in findings:
            finding_type = finding.type.value
            finding_types[finding_type] = finding_types.get(finding_type, 0) + 1

        return {
            "total_findings": len(findings),
            "total_anomalies": len(anomalies),
            "severity_counts": severity_counts,
            "finding_types": finding_types,
            "risk_score": self._calculate_risk_score(severity_counts),
        }

    def _calculate_risk_score(self, severity_counts: dict) -> int:
        """
        Calculate an overall risk score based on findings.

        Score: 0-100, weighted by severity
        """
        weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1,
            "info": 0,
        }

        score = sum(severity_counts.get(sev, 0) * weight for sev, weight in weights.items())

        # Normalize to 0-100 range
        return min(100, score)

    def add_policies(self, policies: List[Policy]) -> None:
        """Add additional policies to the engine."""
        self.policies.extend(policies)
        self.policy_evaluator = PolicyEvaluator(self.policies)
        logger.info(f"Added {len(policies)} policies, total: {len(self.policies)}")

    def load_policies_from_file(self, file_path: str) -> None:
        """Load policies from a YAML or JSON file."""
        from pathlib import Path

        from cloudguard_anomaly.policies.policy_engine import PolicyEngine

        policy_engine = PolicyEngine()
        policies = policy_engine.load_policies(Path(file_path))
        self.add_policies(policies)

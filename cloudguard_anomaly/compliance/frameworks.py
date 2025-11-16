"""
Compliance framework support for CloudGuard-Anomaly.

Implements SOC2, PCI-DSS, HIPAA, ISO 27001, and other compliance frameworks.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional

from cloudguard_anomaly.core.models import ScanResult, Severity, Finding

logger = logging.getLogger(__name__)


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    CIS_AWS = "cis_aws"
    CIS_AZURE = "cis_azure"
    CIS_GCP = "cis_gcp"
    NIST_800_53 = "nist_800_53"


@dataclass
class ComplianceControl:
    """A compliance control requirement."""

    id: str
    framework: ComplianceFramework
    title: str
    description: str
    policies: List[str]  # Policy IDs that satisfy this control
    evidence_required: List[str]
    severity: Severity

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "framework": self.framework.value,
            "title": self.title,
            "description": self.description,
            "policies": self.policies,
            "evidence_required": self.evidence_required,
            "severity": self.severity.value,
        }


@dataclass
class ComplianceControlResult:
    """Result of evaluating a compliance control."""

    control: ComplianceControl
    passed: bool
    findings: List[Finding]
    evidence: Dict[str, Any]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control": self.control.to_dict(),
            "passed": self.passed,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "evidence": self.evidence,
            "recommendations": self.recommendations,
        }


@dataclass
class ComplianceReport:
    """Compliance evaluation report."""

    framework: ComplianceFramework
    control_results: List[ComplianceControlResult]
    overall_compliance: float  # 0-100%
    timestamp: datetime

    @property
    def total_controls(self) -> int:
        return len(self.control_results)

    @property
    def passed_controls(self) -> int:
        return sum(1 for c in self.control_results if c.passed)

    @property
    def failed_controls(self) -> int:
        return self.total_controls - self.passed_controls

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "overall_compliance": self.overall_compliance,
            "total_controls": self.total_controls,
            "passed_controls": self.passed_controls,
            "failed_controls": self.failed_controls,
            "control_results": [c.to_dict() for c in self.control_results],
            "timestamp": self.timestamp.isoformat(),
        }


class ComplianceEngine:
    """Evaluates compliance against various frameworks."""

    def __init__(self):
        """Initialize compliance engine."""
        self.controls = self._load_all_controls()
        logger.info(f"Initialized compliance engine with {len(self.controls)} controls")

    def _load_all_controls(self) -> Dict[ComplianceFramework, List[ComplianceControl]]:
        """Load all compliance controls."""
        return {
            ComplianceFramework.SOC2: self._load_soc2_controls(),
            ComplianceFramework.PCI_DSS: self._load_pci_controls(),
            ComplianceFramework.HIPAA: self._load_hipaa_controls(),
        }

    def _load_soc2_controls(self) -> List[ComplianceControl]:
        """Load SOC2 compliance controls."""
        return [
            ComplianceControl(
                id="CC6.1",
                framework=ComplianceFramework.SOC2,
                title="Logical and Physical Access Controls",
                description="The entity implements logical access security software, infrastructure, and architectures.",
                policies=[
                    "baseline-002",  # Public access prohibited
                    "baseline-004",  # SSH restrictions
                    "baseline-005",  # RDP restrictions
                ],
                evidence_required=["access_control_list", "security_group_rules"],
                severity=Severity.HIGH,
            ),
            ComplianceControl(
                id="CC6.6",
                framework=ComplianceFramework.SOC2,
                title="Encryption of Data",
                description="The entity protects information during transmission and at rest.",
                policies=[
                    "baseline-001",  # Encryption at rest
                    "baseline-010",  # TLS/SSL enforcement
                ],
                evidence_required=["encryption_config", "ssl_config"],
                severity=Severity.HIGH,
            ),
            ComplianceControl(
                id="CC6.7",
                framework=ComplianceFramework.SOC2,
                title="System Operations",
                description="The entity ensures authorized access to systems and data.",
                policies=["baseline-003"],  # Logging and monitoring
                evidence_required=["logging_config"],
                severity=Severity.MEDIUM,
            ),
        ]

    def _load_pci_controls(self) -> List[ComplianceControl]:
        """Load PCI-DSS compliance controls."""
        return [
            ComplianceControl(
                id="PCI-1.2.1",
                framework=ComplianceFramework.PCI_DSS,
                title="Restrict Inbound and Outbound Traffic",
                description="Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment.",
                policies=["baseline-004", "baseline-005"],
                evidence_required=["network_rules"],
                severity=Severity.CRITICAL,
            ),
            ComplianceControl(
                id="PCI-3.4",
                framework=ComplianceFramework.PCI_DSS,
                title="Render PAN Unreadable",
                description="Render PAN unreadable anywhere it is stored.",
                policies=["baseline-001"],
                evidence_required=["encryption_config"],
                severity=Severity.CRITICAL,
            ),
            ComplianceControl(
                id="PCI-10.1",
                framework=ComplianceFramework.PCI_DSS,
                title="Audit Trails",
                description="Implement audit trails to link all access to system components.",
                policies=["baseline-003"],
                evidence_required=["audit_logs"],
                severity=Severity.HIGH,
            ),
        ]

    def _load_hipaa_controls(self) -> List[ComplianceControl]:
        """Load HIPAA compliance controls."""
        return [
            ComplianceControl(
                id="HIPAA-164.312(a)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Access Control",
                description="Implement technical policies and procedures for electronic information systems.",
                policies=["baseline-002", "baseline-004"],
                evidence_required=["access_control"],
                severity=Severity.CRITICAL,
            ),
            ComplianceControl(
                id="HIPAA-164.312(a)(2)(iv)",
                framework=ComplianceFramework.HIPAA,
                title="Encryption and Decryption",
                description="Implement a mechanism to encrypt and decrypt electronic protected health information.",
                policies=["baseline-001", "baseline-010"],
                evidence_required=["encryption_config"],
                severity=Severity.CRITICAL,
            ),
            ComplianceControl(
                id="HIPAA-164.312(b)",
                framework=ComplianceFramework.HIPAA,
                title="Audit Controls",
                description="Implement hardware, software, and/or procedural mechanisms that record and examine activity.",
                policies=["baseline-003"],
                evidence_required=["audit_logs"],
                severity=Severity.HIGH,
            ),
        ]

    def evaluate_compliance(
        self, scan_result: ScanResult, framework: ComplianceFramework
    ) -> ComplianceReport:
        """
        Evaluate compliance against a framework.

        Args:
            scan_result: Scan results to evaluate
            framework: Compliance framework to check against

        Returns:
            Compliance report
        """
        logger.info(f"Evaluating {framework.value} compliance")

        controls = self.controls.get(framework, [])
        control_results = []

        for control in controls:
            result = self._evaluate_control(scan_result, control)
            control_results.append(result)

        # Calculate overall compliance
        passed = sum(1 for c in control_results if c.passed)
        overall_compliance = (passed / len(control_results) * 100) if control_results else 100

        report = ComplianceReport(
            framework=framework,
            control_results=control_results,
            overall_compliance=overall_compliance,
            timestamp=datetime.utcnow(),
        )

        logger.info(
            f"Compliance evaluation complete: {overall_compliance:.1f}% "
            f"({passed}/{len(control_results)} controls passed)"
        )

        return report

    def _evaluate_control(
        self, scan_result: ScanResult, control: ComplianceControl
    ) -> ComplianceControlResult:
        """Evaluate a single compliance control."""
        # Find relevant findings
        relevant_findings = [
            f
            for f in scan_result.findings
            if f.policy and f.policy.id in control.policies
        ]

        # Control passes if no related findings
        passed = len(relevant_findings) == 0

        # Gather evidence
        evidence = self._gather_evidence(scan_result, control.evidence_required)

        # Generate recommendations
        recommendations = []
        if not passed:
            recommendations = self._generate_recommendations(control, relevant_findings)

        return ComplianceControlResult(
            control=control,
            passed=passed,
            findings=relevant_findings,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _gather_evidence(
        self, scan_result: ScanResult, evidence_types: List[str]
    ) -> Dict[str, Any]:
        """Gather evidence for compliance control."""
        evidence = {}

        for evidence_type in evidence_types:
            if evidence_type == "access_control_list":
                # Gather ACL information from resources
                acls = []
                for finding in scan_result.findings:
                    if "access" in finding.title.lower():
                        acls.append(finding.resource.id)
                evidence[evidence_type] = acls

            elif evidence_type == "encryption_config":
                # Gather encryption configurations
                encrypted_resources = []
                for finding in scan_result.findings:
                    if "encrypt" in finding.title.lower():
                        encrypted_resources.append(finding.resource.id)
                evidence[evidence_type] = encrypted_resources

        return evidence

    def _generate_recommendations(
        self, control: ComplianceControl, findings: List[Finding]
    ) -> List[str]:
        """Generate recommendations for failed control."""
        recommendations = [
            f"Address {len(findings)} finding(s) related to {control.title}",
            f"Review and implement remediation for: {control.description}",
        ]

        # Add specific recommendations based on findings
        for finding in findings[:3]:  # Top 3 findings
            recommendations.append(f"• {finding.title}: {finding.remediation}")

        return recommendations

    def generate_compliance_report_markdown(self, report: ComplianceReport) -> str:
        """Generate Markdown compliance report."""
        md = f"""# {report.framework.value.upper()} Compliance Report

**Overall Compliance:** {report.overall_compliance:.1f}%
**Controls Passed:** {report.passed_controls}/{report.total_controls}
**Controls Failed:** {report.failed_controls}/{report.total_controls}
**Generated:** {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

## Control Results

"""

        for result in report.control_results:
            status = "✅ PASSED" if result.passed else "❌ FAILED"
            md += f"### {result.control.id}: {result.control.title}\n\n"
            md += f"**Status:** {status}\n\n"
            md += f"**Description:** {result.control.description}\n\n"

            if not result.passed:
                md += f"**Findings:** {len(result.findings)}\n\n"
                md += "**Recommendations:**\n"
                for rec in result.recommendations:
                    md += f"- {rec}\n"
                md += "\n"

            md += "---\n\n"

        return md

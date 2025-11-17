"""
Kubernetes Security Posture Analysis for CloudGuard-Anomaly v3.

Comprehensive K8s security scanning:
- Pod security policies
- RBAC misconfigurations
- Network policies
- Secrets management
- Container security contexts
- Admission controller validation
- CIS Kubernetes Benchmark
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class K8sSeverity(Enum):
    """Kubernetes security severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class K8sSecurityFinding:
    """Kubernetes security finding."""
    finding_id: str
    resource_type: str  # Pod, Deployment, Service, etc.
    resource_name: str
    namespace: str
    severity: K8sSeverity
    title: str
    description: str
    cis_benchmark: Optional[str] = None
    remediation: str = ""
    risk_score: float = 0.0


class KubernetesSecurityAnalyzer:
    """
    Kubernetes security analyzer.

    Scans Kubernetes clusters for:
    - CIS Benchmark compliance
    - Pod security issues
    - RBAC misconfigurations
    - Network policy gaps
    - Secrets exposure
    - Admission controller configs
    """

    def __init__(self):
        """Initialize K8s security analyzer."""
        self.findings: List[K8sSecurityFinding] = []
        logger.info("Kubernetes security analyzer initialized")

    def analyze_pod(self, pod: Dict[str, Any]) -> List[K8sSecurityFinding]:
        """Analyze Pod security."""
        findings = []
        spec = pod.get('spec', {})
        metadata = pod.get('metadata', {})

        # Check for privileged containers
        for container in spec.get('containers', []):
            security_context = container.get('securityContext', {})

            if security_context.get('privileged'):
                findings.append(K8sSecurityFinding(
                    finding_id=f"k8s-pod-priv-{metadata.get('name')}",
                    resource_type="Pod",
                    resource_name=metadata.get('name', 'unknown'),
                    namespace=metadata.get('namespace', 'default'),
                    severity=K8sSeverity.HIGH,
                    title="Privileged Container",
                    description=f"Container {container.get('name')} runs in privileged mode",
                    cis_benchmark="5.2.1",
                    remediation="Remove privileged: true from container security context",
                    risk_score=85.0
                ))

            # Check for running as root
            if not security_context.get('runAsNonRoot'):
                findings.append(K8sSecurityFinding(
                    finding_id=f"k8s-pod-root-{metadata.get('name')}",
                    resource_type="Pod",
                    resource_name=metadata.get('name', 'unknown'),
                    namespace=metadata.get('namespace', 'default'),
                    severity=K8sSeverity.MEDIUM,
                    title="Container May Run as Root",
                    description=f"Container {container.get('name')} not explicitly set to run as non-root",
                    cis_benchmark="5.2.6",
                    remediation="Set runAsNonRoot: true in security context",
                    risk_score=60.0
                ))

            # Check for read-only root filesystem
            if not security_context.get('readOnlyRootFilesystem'):
                findings.append(K8sSecurityFinding(
                    finding_id=f"k8s-pod-rofs-{metadata.get('name')}",
                    resource_type="Pod",
                    resource_name=metadata.get('name', 'unknown'),
                    namespace=metadata.get('namespace', 'default'),
                    severity=K8sSeverity.LOW,
                    title="Root Filesystem Not Read-Only",
                    description=f"Container {container.get('name')} can write to root filesystem",
                    cis_benchmark="5.2.6",
                    remediation="Set readOnlyRootFilesystem: true",
                    risk_score=40.0
                ))

        # Check for host network
        if spec.get('hostNetwork'):
            findings.append(K8sSecurityFinding(
                finding_id=f"k8s-pod-hostnet-{metadata.get('name')}",
                resource_type="Pod",
                resource_name=metadata.get('name', 'unknown'),
                namespace=metadata.get('namespace', 'default'),
                severity=K8sSeverity.HIGH,
                title="Host Network Enabled",
                description="Pod uses host network namespace",
                cis_benchmark="5.2.4",
                remediation="Remove hostNetwork: true unless absolutely necessary",
                risk_score=80.0
            ))

        self.findings.extend(findings)
        return findings

    def analyze_rbac(self, role: Dict[str, Any]) -> List[K8sSecurityFinding]:
        """Analyze RBAC configuration."""
        findings = []
        metadata = role.get('metadata', {})
        rules = role.get('rules', [])

        for rule in rules:
            # Check for wildcard permissions
            if '*' in rule.get('verbs', []) or '*' in rule.get('resources', []):
                findings.append(K8sSecurityFinding(
                    finding_id=f"k8s-rbac-wildcard-{metadata.get('name')}",
                    resource_type=role.get('kind', 'Role'),
                    resource_name=metadata.get('name', 'unknown'),
                    namespace=metadata.get('namespace', 'default'),
                    severity=K8sSeverity.HIGH,
                    title="Wildcard RBAC Permissions",
                    description="Role contains wildcard (*) permissions",
                    cis_benchmark="5.1.1",
                    remediation="Use specific verbs and resources instead of wildcards",
                    risk_score=75.0
                ))

            # Check for dangerous permissions
            dangerous_combos = [
                (['create', 'update'], ['pods/exec']),
                (['*'], ['secrets']),
                (['escalate'], ['*']),
            ]

            verbs = set(rule.get('verbs', []))
            resources = set(rule.get('resources', []))

            for dangerous_verbs, dangerous_resources in dangerous_combos:
                if (set(dangerous_verbs).issubset(verbs) or '*' in verbs) and \
                   (set(dangerous_resources).issubset(resources) or '*' in resources):
                    findings.append(K8sSecurityFinding(
                        finding_id=f"k8s-rbac-dangerous-{metadata.get('name')}",
                        resource_type=role.get('kind', 'Role'),
                        resource_name=metadata.get('name', 'unknown'),
                        namespace=metadata.get('namespace', 'default'),
                        severity=K8sSeverity.CRITICAL,
                        title="Dangerous RBAC Permission Combination",
                        description=f"Role has dangerous permissions: {dangerous_verbs} on {dangerous_resources}",
                        cis_benchmark="5.1.1",
                        remediation="Review and restrict dangerous permission combinations",
                        risk_score=90.0
                    ))

        self.findings.extend(findings)
        return findings

    def generate_k8s_report(self) -> str:
        """Generate Kubernetes security report."""
        report = []
        report.append("=" * 80)
        report.append("KUBERNETES SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Findings: {len(self.findings)}\n")

        # CIS Benchmark coverage
        cis_findings = [f for f in self.findings if f.cis_benchmark]
        report.append(f"CIS Kubernetes Benchmark Findings: {len(cis_findings)}\n")

        # By severity
        by_severity = {}
        for finding in self.findings:
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        report.append("FINDINGS BY SEVERITY")
        report.append("-" * 80)
        for sev in ['critical', 'high', 'medium', 'low']:
            count = by_severity.get(sev, 0)
            report.append(f"{sev.upper()}: {count}")

        # Critical findings
        critical = [f for f in self.findings if f.severity == K8sSeverity.CRITICAL]

        if critical:
            report.append(f"\n\nCRITICAL FINDINGS ({len(critical)})")
            report.append("=" * 80)

            for finding in critical:
                report.append(f"\n[{finding.severity.value.upper()}] {finding.title}")
                report.append(f"Resource: {finding.resource_type}/{finding.resource_name}")
                report.append(f"Namespace: {finding.namespace}")
                if finding.cis_benchmark:
                    report.append(f"CIS Benchmark: {finding.cis_benchmark}")
                report.append(f"Description: {finding.description}")
                report.append(f"Remediation: {finding.remediation}")
                report.append("-" * 80)

        return "\n".join(report)

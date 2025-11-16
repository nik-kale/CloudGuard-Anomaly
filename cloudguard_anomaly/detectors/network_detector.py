"""
Network exposure detector for CloudGuard-Anomaly.

Detects network security issues such as overly permissive security groups,
public exposure, and insecure network configurations.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Set

from cloudguard_anomaly.core.models import (
    Finding,
    FindingType,
    Resource,
    ResourceType,
    Severity,
)

logger = logging.getLogger(__name__)


class NetworkDetector:
    """Detects network exposure and security issues."""

    def __init__(self):
        """Initialize the network detector."""
        # Common risky ports
        self.critical_ports = {22, 3389, 23, 21}  # SSH, RDP, Telnet, FTP
        self.high_risk_ports = {1433, 3306, 5432, 27017, 6379}  # Databases
        self.medium_risk_ports = {80, 8080, 443, 8443}  # Web services

    def detect(self, resources: List[Resource]) -> List[Finding]:
        """
        Detect network exposure issues.

        Args:
            resources: List of resources to analyze

        Returns:
            List of network-related findings
        """
        findings = []

        # Check security groups
        security_groups = [r for r in resources if r.type == ResourceType.SECURITY_GROUP]
        for sg in security_groups:
            findings.extend(self._check_security_group(sg))

        # Check network resources
        network_resources = [r for r in resources if r.type == ResourceType.NETWORK]
        for net in network_resources:
            findings.extend(self._check_network_resource(net))

        # Check for resources with public IPs
        for resource in resources:
            findings.extend(self._check_public_exposure(resource))

        logger.info(f"Network detector found {len(findings)} issues")
        return findings

    def _check_security_group(self, sg: Resource) -> List[Finding]:
        """Check security group for network issues."""
        findings = []
        props = sg.properties

        ingress_rules = props.get("ingress", [])

        for rule in ingress_rules:
            # Check for unrestricted access
            cidr_blocks = rule.get("cidr_blocks", [])
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)
            protocol = rule.get("protocol", "tcp")

            if "0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks:
                # Determine severity based on ports
                severity = self._assess_port_risk(from_port, to_port)

                finding_id = f"network-{uuid.uuid4()}"
                finding = Finding(
                    id=finding_id,
                    type=FindingType.NETWORK_EXPOSURE,
                    severity=severity,
                    title=f"Security Group Allows Unrestricted Access on Ports {from_port}-{to_port}",
                    description=f"Security group {sg.name} allows {protocol} traffic from 0.0.0.0/0 "
                    f"on ports {from_port}-{to_port}",
                    resource=sg,
                    policy=None,
                    evidence={
                        "resource_id": sg.id,
                        "rule": rule,
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": protocol,
                    },
                    remediation=self._get_port_remediation(from_port, to_port),
                    timestamp=datetime.utcnow(),
                )
                findings.append(finding)

            # Check for overly broad CIDR ranges
            for cidr in cidr_blocks:
                if self._is_overly_broad_cidr(cidr):
                    finding_id = f"network-{uuid.uuid4()}"
                    finding = Finding(
                        id=finding_id,
                        type=FindingType.NETWORK_EXPOSURE,
                        severity=Severity.MEDIUM,
                        title=f"Security Group with Overly Broad CIDR Range",
                        description=f"Security group {sg.name} allows traffic from broad CIDR range {cidr}",
                        resource=sg,
                        policy=None,
                        evidence={
                            "resource_id": sg.id,
                            "cidr": cidr,
                            "rule": rule,
                        },
                        remediation="Restrict CIDR ranges to specific IP addresses or smaller subnets.",
                        timestamp=datetime.utcnow(),
                    )
                    findings.append(finding)

        return findings

    def _check_network_resource(self, net: Resource) -> List[Finding]:
        """Check network resource for security issues."""
        findings = []
        props = net.properties

        # Check for missing flow logs
        if not props.get("flow_logs"):
            finding_id = f"network-{uuid.uuid4()}"
            finding = Finding(
                id=finding_id,
                type=FindingType.NETWORK_EXPOSURE,
                severity=Severity.MEDIUM,
                title="VPC Flow Logs Not Enabled",
                description=f"Network {net.name} does not have flow logs enabled for traffic monitoring",
                resource=net,
                policy=None,
                evidence={
                    "resource_id": net.id,
                },
                remediation="Enable VPC flow logs to monitor network traffic and detect anomalies.",
                timestamp=datetime.utcnow(),
            )
            findings.append(finding)

        return findings

    def _check_public_exposure(self, resource: Resource) -> List[Finding]:
        """Check if resource has public exposure."""
        findings = []
        props = resource.properties

        # Check for public IP addresses
        public_indicators = [
            props.get("public_ip"),
            props.get("public_ip_address"),
            props.get("associate_public_ip_address"),
        ]

        has_public_ip = any(indicator for indicator in public_indicators)

        # Only flag certain resource types
        sensitive_types = [
            ResourceType.DATABASE,
            ResourceType.COMPUTE,
            ResourceType.STORAGE,
        ]

        if has_public_ip and resource.type in sensitive_types:
            severity = Severity.HIGH if resource.type == ResourceType.DATABASE else Severity.MEDIUM

            finding_id = f"network-{uuid.uuid4()}"
            finding = Finding(
                id=finding_id,
                type=FindingType.NETWORK_EXPOSURE,
                severity=severity,
                title=f"{resource.type.value.title()} Resource with Public IP",
                description=f"{resource.type.value.title()} {resource.name} has a public IP address",
                resource=resource,
                policy=None,
                evidence={
                    "resource_id": resource.id,
                    "public_ip": props.get("public_ip") or props.get("public_ip_address"),
                },
                remediation="Remove public IP and access resource through private networking, "
                "VPN, or load balancer.",
                timestamp=datetime.utcnow(),
            )
            findings.append(finding)

        return findings

    def _assess_port_risk(self, from_port: int, to_port: int) -> Severity:
        """Assess risk level based on exposed ports."""
        exposed_ports = set(range(from_port, to_port + 1))

        # Critical if exposing SSH, RDP, etc.
        if exposed_ports & self.critical_ports:
            return Severity.CRITICAL

        # High if exposing database ports
        if exposed_ports & self.high_risk_ports:
            return Severity.HIGH

        # Medium for web ports
        if exposed_ports & self.medium_risk_ports:
            return Severity.MEDIUM

        # Low for other ports
        return Severity.LOW

    def _get_port_remediation(self, from_port: int, to_port: int) -> str:
        """Get remediation advice based on exposed ports."""
        exposed_ports = set(range(from_port, to_port + 1))

        if 22 in exposed_ports:
            return (
                "Remove unrestricted SSH access. Use bastion host, VPN, or "
                "AWS Systems Manager Session Manager for remote access."
            )
        elif 3389 in exposed_ports:
            return (
                "Remove unrestricted RDP access. Use bastion host, VPN, or "
                "Azure Bastion for remote desktop access."
            )
        elif exposed_ports & self.high_risk_ports:
            return (
                "Remove public access to database ports. Databases should only be "
                "accessible from application tier via private networking."
            )
        else:
            return (
                "Restrict access to specific IP ranges or use a load balancer "
                "for controlled public access."
            )

    def _is_overly_broad_cidr(self, cidr: str) -> bool:
        """Check if CIDR range is overly broad."""
        if cidr in ["0.0.0.0/0", "::/0"]:
            return False  # Already caught by other check

        # Extract prefix length
        try:
            if "/" in cidr:
                prefix = int(cidr.split("/")[1])
                # Flag if less than /16 for IPv4 or /64 for IPv6
                if ":" in cidr:
                    return prefix < 64
                else:
                    return prefix < 16
        except (ValueError, IndexError):
            pass

        return False

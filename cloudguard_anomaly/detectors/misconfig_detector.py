"""
Misconfiguration detector for CloudGuard-Anomaly.

Detects common cloud security misconfigurations using pattern matching
and heuristic analysis.
"""

import logging
import uuid
from datetime import datetime
from typing import List

from cloudguard_anomaly.core.models import (
    Finding,
    FindingType,
    Resource,
    ResourceType,
    Severity,
)

logger = logging.getLogger(__name__)


class MisconfigDetector:
    """Detects security misconfigurations in cloud resources."""

    def __init__(self):
        """Initialize the misconfiguration detector."""
        self.detection_rules = self._build_detection_rules()

    def detect(self, resources: List[Resource]) -> List[Finding]:
        """
        Detect misconfigurations across resources.

        Args:
            resources: List of resources to analyze

        Returns:
            List of misconfiguration findings
        """
        findings = []

        for resource in resources:
            resource_findings = self._detect_resource_misconfigs(resource)
            findings.extend(resource_findings)

        logger.info(f"Misconfiguration detector found {len(findings)} issues")
        return findings

    def _detect_resource_misconfigs(self, resource: Resource) -> List[Finding]:
        """Detect misconfigurations for a single resource."""
        findings = []

        # Get applicable detection rules for this resource type
        rules = self.detection_rules.get(resource.type, [])

        for rule in rules:
            if rule["check_func"](resource):
                finding = self._create_finding(resource, rule)
                findings.append(finding)

        return findings

    def _build_detection_rules(self) -> dict:
        """Build detection rules for different resource types."""
        return {
            ResourceType.STORAGE: [
                {
                    "name": "Public Storage Access",
                    "description": "Storage resource allows public access",
                    "severity": Severity.CRITICAL,
                    "check_func": self._check_public_storage,
                    "remediation": "Remove public access permissions from storage resource",
                },
                {
                    "name": "Storage Encryption Disabled",
                    "description": "Storage resource does not have encryption enabled",
                    "severity": Severity.HIGH,
                    "check_func": self._check_storage_encryption,
                    "remediation": "Enable encryption at rest for storage resource",
                },
                {
                    "name": "Storage Versioning Disabled",
                    "description": "Storage resource does not have versioning enabled",
                    "severity": Severity.MEDIUM,
                    "check_func": self._check_storage_versioning,
                    "remediation": "Enable versioning to protect against accidental deletion",
                },
            ],
            ResourceType.DATABASE: [
                {
                    "name": "Database Public Access",
                    "description": "Database is publicly accessible from the internet",
                    "severity": Severity.CRITICAL,
                    "check_func": self._check_public_database,
                    "remediation": "Disable public accessibility and use private networking",
                },
                {
                    "name": "Database Encryption Disabled",
                    "description": "Database does not have encryption at rest enabled",
                    "severity": Severity.HIGH,
                    "check_func": self._check_database_encryption,
                    "remediation": "Enable encryption at rest for database",
                },
                {
                    "name": "Database Backup Disabled",
                    "description": "Database does not have automated backups configured",
                    "severity": Severity.HIGH,
                    "check_func": self._check_database_backup,
                    "remediation": "Configure automated backups with appropriate retention",
                },
            ],
            ResourceType.SECURITY_GROUP: [
                {
                    "name": "Overly Permissive Security Group",
                    "description": "Security group allows traffic from 0.0.0.0/0",
                    "severity": Severity.HIGH,
                    "check_func": self._check_sg_permissive,
                    "remediation": "Restrict security group rules to specific IP ranges",
                },
                {
                    "name": "Unrestricted SSH Access",
                    "description": "Security group allows SSH (port 22) from anywhere",
                    "severity": Severity.CRITICAL,
                    "check_func": self._check_sg_ssh,
                    "remediation": "Restrict SSH access to specific IP ranges or use bastion",
                },
                {
                    "name": "Unrestricted RDP Access",
                    "description": "Security group allows RDP (port 3389) from anywhere",
                    "severity": Severity.CRITICAL,
                    "check_func": self._check_sg_rdp,
                    "remediation": "Restrict RDP access to specific IP ranges",
                },
            ],
            ResourceType.IAM_ROLE: [
                {
                    "name": "Overly Permissive IAM Role",
                    "description": "IAM role has overly broad permissions",
                    "severity": Severity.HIGH,
                    "check_func": self._check_iam_permissions,
                    "remediation": "Apply principle of least privilege to IAM role",
                },
            ],
            ResourceType.COMPUTE: [
                {
                    "name": "Compute Instance Public IP",
                    "description": "Compute instance has public IP address",
                    "severity": Severity.MEDIUM,
                    "check_func": self._check_compute_public_ip,
                    "remediation": "Remove public IP and use NAT gateway or load balancer",
                },
            ],
        }

    # Storage checks
    def _check_public_storage(self, resource: Resource) -> bool:
        """Check if storage allows public access."""
        props = resource.properties

        # Check various public access indicators
        public_patterns = [
            props.get("acl") in ["public-read", "public-read-write"],
            props.get("public_access_block_configuration", {}).get("block_public_acls") == False,
            props.get("public_access_prevention") != "enforced",
            "AllUsers" in str(props.get("iam_members", [])),
            "allUsers" in str(props.get("iam_members", [])),
        ]

        return any(public_patterns)

    def _check_storage_encryption(self, resource: Resource) -> bool:
        """Check if storage lacks encryption."""
        props = resource.properties

        encryption_patterns = [
            props.get("encryption") is None,
            props.get("server_side_encryption_configuration") is None,
            props.get("encrypted") == False,
        ]

        return any(encryption_patterns)

    def _check_storage_versioning(self, resource: Resource) -> bool:
        """Check if storage lacks versioning."""
        props = resource.properties

        versioning = props.get("versioning", {})
        if isinstance(versioning, dict):
            return versioning.get("enabled") != True

        return True

    # Database checks
    def _check_public_database(self, resource: Resource) -> bool:
        """Check if database is publicly accessible."""
        props = resource.properties

        return props.get("publicly_accessible") == True or props.get("public_ip") == True

    def _check_database_encryption(self, resource: Resource) -> bool:
        """Check if database lacks encryption."""
        props = resource.properties

        encryption_patterns = [
            props.get("encrypted") == False,
            props.get("storage_encrypted") == False,
            props.get("transparent_data_encryption", {}).get("status") != "Enabled",
        ]

        return any(encryption_patterns)

    def _check_database_backup(self, resource: Resource) -> bool:
        """Check if database lacks backups."""
        props = resource.properties

        backup_retention = props.get("backup_retention_period", 0)
        if isinstance(backup_retention, int):
            return backup_retention < 1

        return props.get("backup_configuration", {}).get("enabled") != True

    # Security group checks
    def _check_sg_permissive(self, resource: Resource) -> bool:
        """Check if security group is overly permissive."""
        props = resource.properties

        ingress_rules = props.get("ingress", [])
        for rule in ingress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            if "0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks:
                return True

        return False

    def _check_sg_ssh(self, resource: Resource) -> bool:
        """Check for unrestricted SSH access."""
        props = resource.properties

        ingress_rules = props.get("ingress", [])
        for rule in ingress_rules:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)
            cidr_blocks = rule.get("cidr_blocks", [])

            # Check if port 22 is in range and allows 0.0.0.0/0
            if from_port <= 22 <= to_port and "0.0.0.0/0" in cidr_blocks:
                return True

        return False

    def _check_sg_rdp(self, resource: Resource) -> bool:
        """Check for unrestricted RDP access."""
        props = resource.properties

        ingress_rules = props.get("ingress", [])
        for rule in ingress_rules:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)
            cidr_blocks = rule.get("cidr_blocks", [])

            # Check if port 3389 is in range and allows 0.0.0.0/0
            if from_port <= 3389 <= to_port and "0.0.0.0/0" in cidr_blocks:
                return True

        return False

    # IAM checks
    def _check_iam_permissions(self, resource: Resource) -> bool:
        """Check for overly permissive IAM roles."""
        props = resource.properties

        # Check for wildcard permissions
        policies = props.get("policies", [])
        for policy in policies:
            if isinstance(policy, dict):
                actions = policy.get("actions", [])
                if "*" in actions or "all" in str(actions).lower():
                    return True

        # Check inline policies
        inline_policies = props.get("inline_policies", [])
        for policy in inline_policies:
            if "*" in str(policy):
                return True

        return False

    # Compute checks
    def _check_compute_public_ip(self, resource: Resource) -> bool:
        """Check if compute instance has public IP."""
        props = resource.properties

        return (
            props.get("public_ip") is not None
            or props.get("public_ip_address") is not None
            or props.get("associate_public_ip_address") == True
        )

    def _create_finding(self, resource: Resource, rule: dict) -> Finding:
        """Create a finding from a detection rule."""
        finding_id = f"misconfig-{uuid.uuid4()}"

        return Finding(
            id=finding_id,
            type=FindingType.MISCONFIGURATION,
            severity=rule["severity"],
            title=rule["name"],
            description=rule["description"],
            resource=resource,
            policy=None,
            evidence={
                "resource_id": resource.id,
                "resource_type": resource.type.value,
                "detection_rule": rule["name"],
            },
            remediation=rule["remediation"],
            timestamp=datetime.utcnow(),
        )

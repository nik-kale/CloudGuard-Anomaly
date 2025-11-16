"""
Identity and access management detector for CloudGuard-Anomaly.

Detects IAM-related security issues such as overprivileged roles,
unused credentials, and risky permission patterns.
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


class IdentityDetector:
    """Detects identity and access management security issues."""

    def __init__(self):
        """Initialize the identity detector."""
        pass

    def detect(self, resources: List[Resource]) -> List[Finding]:
        """
        Detect IAM-related security issues.

        Args:
            resources: List of resources to analyze

        Returns:
            List of identity-related findings
        """
        findings = []

        # Filter IAM resources
        iam_resources = [
            r for r in resources if r.type in [ResourceType.IAM_ROLE, ResourceType.IAM_POLICY]
        ]

        for resource in iam_resources:
            findings.extend(self._check_wildcard_permissions(resource))
            findings.extend(self._check_privilege_escalation(resource))
            findings.extend(self._check_cross_account_access(resource))
            findings.extend(self._check_unused_credentials(resource))

        # Also check non-IAM resources for IAM-related issues
        for resource in resources:
            if resource.type not in [ResourceType.IAM_ROLE, ResourceType.IAM_POLICY]:
                findings.extend(self._check_resource_iam_issues(resource))

        logger.info(f"Identity detector found {len(findings)} issues")
        return findings

    def _check_wildcard_permissions(self, resource: Resource) -> List[Finding]:
        """Check for wildcard (*) permissions."""
        findings = []
        props = resource.properties

        has_wildcard = False
        wildcard_evidence = []

        # Check policy documents
        policy_document = props.get("policy_document", {})
        if isinstance(policy_document, dict):
            statements = policy_document.get("Statement", [])
            for statement in statements:
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                for action in actions:
                    if action == "*" or ":*" in action:
                        has_wildcard = True
                        wildcard_evidence.append({"action": action, "statement": statement})

        # Check inline policies
        inline_policies = props.get("inline_policies", [])
        for policy in inline_policies:
            if "*" in str(policy):
                has_wildcard = True
                wildcard_evidence.append({"policy": policy})

        if has_wildcard:
            finding_id = f"identity-{uuid.uuid4()}"
            finding = Finding(
                id=finding_id,
                type=FindingType.IDENTITY_RISK,
                severity=Severity.HIGH,
                title="IAM Role with Wildcard Permissions",
                description=f"IAM role {resource.name} has overly broad wildcard (*) permissions",
                resource=resource,
                policy=None,
                evidence={
                    "resource_id": resource.id,
                    "wildcard_evidence": wildcard_evidence,
                },
                remediation="Replace wildcard permissions with specific, least-privilege actions. "
                "Review and apply principle of least privilege.",
                timestamp=datetime.utcnow(),
            )
            findings.append(finding)

        return findings

    def _check_privilege_escalation(self, resource: Resource) -> List[Finding]:
        """Check for privilege escalation risks."""
        findings = []
        props = resource.properties

        # Dangerous permission combinations that allow privilege escalation
        dangerous_permissions = [
            ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
            ["iam:PassRole", "lambda:CreateFunction"],
            ["iam:PassRole", "ec2:RunInstances"],
            ["iam:PutUserPolicy", "iam:PutGroupPolicy"],
            ["iam:AttachUserPolicy", "iam:AttachGroupPolicy"],
        ]

        policy_document = props.get("policy_document", {})
        if isinstance(policy_document, dict):
            statements = policy_document.get("Statement", [])
            all_actions = []

            for statement in statements:
                if statement.get("Effect") == "Allow":
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    all_actions.extend(actions)

            # Check for dangerous combinations
            for dangerous_combo in dangerous_permissions:
                if all(
                    any(action in all_actions or "*" in all_actions for action in [perm])
                    for perm in dangerous_combo
                ):
                    finding_id = f"identity-{uuid.uuid4()}"
                    finding = Finding(
                        id=finding_id,
                        type=FindingType.IDENTITY_RISK,
                        severity=Severity.CRITICAL,
                        title="IAM Privilege Escalation Risk",
                        description=f"IAM role {resource.name} has permissions that could allow privilege escalation",
                        resource=resource,
                        policy=None,
                        evidence={
                            "resource_id": resource.id,
                            "dangerous_permissions": dangerous_combo,
                            "all_actions": all_actions,
                        },
                        remediation="Remove or restrict permissions that allow privilege escalation. "
                        "Separate administrative functions into different roles.",
                        timestamp=datetime.utcnow(),
                    )
                    findings.append(finding)
                    break

        return findings

    def _check_cross_account_access(self, resource: Resource) -> List[Finding]:
        """Check for cross-account access risks."""
        findings = []
        props = resource.properties

        # Check assume role policy
        assume_role_policy = props.get("assume_role_policy", {})
        if isinstance(assume_role_policy, dict):
            statements = assume_role_policy.get("Statement", [])

            for statement in statements:
                principal = statement.get("Principal", {})

                # Check for wildcard principals
                if principal == "*" or "AWS" in principal and principal["AWS"] == "*":
                    finding_id = f"identity-{uuid.uuid4()}"
                    finding = Finding(
                        id=finding_id,
                        type=FindingType.IDENTITY_RISK,
                        severity=Severity.CRITICAL,
                        title="IAM Role Allows Any AWS Account",
                        description=f"IAM role {resource.name} trust policy allows any AWS account to assume it",
                        resource=resource,
                        policy=None,
                        evidence={
                            "resource_id": resource.id,
                            "trust_policy": assume_role_policy,
                        },
                        remediation="Restrict assume role policy to specific AWS accounts or services. "
                        "Add external ID for additional security.",
                        timestamp=datetime.utcnow(),
                    )
                    findings.append(finding)

        return findings

    def _check_unused_credentials(self, resource: Resource) -> List[Finding]:
        """Check for unused or stale credentials."""
        findings = []
        props = resource.properties

        # Check last used timestamp
        last_used = props.get("last_used")
        if last_used:
            # In a real implementation, compare with current time
            # For now, just check if the field exists
            pass

        # Check for inactive access keys (placeholder for real implementation)
        access_keys = props.get("access_keys", [])
        for key in access_keys:
            if key.get("status") == "Inactive":
                finding_id = f"identity-{uuid.uuid4()}"
                finding = Finding(
                    id=finding_id,
                    type=FindingType.IDENTITY_RISK,
                    severity=Severity.LOW,
                    title="Inactive Access Key",
                    description=f"IAM role {resource.name} has inactive access keys that should be removed",
                    resource=resource,
                    policy=None,
                    evidence={
                        "resource_id": resource.id,
                        "access_key_id": key.get("access_key_id"),
                    },
                    remediation="Remove unused access keys to reduce attack surface.",
                    timestamp=datetime.utcnow(),
                )
                findings.append(finding)

        return findings

    def _check_resource_iam_issues(self, resource: Resource) -> List[Finding]:
        """Check non-IAM resources for IAM-related issues."""
        findings = []
        props = resource.properties

        # Check for overly permissive resource policies
        if "policy" in props or "bucket_policy" in props:
            policy = props.get("policy") or props.get("bucket_policy")

            if isinstance(policy, dict):
                statements = policy.get("Statement", [])

                for statement in statements:
                    principal = statement.get("Principal", {})

                    # Check for public access via IAM policy
                    if principal == "*" or "AWS" in principal and principal["AWS"] == "*":
                        finding_id = f"identity-{uuid.uuid4()}"
                        finding = Finding(
                            id=finding_id,
                            type=FindingType.IDENTITY_RISK,
                            severity=Severity.HIGH,
                            title="Resource Policy Allows Public Access",
                            description=f"Resource {resource.name} has a policy allowing access from any principal",
                            resource=resource,
                            policy=None,
                            evidence={
                                "resource_id": resource.id,
                                "resource_policy": policy,
                            },
                            remediation="Restrict resource policy to specific principals or AWS accounts.",
                            timestamp=datetime.utcnow(),
                        )
                        findings.append(finding)

        return findings

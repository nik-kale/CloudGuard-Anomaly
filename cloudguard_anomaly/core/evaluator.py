"""
Policy evaluator for CloudGuard-Anomaly.

This module evaluates resources against security policies and generates findings.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List

from cloudguard_anomaly.core.models import (
    Finding,
    FindingType,
    Policy,
    Resource,
    Severity,
)

logger = logging.getLogger(__name__)


class PolicyEvaluator:
    """Evaluates resources against security policies."""

    def __init__(self, policies: List[Policy]):
        """
        Initialize the evaluator with a set of policies.

        Args:
            policies: List of policies to evaluate against
        """
        self.policies = [p for p in policies if p.enabled]
        logger.info(f"Initialized evaluator with {len(self.policies)} active policies")

    def evaluate_resource(self, resource: Resource) -> List[Finding]:
        """
        Evaluate a single resource against all applicable policies.

        Args:
            resource: Resource to evaluate

        Returns:
            List of findings (violations)
        """
        findings = []

        applicable_policies = self._get_applicable_policies(resource)

        for policy in applicable_policies:
            if self._evaluate_policy(resource, policy):
                finding = self._create_finding(resource, policy)
                findings.append(finding)

        return findings

    def evaluate_resources(self, resources: List[Resource]) -> List[Finding]:
        """
        Evaluate multiple resources against policies.

        Args:
            resources: List of resources to evaluate

        Returns:
            List of all findings
        """
        all_findings = []

        for resource in resources:
            findings = self.evaluate_resource(resource)
            all_findings.extend(findings)

        logger.info(f"Evaluated {len(resources)} resources, found {len(all_findings)} violations")
        return all_findings

    def _get_applicable_policies(self, resource: Resource) -> List[Policy]:
        """Get policies applicable to a specific resource."""
        applicable = []

        for policy in self.policies:
            # Check provider match
            if policy.provider.value not in ["multi", resource.provider.value]:
                continue

            # Check resource type match
            if resource.type not in policy.resource_types:
                continue

            applicable.append(policy)

        return applicable

    def _evaluate_policy(self, resource: Resource, policy: Policy) -> bool:
        """
        Evaluate a single policy against a resource.

        Args:
            resource: Resource to check
            policy: Policy to evaluate

        Returns:
            True if policy is violated (finding should be created)
        """
        condition = policy.condition

        try:
            # Handle different condition types
            if "property_check" in condition:
                return self._check_property(resource, condition["property_check"])
            elif "exists" in condition:
                return self._check_exists(resource, condition["exists"])
            elif "pattern" in condition:
                return self._check_pattern(resource, condition["pattern"])
            elif "custom" in condition:
                return self._check_custom(resource, condition["custom"])
            else:
                logger.warning(f"Unknown condition type in policy {policy.id}")
                return False
        except Exception as e:
            logger.error(f"Error evaluating policy {policy.id} on resource {resource.id}: {e}")
            return False

    def _check_property(self, resource: Resource, check: Dict[str, Any]) -> bool:
        """Check if a resource property meets a condition."""
        property_path = check.get("path", "")
        operator = check.get("operator", "equals")
        expected_value = check.get("value")

        # Navigate property path
        value = resource.properties
        for key in property_path.split("."):
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return False

        # Apply operator
        if operator == "equals":
            return value == expected_value
        elif operator == "not_equals":
            return value != expected_value
        elif operator == "contains":
            return expected_value in value if value else False
        elif operator == "not_contains":
            return expected_value not in value if value else True
        elif operator == "exists":
            return value is not None
        elif operator == "not_exists":
            return value is None
        elif operator == "greater_than":
            return value > expected_value if value is not None else False
        elif operator == "less_than":
            return value < expected_value if value is not None else False
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False

    def _check_exists(self, resource: Resource, check: Dict[str, Any]) -> bool:
        """Check if a property exists or doesn't exist."""
        property_path = check.get("path", "")
        should_exist = check.get("should_exist", True)

        value = resource.properties
        for key in property_path.split("."):
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return not should_exist

        exists = value is not None
        return exists != should_exist  # Violation if doesn't match expectation

    def _check_pattern(self, resource: Resource, check: Dict[str, Any]) -> bool:
        """Check if a property matches a pattern."""
        import re

        property_path = check.get("path", "")
        pattern = check.get("pattern", "")
        match_required = check.get("match_required", False)

        value = resource.properties
        for key in property_path.split("."):
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return match_required

        if value is None:
            return match_required

        matches = bool(re.search(pattern, str(value)))
        return matches != match_required  # Violation if doesn't match expectation

    def _check_custom(self, resource: Resource, check: Dict[str, Any]) -> bool:
        """Execute custom check logic."""
        # This is a placeholder for more complex custom logic
        # In a real implementation, this could use a plugin system
        check_type = check.get("type")

        if check_type == "public_access":
            return self._check_public_access(resource)
        elif check_type == "encryption":
            return self._check_encryption(resource)
        elif check_type == "logging":
            return self._check_logging(resource)

        return False

    def _check_public_access(self, resource: Resource) -> bool:
        """Check if resource has public access enabled."""
        props = resource.properties

        # Check various public access patterns
        public_indicators = [
            props.get("public_access_block_configuration", {}).get("block_public_acls") == False,
            props.get("acl") == "public-read",
            props.get("acl") == "public-read-write",
            "0.0.0.0/0" in str(props.get("cidr_blocks", [])),
            "::/0" in str(props.get("ipv6_cidr_blocks", [])),
        ]

        return any(public_indicators)

    def _check_encryption(self, resource: Resource) -> bool:
        """Check if resource lacks encryption."""
        props = resource.properties

        encryption_indicators = [
            props.get("encryption_enabled") == False,
            props.get("encrypted") == False,
            props.get("encryption") is None,
            props.get("server_side_encryption_configuration") is None,
        ]

        return any(encryption_indicators)

    def _check_logging(self, resource: Resource) -> bool:
        """Check if resource lacks logging/monitoring."""
        props = resource.properties

        logging_indicators = [
            props.get("logging_enabled") == False,
            props.get("logging") is None,
            props.get("access_logging") is None,
        ]

        return any(logging_indicators)

    def _create_finding(self, resource: Resource, policy: Policy) -> Finding:
        """Create a finding from a policy violation."""
        finding_id = f"finding-{uuid.uuid4()}"

        return Finding(
            id=finding_id,
            type=FindingType.MISCONFIGURATION,
            severity=policy.severity,
            title=policy.name,
            description=policy.description,
            resource=resource,
            policy=policy,
            evidence={
                "resource_id": resource.id,
                "resource_type": resource.type.value,
                "policy_id": policy.id,
            },
            remediation=policy.remediation,
            timestamp=datetime.utcnow(),
        )

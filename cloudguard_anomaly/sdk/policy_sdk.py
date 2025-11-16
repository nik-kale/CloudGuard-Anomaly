"""
Policy-as-Code SDK for CloudGuard-Anomaly.

Allows developers to write custom security policies in Python code with
a clean, decorator-based API.
"""

import logging
import inspect
from typing import Callable, Optional, List, Dict, Any
from functools import wraps
from dataclasses import dataclass

from cloudguard_anomaly.core.models import Resource, Finding, Policy, Severity, ResourceType, Provider

logger = logging.getLogger(__name__)


# Global policy registry
_custom_policies: Dict[str, "CustomPolicy"] = {}


@dataclass
class CustomPolicy:
    """Represents a custom policy defined in code."""

    id: str
    name: str
    description: str
    severity: Severity
    provider: Provider
    resource_types: List[ResourceType]
    check_function: Callable[[Resource], Optional[Finding]]
    remediation: str
    metadata: Dict[str, Any]


class PolicyBuilder:
    """Builder for creating custom policies."""

    def __init__(self, policy_id: str):
        """
        Initialize policy builder.

        Args:
            policy_id: Unique policy identifier
        """
        self.policy_id = policy_id
        self.policy_name = ""
        self.policy_description = ""
        self.policy_severity = Severity.MEDIUM
        self.policy_provider = Provider.AWS  # Default
        self.policy_resource_types: List[ResourceType] = []
        self.policy_remediation = ""
        self.policy_metadata: Dict[str, Any] = {}

    def name(self, name: str) -> "PolicyBuilder":
        """Set policy name."""
        self.policy_name = name
        return self

    def description(self, description: str) -> "PolicyBuilder":
        """Set policy description."""
        self.policy_description = description
        return self

    def severity(self, severity: Severity) -> "PolicyBuilder":
        """Set policy severity."""
        self.policy_severity = severity
        return self

    def provider(self, provider: Provider) -> "PolicyBuilder":
        """Set cloud provider."""
        self.policy_provider = provider
        return self

    def resource_types(self, *types: ResourceType) -> "PolicyBuilder":
        """Set applicable resource types."""
        self.policy_resource_types = list(types)
        return self

    def remediation(self, remediation: str) -> "PolicyBuilder":
        """Set remediation instructions."""
        self.policy_remediation = remediation
        return self

    def metadata(self, **kwargs) -> "PolicyBuilder":
        """Add metadata to policy."""
        self.policy_metadata.update(kwargs)
        return self

    def check(self, func: Callable[[Resource], Optional[Finding]]) -> CustomPolicy:
        """
        Register check function and create policy.

        Args:
            func: Function that checks a resource and returns Finding or None

        Returns:
            CustomPolicy instance
        """
        policy = CustomPolicy(
            id=self.policy_id,
            name=self.policy_name or func.__name__.replace('_', ' ').title(),
            description=self.policy_description or func.__doc__ or "",
            severity=self.policy_severity,
            provider=self.policy_provider,
            resource_types=self.policy_resource_types,
            check_function=func,
            remediation=self.policy_remediation,
            metadata=self.policy_metadata
        )

        # Register policy globally
        _custom_policies[self.policy_id] = policy
        logger.info(f"Registered custom policy: {self.policy_id} - {policy.name}")

        return policy


def policy(
    policy_id: str,
    name: str = "",
    description: str = "",
    severity: Severity = Severity.MEDIUM,
    provider: Provider = Provider.AWS,
    resource_types: Optional[List[ResourceType]] = None,
    remediation: str = "",
    **metadata
) -> Callable:
    """
    Decorator for creating custom policies.

    Usage:
        @policy(
            policy_id="custom-001",
            name="Check S3 Encryption",
            severity=Severity.HIGH,
            resource_types=[ResourceType.STORAGE]
        )
        def check_s3_encryption(resource: Resource) -> Optional[Finding]:
            if not resource.properties.get('encryption_enabled'):
                return Finding(
                    resource=resource,
                    policy_id="custom-001",
                    severity=Severity.HIGH,
                    title="S3 bucket not encrypted",
                    description="Bucket does not have server-side encryption enabled"
                )
            return None

    Args:
        policy_id: Unique policy ID
        name: Policy name
        description: Policy description
        severity: Default severity
        provider: Cloud provider
        resource_types: Applicable resource types
        remediation: Remediation instructions
        **metadata: Additional metadata

    Returns:
        Decorator function
    """
    def decorator(func: Callable[[Resource], Optional[Finding]]) -> Callable:
        # Create policy using builder
        builder = PolicyBuilder(policy_id)
        builder.policy_name = name or func.__name__.replace('_', ' ').title()
        builder.policy_description = description or func.__doc__ or ""
        builder.policy_severity = severity
        builder.policy_provider = provider
        builder.policy_resource_types = resource_types or []
        builder.policy_remediation = remediation
        builder.policy_metadata = metadata

        # Register policy
        custom_policy = builder.check(func)

        # Return wrapped function
        @wraps(func)
        def wrapper(resource: Resource) -> Optional[Finding]:
            return func(resource)

        # Attach policy to function
        wrapper.policy = custom_policy

        return wrapper

    return decorator


class PolicySDK:
    """Main SDK interface for custom policies."""

    @staticmethod
    def create(policy_id: str) -> PolicyBuilder:
        """
        Create a new policy using builder pattern.

        Args:
            policy_id: Unique policy identifier

        Returns:
            PolicyBuilder instance

        Example:
            policy = (PolicySDK.create("custom-001")
                     .name("Require CostCenter Tag")
                     .severity(Severity.HIGH)
                     .resource_types(ResourceType.STORAGE, ResourceType.COMPUTE)
                     .remediation("Add CostCenter tag to resource")
                     .check(lambda r: None if 'CostCenter' in r.tags else Finding(...)))
        """
        return PolicyBuilder(policy_id)

    @staticmethod
    def get_policy(policy_id: str) -> Optional[CustomPolicy]:
        """
        Get registered custom policy by ID.

        Args:
            policy_id: Policy ID

        Returns:
            CustomPolicy or None
        """
        return _custom_policies.get(policy_id)

    @staticmethod
    def get_all_policies() -> List[CustomPolicy]:
        """
        Get all registered custom policies.

        Returns:
            List of CustomPolicy instances
        """
        return list(_custom_policies.values())

    @staticmethod
    def clear_policies():
        """Clear all registered policies (useful for testing)."""
        _custom_policies.clear()
        logger.info("Cleared all custom policies")

    @staticmethod
    def evaluate_resource(resource: Resource) -> List[Finding]:
        """
        Evaluate all registered policies against a resource.

        Args:
            resource: Resource to evaluate

        Returns:
            List of findings
        """
        findings = []

        for policy in _custom_policies.values():
            # Check if policy applies to this resource type
            if policy.resource_types and resource.type not in policy.resource_types:
                continue

            # Check if policy applies to this provider
            if resource.provider != policy.provider:
                continue

            try:
                finding = policy.check_function(resource)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Error evaluating policy {policy.id} on resource {resource.id}: {e}")

        return findings

    @staticmethod
    def load_policies_from_module(module_path: str):
        """
        Load custom policies from a Python module.

        Args:
            module_path: Path to Python module (e.g., "my_policies.custom")

        Example:
            PolicySDK.load_policies_from_module("cloudguard_policies.custom")
        """
        import importlib

        try:
            module = importlib.import_module(module_path)

            # Count newly registered policies
            before = len(_custom_policies)

            # Import will trigger policy decorators
            importlib.reload(module)

            after = len(_custom_policies)
            logger.info(f"Loaded {after - before} policies from {module_path}")

        except Exception as e:
            logger.error(f"Error loading policies from {module_path}: {e}")
            raise


# Convenience functions for common checks

def require_tag(tag_name: str, severity: Severity = Severity.MEDIUM) -> Callable:
    """
    Create a policy that requires a specific tag.

    Args:
        tag_name: Required tag name
        severity: Finding severity if tag is missing

    Returns:
        Policy decorator

    Example:
        @require_tag("CostCenter", severity=Severity.HIGH)
        def check_cost_center(resource: Resource) -> Optional[Finding]:
            pass  # Logic handled by decorator
    """
    def check_func(resource: Resource) -> Optional[Finding]:
        if tag_name not in resource.tags:
            return Finding(
                resource=resource,
                policy_id=f"tag-{tag_name}",
                severity=severity,
                title=f"Missing required tag: {tag_name}",
                description=f"Resource does not have required '{tag_name}' tag",
                remediation=f"Add '{tag_name}' tag to resource"
            )
        return None

    return check_func


def require_encryption(severity: Severity = Severity.HIGH) -> Callable:
    """
    Create a policy that requires encryption.

    Args:
        severity: Finding severity if not encrypted

    Returns:
        Policy check function

    Example:
        @policy("enc-001", name="Require Encryption")
        @require_encryption(severity=Severity.CRITICAL)
        def check_encryption(resource: Resource) -> Optional[Finding]:
            pass  # Logic handled by decorator
    """
    def check_func(resource: Resource) -> Optional[Finding]:
        encrypted = resource.properties.get('encryption_enabled') or \
                   resource.properties.get('encrypted')

        if not encrypted:
            return Finding(
                resource=resource,
                policy_id="encryption-required",
                severity=severity,
                title="Encryption not enabled",
                description="Resource does not have encryption enabled",
                remediation="Enable encryption at rest for this resource"
            )
        return None

    return check_func


def deny_public_access(severity: Severity = Severity.CRITICAL) -> Callable:
    """
    Create a policy that denies public access.

    Args:
        severity: Finding severity if publicly accessible

    Returns:
        Policy check function

    Example:
        @policy("pub-001", name="Deny Public Access")
        @deny_public_access()
        def check_public_access(resource: Resource) -> Optional[Finding]:
            pass  # Logic handled by decorator
    """
    def check_func(resource: Resource) -> Optional[Finding]:
        public = resource.properties.get('public_access') or \
                resource.properties.get('publicly_accessible')

        if public:
            return Finding(
                resource=resource,
                policy_id="public-access-denied",
                severity=severity,
                title="Resource is publicly accessible",
                description="Resource allows public access which may expose sensitive data",
                remediation="Restrict access to authorized users/networks only"
            )
        return None

    return check_func


# Example custom policies (for documentation/testing)

@policy(
    policy_id="example-001",
    name="Example: Require Production Tag",
    description="Ensures all resources have a 'Production' tag",
    severity=Severity.MEDIUM,
    resource_types=[ResourceType.STORAGE, ResourceType.COMPUTE, ResourceType.DATABASE],
    remediation="Add 'Production' tag with value 'true' or 'false'"
)
def example_require_production_tag(resource: Resource) -> Optional[Finding]:
    """Example policy: require Production tag."""
    if 'Production' not in resource.tags:
        return Finding(
            resource=resource,
            policy_id="example-001",
            severity=Severity.MEDIUM,
            title="Missing Production tag",
            description="Resource does not have a 'Production' tag",
            remediation="Add 'Production' tag to indicate if this is a production resource"
        )
    return None


@policy(
    policy_id="example-002",
    name="Example: Check S3 Versioning",
    description="Ensures S3 buckets have versioning enabled",
    severity=Severity.HIGH,
    provider=Provider.AWS,
    resource_types=[ResourceType.STORAGE],
    remediation="Enable versioning on S3 bucket"
)
def example_check_s3_versioning(resource: Resource) -> Optional[Finding]:
    """Example policy: S3 versioning check."""
    versioning = resource.properties.get('versioning_enabled', False)

    if not versioning:
        return Finding(
            resource=resource,
            policy_id="example-002",
            severity=Severity.HIGH,
            title="S3 bucket versioning disabled",
            description="Bucket does not have versioning enabled, risking data loss",
            remediation="Enable versioning: aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled"
        )
    return None

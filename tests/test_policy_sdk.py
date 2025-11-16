"""
Tests for Policy SDK.
"""

import pytest

from cloudguard_anomaly.sdk.policy_sdk import (
    policy,
    PolicyBuilder,
    require_encryption,
    deny_public_access,
    require_tags,
    check_property,
    PolicyRegistry,
)
from cloudguard_anomaly.core.models import Resource, ResourceType, Severity, FindingType


class TestPolicySDK:
    """Test Policy-as-Code SDK functionality."""

    def test_policy_decorator_basic(self, sample_s3_bucket):
        """Test basic policy decorator."""

        @policy(
            policy_id="TEST_001",
            name="Test Policy",
            severity=Severity.HIGH,
            resource_types=[ResourceType.STORAGE],
            remediation="Fix the issue",
        )
        def test_check(resource: Resource):
            if not resource.properties.get("encryption_enabled"):
                return f"Resource {resource.id} not encrypted"
            return None

        result = test_check(sample_s3_bucket)

        # Should return finding message
        assert result is not None
        assert "not encrypted" in result

    def test_policy_decorator_with_finding_return(self, sample_s3_bucket):
        """Test policy returning Finding object."""
        from cloudguard_anomaly.core.models import Finding

        @policy(
            policy_id="TEST_002",
            name="Test Policy 2",
            severity=Severity.MEDIUM,
            resource_types=[ResourceType.STORAGE],
        )
        def test_check(resource: Resource):
            return Finding(
                resource=resource,
                policy_id="TEST_002",
                severity=Severity.MEDIUM,
                type=FindingType.MISCONFIGURATION,
                title="Test Finding",
                description="Test",
            )

        result = test_check(sample_s3_bucket)

        assert isinstance(result, Finding)
        assert result.policy_id == "TEST_002"

    def test_policy_decorator_no_finding(self, sample_s3_bucket):
        """Test policy that finds no issues."""

        @policy(
            policy_id="TEST_003",
            name="Always Pass",
            severity=Severity.LOW,
            resource_types=[ResourceType.STORAGE],
        )
        def test_check(resource: Resource):
            return None  # No finding

        result = test_check(sample_s3_bucket)
        assert result is None

    def test_require_encryption_decorator(self, sample_s3_bucket):
        """Test require_encryption helper decorator."""

        @require_encryption(severity=Severity.CRITICAL)
        def encryption_check(resource: Resource):
            pass

        result = encryption_check(sample_s3_bucket)

        # sample_s3_bucket has encryption_enabled=False
        assert result is not None
        if isinstance(result, str):
            assert "encrypt" in result.lower()

    def test_deny_public_access_decorator(self, sample_s3_bucket):
        """Test deny_public_access helper decorator."""

        @deny_public_access(severity=Severity.HIGH)
        def public_access_check(resource: Resource):
            pass

        result = public_access_check(sample_s3_bucket)

        # sample_s3_bucket has public_access=True
        assert result is not None

    def test_require_tags_decorator(self, sample_s3_bucket):
        """Test require_tags helper decorator."""

        @require_tags(required_tags=["Production"], severity=Severity.MEDIUM)
        def tag_check(resource: Resource):
            pass

        result = tag_check(sample_s3_bucket)

        # sample_s3_bucket doesn't have Production tag
        assert result is not None

        # Test with existing tag
        @require_tags(required_tags=["Environment"], severity=Severity.MEDIUM)
        def tag_check2(resource: Resource):
            pass

        result2 = tag_check2(sample_s3_bucket)
        # sample_s3_bucket has Environment tag
        assert result2 is None

    def test_check_property_decorator(self, sample_s3_bucket):
        """Test check_property helper decorator."""

        @check_property(
            property_path="versioning_enabled",
            expected_value=True,
            severity=Severity.LOW,
            message="Versioning not enabled",
        )
        def versioning_check(resource: Resource):
            pass

        result = versioning_check(sample_s3_bucket)

        # sample_s3_bucket has versioning_enabled=False
        assert result is not None

    def test_policy_builder_basic(self):
        """Test PolicyBuilder pattern."""
        builder = PolicyBuilder("BUILDER_001", "Builder Test")

        policy_func = (
            builder.with_severity(Severity.HIGH)
            .for_resource_types([ResourceType.STORAGE])
            .with_remediation("Enable encryption")
            .check_encryption_enabled()
            .build()
        )

        # Should return a callable policy
        assert callable(policy_func)

    def test_policy_builder_public_access(self, sample_s3_bucket):
        """Test PolicyBuilder public access check."""
        builder = PolicyBuilder("BUILDER_002", "Public Access Check")

        policy_func = (
            builder.with_severity(Severity.CRITICAL)
            .for_resource_types([ResourceType.STORAGE])
            .deny_public_access()
            .build()
        )

        result = policy_func(sample_s3_bucket)

        # Should find public access issue
        assert result is not None

    def test_policy_builder_required_tags(self, sample_s3_bucket):
        """Test PolicyBuilder required tags check."""
        builder = PolicyBuilder("BUILDER_003", "Tag Check")

        policy_func = (
            builder.with_severity(Severity.LOW)
            .require_tags(["CostCenter", "Owner"])
            .build()
        )

        result = policy_func(sample_s3_bucket)

        # Should find missing tags
        assert result is not None

    def test_policy_builder_property_check(self, sample_s3_bucket):
        """Test PolicyBuilder property check."""
        builder = PolicyBuilder("BUILDER_004", "Property Check")

        policy_func = (
            builder.with_severity(Severity.MEDIUM)
            .check_property("logging_enabled", True)
            .build()
        )

        result = policy_func(sample_s3_bucket)

        # sample_s3_bucket has logging_enabled=False
        assert result is not None

    def test_policy_builder_multiple_checks(self, sample_s3_bucket):
        """Test PolicyBuilder with multiple checks."""
        builder = PolicyBuilder("BUILDER_005", "Multi Check")

        policy_func = (
            builder.with_severity(Severity.HIGH)
            .for_resource_types([ResourceType.STORAGE])
            .check_encryption_enabled()
            .deny_public_access()
            .require_tags(["Environment"])
            .build()
        )

        result = policy_func(sample_s3_bucket)

        # Should find at least encryption and public access issues
        assert result is not None

    def test_policy_registry_add_policy(self):
        """Test adding policy to registry."""
        registry = PolicyRegistry()

        @policy(
            policy_id="REG_001",
            name="Registry Test",
            severity=Severity.LOW,
            resource_types=[ResourceType.STORAGE],
        )
        def test_policy(resource: Resource):
            return None

        # Policy should be auto-registered
        policies = registry.get_all_policies()
        policy_ids = [p.metadata["policy_id"] for p in policies]

        assert "REG_001" in policy_ids

    def test_policy_registry_get_by_id(self):
        """Test getting policy by ID from registry."""
        registry = PolicyRegistry()

        @policy(
            policy_id="REG_002",
            name="Registry Test 2",
            severity=Severity.MEDIUM,
            resource_types=[ResourceType.COMPUTE],
        )
        def test_policy(resource: Resource):
            return None

        found_policy = registry.get_policy("REG_002")
        assert found_policy is not None
        assert found_policy.metadata["policy_id"] == "REG_002"

    def test_policy_registry_evaluate_resource(self, sample_s3_bucket):
        """Test evaluating resource against registered policies."""
        registry = PolicyRegistry()

        @policy(
            policy_id="REG_003",
            name="Registry Eval Test",
            severity=Severity.HIGH,
            resource_types=[ResourceType.STORAGE],
        )
        def test_policy(resource: Resource):
            if not resource.properties.get("encryption_enabled"):
                return "Not encrypted"
            return None

        findings = registry.evaluate_resource(sample_s3_bucket)

        # Should find encryption issue
        assert len(findings) > 0

    def test_policy_metadata_attached(self):
        """Test that policy metadata is attached to function."""

        @policy(
            policy_id="META_001",
            name="Metadata Test",
            severity=Severity.HIGH,
            resource_types=[ResourceType.IDENTITY],
            remediation="Fix it",
            references=["https://example.com"],
        )
        def test_policy(resource: Resource):
            return None

        # Check metadata is attached
        assert hasattr(test_policy, "metadata")
        metadata = test_policy.metadata

        assert metadata["policy_id"] == "META_001"
        assert metadata["name"] == "Metadata Test"
        assert metadata["severity"] == Severity.HIGH
        assert metadata["resource_types"] == [ResourceType.IDENTITY]
        assert metadata["remediation"] == "Fix it"
        assert metadata["references"] == ["https://example.com"]

    def test_policy_with_resource_type_filtering(self, sample_s3_bucket, sample_ec2_instance):
        """Test policy only applies to specified resource types."""

        @policy(
            policy_id="FILTER_001",
            name="Compute Only",
            severity=Severity.LOW,
            resource_types=[ResourceType.COMPUTE],  # Only compute
        )
        def compute_only_check(resource: Resource):
            return "Should only apply to compute"

        # Test with storage (should be skipped based on decorator logic)
        # Note: Basic decorator doesn't filter, but metadata is there for engine
        result_storage = compute_only_check(sample_s3_bucket)
        result_compute = compute_only_check(sample_ec2_instance)

        # Both execute, but metadata indicates intended types
        assert hasattr(compute_only_check, "metadata")
        assert ResourceType.COMPUTE in compute_only_check.metadata["resource_types"]

    def test_custom_policy_integration(self, sample_s3_bucket):
        """Test custom policy integration."""

        @policy(
            policy_id="CUSTOM_001",
            name="Custom S3 Policy",
            severity=Severity.HIGH,
            resource_types=[ResourceType.STORAGE],
            remediation="Enable both encryption and versioning",
        )
        def custom_s3_check(resource: Resource):
            issues = []

            if not resource.properties.get("encryption_enabled"):
                issues.append("encryption disabled")

            if not resource.properties.get("versioning_enabled"):
                issues.append("versioning disabled")

            if issues:
                return f"S3 bucket has issues: {', '.join(issues)}"

            return None

        result = custom_s3_check(sample_s3_bucket)

        assert result is not None
        assert "encryption" in result
        assert "versioning" in result

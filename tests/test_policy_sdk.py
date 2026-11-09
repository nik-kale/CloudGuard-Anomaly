"""Tests for the Policy-as-Code SDK."""

import pytest

from cloudguard_anomaly.core.models import Finding, Provider, Resource, ResourceType, Severity
from cloudguard_anomaly.sdk.policy_sdk import (
    PolicyBuilder,
    PolicySDK,
    deny_public_access,
    policy,
    require_encryption,
    require_tag,
)


@pytest.fixture(autouse=True)
def isolated_registry():
    PolicySDK.clear_policies()
    yield
    PolicySDK.clear_policies()


def _missing_encryption(resource: Resource) -> Finding | None:
    if resource.properties.get("encryption_enabled"):
        return None
    return Finding(
        resource=resource,
        policy_id="SDK_1",
        severity=Severity.HIGH,
        title="Not encrypted",
        description="d",
    )


class TestPolicyDecorator:
    def test_registers_and_attaches_the_policy(self):
        @policy("SDK_1", name="Encrypted", severity=Severity.HIGH)
        def check(resource):
            return None

        assert PolicySDK.get_policy("SDK_1").name == "Encrypted"
        assert check.policy.severity is Severity.HIGH

    def test_wrapped_function_still_runs(self, sample_s3_bucket):
        @policy("SDK_1")
        def check(resource):
            return _missing_encryption(resource)

        result = check(sample_s3_bucket)
        assert isinstance(result, Finding)
        assert result.policy_id == "SDK_1"
        assert result.id

    def test_finding_serialises_its_policy_id(self, sample_s3_bucket):
        assert _missing_encryption(sample_s3_bucket).to_dict()["policy_id"] == "SDK_1"


class TestPolicyBuilder:
    def test_fluent_policy_is_registered(self):
        built = (
            PolicyBuilder("B1")
            .name("Builder")
            .severity(Severity.CRITICAL)
            .provider(Provider.GCP)
            .resource_types(ResourceType.STORAGE)
            .remediation("fix")
            .metadata(owner="sec")
            .check(_missing_encryption)
        )
        assert PolicySDK.get_policy("B1") is built
        assert built.provider is Provider.GCP
        assert built.metadata == {"owner": "sec"}


class TestEvaluateResource:
    def test_resource_type_filter(self, sample_s3_bucket, sample_ec2_instance):
        PolicyBuilder("B1").resource_types(ResourceType.STORAGE).check(_missing_encryption)

        assert len(PolicySDK.evaluate_resource(sample_s3_bucket)) == 1
        assert PolicySDK.evaluate_resource(sample_ec2_instance) == []

    def test_provider_filter(self, sample_s3_bucket):
        PolicyBuilder("B1").provider(Provider.AZURE).check(_missing_encryption)
        assert PolicySDK.evaluate_resource(sample_s3_bucket) == []

    def test_multi_provider_policy_applies_everywhere(self, sample_s3_bucket):
        """MULTI means cross-cloud; it was compared for equality and never matched."""
        PolicyBuilder("B1").provider(Provider.MULTI).check(_missing_encryption)
        assert len(PolicySDK.evaluate_resource(sample_s3_bucket)) == 1

    def test_failing_check_does_not_stop_evaluation(self, sample_s3_bucket):
        def broken(resource):
            raise RuntimeError("boom")

        PolicyBuilder("B1").check(broken)
        PolicyBuilder("B2").check(_missing_encryption)
        assert len(PolicySDK.evaluate_resource(sample_s3_bucket)) == 1


class TestHelpers:
    def test_require_encryption_called_directly(self, sample_s3_bucket):
        finding = require_encryption(severity=Severity.CRITICAL)(sample_s3_bucket)
        assert finding.severity is Severity.CRITICAL

    def test_require_tag(self, sample_s3_bucket):
        assert require_tag("Environment")(sample_s3_bucket) is None
        assert require_tag("CostCenter")(sample_s3_bucket).title.endswith("CostCenter")

    def test_deny_public_access(self, sample_s3_bucket):
        assert deny_public_access()(sample_s3_bucket) is not None

    def test_helpers_work_as_decorators(self, sample_s3_bucket):
        """The docstrings show them stacked on a function, which used to crash."""

        @policy("SDK_2", name="Encrypted")
        @require_encryption(severity=Severity.HIGH)
        def check(resource):
            pass

        assert check(sample_s3_bucket).severity is Severity.HIGH

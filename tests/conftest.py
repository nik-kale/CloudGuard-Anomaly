"""
Pytest configuration and shared fixtures for CloudGuard-Anomaly tests.
"""

import os
import tempfile
from datetime import datetime
from typing import List
import pytest

from cloudguard_anomaly.core.models import (
    Resource,
    ResourceType,
    CloudProvider,
    Environment,
    Finding,
    Anomaly,
    Severity,
    FindingType,
    ScanResult,
)
from cloudguard_anomaly.storage.database import DatabaseStorage


@pytest.fixture(scope="session")
def test_database_url():
    """Create temporary SQLite database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield f"sqlite:///{path}"
    os.unlink(path)


@pytest.fixture
def database(test_database_url):
    """Create database instance for testing."""
    db = DatabaseStorage(test_database_url)
    yield db
    # Cleanup
    db.cleanup_old_data(days=0)


@pytest.fixture
def sample_s3_bucket():
    """Sample S3 bucket resource."""
    return Resource(
        id="s3-bucket-test-123",
        name="test-bucket",
        type=ResourceType.STORAGE,
        provider=CloudProvider.AWS,
        region="us-east-1",
        properties={
            "encryption_enabled": False,
            "public_access": True,
            "versioning_enabled": False,
            "logging_enabled": False,
        },
        tags={"Environment": "test", "Owner": "security-team"},
        metadata={"bucket_name": "test-bucket"},
    )


@pytest.fixture
def sample_ec2_instance():
    """Sample EC2 instance resource."""
    return Resource(
        id="i-1234567890abcdef0",
        name="test-instance",
        type=ResourceType.COMPUTE,
        provider=CloudProvider.AWS,
        region="us-east-1",
        properties={
            "instance_type": "t2.micro",
            "public_ip": "1.2.3.4",
            "security_groups": ["sg-12345"],
            "encrypted_volumes": False,
            "monitoring_enabled": False,
        },
        tags={"Name": "test-instance"},
    )


@pytest.fixture
def sample_security_group():
    """Sample security group resource."""
    return Resource(
        id="sg-12345",
        name="test-sg",
        type=ResourceType.NETWORK,
        provider=CloudProvider.AWS,
        region="us-east-1",
        properties={
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                },
                {
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ]
        },
    )


@pytest.fixture
def sample_iam_role():
    """Sample IAM role resource."""
    return Resource(
        id="arn:aws:iam::123456789012:role/test-role",
        name="test-role",
        type=ResourceType.IDENTITY,
        provider=CloudProvider.AWS,
        region="us-east-1",
        properties={
            "assume_role_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "policies": [
                {
                    "PolicyName": "AdminAccess",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    },
                }
            ],
        },
    )


@pytest.fixture
def sample_resources(sample_s3_bucket, sample_ec2_instance, sample_security_group, sample_iam_role):
    """Collection of sample resources."""
    return [sample_s3_bucket, sample_ec2_instance, sample_security_group, sample_iam_role]


@pytest.fixture
def sample_environment(sample_resources):
    """Sample cloud environment."""
    return Environment(
        name="test-environment",
        provider=CloudProvider.AWS,
        region="us-east-1",
        resources=sample_resources,
        metadata={"account_id": "123456789012"},
    )


@pytest.fixture
def sample_finding(sample_s3_bucket):
    """Sample security finding."""
    return Finding(
        id="finding-001",
        resource=sample_s3_bucket,
        policy_id="S3_ENCRYPTION_REQUIRED",
        severity=Severity.HIGH,
        type=FindingType.MISCONFIGURATION,
        title="S3 Bucket Not Encrypted",
        description="S3 bucket 'test-bucket' does not have encryption enabled",
        remediation="Enable server-side encryption on the S3 bucket",
        timestamp=datetime.utcnow(),
    )


@pytest.fixture
def sample_anomaly(sample_s3_bucket):
    """Sample configuration anomaly."""
    return Anomaly(
        id="anomaly-001",
        resource=sample_s3_bucket,
        type="configuration_drift",
        severity=Severity.MEDIUM,
        description="Bucket public access settings changed",
        expected_value={"public_access": False},
        actual_value={"public_access": True},
        timestamp=datetime.utcnow(),
    )


@pytest.fixture
def sample_scan_result(sample_environment, sample_finding, sample_anomaly):
    """Sample scan result."""
    return ScanResult(
        environment=sample_environment,
        findings=[sample_finding],
        anomalies=[sample_anomaly],
        summary={
            "total_findings": 1,
            "total_anomalies": 1,
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "finding_types": {"misconfiguration": 1},
            "risk_score": 5,
        },
        narratives=["Test environment has 1 high severity finding"],
        timestamp=datetime.utcnow(),
    )


@pytest.fixture
def mock_llm_provider():
    """Mock LLM provider for testing."""
    from cloudguard_anomaly.agents.llm.providers import LLMProvider

    class MockLLMProvider(LLMProvider):
        def generate(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
            return "This is a mock LLM response for testing purposes."

    return MockLLMProvider()

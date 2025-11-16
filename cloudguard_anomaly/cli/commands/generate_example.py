"""
Generate example environment command implementation.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)


def execute_generate(
    name: str,
    provider: str = "aws",
    output_path: Path = Path("./examples/environments"),
    resource_count: int = 10,
    with_issues: bool = False,
) -> None:
    """
    Generate a synthetic cloud environment.

    Args:
        name: Name of the environment
        provider: Cloud provider (aws, azure, gcp)
        output_path: Output directory
        resource_count: Number of resources to generate
        with_issues: Whether to include intentional security issues
    """
    logger.info(f"Generating example environment: {name}")

    env_dir = output_path / name
    env_dir.mkdir(parents=True, exist_ok=True)

    runtime_dir = env_dir / "runtime_snapshot"
    runtime_dir.mkdir(exist_ok=True)

    # Generate environment metadata
    env_config = {
        "name": name,
        "provider": provider,
        "metadata": {
            "generated": True,
            "description": f"Synthetic {provider.upper()} environment for testing",
        },
    }

    env_file = env_dir / "environment.yaml"
    with open(env_file, "w") as f:
        yaml.dump(env_config, f, default_flow_style=False)

    logger.info(f"Created environment config: {env_file}")

    # Generate resources
    resources = generate_resources(provider, resource_count, with_issues)

    # Save resources to files
    for i, resource in enumerate(resources):
        resource_file = runtime_dir / f"resource_{i:03d}.json"
        with open(resource_file, "w") as f:
            json.dump({"resources": [resource]}, f, indent=2)

    logger.info(f"Generated {len(resources)} resources in {runtime_dir}")

    print(f"\n✓ Generated environment '{name}' with {len(resources)} resources")
    print(f"  Location: {env_dir}")
    print(f"  Provider: {provider.upper()}")
    if with_issues:
        print(f"  ⚠️  Includes intentional security issues for demonstration")
    print(f"\nTo scan this environment:")
    print(f"  cloudguard-anomaly scan --env {env_dir}")


def generate_resources(provider: str, count: int, with_issues: bool) -> List[Dict[str, Any]]:
    """Generate synthetic resources."""
    resources = []

    if provider == "aws":
        resources.extend(generate_aws_resources(count, with_issues))
    elif provider == "azure":
        resources.extend(generate_azure_resources(count, with_issues))
    elif provider == "gcp":
        resources.extend(generate_gcp_resources(count, with_issues))

    return resources


def generate_aws_resources(count: int, with_issues: bool) -> List[Dict[str, Any]]:
    """Generate AWS resources."""
    resources = []

    # S3 Bucket
    if count > 0:
        bucket = {
            "id": "s3-bucket-example-001",
            "name": "example-data-bucket",
            "type": "aws_s3_bucket",
            "region": "us-east-1",
            "properties": {
                "bucket_name": "example-data-bucket",
                "versioning": {"enabled": False if with_issues else True},
                "encryption": None if with_issues else {"sse_algorithm": "AES256"},
                "acl": "public-read" if with_issues else "private",
                "public_access_block_configuration": {
                    "block_public_acls": False if with_issues else True,
                    "block_public_policy": False if with_issues else True,
                    "ignore_public_acls": False if with_issues else True,
                    "restrict_public_buckets": False if with_issues else True,
                },
            },
            "tags": {"Environment": "dev", "Owner": "security-team"},
        }
        resources.append(bucket)

    # RDS Database
    if count > 1:
        database = {
            "id": "rds-instance-001",
            "name": "production-database",
            "type": "aws_rds_instance",
            "region": "us-east-1",
            "properties": {
                "engine": "postgres",
                "publicly_accessible": with_issues,
                "encrypted": not with_issues,
                "backup_retention_period": 0 if with_issues else 7,
                "multi_az": not with_issues,
            },
            "tags": {"Environment": "prod", "Criticality": "high"},
        }
        resources.append(database)

    # Security Group
    if count > 2:
        sg_rules = [
            {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"] if with_issues else ["10.0.0.0/8"],
            }
        ]

        if with_issues:
            sg_rules.append(
                {"from_port": 3389, "to_port": 3389, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
            )

        security_group = {
            "id": "sg-12345678",
            "name": "app-security-group",
            "type": "aws_security_group",
            "region": "us-east-1",
            "properties": {"ingress": sg_rules, "egress": []},
            "tags": {},
        }
        resources.append(security_group)

    # EC2 Instance
    if count > 3:
        instance = {
            "id": "i-1234567890abcdef0",
            "name": "web-server-01",
            "type": "aws_instance",
            "region": "us-east-1",
            "properties": {
                "instance_type": "t3.medium",
                "associate_public_ip_address": with_issues,
                "metadata_options": {
                    "http_tokens": "optional" if with_issues else "required",
                    "http_endpoint": "enabled",
                },
            },
            "tags": {"Environment": "prod", "Role": "web-server"},
        }
        resources.append(instance)

    # IAM Role
    if count > 4:
        iam_role = {
            "id": "role-admin-access",
            "name": "AdminRole",
            "type": "aws_iam_role",
            "region": "global",
            "properties": {
                "assume_role_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*" if with_issues else "arn:aws:iam::123456789012:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "policy_document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*" if with_issues else ["s3:GetObject", "s3:ListBucket"],
                            "Resource": "*",
                        }
                    ]
                },
            },
            "tags": {},
        }
        resources.append(iam_role)

    # Add more generic resources to reach count
    for i in range(len(resources), min(count, 10)):
        resources.append(
            {
                "id": f"resource-{i:03d}",
                "name": f"generic-resource-{i}",
                "type": "aws_instance",
                "region": "us-east-1",
                "properties": {},
                "tags": {},
            }
        )

    return resources


def generate_azure_resources(count: int, with_issues: bool) -> List[Dict[str, Any]]:
    """Generate Azure resources."""
    resources = []

    # Storage Account
    if count > 0:
        storage = {
            "id": "/subscriptions/12345/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/examplestorage",
            "name": "examplestorage",
            "type": "azurerm_storage_account",
            "region": "eastus",
            "properties": {
                "enable_https_traffic_only": not with_issues,
                "minimum_tls_version": "TLS1_0" if with_issues else "TLS1_2",
                "network_rule_set": {"default_action": "Allow" if with_issues else "Deny"},
            },
            "tags": {"environment": "dev"},
        }
        resources.append(storage)

    # SQL Database
    if count > 1:
        sql_db = {
            "id": "/subscriptions/12345/resourceGroups/rg1/providers/Microsoft.Sql/servers/sqlserver1/databases/db1",
            "name": "production-db",
            "type": "azurerm_sql_database",
            "region": "eastus",
            "properties": {
                "transparent_data_encryption": {"status": "Disabled" if with_issues else "Enabled"},
                "auditing_policy": None if with_issues else {"enabled": True},
            },
            "tags": {"environment": "prod"},
        }
        resources.append(sql_db)

    # Fill remaining with generic resources
    for i in range(len(resources), min(count, 10)):
        resources.append(
            {
                "id": f"/subscriptions/12345/resourceGroups/rg1/providers/resource-{i}",
                "name": f"azure-resource-{i}",
                "type": "azurerm_virtual_machine",
                "region": "eastus",
                "properties": {},
                "tags": {},
            }
        )

    return resources


def generate_gcp_resources(count: int, with_issues: bool) -> List[Dict[str, Any]]:
    """Generate GCP resources."""
    resources = []

    # Storage Bucket
    if count > 0:
        bucket = {
            "id": "example-gcs-bucket",
            "name": "example-gcs-bucket",
            "type": "google_storage_bucket",
            "region": "us-central1",
            "properties": {
                "iam_configuration": {
                    "uniform_bucket_level_access": {"enabled": not with_issues},
                    "public_access_prevention": "inherited" if with_issues else "enforced",
                },
            },
            "labels": {"environment": "dev"},
        }
        resources.append(bucket)

    # Cloud SQL Instance
    if count > 1:
        sql_instance = {
            "id": "sql-instance-1",
            "name": "production-sql",
            "type": "google_sql_database_instance",
            "region": "us-central1",
            "properties": {
                "settings": {
                    "backup_configuration": {"enabled": not with_issues},
                    "ip_configuration": {
                        "ipv4_enabled": with_issues,
                        "require_ssl": not with_issues,
                    },
                },
            },
            "labels": {"environment": "prod"},
        }
        resources.append(sql_instance)

    # Fill remaining
    for i in range(len(resources), min(count, 10)):
        resources.append(
            {
                "id": f"gcp-resource-{i}",
                "name": f"gcp-resource-{i}",
                "type": "google_compute_instance",
                "region": "us-central1",
                "properties": {},
                "labels": {},
            }
        )

    return resources

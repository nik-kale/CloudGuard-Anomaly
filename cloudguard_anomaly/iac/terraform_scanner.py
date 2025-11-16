"""
Terraform IaC scanner for CloudGuard-Anomaly.

Scans Terraform files (.tf) for security issues before deployment.
"""

import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False

from cloudguard_anomaly.core.models import (
    Resource,
    Environment,
    Provider,
    ResourceType,
    Finding,
    Severity
)

logger = logging.getLogger(__name__)


class TerraformScanner:
    """Scans Terraform IaC files for security issues."""

    def __init__(self):
        """Initialize Terraform scanner."""
        if not HCL2_AVAILABLE:
            raise ImportError(
                "python-hcl2 required for Terraform scanning. "
                "Install with: pip install python-hcl2"
            )

        logger.info("Terraform scanner initialized")

    def scan_directory(self, path: str) -> Environment:
        """
        Scan a directory containing Terraform files.

        Args:
            path: Path to directory with .tf files

        Returns:
            Environment object with resources from Terraform config
        """
        directory = Path(path)

        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        # Find all .tf files
        tf_files = list(directory.glob("*.tf")) + list(directory.glob("**/*.tf"))

        if not tf_files:
            logger.warning(f"No Terraform files found in {path}")
            return Environment(
                name=f"terraform-{directory.name}",
                provider=Provider.AWS,  # Default
                resources=[]
            )

        logger.info(f"Found {len(tf_files)} Terraform files")

        # Parse all Terraform files
        resources = []
        for tf_file in tf_files:
            try:
                file_resources = self.parse_terraform_file(tf_file)
                resources.extend(file_resources)
            except Exception as e:
                logger.error(f"Error parsing {tf_file}: {e}")

        environment = Environment(
            name=f"terraform-{directory.name}",
            provider=self._detect_provider(resources),
            resources=resources
        )

        logger.info(f"Parsed {len(resources)} resources from Terraform")
        return environment

    def parse_terraform_file(self, file_path: Path) -> List[Resource]:
        """
        Parse a single Terraform file.

        Args:
            file_path: Path to .tf file

        Returns:
            List of Resource objects
        """
        with open(file_path, 'r') as f:
            try:
                tf_config = hcl2.load(f)
            except Exception as e:
                logger.error(f"HCL2 parse error in {file_path}: {e}")
                return []

        resources = []

        # Parse resource blocks
        if 'resource' in tf_config:
            for resource_type, resource_configs in tf_config['resource'].items():
                for resource_name, config in resource_configs.items():
                    resource = self._convert_to_resource(
                        resource_type,
                        resource_name,
                        config,
                        str(file_path)
                    )
                    if resource:
                        resources.append(resource)

        return resources

    def _convert_to_resource(
        self,
        tf_type: str,
        name: str,
        config: Dict[str, Any],
        source_file: str
    ) -> Optional[Resource]:
        """
        Convert Terraform resource to CloudGuard Resource.

        Args:
            tf_type: Terraform resource type (e.g., aws_s3_bucket)
            name: Resource name
            config: Resource configuration
            source_file: Source .tf file path

        Returns:
            Resource object or None
        """
        # Determine provider and resource type
        provider = self._get_provider_from_type(tf_type)
        resource_type = self._map_terraform_type(tf_type)

        if not resource_type:
            logger.debug(f"Skipping unsupported resource type: {tf_type}")
            return None

        # Extract properties from config
        properties = {}

        # S3 bucket
        if tf_type == "aws_s3_bucket":
            properties['encryption_enabled'] = bool(config.get('server_side_encryption_configuration'))
            properties['versioning_enabled'] = bool(config.get('versioning'))
            properties['public_access'] = not bool(config.get('block_public_acls'))
            properties['logging_enabled'] = bool(config.get('logging'))

        # EC2 instance
        elif tf_type == "aws_instance":
            properties['instance_type'] = config.get('instance_type', 'unknown')
            properties['monitoring_enabled'] = config.get('monitoring', False)
            properties['public_ip'] = bool(config.get('associate_public_ip_address'))

        # Security Group
        elif tf_type == "aws_security_group":
            ingress_rules = config.get('ingress', [])
            properties['ingress_rules'] = self._parse_security_group_rules(ingress_rules)
            properties['allows_all'] = any(
                rule.get('cidr_blocks', [{}])[0] == '0.0.0.0/0'
                for rule in ingress_rules
            )

        # RDS instance
        elif tf_type == "aws_db_instance":
            properties['encrypted'] = config.get('storage_encrypted', False)
            properties['publicly_accessible'] = config.get('publicly_accessible', False)
            properties['backup_retention_period'] = config.get('backup_retention_period', 0)
            properties['multi_az'] = config.get('multi_az', False)

        # Azure Storage Account
        elif tf_type == "azurerm_storage_account":
            properties['encryption_enabled'] = bool(config.get('enable_https_traffic_only'))
            properties['public_access'] = config.get('allow_blob_public_access', False)

        # GCP Storage Bucket
        elif tf_type == "google_storage_bucket":
            properties['encryption_enabled'] = bool(config.get('encryption'))
            properties['versioning_enabled'] = bool(config.get('versioning'))
            properties['public_access'] = config.get('uniform_bucket_level_access', {}).get('enabled') == False

        # Generic properties
        properties.update({
            'terraform_type': tf_type,
            'terraform_name': name,
            'source_file': source_file,
            'raw_config': config
        })

        resource = Resource(
            id=f"{tf_type}.{name}",
            name=name,
            type=resource_type,
            provider=provider,
            region=config.get('region', 'us-east-1'),
            properties=properties,
            tags=config.get('tags', {}),
            metadata={'iac_type': 'terraform', 'source': source_file}
        )

        return resource

    def _get_provider_from_type(self, tf_type: str) -> Provider:
        """Determine cloud provider from Terraform type."""
        if tf_type.startswith('aws_'):
            return Provider.AWS
        elif tf_type.startswith('azurerm_'):
            return Provider.AZURE
        elif tf_type.startswith('google_'):
            return Provider.GCP
        else:
            return Provider.AWS  # Default

    def _map_terraform_type(self, tf_type: str) -> Optional[ResourceType]:
        """Map Terraform type to CloudGuard ResourceType."""
        # AWS
        if 'bucket' in tf_type or 'storage' in tf_type:
            return ResourceType.STORAGE
        elif 'instance' in tf_type or 'vm' in tf_type:
            return ResourceType.COMPUTE
        elif 'db' in tf_type or 'database' in tf_type or 'sql' in tf_type:
            return ResourceType.DATABASE
        elif 'security_group' in tf_type or 'firewall' in tf_type:
            return ResourceType.SECURITY_GROUP
        elif 'vpc' in tf_type or 'network' in tf_type or 'vnet' in tf_type:
            return ResourceType.NETWORK
        elif 'lambda' in tf_type or 'function' in tf_type:
            return ResourceType.FUNCTION
        elif 'role' in tf_type or 'policy' in tf_type:
            return ResourceType.IAM_ROLE
        else:
            return None

    def _parse_security_group_rules(self, ingress_rules: List[Dict]) -> List[Dict]:
        """Parse security group ingress rules."""
        parsed_rules = []

        for rule in ingress_rules:
            parsed_rule = {
                'from_port': rule.get('from_port'),
                'to_port': rule.get('to_port'),
                'protocol': rule.get('protocol'),
                'cidr_blocks': rule.get('cidr_blocks', []),
                'description': rule.get('description', '')
            }
            parsed_rules.append(parsed_rule)

        return parsed_rules

    def _detect_provider(self, resources: List[Resource]) -> Provider:
        """Detect primary cloud provider from resources."""
        if not resources:
            return Provider.AWS  # Default

        # Count providers
        provider_counts = {}
        for resource in resources:
            provider = resource.provider
            provider_counts[provider] = provider_counts.get(provider, 0) + 1

        # Return most common
        return max(provider_counts, key=provider_counts.get)

    def scan_for_security_issues(self, environment: Environment) -> List[Finding]:
        """
        Scan Terraform resources for security issues.

        Args:
            environment: Environment from Terraform parsing

        Returns:
            List of security findings
        """
        findings = []

        for resource in environment.resources:
            # Check for unencrypted storage
            if resource.type == ResourceType.STORAGE:
                if not resource.properties.get('encryption_enabled'):
                    findings.append(Finding(
                        resource=resource,
                        policy_id="iac-tf-001",
                        severity=Severity.HIGH,
                        title="Unencrypted storage in Terraform",
                        description=f"Storage resource '{resource.id}' does not have encryption enabled",
                        remediation="Add encryption configuration to your Terraform resource"
                    ))

            # Check for public access
            if resource.properties.get('public_access') or resource.properties.get('publicly_accessible'):
                findings.append(Finding(
                    resource=resource,
                    policy_id="iac-tf-002",
                    severity=Severity.CRITICAL,
                    title="Public access enabled in Terraform",
                    description=f"Resource '{resource.id}' is configured with public access",
                    remediation="Set public access to false in Terraform configuration"
                ))

            # Check for unrestricted security groups
            if resource.type == ResourceType.SECURITY_GROUP:
                if resource.properties.get('allows_all'):
                    findings.append(Finding(
                        resource=resource,
                        policy_id="iac-tf-003",
                        severity=Severity.HIGH,
                        title="Security group allows traffic from 0.0.0.0/0",
                        description=f"Security group '{resource.id}' allows unrestricted access",
                        remediation="Restrict CIDR blocks to specific IP ranges"
                    ))

        logger.info(f"Terraform scan found {len(findings)} security issues")
        return findings

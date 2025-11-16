"""
CloudFormation IaC scanner for CloudGuard-Anomaly.

Scans AWS CloudFormation templates for security issues before deployment.
"""

import logging
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional

from cloudguard_anomaly.core.models import (
    Resource,
    Environment,
    Provider,
    ResourceType,
    Finding,
    Severity
)

logger = logging.getLogger(__name__)


class CloudFormationScanner:
    """Scans CloudFormation templates for security issues."""

    def __init__(self):
        """Initialize CloudFormation scanner."""
        logger.info("CloudFormation scanner initialized")

    def scan_template(self, template_path: str) -> Environment:
        """
        Scan a CloudFormation template file.

        Args:
            template_path: Path to template file (.yaml, .yml, or .json)

        Returns:
            Environment object with resources from template
        """
        path = Path(template_path)

        if not path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        # Load template
        with open(path, 'r') as f:
            if path.suffix in ['.yaml', '.yml']:
                template = yaml.safe_load(f)
            elif path.suffix == '.json':
                template = json.load(f)
            else:
                raise ValueError(f"Unsupported template format: {path.suffix}")

        # Parse resources
        resources = self._parse_resources(template, str(path))

        environment = Environment(
            name=f"cloudformation-{path.stem}",
            provider=Provider.AWS,  # CloudFormation is AWS-only
            resources=resources
        )

        logger.info(f"Parsed {len(resources)} resources from CloudFormation")
        return environment

    def _parse_resources(self, template: Dict, source_file: str) -> List[Resource]:
        """Parse resources from CloudFormation template."""
        resources = []

        template_resources = template.get('Resources', {})

        for logical_id, resource_def in template_resources.items():
            resource_type_cf = resource_def.get('Type', '')
            properties = resource_def.get('Properties', {})

            resource = self._convert_cfn_resource(
                logical_id,
                resource_type_cf,
                properties,
                source_file
            )

            if resource:
                resources.append(resource)

        return resources

    def _convert_cfn_resource(
        self,
        logical_id: str,
        cfn_type: str,
        properties: Dict[str, Any],
        source_file: str
    ) -> Optional[Resource]:
        """Convert CloudFormation resource to CloudGuard Resource."""
        # Map CFN type to CloudGuard type
        resource_type = self._map_cfn_type(cfn_type)

        if not resource_type:
            logger.debug(f"Skipping unsupported CFN type: {cfn_type}")
            return None

        # Extract security-relevant properties
        extracted_props = {}

        # S3 Bucket
        if cfn_type == 'AWS::S3::Bucket':
            encryption_config = properties.get('BucketEncryption')
            extracted_props['encryption_enabled'] = bool(encryption_config)

            versioning_config = properties.get('VersioningConfiguration', {})
            extracted_props['versioning_enabled'] = versioning_config.get('Status') == 'Enabled'

            public_access_config = properties.get('PublicAccessBlockConfiguration', {})
            extracted_props['public_access'] = not all([
                public_access_config.get('BlockPublicAcls', False),
                public_access_config.get('BlockPublicPolicy', False),
                public_access_config.get('IgnorePublicAcls', False),
                public_access_config.get('RestrictPublicBuckets', False)
            ])

        # EC2 Instance
        elif cfn_type == 'AWS::EC2::Instance':
            extracted_props['instance_type'] = properties.get('InstanceType', 'unknown')
            extracted_props['monitoring_enabled'] = properties.get('Monitoring', False)
            extracted_props['public_ip'] = bool(properties.get('NetworkInterfaces', [{}])[0].get('AssociatePublicIpAddress'))

        # Security Group
        elif cfn_type == 'AWS::EC2::SecurityGroup':
            ingress_rules = properties.get('SecurityGroupIngress', [])
            extracted_props['ingress_rules'] = ingress_rules
            extracted_props['allows_all'] = any(
                rule.get('CidrIp') == '0.0.0.0/0' or rule.get('CidrIpv6') == '::/0'
                for rule in ingress_rules
            )

        # RDS Instance
        elif cfn_type == 'AWS::RDS::DBInstance':
            extracted_props['encrypted'] = properties.get('StorageEncrypted', False)
            extracted_props['publicly_accessible'] = properties.get('PubliclyAccessible', False)
            extracted_props['backup_retention_period'] = properties.get('BackupRetentionPeriod', 0)
            extracted_props['multi_az'] = properties.get('MultiAZ', False)

        # Generic properties
        extracted_props.update({
            'cloudformation_type': cfn_type,
            'logical_id': logical_id,
            'source_file': source_file,
            'raw_properties': properties
        })

        resource = Resource(
            id=f"cfn-{logical_id}",
            name=logical_id,
            type=resource_type,
            provider=Provider.AWS,
            region='us-east-1',  # Default, may be overridden
            properties=extracted_props,
            tags=properties.get('Tags', {}),
            metadata={'iac_type': 'cloudformation', 'source': source_file}
        )

        return resource

    def _map_cfn_type(self, cfn_type: str) -> Optional[ResourceType]:
        """Map CloudFormation type to CloudGuard ResourceType."""
        type_mapping = {
            'AWS::S3::Bucket': ResourceType.STORAGE,
            'AWS::EC2::Instance': ResourceType.COMPUTE,
            'AWS::RDS::DBInstance': ResourceType.DATABASE,
            'AWS::RDS::DBCluster': ResourceType.DATABASE,
            'AWS::EC2::SecurityGroup': ResourceType.SECURITY_GROUP,
            'AWS::EC2::VPC': ResourceType.NETWORK,
            'AWS::Lambda::Function': ResourceType.FUNCTION,
            'AWS::IAM::Role': ResourceType.IAM_ROLE,
            'AWS::IAM::Policy': ResourceType.IAM_ROLE,
        }

        return type_mapping.get(cfn_type)

    def scan_for_security_issues(self, environment: Environment) -> List[Finding]:
        """Scan CloudFormation resources for security issues."""
        findings = []

        for resource in environment.resources:
            # Check for unencrypted storage
            if resource.type == ResourceType.STORAGE:
                if not resource.properties.get('encryption_enabled'):
                    findings.append(Finding(
                        resource=resource,
                        policy_id="iac-cfn-001",
                        severity=Severity.HIGH,
                        title="Unencrypted S3 bucket in CloudFormation",
                        description=f"S3 bucket '{resource.name}' does not have encryption enabled",
                        remediation="Add BucketEncryption configuration to your CloudFormation template"
                    ))

            # Check for public access
            if resource.properties.get('public_access') or resource.properties.get('publicly_accessible'):
                findings.append(Finding(
                    resource=resource,
                    policy_id="iac-cfn-002",
                    severity=Severity.CRITICAL,
                    title="Public access enabled in CloudFormation",
                    description=f"Resource '{resource.name}' is configured with public access",
                    remediation="Configure PublicAccessBlockConfiguration in CloudFormation"
                ))

            # Check for unrestricted security groups
            if resource.type == ResourceType.SECURITY_GROUP:
                if resource.properties.get('allows_all'):
                    findings.append(Finding(
                        resource=resource,
                        policy_id="iac-cfn-003",
                        severity=Severity.HIGH,
                        title="Security group allows traffic from 0.0.0.0/0",
                        description=f"Security group '{resource.name}' allows unrestricted access",
                        remediation="Restrict CidrIp to specific IP ranges in CloudFormation"
                    ))

        logger.info(f"CloudFormation scan found {len(findings)} security issues")
        return findings

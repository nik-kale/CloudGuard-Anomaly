"""AWS provider implementation."""

from typing import Any, Dict, List

from cloudguard_anomaly.core.models import Provider, Resource, ResourceType
from cloudguard_anomaly.providers.base import BaseProvider


class AWSProvider(BaseProvider):
    """AWS-specific provider implementation."""

    def __init__(self):
        super().__init__("aws")

    def get_resource_type_mapping(self) -> Dict[str, ResourceType]:
        """Map AWS resource types to standard types."""
        return {
            # Compute
            "aws_instance": ResourceType.COMPUTE,
            "aws_ec2_instance": ResourceType.COMPUTE,
            "aws_lambda_function": ResourceType.FUNCTION,
            # Storage
            "aws_s3_bucket": ResourceType.STORAGE,
            "aws_ebs_volume": ResourceType.STORAGE,
            "aws_efs_file_system": ResourceType.STORAGE,
            # Database
            "aws_rds_instance": ResourceType.DATABASE,
            "aws_dynamodb_table": ResourceType.DATABASE,
            "aws_redshift_cluster": ResourceType.DATABASE,
            # Network
            "aws_vpc": ResourceType.NETWORK,
            "aws_subnet": ResourceType.NETWORK,
            "aws_security_group": ResourceType.SECURITY_GROUP,
            "aws_network_acl": ResourceType.NETWORK,
            "aws_route_table": ResourceType.NETWORK,
            # IAM
            "aws_iam_role": ResourceType.IAM_ROLE,
            "aws_iam_policy": ResourceType.IAM_POLICY,
            "aws_iam_user": ResourceType.IAM_ROLE,
            # Load Balancers
            "aws_elb": ResourceType.LOAD_BALANCER,
            "aws_alb": ResourceType.LOAD_BALANCER,
            "aws_lb": ResourceType.LOAD_BALANCER,
            # Other
            "aws_api_gateway": ResourceType.API_GATEWAY,
            "aws_sqs_queue": ResourceType.QUEUE,
            "aws_sns_topic": ResourceType.TOPIC,
            "aws_kms_key": ResourceType.KEY,
            "aws_secretsmanager_secret": ResourceType.SECRET,
        }

    def normalize_resource(self, raw_resource: Dict[str, Any]) -> Resource:
        """Normalize AWS resource to standard format."""
        resource_type = self.detect_resource_type(raw_resource)

        return Resource(
            id=raw_resource.get("id", raw_resource.get("arn", "unknown")),
            name=raw_resource.get("name", raw_resource.get("id", "unnamed")),
            type=resource_type,
            provider=Provider.AWS,
            region=self.extract_region(raw_resource),
            properties=raw_resource.get("properties", raw_resource),
            tags=self.extract_tags(raw_resource),
            metadata={
                "arn": raw_resource.get("arn"),
                "account_id": raw_resource.get("account_id"),
            },
        )

    def extract_tags(self, raw_resource: Dict[str, Any]) -> Dict[str, str]:
        """Extract tags from AWS resource format."""
        tags = raw_resource.get("tags", {})

        # AWS tags can be in different formats
        if isinstance(tags, list):
            # [{"Key": "k1", "Value": "v1"}] format
            return {tag["Key"]: tag["Value"] for tag in tags}
        elif isinstance(tags, dict):
            # {"k1": "v1"} format
            return tags

        return {}

    def extract_region(self, raw_resource: Dict[str, Any]) -> str:
        """Extract region from AWS resource."""
        # Try different region fields
        region = raw_resource.get("region")
        if region:
            return region

        # Extract from ARN if available
        arn = raw_resource.get("arn", "")
        if arn:
            parts = arn.split(":")
            if len(parts) > 3:
                return parts[3] or "global"

        return "us-east-1"  # Default region

    def validate_resource(self, resource: Resource) -> List[str]:
        """Validate AWS resource configuration."""
        errors = []

        # Basic validation
        if not resource.id:
            errors.append("Resource must have an ID")

        if not resource.name:
            errors.append("Resource must have a name")

        # Type-specific validation
        if resource.type == ResourceType.STORAGE:
            errors.extend(self._validate_s3_bucket(resource))
        elif resource.type == ResourceType.SECURITY_GROUP:
            errors.extend(self._validate_security_group(resource))
        elif resource.type == ResourceType.IAM_ROLE:
            errors.extend(self._validate_iam_role(resource))

        return errors

    def _validate_s3_bucket(self, resource: Resource) -> List[str]:
        """Validate S3 bucket configuration."""
        errors = []
        props = resource.properties

        # Check bucket name
        bucket_name = props.get("bucket_name", props.get("name"))
        if not bucket_name:
            errors.append("S3 bucket must have a name")

        return errors

    def _validate_security_group(self, resource: Resource) -> List[str]:
        """Validate security group configuration."""
        errors = []
        props = resource.properties

        # Check ingress rules
        ingress_rules = props.get("ingress", [])
        if not isinstance(ingress_rules, list):
            errors.append("Security group ingress must be a list")

        return errors

    def _validate_iam_role(self, resource: Resource) -> List[str]:
        """Validate IAM role configuration."""
        errors = []
        props = resource.properties

        # Check assume role policy
        if "assume_role_policy" not in props:
            errors.append("IAM role must have assume_role_policy")

        return errors

"""
AWS Live Integration for CloudGuard-Anomaly.

Provides real-time resource discovery and analysis from live AWS accounts.
"""

import logging
from typing import List, Optional, Dict, Any

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from cloudguard_anomaly.core.models import Resource, ResourceType, Provider, Environment

logger = logging.getLogger(__name__)


class AWSLiveIntegration:
    """Real-time AWS resource discovery and analysis."""

    def __init__(
        self,
        profile: Optional[str] = None,
        region: str = "us-east-1",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
    ):
        """
        Initialize AWS live integration.

        Args:
            profile: AWS profile name
            region: AWS region
            access_key: AWS access key ID
            secret_key: AWS secret access key
        """
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 is required for AWS live integration. Install with: pip install boto3")

        if access_key and secret_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
        else:
            self.session = boto3.Session(profile_name=profile, region_name=region)

        self.region = region
        self.account_id = self._get_account_id()

        logger.info(f"Initialized AWS integration for account {self.account_id} in {region}")

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as e:
            logger.warning(f"Could not get account ID: {e}")
            return "unknown"

    def discover_all_resources(self) -> Environment:
        """
        Discover all resources across AWS account.

        Returns:
            Environment with discovered resources
        """
        resources = []

        logger.info("Starting AWS resource discovery...")

        # Discover different resource types
        resources.extend(self._discover_ec2_instances())
        resources.extend(self._discover_s3_buckets())
        resources.extend(self._discover_rds_instances())
        resources.extend(self._discover_security_groups())
        resources.extend(self._discover_iam_roles())
        resources.extend(self._discover_lambda_functions())

        logger.info(f"Discovered {len(resources)} AWS resources")

        return Environment(
            name=f"aws-live-{self.account_id}",
            provider=Provider.AWS,
            resources=resources,
            metadata={
                "account_id": self.account_id,
                "region": self.region,
                "discovery_type": "live",
            },
        )

    def _discover_s3_buckets(self) -> List[Resource]:
        """Discover S3 buckets with full configuration."""
        resources = []

        try:
            s3 = self.session.client("s3")
            buckets = s3.list_buckets()["Buckets"]

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    # Get bucket location
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    location = location_response["LocationConstraint"] or "us-east-1"

                    # Get encryption
                    encrypted = False
                    encryption_config = None
                    try:
                        encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                        encrypted = True
                        encryption_config = encryption_response["ServerSideEncryptionConfiguration"]
                    except ClientError:
                        pass

                    # Get public access block
                    public_access = {
                        "BlockPublicAcls": False,
                        "BlockPublicPolicy": False,
                        "IgnorePublicAcls": False,
                        "RestrictPublicBuckets": False,
                    }
                    try:
                        pab_response = s3.get_public_access_block(Bucket=bucket_name)
                        public_access = pab_response["PublicAccessBlockConfiguration"]
                    except ClientError:
                        pass

                    # Get versioning
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)

                    # Get tags
                    tags = {}
                    try:
                        tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                        tags = {tag["Key"]: tag["Value"] for tag in tags_response["TagSet"]}
                    except ClientError:
                        pass

                    resource = Resource(
                        id=f"arn:aws:s3:::{bucket_name}",
                        name=bucket_name,
                        type=ResourceType.STORAGE,
                        provider=Provider.AWS,
                        region=location,
                        properties={
                            "bucket_name": bucket_name,
                            "encrypted": encrypted,
                            "encryption": encryption_config,
                            "versioning": versioning,
                            "public_access_block_configuration": public_access,
                            "creation_date": bucket["CreationDate"].isoformat(),
                        },
                        tags=tags,
                        metadata={"arn": f"arn:aws:s3:::{bucket_name}"},
                    )

                    resources.append(resource)

                except Exception as e:
                    logger.warning(f"Failed to get details for bucket {bucket_name}: {e}")

        except Exception as e:
            logger.error(f"Failed to discover S3 buckets: {e}")

        logger.info(f"Discovered {len(resources)} S3 buckets")
        return resources

    def _discover_ec2_instances(self) -> List[Resource]:
        """Discover EC2 instances."""
        resources = []

        try:
            ec2 = self.session.client("ec2")
            paginator = ec2.get_paginator("describe_instances")

            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}

                        # Get instance metadata
                        metadata_options = instance.get("MetadataOptions", {})

                        resource = Resource(
                            id=instance["InstanceId"],
                            name=tags.get("Name", instance["InstanceId"]),
                            type=ResourceType.COMPUTE,
                            provider=Provider.AWS,
                            region=instance["Placement"]["AvailabilityZone"][:-1],
                            properties={
                                "instance_type": instance["InstanceType"],
                                "state": instance["State"]["Name"],
                                "public_ip": instance.get("PublicIpAddress"),
                                "private_ip": instance.get("PrivateIpAddress"),
                                "vpc_id": instance.get("VpcId"),
                                "subnet_id": instance.get("SubnetId"),
                                "security_groups": instance.get("SecurityGroups", []),
                                "iam_instance_profile": instance.get("IamInstanceProfile"),
                                "metadata_options": metadata_options,
                                "launch_time": instance["LaunchTime"].isoformat(),
                            },
                            tags=tags,
                            metadata={
                                "arn": f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{instance['InstanceId']}"
                            },
                        )

                        resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover EC2 instances: {e}")

        logger.info(f"Discovered {len(resources)} EC2 instances")
        return resources

    def _discover_rds_instances(self) -> List[Resource]:
        """Discover RDS database instances."""
        resources = []

        try:
            rds = self.session.client("rds")
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    # Get tags
                    tags = {}
                    try:
                        tags_response = rds.list_tags_for_resource(
                            ResourceName=db["DBInstanceArn"]
                        )
                        tags = {tag["Key"]: tag["Value"] for tag in tags_response["TagList"]}
                    except Exception:
                        pass

                    resource = Resource(
                        id=db["DBInstanceIdentifier"],
                        name=db["DBInstanceIdentifier"],
                        type=ResourceType.DATABASE,
                        provider=Provider.AWS,
                        region=db["AvailabilityZone"][:-1] if db.get("AvailabilityZone") else self.region,
                        properties={
                            "engine": db["Engine"],
                            "engine_version": db["EngineVersion"],
                            "instance_class": db["DBInstanceClass"],
                            "publicly_accessible": db["PubliclyAccessible"],
                            "encrypted": db.get("StorageEncrypted", False),
                            "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                            "multi_az": db.get("MultiAZ", False),
                            "status": db["DBInstanceStatus"],
                        },
                        tags=tags,
                        metadata={"arn": db["DBInstanceArn"]},
                    )

                    resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover RDS instances: {e}")

        logger.info(f"Discovered {len(resources)} RDS instances")
        return resources

    def _discover_security_groups(self) -> List[Resource]:
        """Discover security groups."""
        resources = []

        try:
            ec2 = self.session.client("ec2")
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    # Get tags
                    tags = {tag["Key"]: tag["Value"] for tag in sg.get("Tags", [])}

                    resource = Resource(
                        id=sg["GroupId"],
                        name=sg["GroupName"],
                        type=ResourceType.SECURITY_GROUP,
                        provider=Provider.AWS,
                        region=self.region,
                        properties={
                            "group_name": sg["GroupName"],
                            "description": sg["Description"],
                            "vpc_id": sg.get("VpcId"),
                            "ingress": sg.get("IpPermissions", []),
                            "egress": sg.get("IpPermissionsEgress", []),
                        },
                        tags=tags,
                        metadata={
                            "arn": f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg['GroupId']}"
                        },
                    )

                    resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover security groups: {e}")

        logger.info(f"Discovered {len(resources)} security groups")
        return resources

    def _discover_iam_roles(self) -> List[Resource]:
        """Discover IAM roles."""
        resources = []

        try:
            iam = self.session.client("iam")
            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page["Roles"]:
                    # Get inline policies
                    inline_policies = []
                    try:
                        policy_paginator = iam.get_paginator("list_role_policies")
                        for policy_page in policy_paginator.paginate(RoleName=role["RoleName"]):
                            inline_policies.extend(policy_page["PolicyNames"])
                    except Exception:
                        pass

                    # Get tags
                    tags = {tag["Key"]: tag["Value"] for tag in role.get("Tags", [])}

                    resource = Resource(
                        id=role["RoleId"],
                        name=role["RoleName"],
                        type=ResourceType.IAM_ROLE,
                        provider=Provider.AWS,
                        region="global",
                        properties={
                            "role_name": role["RoleName"],
                            "assume_role_policy": role["AssumeRolePolicyDocument"],
                            "inline_policies": inline_policies,
                            "created_date": role["CreateDate"].isoformat(),
                        },
                        tags=tags,
                        metadata={"arn": role["Arn"]},
                    )

                    resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover IAM roles: {e}")

        logger.info(f"Discovered {len(resources)} IAM roles")
        return resources

    def _discover_lambda_functions(self) -> List[Resource]:
        """Discover Lambda functions."""
        resources = []

        try:
            lambda_client = self.session.client("lambda")
            paginator = lambda_client.get_paginator("list_functions")

            for page in paginator.paginate():
                for func in page["Functions"]:
                    # Get tags
                    tags = {}
                    try:
                        tags_response = lambda_client.list_tags(Resource=func["FunctionArn"])
                        tags = tags_response.get("Tags", {})
                    except Exception:
                        pass

                    resource = Resource(
                        id=func["FunctionName"],
                        name=func["FunctionName"],
                        type=ResourceType.FUNCTION,
                        provider=Provider.AWS,
                        region=self.region,
                        properties={
                            "runtime": func.get("Runtime"),
                            "handler": func.get("Handler"),
                            "role": func.get("Role"),
                            "vpc_config": func.get("VpcConfig"),
                            "environment": func.get("Environment"),
                        },
                        tags=tags,
                        metadata={"arn": func["FunctionArn"]},
                    )

                    resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover Lambda functions: {e}")

        logger.info(f"Discovered {len(resources)} Lambda functions")
        return resources

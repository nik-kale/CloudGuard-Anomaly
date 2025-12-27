"""
Multi-account and multi-region AWS scanner for CloudGuard-Anomaly.

Supports scanning across AWS Organizations with cross-account role assumption
and parallel region scanning for comprehensive security posture analysis.
"""

import logging
import concurrent.futures
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from cloudguard_anomaly.core.models import Environment, Resource, Provider

logger = logging.getLogger(__name__)


@dataclass
class AWSAccount:
    """Represents an AWS account to scan."""
    account_id: str
    account_name: str
    role_arn: Optional[str] = None
    regions: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class MultiAccountScanResult:
    """Results from multi-account scan."""
    organization_id: Optional[str]
    accounts_scanned: List[str]
    regions_scanned: List[str]
    total_resources: int
    environments: List[Environment]
    scan_timestamp: datetime
    errors: List[Dict[str, str]] = field(default_factory=list)


class AWSMultiAccountScanner:
    """
    Scans multiple AWS accounts and regions for security posture analysis.

    Features:
    - AWS Organizations integration
    - Cross-account role assumption (STS AssumeRole)
    - Parallel region scanning
    - Centralized findings aggregation
    - Support for custom account lists
    """

    def __init__(
        self,
        master_profile: Optional[str] = None,
        default_regions: Optional[List[str]] = None,
        max_workers: int = 10
    ):
        """
        Initialize multi-account scanner.

        Args:
            master_profile: AWS profile for master/management account
            default_regions: Default regions to scan if not specified per account
            max_workers: Maximum parallel workers for scanning
        """
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 required for AWS scanning. Install with: pip install boto3")

        self.master_profile = master_profile
        self.default_regions = default_regions or ['us-east-1', 'us-west-2']
        self.max_workers = max_workers

        # Initialize master session
        if master_profile:
            self.master_session = boto3.Session(profile_name=master_profile)
        else:
            self.master_session = boto3.Session()

        logger.info(f"AWS Multi-Account Scanner initialized (regions: {self.default_regions})")

    def discover_organization_accounts(self) -> List[AWSAccount]:
        """
        Discover all accounts in AWS Organization.

        Returns:
            List of AWS accounts in the organization
        """
        logger.info("Discovering AWS Organization accounts...")

        accounts = []

        try:
            org_client = self.master_session.client('organizations')

            # Get organization info
            try:
                org_info = org_client.describe_organization()
                org_id = org_info['Organization']['Id']
                logger.info(f"Found organization: {org_id}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                    logger.warning("AWS Organizations not enabled for this account")
                    return []
                raise

            # List accounts
            paginator = org_client.get_paginator('list_accounts')

            for page in paginator.paginate():
                for account in page['Accounts']:
                    if account['Status'] == 'ACTIVE':
                        accounts.append(AWSAccount(
                            account_id=account['Id'],
                            account_name=account['Name'],
                            role_arn=None,  # Will be set per account
                            regions=self.default_regions.copy()
                        ))

            logger.info(f"Discovered {len(accounts)} active accounts")

        except ClientError as e:
            logger.error(f"Error discovering organization accounts: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        return accounts

    def scan_accounts(
        self,
        accounts: List[AWSAccount],
        assume_role_name: str = 'CloudGuardAnomalyScanner',
        services: Optional[List[str]] = None
    ) -> MultiAccountScanResult:
        """
        Scan multiple AWS accounts across regions.

        Args:
            accounts: List of AWS accounts to scan
            assume_role_name: Role name to assume in each account
            services: AWS services to scan (default: all supported)

        Returns:
            Multi-account scan results
        """
        logger.info(f"Starting multi-account scan across {len(accounts)} accounts")

        start_time = datetime.utcnow()
        environments = []
        errors = []
        accounts_scanned = []
        regions_scanned = set()

        # Scan accounts in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_account = {
                executor.submit(
                    self._scan_single_account,
                    account,
                    assume_role_name,
                    services
                ): account
                for account in accounts
            }

            for future in concurrent.futures.as_completed(future_to_account):
                account = future_to_account[future]

                try:
                    account_envs, account_errors = future.result()

                    if account_envs:
                        environments.extend(account_envs)
                        accounts_scanned.append(account.account_id)

                        # Track regions
                        for env in account_envs:
                            if hasattr(env, 'region'):
                                regions_scanned.add(env.region)

                    if account_errors:
                        errors.extend(account_errors)

                    logger.info(
                        f"Account {account.account_id} scan complete: "
                        f"{len(account_envs)} environments, {len(account_errors)} errors"
                    )

                except Exception as e:
                    logger.error(f"Failed to scan account {account.account_id}: {e}")
                    errors.append({
                        'account_id': account.account_id,
                        'error': str(e),
                        'type': 'account_scan_failure'
                    })

        # Calculate totals
        total_resources = sum(len(env.resources) for env in environments)

        result = MultiAccountScanResult(
            organization_id=None,  # TODO: Get from org_info
            accounts_scanned=accounts_scanned,
            regions_scanned=sorted(list(regions_scanned)),
            total_resources=total_resources,
            environments=environments,
            scan_timestamp=start_time,
            errors=errors
        )

        logger.info(
            f"Multi-account scan complete: {len(accounts_scanned)} accounts, "
            f"{len(regions_scanned)} regions, {total_resources} resources"
        )

        return result

    def _scan_single_account(
        self,
        account: AWSAccount,
        assume_role_name: str,
        services: Optional[List[str]]
    ) -> tuple[List[Environment], List[Dict]]:
        """Scan a single AWS account across all specified regions."""
        environments = []
        errors = []

        # Assume role in target account if role_arn provided
        if account.role_arn:
            session = self._assume_role(account.role_arn)
        else:
            # Construct role ARN from account ID and role name
            role_arn = f"arn:aws:iam::{account.account_id}:role/{assume_role_name}"
            try:
                session = self._assume_role(role_arn)
            except Exception as e:
                logger.warning(
                    f"Could not assume role {role_arn}: {e}. "
                    f"Using current credentials for account {account.account_id}"
                )
                session = self.master_session

        # Scan each region in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(account.regions)) as executor:
            future_to_region = {
                executor.submit(
                    self._scan_single_region,
                    session,
                    region,
                    account,
                    services
                ): region
                for region in account.regions
            }

            for future in concurrent.futures.as_completed(future_to_region):
                region = future_to_region[future]

                try:
                    env = future.result()
                    if env:
                        environments.append(env)
                except Exception as e:
                    logger.error(f"Failed to scan region {region} in account {account.account_id}: {e}")
                    errors.append({
                        'account_id': account.account_id,
                        'region': region,
                        'error': str(e),
                        'type': 'region_scan_failure'
                    })

        return environments, errors

    def _scan_single_region(
        self,
        session: boto3.Session,
        region: str,
        account: AWSAccount,
        services: Optional[List[str]]
    ) -> Optional[Environment]:
        """Scan a single region for an account."""
        logger.debug(f"Scanning region {region} for account {account.account_id}")

        # Import AWS live scanner
        from cloudguard_anomaly.integrations.aws_live import AWSLiveIntegration

        try:
            # Create scanner for this region
            scanner = AWSLiveIntegration(
                profile_name=None,  # Using session instead
                region=region,
                session=session
            )

            # Discover resources
            resources = scanner.discover_resources()

            # Create environment
            env = Environment(
                name=f"{account.account_name}-{region}",
                provider=Provider.AWS,
                resources=resources,
                metadata={
                    'account_id': account.account_id,
                    'account_name': account.account_name,
                    'region': region,
                    'scan_type': 'multi_account'
                }
            )

            # Add region attribute
            env.region = region

            logger.debug(f"Found {len(resources)} resources in {region}/{account.account_id}")

            return env

        except Exception as e:
            logger.error(f"Error scanning {region} in account {account.account_id}: {e}")
            return None

    def _assume_role(self, role_arn: str, duration_seconds: int = 3600) -> boto3.Session:
        """
        Assume an IAM role and return a session.

        Args:
            role_arn: ARN of role to assume
            duration_seconds: Session duration (default: 1 hour)

        Returns:
            boto3.Session with assumed role credentials
        """
        logger.debug(f"Assuming role: {role_arn}")

        sts_client = self.master_session.client('sts')

        try:
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='CloudGuardAnomalyScanner',
                DurationSeconds=duration_seconds
            )

            credentials = response['Credentials']

            # Create new session with temporary credentials
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

            return session

        except ClientError as e:
            logger.error(f"Failed to assume role {role_arn}: {e}")
            raise

    def generate_aggregate_report(self, result: MultiAccountScanResult) -> Dict[str, Any]:
        """
        Generate aggregate report across all accounts and regions.

        Args:
            result: Multi-account scan result

        Returns:
            Aggregate report dictionary
        """
        report = {
            'scan_summary': {
                'timestamp': result.scan_timestamp.isoformat(),
                'accounts_scanned': len(result.accounts_scanned),
                'regions_scanned': len(result.regions_scanned),
                'total_resources': result.total_resources,
                'total_errors': len(result.errors)
            },
            'accounts': result.accounts_scanned,
            'regions': result.regions_scanned,
            'resource_breakdown': {},
            'account_breakdown': [],
            'region_breakdown': [],
            'errors': result.errors
        }

        # Resource breakdown by type
        resource_types = {}
        for env in result.environments:
            for resource in env.resources:
                rtype = resource.type.value if hasattr(resource.type, 'value') else str(resource.type)
                resource_types[rtype] = resource_types.get(rtype, 0) + 1

        report['resource_breakdown'] = resource_types

        # Account breakdown
        account_resources = {}
        for env in result.environments:
            account_id = env.metadata.get('account_id', 'unknown')
            if account_id not in account_resources:
                account_resources[account_id] = {
                    'account_id': account_id,
                    'account_name': env.metadata.get('account_name', account_id),
                    'resource_count': 0,
                    'regions': []
                }
            account_resources[account_id]['resource_count'] += len(env.resources)
            region = env.metadata.get('region')
            if region and region not in account_resources[account_id]['regions']:
                account_resources[account_id]['regions'].append(region)

        report['account_breakdown'] = list(account_resources.values())

        # Region breakdown
        region_resources = {}
        for env in result.environments:
            region = env.metadata.get('region', 'unknown')
            if region not in region_resources:
                region_resources[region] = {
                    'region': region,
                    'resource_count': 0,
                    'accounts': []
                }
            region_resources[region]['resource_count'] += len(env.resources)
            account_id = env.metadata.get('account_id')
            if account_id and account_id not in region_resources[region]['accounts']:
                region_resources[region]['accounts'].append(account_id)

        report['region_breakdown'] = list(region_resources.values())

        return report


def create_cross_account_role_policy() -> Dict[str, Any]:
    """
    Generate IAM policy for cross-account scanning role.

    Returns:
        IAM policy document dictionary
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:Describe*",
                    "s3:GetBucket*",
                    "s3:ListAllMyBuckets",
                    "rds:Describe*",
                    "lambda:List*",
                    "lambda:GetFunction",
                    "iam:List*",
                    "iam:Get*",
                    "cloudtrail:Describe*",
                    "cloudtrail:LookupEvents",
                    "cloudwatch:Describe*",
                    "config:Describe*",
                    "guardduty:List*",
                    "securityhub:Describe*",
                    "kms:List*",
                    "kms:Describe*"
                ],
                "Resource": "*"
            }
        ]
    }


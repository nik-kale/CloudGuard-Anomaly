"""
Azure Live Integration for CloudGuard-Anomaly.

Provides real-time resource discovery and analysis from live Azure subscriptions.
"""

import logging
from typing import List, Optional

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False

from cloudguard_anomaly.core.models import Resource, ResourceType, Provider, Environment

logger = logging.getLogger(__name__)


class AzureLiveIntegration:
    """Real-time Azure resource discovery and analysis."""

    def __init__(self, subscription_id: str):
        """
        Initialize Azure live integration.

        Args:
            subscription_id: Azure subscription ID
        """
        if not AZURE_SDK_AVAILABLE:
            raise ImportError("Azure SDK is required. Install with: pip install azure-identity azure-mgmt-resource azure-mgmt-storage azure-mgmt-sql azure-mgmt-compute")

        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()

        self.resource_client = ResourceManagementClient(self.credential, subscription_id)
        self.storage_client = StorageManagementClient(self.credential, subscription_id)
        self.sql_client = SqlManagementClient(self.credential, subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, subscription_id)

        logger.info(f"Initialized Azure integration for subscription {subscription_id}")

    def discover_all_resources(self) -> Environment:
        """Discover all resources across Azure subscription."""
        resources = []

        logger.info("Starting Azure resource discovery...")

        resources.extend(self._discover_storage_accounts())
        resources.extend(self._discover_sql_databases())
        resources.extend(self._discover_virtual_machines())

        logger.info(f"Discovered {len(resources)} Azure resources")

        return Environment(
            name=f"azure-live-{self.subscription_id[:8]}",
            provider=Provider.AZURE,
            resources=resources,
            metadata={
                "subscription_id": self.subscription_id,
                "discovery_type": "live",
            },
        )

    def _discover_storage_accounts(self) -> List[Resource]:
        """Discover Azure storage accounts."""
        resources = []

        try:
            for account in self.storage_client.storage_accounts.list():
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type=ResourceType.STORAGE,
                    provider=Provider.AZURE,
                    region=account.location,
                    properties={
                        "enable_https_traffic_only": account.enable_https_traffic_only,
                        "minimum_tls_version": str(account.minimum_tls_version) if account.minimum_tls_version else None,
                        "allow_blob_public_access": account.allow_blob_public_access,
                    },
                    tags=account.tags or {},
                    metadata={"resource_group": account.id.split("/")[4]},
                )
                resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover storage accounts: {e}")

        return resources

    def _discover_sql_databases(self) -> List[Resource]:
        """Discover Azure SQL databases."""
        resources = []

        try:
            for server in self.sql_client.servers.list():
                rg = server.id.split("/")[4]

                for db in self.sql_client.databases.list_by_server(rg, server.name):
                    resource = Resource(
                        id=db.id,
                        name=db.name,
                        type=ResourceType.DATABASE,
                        provider=Provider.AZURE,
                        region=db.location,
                        properties={
                            "server_name": server.name,
                            "status": db.status,
                        },
                        tags=db.tags or {},
                        metadata={"resource_group": rg},
                    )
                    resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover SQL databases: {e}")

        return resources

    def _discover_virtual_machines(self) -> List[Resource]:
        """Discover Azure virtual machines."""
        resources = []

        try:
            for vm in self.compute_client.virtual_machines.list_all():
                resource = Resource(
                    id=vm.id,
                    name=vm.name,
                    type=ResourceType.COMPUTE,
                    provider=Provider.AZURE,
                    region=vm.location,
                    properties={
                        "vm_size": vm.hardware_profile.vm_size,
                        "os_type": str(vm.storage_profile.os_disk.os_type),
                    },
                    tags=vm.tags or {},
                    metadata={"resource_group": vm.id.split("/")[4]},
                )
                resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover VMs: {e}")

        return resources

"""Azure provider implementation."""

from typing import Any, Dict, List

from cloudguard_anomaly.core.models import Provider, Resource, ResourceType
from cloudguard_anomaly.providers.base import BaseProvider


class AzureProvider(BaseProvider):
    """Azure-specific provider implementation."""

    def __init__(self):
        super().__init__("azure")

    def get_resource_type_mapping(self) -> Dict[str, ResourceType]:
        """Map Azure resource types to standard types."""
        return {
            # Compute
            "azurerm_virtual_machine": ResourceType.COMPUTE,
            "azurerm_linux_virtual_machine": ResourceType.COMPUTE,
            "azurerm_windows_virtual_machine": ResourceType.COMPUTE,
            "azurerm_function_app": ResourceType.FUNCTION,
            # Storage
            "azurerm_storage_account": ResourceType.STORAGE,
            "azurerm_storage_blob": ResourceType.STORAGE,
            "azurerm_managed_disk": ResourceType.STORAGE,
            # Database
            "azurerm_sql_database": ResourceType.DATABASE,
            "azurerm_postgresql_server": ResourceType.DATABASE,
            "azurerm_mysql_server": ResourceType.DATABASE,
            "azurerm_cosmosdb_account": ResourceType.DATABASE,
            # Network
            "azurerm_virtual_network": ResourceType.NETWORK,
            "azurerm_subnet": ResourceType.NETWORK,
            "azurerm_network_security_group": ResourceType.SECURITY_GROUP,
            # IAM
            "azurerm_role_assignment": ResourceType.IAM_ROLE,
            "azurerm_role_definition": ResourceType.IAM_POLICY,
            # Load Balancers
            "azurerm_lb": ResourceType.LOAD_BALANCER,
            "azurerm_application_gateway": ResourceType.LOAD_BALANCER,
            # Other
            "azurerm_api_management": ResourceType.API_GATEWAY,
            "azurerm_key_vault": ResourceType.SECRET,
            "azurerm_key_vault_key": ResourceType.KEY,
        }

    def normalize_resource(self, raw_resource: Dict[str, Any]) -> Resource:
        """Normalize Azure resource to standard format."""
        resource_type = self.detect_resource_type(raw_resource)

        return Resource(
            id=raw_resource.get("id", raw_resource.get("resource_id", "unknown")),
            name=raw_resource.get("name", "unnamed"),
            type=resource_type,
            provider=Provider.AZURE,
            region=self.extract_region(raw_resource),
            properties=raw_resource.get("properties", raw_resource),
            tags=self.extract_tags(raw_resource),
            metadata={
                "resource_group": raw_resource.get("resource_group"),
                "subscription_id": raw_resource.get("subscription_id"),
            },
        )

    def extract_tags(self, raw_resource: Dict[str, Any]) -> Dict[str, str]:
        """Extract tags from Azure resource format."""
        return raw_resource.get("tags", {})

    def extract_region(self, raw_resource: Dict[str, Any]) -> str:
        """Extract location/region from Azure resource."""
        return raw_resource.get("location", raw_resource.get("region", "eastus"))

    def validate_resource(self, resource: Resource) -> List[str]:
        """Validate Azure resource configuration."""
        errors = []

        if not resource.id:
            errors.append("Resource must have an ID")

        if not resource.name:
            errors.append("Resource must have a name")

        # Azure-specific validation
        if "resource_group" not in resource.metadata:
            errors.append("Azure resource should specify resource_group")

        return errors

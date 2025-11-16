"""
Base provider abstraction for cloud platforms.

This module defines the abstract interface that all cloud provider
implementations must follow.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from cloudguard_anomaly.core.models import Resource, ResourceType


class BaseProvider(ABC):
    """Abstract base class for cloud provider implementations."""

    def __init__(self, provider_name: str):
        """
        Initialize the provider.

        Args:
            provider_name: Name of the cloud provider
        """
        self.provider_name = provider_name

    @abstractmethod
    def normalize_resource(self, raw_resource: Dict[str, Any]) -> Resource:
        """
        Normalize a provider-specific resource into standard Resource model.

        Args:
            raw_resource: Provider-specific resource configuration

        Returns:
            Normalized Resource object
        """
        pass

    @abstractmethod
    def get_resource_type_mapping(self) -> Dict[str, ResourceType]:
        """
        Get mapping from provider-specific resource types to standard types.

        Returns:
            Dictionary mapping provider types to ResourceType enum
        """
        pass

    @abstractmethod
    def validate_resource(self, resource: Resource) -> List[str]:
        """
        Validate resource configuration against provider-specific requirements.

        Args:
            resource: Resource to validate

        Returns:
            List of validation errors (empty if valid)
        """
        pass

    def detect_resource_type(self, raw_resource: Dict[str, Any]) -> ResourceType:
        """
        Detect the standard resource type from provider-specific configuration.

        Args:
            raw_resource: Provider-specific resource

        Returns:
            Standard ResourceType
        """
        mapping = self.get_resource_type_mapping()
        provider_type = raw_resource.get("type", "unknown")

        return mapping.get(provider_type, ResourceType.UNKNOWN)

    def extract_tags(self, raw_resource: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract tags/labels from provider-specific format.

        Args:
            raw_resource: Provider-specific resource

        Returns:
            Normalized tags dictionary
        """
        # Default implementation
        return raw_resource.get("tags", {})

    def extract_region(self, raw_resource: Dict[str, Any]) -> str:
        """
        Extract region/location from provider-specific format.

        Args:
            raw_resource: Provider-specific resource

        Returns:
            Region identifier
        """
        return raw_resource.get("region", "global")

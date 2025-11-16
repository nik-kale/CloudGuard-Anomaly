"""GCP provider implementation."""

from typing import Any, Dict, List

from cloudguard_anomaly.core.models import Provider, Resource, ResourceType
from cloudguard_anomaly.providers.base import BaseProvider


class GCPProvider(BaseProvider):
    """GCP-specific provider implementation."""

    def __init__(self):
        super().__init__("gcp")

    def get_resource_type_mapping(self) -> Dict[str, ResourceType]:
        """Map GCP resource types to standard types."""
        return {
            # Compute
            "google_compute_instance": ResourceType.COMPUTE,
            "google_cloud_run_service": ResourceType.FUNCTION,
            "google_cloudfunctions_function": ResourceType.FUNCTION,
            # Storage
            "google_storage_bucket": ResourceType.STORAGE,
            "google_compute_disk": ResourceType.STORAGE,
            # Database
            "google_sql_database_instance": ResourceType.DATABASE,
            "google_bigtable_instance": ResourceType.DATABASE,
            "google_firestore_database": ResourceType.DATABASE,
            # Network
            "google_compute_network": ResourceType.NETWORK,
            "google_compute_subnetwork": ResourceType.NETWORK,
            "google_compute_firewall": ResourceType.SECURITY_GROUP,
            # IAM
            "google_project_iam_binding": ResourceType.IAM_ROLE,
            "google_project_iam_member": ResourceType.IAM_ROLE,
            "google_iam_role": ResourceType.IAM_POLICY,
            # Load Balancers
            "google_compute_backend_service": ResourceType.LOAD_BALANCER,
            "google_compute_url_map": ResourceType.LOAD_BALANCER,
            # Other
            "google_api_gateway_api": ResourceType.API_GATEWAY,
            "google_pubsub_topic": ResourceType.TOPIC,
            "google_pubsub_subscription": ResourceType.QUEUE,
            "google_kms_crypto_key": ResourceType.KEY,
            "google_secret_manager_secret": ResourceType.SECRET,
        }

    def normalize_resource(self, raw_resource: Dict[str, Any]) -> Resource:
        """Normalize GCP resource to standard format."""
        resource_type = self.detect_resource_type(raw_resource)

        return Resource(
            id=raw_resource.get("id", raw_resource.get("self_link", "unknown")),
            name=raw_resource.get("name", "unnamed"),
            type=resource_type,
            provider=Provider.GCP,
            region=self.extract_region(raw_resource),
            properties=raw_resource.get("properties", raw_resource),
            tags=self.extract_tags(raw_resource),
            metadata={
                "project": raw_resource.get("project"),
                "self_link": raw_resource.get("self_link"),
            },
        )

    def extract_tags(self, raw_resource: Dict[str, Any]) -> Dict[str, str]:
        """Extract labels from GCP resource format."""
        # GCP uses 'labels' instead of 'tags'
        return raw_resource.get("labels", raw_resource.get("tags", {}))

    def extract_region(self, raw_resource: Dict[str, Any]) -> str:
        """Extract zone/region from GCP resource."""
        # GCP uses zone or region
        zone = raw_resource.get("zone", "")
        if zone:
            # Extract region from zone (e.g., us-central1-a -> us-central1)
            parts = zone.rsplit("-", 1)
            return parts[0] if len(parts) > 1 else zone

        return raw_resource.get("region", "global")

    def validate_resource(self, resource: Resource) -> List[str]:
        """Validate GCP resource configuration."""
        errors = []

        if not resource.id:
            errors.append("Resource must have an ID")

        if not resource.name:
            errors.append("Resource must have a name")

        # GCP-specific validation
        if "project" not in resource.metadata:
            errors.append("GCP resource should specify project")

        return errors

"""
GCP Live Integration for CloudGuard-Anomaly.

Provides real-time resource discovery and analysis from live GCP projects.
"""

import logging
from typing import List, Optional

try:
    from google.cloud import storage, compute_v1, sql_v1
    from google.oauth2 import service_account
    GCP_SDK_AVAILABLE = True
except ImportError:
    GCP_SDK_AVAILABLE = False

from cloudguard_anomaly.core.models import Resource, ResourceType, Provider, Environment

logger = logging.getLogger(__name__)


class GCPLiveIntegration:
    """Real-time GCP resource discovery and analysis."""

    def __init__(self, project_id: str, credentials_path: Optional[str] = None):
        """
        Initialize GCP live integration.

        Args:
            project_id: GCP project ID
            credentials_path: Path to service account JSON (optional)
        """
        if not GCP_SDK_AVAILABLE:
            raise ImportError("Google Cloud SDK required. Install with: pip install google-cloud-storage google-cloud-compute google-cloud-sql")

        self.project_id = project_id

        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
            self.storage_client = storage.Client(project=project_id, credentials=credentials)
        else:
            self.storage_client = storage.Client(project=project_id)

        logger.info(f"Initialized GCP integration for project {project_id}")

    def discover_all_resources(self) -> Environment:
        """Discover all resources across GCP project."""
        resources = []

        logger.info("Starting GCP resource discovery...")

        resources.extend(self._discover_storage_buckets())
        # Add more GCP resource types as needed

        logger.info(f"Discovered {len(resources)} GCP resources")

        return Environment(
            name=f"gcp-live-{self.project_id}",
            provider=Provider.GCP,
            resources=resources,
            metadata={
                "project_id": self.project_id,
                "discovery_type": "live",
            },
        )

    def _discover_storage_buckets(self) -> List[Resource]:
        """Discover GCS buckets."""
        resources = []

        try:
            for bucket in self.storage_client.list_buckets():
                resource = Resource(
                    id=bucket.name,
                    name=bucket.name,
                    type=ResourceType.STORAGE,
                    provider=Provider.GCP,
                    region=bucket.location,
                    properties={
                        "storage_class": bucket.storage_class,
                        "versioning_enabled": bucket.versioning_enabled,
                        "created": str(bucket.time_created),
                    },
                    tags=bucket.labels or {},
                    metadata={"project": self.project_id},
                )
                resources.append(resource)

        except Exception as e:
            logger.error(f"Failed to discover storage buckets: {e}")

        return resources

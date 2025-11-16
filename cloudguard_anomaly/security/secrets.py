"""
Secrets Management for CloudGuard-Anomaly.

Integrates with HashiCorp Vault, AWS Secrets Manager, and environment variables.
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class SecretsBackend(Enum):
    """Secrets management backends."""
    ENV = "env"  # Environment variables
    VAULT = "vault"  # HashiCorp Vault
    AWS = "aws"  # AWS Secrets Manager
    AZURE = "azure"  # Azure Key Vault
    GCP = "gcp"  # GCP Secret Manager


class SecretsManager:
    """Unified secrets management interface."""

    def __init__(self, backend: str = "env"):
        """
        Initialize secrets manager.

        Args:
            backend: Backend to use (env, vault, aws, azure, gcp)
        """
        self.backend = SecretsBackend(backend)
        self.client = None

        if self.backend == SecretsBackend.VAULT:
            self._init_vault()
        elif self.backend == SecretsBackend.AWS:
            self._init_aws()
        elif self.backend == SecretsBackend.AZURE:
            self._init_azure()
        elif self.backend == SecretsBackend.GCP:
            self._init_gcp()

        logger.info(f"Secrets manager initialized with backend: {self.backend.value}")

    def _init_vault(self):
        """Initialize HashiCorp Vault client."""
        try:
            import hvac

            vault_url = os.getenv("VAULT_URL")
            vault_token = os.getenv("VAULT_TOKEN")

            if not vault_url:
                raise ValueError("VAULT_URL environment variable not set")

            self.client = hvac.Client(url=vault_url, token=vault_token)

            if not self.client.is_authenticated():
                raise ValueError("Vault authentication failed")

            logger.info(f"Connected to Vault at {vault_url}")

        except ImportError:
            raise ImportError(
                "hvac package required for Vault support. "
                "Install with: pip install hvac"
            )

    def _init_aws(self):
        """Initialize AWS Secrets Manager client."""
        try:
            import boto3

            region = os.getenv("AWS_REGION", "us-east-1")
            self.client = boto3.client('secretsmanager', region_name=region)

            logger.info(f"Connected to AWS Secrets Manager in {region}")

        except ImportError:
            raise ImportError(
                "boto3 package required for AWS support. "
                "Install with: pip install boto3"
            )

    def _init_azure(self):
        """Initialize Azure Key Vault client."""
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential

            vault_url = os.getenv("AZURE_KEYVAULT_URL")
            if not vault_url:
                raise ValueError("AZURE_KEYVAULT_URL environment variable not set")

            credential = DefaultAzureCredential()
            self.client = SecretClient(vault_url=vault_url, credential=credential)

            logger.info(f"Connected to Azure Key Vault at {vault_url}")

        except ImportError:
            raise ImportError(
                "azure-keyvault-secrets and azure-identity required for Azure support. "
                "Install with: pip install azure-keyvault-secrets azure-identity"
            )

    def _init_gcp(self):
        """Initialize GCP Secret Manager client."""
        try:
            from google.cloud import secretmanager

            self.client = secretmanager.SecretManagerServiceClient()

            project_id = os.getenv("GCP_PROJECT_ID")
            if not project_id:
                raise ValueError("GCP_PROJECT_ID environment variable not set")

            self.project_id = project_id
            logger.info(f"Connected to GCP Secret Manager for project {project_id}")

        except ImportError:
            raise ImportError(
                "google-cloud-secret-manager required for GCP support. "
                "Install with: pip install google-cloud-secret-manager"
            )

    def get_secret(self, path: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieve secret from configured backend.

        Args:
            path: Secret path/key
            default: Default value if secret not found

        Returns:
            Secret value or default
        """
        try:
            if self.backend == SecretsBackend.ENV:
                return os.getenv(path, default)

            elif self.backend == SecretsBackend.VAULT:
                return self._get_vault_secret(path, default)

            elif self.backend == SecretsBackend.AWS:
                return self._get_aws_secret(path, default)

            elif self.backend == SecretsBackend.AZURE:
                return self._get_azure_secret(path, default)

            elif self.backend == SecretsBackend.GCP:
                return self._get_gcp_secret(path, default)

        except Exception as e:
            logger.error(f"Error retrieving secret '{path}': {e}")
            return default

    def _get_vault_secret(self, path: str, default: Optional[str]) -> Optional[str]:
        """Get secret from Vault."""
        try:
            # Try KV v2 first
            secret_version = self.client.secrets.kv.v2.read_secret_version(path=path)
            return secret_version['data']['data'].get('value', default)
        except:
            try:
                # Fallback to KV v1
                secret = self.client.secrets.kv.v1.read_secret(path=path)
                return secret['data'].get('value', default)
            except:
                return default

    def _get_aws_secret(self, path: str, default: Optional[str]) -> Optional[str]:
        """Get secret from AWS Secrets Manager."""
        try:
            response = self.client.get_secret_value(SecretId=path)

            if 'SecretString' in response:
                secret = json.loads(response['SecretString'])
                # If it's a dict, get 'value' key, otherwise return the whole thing
                if isinstance(secret, dict):
                    return secret.get('value', default)
                return secret
            else:
                # Binary secret
                return response['SecretBinary'].decode('utf-8')

        except self.client.exceptions.ResourceNotFoundException:
            return default
        except Exception as e:
            logger.error(f"AWS Secrets Manager error: {e}")
            return default

    def _get_azure_secret(self, path: str, default: Optional[str]) -> Optional[str]:
        """Get secret from Azure Key Vault."""
        try:
            secret = self.client.get_secret(path)
            return secret.value
        except Exception as e:
            logger.error(f"Azure Key Vault error: {e}")
            return default

    def _get_gcp_secret(self, path: str, default: Optional[str]) -> Optional[str]:
        """Get secret from GCP Secret Manager."""
        try:
            name = f"projects/{self.project_id}/secrets/{path}/versions/latest"
            response = self.client.access_secret_version(request={"name": name})
            return response.payload.data.decode('UTF-8')
        except Exception as e:
            logger.error(f"GCP Secret Manager error: {e}")
            return default

    def set_secret(self, path: str, value: str) -> bool:
        """
        Store secret in configured backend.

        Args:
            path: Secret path/key
            value: Secret value

        Returns:
            True if successful
        """
        try:
            if self.backend == SecretsBackend.ENV:
                # Can't set env vars at runtime, warn user
                logger.warning(f"Cannot set env var '{path}' at runtime. Set it before starting the application.")
                return False

            elif self.backend == SecretsBackend.VAULT:
                return self._set_vault_secret(path, value)

            elif self.backend == SecretsBackend.AWS:
                return self._set_aws_secret(path, value)

            elif self.backend == SecretsBackend.AZURE:
                return self._set_azure_secret(path, value)

            elif self.backend == SecretsBackend.GCP:
                return self._set_gcp_secret(path, value)

        except Exception as e:
            logger.error(f"Error setting secret '{path}': {e}")
            return False

    def _set_vault_secret(self, path: str, value: str) -> bool:
        """Set secret in Vault."""
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={'value': value}
            )
            logger.info(f"Secret '{path}' stored in Vault")
            return True
        except:
            try:
                # Fallback to KV v1
                self.client.secrets.kv.v1.create_or_update_secret(
                    path=path,
                    secret={'value': value}
                )
                logger.info(f"Secret '{path}' stored in Vault (KV v1)")
                return True
            except Exception as e:
                logger.error(f"Vault error: {e}")
                return False

    def _set_aws_secret(self, path: str, value: str) -> bool:
        """Set secret in AWS Secrets Manager."""
        try:
            # Try to update existing secret
            self.client.put_secret_value(
                SecretId=path,
                SecretString=json.dumps({'value': value})
            )
            logger.info(f"Secret '{path}' updated in AWS Secrets Manager")
            return True
        except self.client.exceptions.ResourceNotFoundException:
            # Create new secret
            self.client.create_secret(
                Name=path,
                SecretString=json.dumps({'value': value})
            )
            logger.info(f"Secret '{path}' created in AWS Secrets Manager")
            return True
        except Exception as e:
            logger.error(f"AWS Secrets Manager error: {e}")
            return False

    def _set_azure_secret(self, path: str, value: str) -> bool:
        """Set secret in Azure Key Vault."""
        try:
            self.client.set_secret(path, value)
            logger.info(f"Secret '{path}' stored in Azure Key Vault")
            return True
        except Exception as e:
            logger.error(f"Azure Key Vault error: {e}")
            return False

    def _set_gcp_secret(self, path: str, value: str) -> bool:
        """Set secret in GCP Secret Manager."""
        try:
            parent = f"projects/{self.project_id}"

            # Check if secret exists
            try:
                secret_name = f"{parent}/secrets/{path}"
                self.client.get_secret(request={"name": secret_name})
                exists = True
            except:
                exists = False

            if not exists:
                # Create secret
                secret = self.client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": path,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
                secret_name = secret.name

            # Add secret version
            self.client.add_secret_version(
                request={
                    "parent": secret_name,
                    "payload": {"data": value.encode('UTF-8')},
                }
            )

            logger.info(f"Secret '{path}' stored in GCP Secret Manager")
            return True

        except Exception as e:
            logger.error(f"GCP Secret Manager error: {e}")
            return False


# Global secrets manager instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager(backend: Optional[str] = None) -> SecretsManager:
    """Get global secrets manager instance."""
    global _secrets_manager

    if _secrets_manager is None:
        from cloudguard_anomaly.config import get_config
        config = get_config()
        backend = backend or config.secrets_backend
        _secrets_manager = SecretsManager(backend=backend)

    return _secrets_manager


def get_secret(path: str, default: Optional[str] = None) -> Optional[str]:
    """
    Convenience function to get a secret.

    Args:
        path: Secret path/key
        default: Default value if not found

    Returns:
        Secret value or default
    """
    manager = get_secrets_manager()
    return manager.get_secret(path, default)

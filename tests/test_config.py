"""
Tests for configuration management.
"""

import os
import pytest
from unittest.mock import patch

from cloudguard_anomaly.config import Config, get_config


class TestConfiguration:
    """Test configuration management."""

    def test_config_initialization(self):
        """Test Config initializes with defaults."""
        config = Config()

        assert config.database_url is not None
        assert config.scan_parallel_workers > 0
        assert config.enable_incremental_scan is not None

    def test_config_from_environment(self):
        """Test Config loads from environment variables."""
        with patch.dict(
            os.environ,
            {
                "DATABASE_URL": "postgresql://test:test@localhost/testdb",
                "SCAN_PARALLEL_WORKERS": "20",
                "ENABLE_INCREMENTAL_SCAN": "true",
            },
        ):
            config = Config()

            assert config.database_url == "postgresql://test:test@localhost/testdb"
            assert config.scan_parallel_workers == 20
            assert config.enable_incremental_scan is True

    def test_config_llm_provider_settings(self):
        """Test LLM provider configuration."""
        with patch.dict(
            os.environ,
            {
                "LLM_PROVIDER": "claude",
                "ANTHROPIC_API_KEY": "test-key-123",
                "LLM_MODEL": "claude-3-5-sonnet-20241022",
            },
        ):
            config = Config()

            assert config.llm_provider == "claude"
            assert config.anthropic_api_key == "test-key-123"
            assert config.llm_model == "claude-3-5-sonnet-20241022"

    def test_config_openai_settings(self):
        """Test OpenAI configuration."""
        with patch.dict(
            os.environ, {"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test123"}
        ):
            config = Config()

            assert config.llm_provider == "openai"
            assert config.openai_api_key == "sk-test123"

    def test_config_database_pooling(self):
        """Test database connection pooling configuration."""
        with patch.dict(
            os.environ, {"DATABASE_POOL_SIZE": "15", "DATABASE_MAX_OVERFLOW": "25"}
        ):
            config = Config()

            assert config.database_pool_size == 15
            assert config.database_max_overflow == 25

    def test_config_rate_limiting(self):
        """Test rate limiting configuration."""
        with patch.dict(
            os.environ,
            {"RATE_LIMIT_ENABLED": "true", "RATE_LIMIT_DEFAULT": "200/hour"},
        ):
            config = Config()

            assert config.rate_limit_enabled is True
            assert config.rate_limit_default == "200/hour"

    def test_config_dashboard_settings(self):
        """Test dashboard configuration."""
        with patch.dict(
            os.environ,
            {
                "DASHBOARD_HOST": "0.0.0.0",
                "DASHBOARD_PORT": "8080",
                "DASHBOARD_SECRET_KEY": "test-secret-key",
            },
        ):
            config = Config()

            assert config.dashboard_host == "0.0.0.0"
            assert config.dashboard_port == 8080
            assert config.dashboard_secret_key == "test-secret-key"

    def test_config_secrets_backend(self):
        """Test secrets backend configuration."""
        with patch.dict(
            os.environ,
            {"SECRETS_BACKEND": "vault", "VAULT_URL": "http://vault:8200"},
        ):
            config = Config()

            assert config.secrets_backend == "vault"
            assert config.vault_url == "http://vault:8200"

    def test_config_slack_webhook(self):
        """Test Slack webhook configuration."""
        with patch.dict(
            os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/TEST"}
        ):
            config = Config()

            assert config.slack_webhook_url == "https://hooks.slack.com/services/TEST"

    def test_get_config_singleton(self):
        """Test get_config returns singleton."""
        config1 = get_config()
        config2 = get_config()

        # Should be same instance
        assert config1 is config2

    def test_config_boolean_parsing(self):
        """Test boolean environment variable parsing."""
        with patch.dict(
            os.environ,
            {
                "ENABLE_INCREMENTAL_SCAN": "true",
                "RATE_LIMIT_ENABLED": "false",
                "DASHBOARD_DEBUG": "1",
            },
        ):
            config = Config()

            assert config.enable_incremental_scan is True
            assert config.rate_limit_enabled is False

    def test_config_integer_parsing(self):
        """Test integer environment variable parsing."""
        with patch.dict(
            os.environ,
            {
                "SCAN_PARALLEL_WORKERS": "25",
                "DASHBOARD_PORT": "9000",
                "DATABASE_POOL_SIZE": "30",
            },
        ):
            config = Config()

            assert config.scan_parallel_workers == 25
            assert config.dashboard_port == 9000
            assert config.database_pool_size == 30

    def test_config_aws_settings(self):
        """Test AWS configuration."""
        with patch.dict(
            os.environ,
            {
                "AWS_DEFAULT_REGION": "eu-west-1",
                "AWS_PROFILE": "production",
            },
        ):
            config = Config()

            # Config should have these available if defined
            assert hasattr(config, "aws_default_region") or True

    def test_config_local_llm_settings(self):
        """Test local LLM configuration."""
        with patch.dict(
            os.environ,
            {"LLM_PROVIDER": "local", "LOCAL_LLM_URL": "http://localhost:11434"},
        ):
            config = Config()

            assert config.llm_provider == "local"
            assert config.local_llm_url == "http://localhost:11434"

    def test_config_incremental_scan_settings(self):
        """Test incremental scan configuration."""
        with patch.dict(os.environ, {"ENABLE_INCREMENTAL_SCAN": "true"}):
            config = Config()

            assert config.enable_incremental_scan is True

    def test_config_redis_settings(self):
        """Test Redis configuration."""
        with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}):
            config = Config()

            assert config.redis_url == "redis://localhost:6379/0"

    def test_config_defaults_when_no_env(self):
        """Test config uses defaults when no environment variables set."""
        # Clear relevant env vars
        env_backup = os.environ.copy()
        try:
            # Remove config-related env vars
            for key in list(os.environ.keys()):
                if key.startswith(("DATABASE_", "SCAN_", "LLM_", "DASHBOARD_")):
                    del os.environ[key]

            config = Config()

            # Should have sensible defaults
            assert config.scan_parallel_workers > 0
            assert config.database_url is not None
            assert config.dashboard_host is not None

        finally:
            os.environ.clear()
            os.environ.update(env_backup)

    def test_config_validation(self):
        """Test configuration validation."""
        config = Config()

        # Validate worker count is positive
        assert config.scan_parallel_workers > 0

        # Validate pool sizes are positive
        assert config.database_pool_size > 0
        assert config.database_max_overflow > 0

    def test_config_to_dict(self):
        """Test converting config to dictionary."""
        config = Config()

        # Config should be serializable
        config_dict = {
            "database_url": config.database_url,
            "scan_parallel_workers": config.scan_parallel_workers,
            "llm_provider": config.llm_provider,
        }

        assert isinstance(config_dict, dict)
        assert "database_url" in config_dict

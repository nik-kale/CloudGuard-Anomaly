"""
Configuration management for CloudGuard-Anomaly.

Centralized configuration with environment variable support.
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class Config:
    """Application configuration."""

    # Database
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///cloudguard.db")
    )
    database_pool_size: int = field(
        default_factory=lambda: int(os.getenv("DATABASE_POOL_SIZE", "10"))
    )
    database_max_overflow: int = field(
        default_factory=lambda: int(os.getenv("DATABASE_MAX_OVERFLOW", "20"))
    )

    # LLM Providers
    anthropic_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY")
    )
    openai_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY")
    )
    llm_provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "auto")  # auto, claude, openai, local, none
    )
    llm_model: Optional[str] = field(
        default_factory=lambda: os.getenv("LLM_MODEL")  # e.g., claude-3-5-sonnet-20241022
    )
    local_llm_url: str = field(
        default_factory=lambda: os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
    )

    # Dashboard
    dashboard_secret_key: str = field(
        default_factory=lambda: os.getenv("DASHBOARD_SECRET_KEY", "")
    )
    dashboard_host: str = field(
        default_factory=lambda: os.getenv("DASHBOARD_HOST", "0.0.0.0")
    )
    dashboard_port: int = field(
        default_factory=lambda: int(os.getenv("DASHBOARD_PORT", "5000"))
    )
    dashboard_debug: bool = field(
        default_factory=lambda: os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"
    )
    cors_origins: str = field(
        default_factory=lambda: os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5000")
    )

    # Authentication
    enable_auth: bool = field(
        default_factory=lambda: os.getenv("ENABLE_AUTH", "false").lower() == "true"
    )
    session_timeout: int = field(
        default_factory=lambda: int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour
    )

    # Logging configuration
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )
    log_format: str = field(
        default_factory=lambda: os.getenv("LOG_FORMAT", "json")
    )

    # Notifications
    slack_webhook_url: Optional[str] = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL")
    )
    webhook_url: Optional[str] = field(
        default_factory=lambda: os.getenv("WEBHOOK_URL")
    )

    # Secrets Management
    secrets_backend: str = field(
        default_factory=lambda: os.getenv("SECRETS_BACKEND", "env")  # env, vault, aws
    )
    vault_url: Optional[str] = field(
        default_factory=lambda: os.getenv("VAULT_URL")
    )
    vault_token: Optional[str] = field(
        default_factory=lambda: os.getenv("VAULT_TOKEN")
    )

    # AWS Cloud Provider
    aws_profile: Optional[str] = field(
        default_factory=lambda: os.getenv("AWS_PROFILE")
    )
    aws_region: str = field(
        default_factory=lambda: os.getenv("AWS_REGION", "us-east-1")
    )

    # Azure Cloud Provider
    azure_subscription_id: Optional[str] = field(
        default_factory=lambda: os.getenv("AZURE_SUBSCRIPTION_ID")
    )

    # GCP Cloud Provider
    gcp_project_id: Optional[str] = field(
        default_factory=lambda: os.getenv("GCP_PROJECT_ID")
    )

    # Scanning
    scan_parallel_workers: int = field(
        default_factory=lambda: int(os.getenv("SCAN_PARALLEL_WORKERS", "10"))
    )
    enable_incremental_scan: bool = field(
        default_factory=lambda: os.getenv("ENABLE_INCREMENTAL_SCAN", "true").lower() == "true"
    )

    # Monitoring
    monitoring_interval: int = field(
        default_factory=lambda: int(os.getenv("MONITORING_INTERVAL", "3600"))  # 1 hour
    )

    # Cache
    cache_backend: str = field(
        default_factory=lambda: os.getenv("CACHE_BACKEND", "simple")  # simple, redis
    )
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )

    # Rate Limiting
    rate_limit_enabled: bool = field(
        default_factory=lambda: os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    )
    rate_limit_default: str = field(
        default_factory=lambda: os.getenv("RATE_LIMIT_DEFAULT", "100 per hour")
    )

    # Logging
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )
    log_format: str = field(
        default_factory=lambda: os.getenv("LOG_FORMAT", "text")  # text, json
    )

    # Reports
    reports_dir: Path = field(
        default_factory=lambda: Path(os.getenv("REPORTS_DIR", "./reports"))
    )

    def __post_init__(self):
        """Validate configuration."""
        # Validate secret key if dashboard is not in debug mode
        if not self.dashboard_debug and not self.dashboard_secret_key:
            raise ValueError(
                "DASHBOARD_SECRET_KEY must be set when not in debug mode. "
                "Generate a secure key with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )

        # Warn if auth is enabled but no secret key
        if self.enable_auth and not self.dashboard_secret_key:
            raise ValueError(
                "DASHBOARD_SECRET_KEY must be set when authentication is enabled"
            )

        # Create reports directory if it doesn't exist
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def get_llm_api_key(self) -> Optional[str]:
        """Get the appropriate LLM API key based on provider."""
        if self.llm_provider == "claude" or (self.llm_provider == "auto" and self.anthropic_api_key):
            return self.anthropic_api_key
        elif self.llm_provider == "openai" or (self.llm_provider == "auto" and self.openai_api_key):
            return self.openai_api_key
        return None


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config):
    """Set global configuration instance."""
    global _config
    _config = config


def load_config_from_file(path: str):
    """Load configuration from .env file."""
    try:
        from dotenv import load_dotenv
        load_dotenv(path)
        # Reset config to reload from new env vars
        global _config
        _config = None
        return get_config()
    except ImportError:
        raise ImportError(
            "python-dotenv is required to load .env files. "
            "Install with: pip install python-dotenv"
        )

"""
Configuration loader for CloudGuard-Anomaly.

This module handles loading infrastructure-as-code (IaC) files and runtime
configuration snapshots from various formats (JSON, YAML, etc.)
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from cloudguard_anomaly.core.models import (
    Environment,
    Provider,
    Resource,
    ResourceType,
)

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Loads cloud environment configurations from various sources."""

    @staticmethod
    def load_json(file_path: Path) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load JSON from {file_path}: {e}")
            raise

    @staticmethod
    def load_yaml(file_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(file_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load YAML from {file_path}: {e}")
            raise

    @staticmethod
    def load_config_file(file_path: Path) -> Dict[str, Any]:
        """Load configuration file based on extension."""
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            return ConfigLoader.load_json(file_path)
        elif suffix in [".yaml", ".yml"]:
            return ConfigLoader.load_yaml(file_path)
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

    @staticmethod
    def parse_resource(resource_data: Dict[str, Any], provider: Provider) -> Resource:
        """Parse a resource from configuration data."""
        return Resource(
            id=resource_data.get("id", resource_data.get("name", "unknown")),
            name=resource_data.get("name", "unnamed"),
            type=ResourceType(resource_data.get("type", "unknown")),
            provider=provider,
            region=resource_data.get("region", "global"),
            properties=resource_data.get("properties", {}),
            tags=resource_data.get("tags", {}),
            metadata=resource_data.get("metadata", {}),
        )

    @staticmethod
    def load_environment(env_path: Path) -> Environment:
        """
        Load a complete environment from a directory.

        Expected structure:
        env_path/
          - environment.yaml  (environment metadata)
          - runtime_snapshot/ (current resource configs)
          - iac/             (infrastructure-as-code definitions)
          - baseline/        (optional baseline configs)
        """
        env_path = Path(env_path)
        if not env_path.exists():
            raise FileNotFoundError(f"Environment path not found: {env_path}")

        # Load environment metadata
        env_file = env_path / "environment.yaml"
        if not env_file.exists():
            env_file = env_path / "environment.json"

        if env_file.exists():
            env_config = ConfigLoader.load_config_file(env_file)
        else:
            # Default environment config
            env_config = {
                "name": env_path.name,
                "provider": "aws",
                "metadata": {},
            }

        provider = Provider(env_config.get("provider", "aws"))

        # Load current/runtime resources
        resources = []
        runtime_path = env_path / "runtime_snapshot"
        if runtime_path.exists():
            resources.extend(ConfigLoader._load_resources_from_dir(runtime_path, provider))

        # Load IaC resources if no runtime snapshot
        if not resources:
            iac_path = env_path / "iac"
            if iac_path.exists():
                resources.extend(ConfigLoader._load_resources_from_dir(iac_path, provider))

        # Load baseline resources if available
        baseline_resources = None
        baseline_path = env_path / "baseline"
        if baseline_path.exists():
            baseline_resources = ConfigLoader._load_resources_from_dir(baseline_path, provider)

        return Environment(
            name=env_config.get("name", env_path.name),
            provider=provider,
            resources=resources,
            baseline_resources=baseline_resources,
            metadata=env_config.get("metadata", {}),
        )

    @staticmethod
    def _load_resources_from_dir(dir_path: Path, provider: Provider) -> List[Resource]:
        """Load all resources from a directory of config files."""
        resources = []

        for file_path in dir_path.glob("*.json"):
            try:
                config = ConfigLoader.load_json(file_path)
                resources.extend(ConfigLoader._parse_resources(config, provider))
            except Exception as e:
                logger.warning(f"Failed to load {file_path}: {e}")

        for file_path in dir_path.glob("*.yaml"):
            try:
                config = ConfigLoader.load_yaml(file_path)
                resources.extend(ConfigLoader._parse_resources(config, provider))
            except Exception as e:
                logger.warning(f"Failed to load {file_path}: {e}")

        return resources

    @staticmethod
    def _parse_resources(config: Dict[str, Any], provider: Provider) -> List[Resource]:
        """Parse resources from a configuration dictionary."""
        resources = []

        # Handle both single resource and resource list formats
        if "resources" in config:
            resource_list = config["resources"]
        elif "resource" in config:
            resource_list = [config["resource"]]
        elif isinstance(config, list):
            resource_list = config
        else:
            # Assume entire config is a single resource
            resource_list = [config]

        for resource_data in resource_list:
            try:
                resource = ConfigLoader.parse_resource(resource_data, provider)
                resources.append(resource)
            except Exception as e:
                logger.warning(f"Failed to parse resource: {e}")

        return resources

    @staticmethod
    def load_drift_scenario(scenario_path: Path) -> tuple[Environment, Environment]:
        """
        Load a drift scenario with baseline and current states.

        Expected structure:
        scenario_path/
          - baseline/     (baseline resource configs)
          - current/      (current resource configs)
          - scenario.yaml (scenario metadata)
        """
        scenario_path = Path(scenario_path)
        if not scenario_path.exists():
            raise FileNotFoundError(f"Scenario path not found: {scenario_path}")

        # Load scenario metadata
        scenario_file = scenario_path / "scenario.yaml"
        if scenario_file.exists():
            scenario_config = ConfigLoader.load_config_file(scenario_file)
        else:
            scenario_config = {"name": scenario_path.name, "provider": "aws"}

        provider = Provider(scenario_config.get("provider", "aws"))

        # Load baseline
        baseline_path = scenario_path / "baseline"
        baseline_resources = ConfigLoader._load_resources_from_dir(baseline_path, provider)
        baseline_env = Environment(
            name=f"{scenario_config['name']}_baseline",
            provider=provider,
            resources=baseline_resources,
        )

        # Load current state
        current_path = scenario_path / "current"
        current_resources = ConfigLoader._load_resources_from_dir(current_path, provider)
        current_env = Environment(
            name=scenario_config["name"],
            provider=provider,
            resources=current_resources,
            baseline_resources=baseline_resources,
        )

        return baseline_env, current_env

"""
Policy engine for loading and managing security policies.

This module handles loading policies from YAML/JSON files and converting
them into Policy objects for evaluation.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

from cloudguard_anomaly.core.models import Policy, Provider, ResourceType, Severity

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Engine for loading and managing security policies."""

    def __init__(self):
        """Initialize the policy engine."""
        self.policies: List[Policy] = []

    def load_policies(self, policy_file: Path) -> List[Policy]:
        """
        Load policies from a YAML or JSON file.

        Args:
            policy_file: Path to policy file

        Returns:
            List of Policy objects
        """
        logger.info(f"Loading policies from {policy_file}")

        try:
            with open(policy_file, "r") as f:
                if policy_file.suffix in [".yaml", ".yml"]:
                    policy_data = yaml.safe_load(f)
                else:
                    import json

                    policy_data = json.load(f)

            policies = self._parse_policies(policy_data)
            logger.info(f"Loaded {len(policies)} policies from {policy_file}")

            return policies

        except Exception as e:
            logger.error(f"Failed to load policies from {policy_file}: {e}")
            raise

    def _parse_policies(self, policy_data: Dict[str, Any]) -> List[Policy]:
        """Parse policy data into Policy objects."""
        policies = []

        policy_list = policy_data.get("policies", [])

        for policy_dict in policy_list:
            try:
                policy = self._parse_policy(policy_dict)
                policies.append(policy)
            except Exception as e:
                logger.warning(f"Failed to parse policy: {e}")

        return policies

    def _parse_policy(self, policy_dict: Dict[str, Any]) -> Policy:
        """Parse a single policy dictionary into a Policy object."""
        return Policy(
            id=policy_dict["id"],
            name=policy_dict["name"],
            description=policy_dict["description"],
            severity=Severity(policy_dict.get("severity", "medium")),
            provider=Provider(policy_dict.get("provider", "multi")),
            resource_types=[
                ResourceType(rt) for rt in policy_dict.get("resource_types", [])
            ],
            condition=policy_dict.get("condition", {}),
            remediation=policy_dict.get("remediation", ""),
            references=policy_dict.get("references", []),
            enabled=policy_dict.get("enabled", True),
        )

    def load_policy_directory(self, policy_dir: Path) -> List[Policy]:
        """
        Load all policies from a directory.

        Args:
            policy_dir: Directory containing policy files

        Returns:
            List of all loaded policies
        """
        all_policies = []

        for policy_file in policy_dir.glob("*.yaml"):
            try:
                policies = self.load_policies(policy_file)
                all_policies.extend(policies)
            except Exception as e:
                logger.warning(f"Failed to load {policy_file}: {e}")

        for policy_file in policy_dir.glob("*.json"):
            try:
                policies = self.load_policies(policy_file)
                all_policies.extend(policies)
            except Exception as e:
                logger.warning(f"Failed to load {policy_file}: {e}")

        logger.info(f"Loaded {len(all_policies)} total policies from {policy_dir}")
        return all_policies

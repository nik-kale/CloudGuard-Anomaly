"""
Validate command implementation.
"""

import logging
from pathlib import Path

from cloudguard_anomaly.core.loader import ConfigLoader
from cloudguard_anomaly.policies.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


def execute_validate(env_path: Path = None, policy_path: Path = None) -> None:
    """
    Validate environment and policy configurations.

    Args:
        env_path: Path to environment directory
        policy_path: Path to policies file or directory
    """
    errors = []
    warnings = []

    if env_path:
        print(f"\nValidating environment: {env_path}")
        print("-" * 80)

        try:
            loader = ConfigLoader()
            environment = loader.load_environment(env_path)

            print(f"✓ Environment loaded successfully")
            print(f"  Name: {environment.name}")
            print(f"  Provider: {environment.provider.value}")
            print(f"  Resources: {len(environment.resources)}")

            # Validate resources
            for resource in environment.resources:
                if not resource.id:
                    errors.append(f"Resource '{resource.name}' missing ID")
                if not resource.name:
                    errors.append(f"Resource '{resource.id}' missing name")

            if not errors:
                print(f"✓ All {len(environment.resources)} resources validated")

        except Exception as e:
            errors.append(f"Failed to load environment: {e}")
            logger.error(f"Environment validation failed", exc_info=True)

    if policy_path:
        print(f"\nValidating policies: {policy_path}")
        print("-" * 80)

        try:
            policy_engine = PolicyEngine()

            if policy_path.is_dir():
                policies = policy_engine.load_policy_directory(policy_path)
            else:
                policies = policy_engine.load_policies(policy_path)

            print(f"✓ Loaded {len(policies)} policies")

            # Validate policies
            for policy in policies:
                if not policy.id:
                    errors.append("Policy missing ID")
                if not policy.name:
                    errors.append(f"Policy '{policy.id}' missing name")
                if not policy.condition:
                    warnings.append(f"Policy '{policy.id}' has no condition")

            if not errors:
                print(f"✓ All {len(policies)} policies validated")

        except Exception as e:
            errors.append(f"Failed to load policies: {e}")
            logger.error(f"Policy validation failed", exc_info=True)

    # Print results
    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)

    if errors:
        print(f"\n❌ {len(errors)} Error(s):")
        for error in errors:
            print(f"  - {error}")

    if warnings:
        print(f"\n⚠️  {len(warnings)} Warning(s):")
        for warning in warnings:
            print(f"  - {warning}")

    if not errors and not warnings:
        print("\n✓ Validation passed with no errors or warnings")

    print("=" * 80 + "\n")

    if errors:
        exit(1)

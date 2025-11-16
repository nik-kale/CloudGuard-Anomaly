"""
Drift detector for CloudGuard-Anomaly.

Detects configuration drift by comparing baseline and current resource states.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cloudguard_anomaly.core.models import Anomaly, Resource, Severity

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detects configuration drift between baseline and current states."""

    def __init__(self):
        """Initialize the drift detector."""
        pass

    def detect_drift(
        self, baseline_resources: List[Resource], current_resources: List[Resource]
    ) -> List[Anomaly]:
        """
        Detect drift between baseline and current resource configurations.

        Args:
            baseline_resources: Baseline resource configurations
            current_resources: Current resource configurations

        Returns:
            List of detected anomalies (drift)
        """
        anomalies = []

        # Create resource maps for efficient lookup
        baseline_map = {r.id: r for r in baseline_resources}
        current_map = {r.id: r for r in current_resources}

        # Check for modified resources
        for resource_id, current_resource in current_map.items():
            if resource_id in baseline_map:
                baseline_resource = baseline_map[resource_id]
                drift = self._detect_resource_drift(baseline_resource, current_resource)
                if drift:
                    anomalies.append(drift)

        # Check for deleted resources
        deleted_ids = set(baseline_map.keys()) - set(current_map.keys())
        for resource_id in deleted_ids:
            baseline_resource = baseline_map[resource_id]
            anomaly = self._create_deletion_anomaly(baseline_resource)
            anomalies.append(anomaly)

        # Check for new resources
        new_ids = set(current_map.keys()) - set(baseline_map.keys())
        for resource_id in new_ids:
            current_resource = current_map[resource_id]
            anomaly = self._create_addition_anomaly(current_resource)
            anomalies.append(anomaly)

        logger.info(f"Drift detector found {len(anomalies)} anomalies")
        return anomalies

    def _detect_resource_drift(
        self, baseline: Resource, current: Resource
    ) -> Optional[Anomaly]:
        """Detect drift for a single resource."""
        changes = self._compare_resources(baseline, current)

        if not changes:
            return None

        # Assess severity based on changes
        severity = self._assess_drift_severity(changes, current)

        # Assess impact
        impact = self._assess_drift_impact(changes, current)

        anomaly_id = f"drift-{uuid.uuid4()}"

        return Anomaly(
            id=anomaly_id,
            type="configuration_drift",
            severity=severity,
            resource=current,
            baseline=baseline.properties,
            current=current.properties,
            changes=changes,
            impact=impact,
            timestamp=datetime.utcnow(),
        )

    def _compare_resources(self, baseline: Resource, current: Resource) -> List[Dict[str, Any]]:
        """Compare two resource configurations and identify changes."""
        changes = []

        # Compare properties
        baseline_props = baseline.properties
        current_props = current.properties

        # Find modified and added properties
        all_keys = set(baseline_props.keys()) | set(current_props.keys())

        for key in all_keys:
            baseline_value = baseline_props.get(key)
            current_value = current_props.get(key)

            if baseline_value != current_value:
                change = {
                    "property": key,
                    "baseline_value": baseline_value,
                    "current_value": current_value,
                    "change_type": self._classify_change(baseline_value, current_value),
                }
                changes.append(change)

        # Compare tags
        if baseline.tags != current.tags:
            changes.append(
                {
                    "property": "tags",
                    "baseline_value": baseline.tags,
                    "current_value": current.tags,
                    "change_type": "modified",
                }
            )

        return changes

    def _classify_change(self, baseline_value: Any, current_value: Any) -> str:
        """Classify the type of change."""
        if baseline_value is None and current_value is not None:
            return "added"
        elif baseline_value is not None and current_value is None:
            return "removed"
        else:
            return "modified"

    def _assess_drift_severity(self, changes: List[Dict[str, Any]], resource: Resource) -> Severity:
        """Assess the severity of drift based on changes."""
        # Security-critical properties
        critical_properties = [
            "public_access",
            "encryption",
            "publicly_accessible",
            "acl",
            "iam_members",
            "ingress",
            "egress",
        ]

        high_risk_properties = [
            "backup",
            "logging",
            "monitoring",
            "versioning",
            "ssl_policy",
        ]

        for change in changes:
            prop = change["property"]

            # Check if security posture worsened
            if prop in critical_properties:
                if self._is_security_degradation(change):
                    return Severity.CRITICAL

            if prop in high_risk_properties:
                if self._is_security_degradation(change):
                    return Severity.HIGH

        # Default to medium if changes exist but aren't critical
        return Severity.MEDIUM

    def _is_security_degradation(self, change: Dict[str, Any]) -> bool:
        """Determine if a change represents security degradation."""
        prop = change["property"]
        baseline_value = change["baseline_value"]
        current_value = change["current_value"]

        # Encryption disabled
        if "encrypt" in prop.lower():
            if baseline_value == True and current_value == False:
                return True

        # Public access enabled
        if "public" in prop.lower():
            if baseline_value == False and current_value == True:
                return True
            if baseline_value == "private" and current_value == "public":
                return True

        # Security controls disabled
        if any(
            keyword in prop.lower() for keyword in ["logging", "monitoring", "backup", "versioning"]
        ):
            if baseline_value == True and current_value == False:
                return True

        # Network exposure widened
        if prop == "ingress" or prop == "cidr_blocks":
            if "0.0.0.0/0" in str(current_value) and "0.0.0.0/0" not in str(baseline_value):
                return True

        return False

    def _assess_drift_impact(self, changes: List[Dict[str, Any]], resource: Resource) -> str:
        """Generate impact assessment for drift."""
        impact_statements = []

        for change in changes:
            prop = change["property"]
            change_type = change["change_type"]

            if self._is_security_degradation(change):
                impact_statements.append(
                    f"Security posture degraded: {prop} changed from "
                    f"{change['baseline_value']} to {change['current_value']}"
                )
            elif change_type == "added":
                impact_statements.append(f"New property added: {prop} = {change['current_value']}")
            elif change_type == "removed":
                impact_statements.append(f"Property removed: {prop} (was {change['baseline_value']})")
            else:
                impact_statements.append(
                    f"Property modified: {prop} changed from "
                    f"{change['baseline_value']} to {change['current_value']}"
                )

        return "; ".join(impact_statements) if impact_statements else "Configuration changed"

    def _create_deletion_anomaly(self, baseline_resource: Resource) -> Anomaly:
        """Create anomaly for deleted resource."""
        anomaly_id = f"drift-deleted-{uuid.uuid4()}"

        return Anomaly(
            id=anomaly_id,
            type="resource_deleted",
            severity=Severity.MEDIUM,
            resource=baseline_resource,
            baseline=baseline_resource.properties,
            current={},
            changes=[{"change_type": "deleted", "resource_id": baseline_resource.id}],
            impact=f"Resource {baseline_resource.name} ({baseline_resource.type.value}) was deleted",
            timestamp=datetime.utcnow(),
        )

    def _create_addition_anomaly(self, current_resource: Resource) -> Anomaly:
        """Create anomaly for newly added resource."""
        anomaly_id = f"drift-added-{uuid.uuid4()}"

        # New resources might be risky if they're publicly accessible
        severity = Severity.LOW

        # Check if new resource is publicly accessible
        props = current_resource.properties
        if props.get("publicly_accessible") or props.get("public_access"):
            severity = Severity.HIGH

        return Anomaly(
            id=anomaly_id,
            type="resource_added",
            severity=severity,
            resource=current_resource,
            baseline={},
            current=current_resource.properties,
            changes=[{"change_type": "added", "resource_id": current_resource.id}],
            impact=f"New resource {current_resource.name} ({current_resource.type.value}) was added",
            timestamp=datetime.utcnow(),
        )

"""
Finding aggregation for CloudGuard-Anomaly.

Groups and aggregates findings by various dimensions for better analysis.
"""

from collections import defaultdict
from typing import Any

from cloudguard_anomaly.core.models import Finding, Resource


class FindingAggregator:
    """Aggregates findings by various dimensions."""

    @staticmethod
    def group_by_resource(findings: list[Finding]) -> dict[str, list[Finding]]:
        """
        Group findings by resource.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping resource ID to findings
        """
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.resource.id].append(finding)
        return dict(grouped)

    @staticmethod
    def group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
        """
        Group findings by severity.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping severity to findings
        """
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.severity.value].append(finding)
        return dict(grouped)

    @staticmethod
    def group_by_type(findings: list[Finding]) -> dict[str, list[Finding]]:
        """
        Group findings by finding type.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping finding type to findings
        """
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.type.value].append(finding)
        return dict(grouped)

    @staticmethod
    def group_by_resource_type(findings: list[Finding]) -> dict[str, list[Finding]]:
        """
        Group findings by resource type.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping resource type to findings
        """
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.resource.type.value].append(finding)
        return dict(grouped)

    @staticmethod
    def get_top_issues(findings: list[Finding], limit: int = 10) -> list[Finding]:
        """
        Get top issues by severity.

        Args:
            findings: List of findings
            limit: Maximum number of issues to return

        Returns:
            List of top findings
        """
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 5))

        return sorted_findings[:limit]

    @staticmethod
    def get_affected_resources(findings: list[Finding]) -> list[Resource]:
        """
        Get unique list of affected resources.

        Args:
            findings: List of findings

        Returns:
            List of unique resources
        """
        resource_map = {}
        for finding in findings:
            resource_map[finding.resource.id] = finding.resource

        return list(resource_map.values())

    @staticmethod
    def calculate_statistics(findings: list[Finding]) -> dict[str, Any]:
        """
        Calculate statistics about findings.

        Args:
            findings: List of findings

        Returns:
            Dictionary of statistics
        """
        severity_counts: dict[str, int] = defaultdict(int)
        type_counts: dict[str, int] = defaultdict(int)
        resource_type_counts: dict[str, int] = defaultdict(int)

        for finding in findings:
            severity_counts[finding.severity.value] += 1
            type_counts[finding.type.value] += 1
            resource_type_counts[finding.resource.type.value] += 1

        return {
            "total_findings": len(findings),
            "severity_distribution": dict(severity_counts),
            "type_distribution": dict(type_counts),
            "resource_type_distribution": dict(resource_type_counts),
            "unique_resources": len(set(f.resource.id for f in findings)),
        }

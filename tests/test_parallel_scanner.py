"""
Tests for parallel scanning functionality.
"""

import time
from typing import List
import pytest

from cloudguard_anomaly.core.parallel import ParallelScanner
from cloudguard_anomaly.core.models import Resource, Finding, Severity, FindingType


class TestParallelScanner:
    """Test parallel scanning capabilities."""

    def test_parallel_scanner_initialization(self):
        """Test scanner initializes with correct worker count."""
        scanner = ParallelScanner(max_workers=5)
        assert scanner.max_workers == 5
        assert scanner.enabled is True

    def test_parallel_scanner_disabled(self):
        """Test scanner can be disabled."""
        scanner = ParallelScanner(max_workers=1)
        scanner.enabled = False
        assert scanner.enabled is False

    def test_scan_resources_parallel_performance(self, sample_resources):
        """Test parallel scanning is faster than sequential."""

        def slow_scan_func(resource: Resource) -> List[Finding]:
            """Simulated slow scan function."""
            time.sleep(0.1)  # Simulate I/O delay
            return [
                Finding(
                    resource=resource,
                    policy_id="TEST_POLICY",
                    severity=Severity.LOW,
                    type=FindingType.MISCONFIGURATION,
                    title="Test Finding",
                    description="Test",
                )
            ]

        scanner = ParallelScanner(max_workers=4)

        # Parallel scan
        start = time.time()
        findings = scanner.scan_resources_parallel(sample_resources, slow_scan_func)
        parallel_time = time.time() - start

        # Sequential scan for comparison
        start = time.time()
        sequential_findings = []
        for resource in sample_resources:
            sequential_findings.extend(slow_scan_func(resource))
        sequential_time = time.time() - start

        # Parallel should be faster
        assert parallel_time < sequential_time
        assert len(findings) == len(sequential_findings) == len(sample_resources)

    def test_scan_resources_parallel_results(self, sample_resources):
        """Test parallel scanning produces correct results."""

        def test_scan_func(resource: Resource) -> List[Finding]:
            return [
                Finding(
                    resource=resource,
                    policy_id="TEST",
                    severity=Severity.INFO,
                    type=FindingType.MISCONFIGURATION,
                    title=f"Finding for {resource.id}",
                    description="Test finding",
                )
            ]

        scanner = ParallelScanner(max_workers=4)
        findings = scanner.scan_resources_parallel(sample_resources, test_scan_func)

        assert len(findings) == len(sample_resources)

        # Verify all resources were scanned
        scanned_resource_ids = {f.resource.id for f in findings}
        expected_resource_ids = {r.id for r in sample_resources}
        assert scanned_resource_ids == expected_resource_ids

    def test_scan_resources_parallel_error_handling(self, sample_resources):
        """Test parallel scanner handles errors gracefully."""

        def error_scan_func(resource: Resource) -> List[Finding]:
            if "s3" in resource.id:
                raise ValueError("Simulated error")
            return []

        scanner = ParallelScanner(max_workers=4)

        # Should not crash, should log errors
        findings = scanner.scan_resources_parallel(sample_resources, error_scan_func)

        # Should still process resources that don't error
        assert isinstance(findings, list)

    def test_evaluate_policies_parallel(self, sample_resources):
        """Test parallel policy evaluation."""
        from cloudguard_anomaly.core.models import Policy

        policy = Policy(
            id="TEST_POLICY",
            name="Test Policy",
            description="Test",
            severity=Severity.MEDIUM,
            resource_types=["*"],
            conditions=[{"property": "encryption_enabled", "operator": "equals", "value": False}],
        )

        scanner = ParallelScanner(max_workers=4)
        findings = scanner.evaluate_policies_parallel(sample_resources, [policy])

        assert isinstance(findings, list)
        # Should find at least one resource without encryption
        assert len(findings) >= 1

    def test_run_detectors_parallel(self, sample_resources):
        """Test parallel detector execution."""
        from cloudguard_anomaly.detectors.misconfig_detector import MisconfigDetector
        from cloudguard_anomaly.detectors.network_detector import NetworkDetector

        detectors = [MisconfigDetector(), NetworkDetector()]
        scanner = ParallelScanner(max_workers=2)

        findings = scanner.run_detectors_parallel(sample_resources, detectors)

        assert isinstance(findings, list)
        # Should find some misconfigurations
        assert len(findings) > 0

    def test_disabled_scanner_falls_back_to_sequential(self, sample_resources):
        """Test disabled scanner falls back to sequential processing."""

        def test_scan_func(resource: Resource) -> List[Finding]:
            return [
                Finding(
                    resource=resource,
                    policy_id="TEST",
                    severity=Severity.INFO,
                    type=FindingType.MISCONFIGURATION,
                    title="Test",
                    description="Test",
                )
            ]

        scanner = ParallelScanner(max_workers=4)
        scanner.enabled = False

        findings = scanner.scan_resources_parallel(sample_resources, test_scan_func)

        # Should still work, just sequentially
        assert len(findings) == len(sample_resources)

    def test_worker_count_configuration(self):
        """Test worker count respects configuration."""
        scanner = ParallelScanner(max_workers=10)
        assert scanner.max_workers == 10

        scanner2 = ParallelScanner(max_workers=1)
        assert scanner2.max_workers == 1

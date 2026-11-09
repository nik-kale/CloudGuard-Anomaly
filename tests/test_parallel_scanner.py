"""Tests for parallel scanning functionality."""

import time

from cloudguard_anomaly.core.evaluator import PolicyEvaluator
from cloudguard_anomaly.core.models import (
    Environment,
    Finding,
    Policy,
    Provider,
    Resource,
    ResourceType,
    Severity,
)
from cloudguard_anomaly.core.parallel import ParallelScanner
from cloudguard_anomaly.detectors.drift_detector import DriftDetector
from cloudguard_anomaly.detectors.misconfig_detector import MisconfigDetector
from cloudguard_anomaly.detectors.network_detector import NetworkDetector


def _finding(resource: Resource) -> list[Finding]:
    return [Finding(resource=resource, severity=Severity.LOW, title="t", description="d")]


class TestParallelScanner:
    def test_initialization(self):
        assert ParallelScanner(max_workers=5).max_workers == 5

    def test_scans_concurrently(self, sample_resources):
        def slow(resource):
            time.sleep(0.1)
            return _finding(resource)

        start = time.time()
        findings = ParallelScanner(max_workers=4).scan_resources_parallel(sample_resources, slow)

        assert time.time() - start < 0.1 * len(sample_resources)
        assert len(findings) == len(sample_resources)

    def test_every_resource_is_scanned(self, sample_resources):
        findings = ParallelScanner(max_workers=4).scan_resources_parallel(
            sample_resources, _finding
        )
        assert {f.resource.id for f in findings} == {r.id for r in sample_resources}

    def test_one_failure_does_not_lose_the_rest(self, sample_resources):
        def flaky(resource):
            if "s3" in resource.id:
                raise ValueError("boom")
            return _finding(resource)

        findings = ParallelScanner(max_workers=4).scan_resources_parallel(sample_resources, flaky)
        assert len(findings) == len(sample_resources) - 1

    def test_empty_input_is_a_no_op(self):
        scanner = ParallelScanner(max_workers=2)
        assert scanner.scan_resources_parallel([], _finding) == []
        assert scanner.run_detectors_parallel([], Environment("e", Provider.AWS)) == {}

    def test_evaluate_policies_parallel_returns_findings(self, sample_s3_bucket):
        """evaluate_policy never existed, so every check failed and was swallowed."""
        policy = Policy(
            id="P1",
            name="No public buckets",
            description="d",
            severity=Severity.HIGH,
            provider=Provider.AWS,
            resource_types=[ResourceType.STORAGE],
            condition={
                "property_check": {"path": "public_access", "operator": "equals", "value": True}
            },
            remediation="r",
        )
        findings = ParallelScanner(max_workers=2).evaluate_policies_parallel(
            [sample_s3_bucket], [policy], PolicyEvaluator([policy])
        )
        assert [f.policy_id for f in findings] == ["P1"]

    def test_detectors_receive_resources(self, sample_environment):
        """Detectors iterate resources; handing them an Environment returned nothing."""
        results = ParallelScanner(max_workers=2).run_detectors_parallel(
            [MisconfigDetector(), NetworkDetector()], sample_environment
        )
        assert results["MisconfigDetector"]
        assert results["NetworkDetector"]

    def test_drift_detector_gets_baseline_then_current(self, sample_s3_bucket):
        changed = Resource(
            id=sample_s3_bucket.id,
            name=sample_s3_bucket.name,
            type=sample_s3_bucket.type,
            provider=sample_s3_bucket.provider,
            region=sample_s3_bucket.region,
            properties={**sample_s3_bucket.properties, "public_access": False},
        )
        current = Environment("e", Provider.AWS, resources=[changed])
        baseline = Environment("b", Provider.AWS, resources=[sample_s3_bucket])

        anomalies = ParallelScanner(max_workers=1).run_detectors_parallel(
            [DriftDetector()], current, baseline
        )["DriftDetector"]

        assert anomalies
        assert anomalies[0].baseline["public_access"] is True

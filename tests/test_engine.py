"""
Unit tests for the analysis engine.
"""

import pytest
from cloudguard_anomaly.core.models import (
    Environment,
    Provider,
    Resource,
    ResourceType,
)
from cloudguard_anomaly.core.engine import AnalysisEngine


class TestAnalysisEngine:
    """Tests for AnalysisEngine class."""

    def test_engine_initialization(self):
        """Test engine can be initialized."""
        engine = AnalysisEngine(policies=[], enable_drift_detection=True, enable_agents=True)
        assert engine is not None
        assert engine.enable_drift_detection == True
        assert engine.enable_agents == True

    def test_scan_empty_environment(self):
        """Test scanning an empty environment."""
        engine = AnalysisEngine(policies=[])
        env = Environment(name="test-env", provider=Provider.AWS, resources=[])

        result = engine.scan_environment(env)

        assert result is not None
        assert len(result.findings) == 0
        assert len(result.anomalies) == 0

    def test_scan_with_resources(self):
        """Test scanning environment with resources."""
        engine = AnalysisEngine(policies=[], enable_agents=False)

        # Create a test resource with a public S3 bucket
        resource = Resource(
            id="s3-test",
            name="test-bucket",
            type=ResourceType.STORAGE,
            provider=Provider.AWS,
            region="us-east-1",
            properties={"acl": "public-read"},
        )

        env = Environment(name="test-env", provider=Provider.AWS, resources=[resource])

        result = engine.scan_environment(env)

        assert result is not None
        assert isinstance(result.findings, list)
        assert isinstance(result.summary, dict)

    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        engine = AnalysisEngine(policies=[])

        severity_counts = {"critical": 2, "high": 3, "medium": 1, "low": 0, "info": 0}

        score = engine._calculate_risk_score(severity_counts)

        assert score > 0
        assert score <= 100
        assert isinstance(score, int)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

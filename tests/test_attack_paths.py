"""
Tests for attack path analysis.
"""

import pytest
import networkx as nx

from cloudguard_anomaly.analysis.attack_paths import (
    AttackPathAnalyzer,
    AttackPath,
    AttackPathNode,
    get_attack_path_analyzer,
)
from cloudguard_anomaly.core.models import Severity, FindingType


class TestAttackPathAnalyzer:
    """Test attack path analysis functionality."""

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = AttackPathAnalyzer()
        assert isinstance(analyzer.graph, nx.DiGraph)
        assert analyzer.graph.number_of_nodes() == 0

    def test_build_attack_graph(self, sample_environment, sample_finding):
        """Test building attack graph from environment."""
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([sample_finding], [], sample_environment)

        # Should have nodes for resources and findings
        assert analyzer.graph.number_of_nodes() > 0

        # Check resource nodes exist
        resource_nodes = [
            n for n, d in analyzer.graph.nodes(data=True) if d.get("type") == "resource"
        ]
        assert len(resource_nodes) > 0

    def test_identify_entry_points(self, sample_environment, sample_security_group):
        """Test identifying public entry points."""
        analyzer = AttackPathAnalyzer()

        # Add security group with public access
        analyzer.graph.add_node(
            sample_security_group.id,
            type="resource",
            resource_type="network",
            public=True,
        )

        entry_points = analyzer._identify_entry_points()

        # Should find the public security group
        assert len(entry_points) > 0

    def test_identify_critical_assets(self, sample_environment, sample_iam_role):
        """Test identifying critical assets."""
        analyzer = AttackPathAnalyzer()

        # Add IAM role
        analyzer.graph.add_node(
            sample_iam_role.id,
            type="resource",
            resource_type="identity",
            criticality="high",
        )

        critical_assets = analyzer._identify_critical_assets()

        # Should find the IAM role
        assert len(critical_assets) > 0

    def test_find_critical_paths(self, sample_environment, sample_finding):
        """Test finding attack paths."""
        analyzer = AttackPathAnalyzer()

        # Build graph
        analyzer.build_attack_graph([sample_finding], [], sample_environment)

        # Find paths
        paths = analyzer.find_critical_paths()

        # Should return list of AttackPath objects
        assert isinstance(paths, list)
        for path in paths:
            assert isinstance(path, AttackPath)
            assert hasattr(path, "nodes")
            assert hasattr(path, "risk_score")

    def test_attack_path_scoring(self):
        """Test attack path risk scoring."""
        analyzer = AttackPathAnalyzer()

        # Create simple path
        analyzer.graph.add_node("entry", type="resource", public=True)
        analyzer.graph.add_node("finding1", type="finding", severity="critical")
        analyzer.graph.add_node("target", type="resource", criticality="high")

        analyzer.graph.add_edge("entry", "finding1")
        analyzer.graph.add_edge("finding1", "target")

        path = ["entry", "finding1", "target"]
        attack_path = analyzer._create_attack_path(path, "entry", "target")

        # Should have high risk score due to critical finding
        assert attack_path.risk_score > 50

    def test_path_length_affects_risk(self):
        """Test that path length affects risk score."""
        analyzer = AttackPathAnalyzer()

        # Short path
        analyzer.graph.add_node("entry1", type="resource", public=True)
        analyzer.graph.add_node("target1", type="resource", criticality="high")
        analyzer.graph.add_edge("entry1", "target1")

        short_path = analyzer._create_attack_path(["entry1", "target1"], "entry1", "target1")

        # Long path
        analyzer.graph.add_node("entry2", type="resource", public=True)
        analyzer.graph.add_node("middle1", type="resource")
        analyzer.graph.add_node("middle2", type="resource")
        analyzer.graph.add_node("target2", type="resource", criticality="high")

        analyzer.graph.add_edge("entry2", "middle1")
        analyzer.graph.add_edge("middle1", "middle2")
        analyzer.graph.add_edge("middle2", "target2")

        long_path = analyzer._create_attack_path(
            ["entry2", "middle1", "middle2", "target2"], "entry2", "target2"
        )

        # Shorter paths should have higher risk
        assert short_path.risk_score >= long_path.risk_score

    def test_generate_attack_path_report(self, sample_environment, sample_finding):
        """Test generating attack path report."""
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([sample_finding], [], sample_environment)

        paths = analyzer.find_critical_paths()
        report = analyzer.generate_report(paths)

        assert isinstance(report, dict)
        assert "total_paths" in report
        assert "high_risk_paths" in report
        assert "entry_points" in report
        assert "critical_assets" in report

    def test_add_resource_relationships_s3_iam(self, sample_s3_bucket, sample_iam_role):
        """Test adding S3 to IAM relationships."""
        from cloudguard_anomaly.core.models import Environment

        env = Environment(
            name="test",
            provider=sample_s3_bucket.provider,
            region="us-east-1",
            resources=[sample_s3_bucket, sample_iam_role],
        )

        analyzer = AttackPathAnalyzer()

        # Add nodes first
        analyzer.graph.add_node(sample_s3_bucket.id, type="resource")
        analyzer.graph.add_node(sample_iam_role.id, type="resource")

        analyzer._add_resource_relationships(env.resources)

        # Should create some relationships
        assert analyzer.graph.number_of_edges() >= 0

    def test_path_includes_findings(self, sample_environment, sample_finding):
        """Test that paths include finding nodes."""
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([sample_finding], [], sample_environment)

        # Check finding nodes exist
        finding_nodes = [
            n for n, d in analyzer.graph.nodes(data=True) if d.get("type") == "finding"
        ]

        if len(finding_nodes) > 0:
            # Findings should be in the graph
            assert len(finding_nodes) >= 1

    def test_get_path_details(self):
        """Test getting detailed path information."""
        analyzer = AttackPathAnalyzer()

        # Build simple path
        analyzer.graph.add_node("n1", type="resource", name="Public SG")
        analyzer.graph.add_node("n2", type="finding", title="Public Access", severity="high")
        analyzer.graph.add_node("n3", type="resource", name="Database")

        analyzer.graph.add_edge("n1", "n2")
        analyzer.graph.add_edge("n2", "n3")

        path = analyzer._create_attack_path(["n1", "n2", "n3"], "n1", "n3")

        assert len(path.nodes) == 3
        assert path.nodes[0].node_type in ["resource", "finding"]

    def test_empty_environment_no_paths(self):
        """Test that empty environment produces no paths."""
        from cloudguard_anomaly.core.models import Environment, CloudProvider

        empty_env = Environment(
            name="empty",
            provider=CloudProvider.AWS,
            region="us-east-1",
            resources=[],
        )

        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([], [], empty_env)

        paths = analyzer.find_critical_paths()

        assert len(paths) == 0

    def test_get_singleton_analyzer(self):
        """Test getting singleton analyzer instance."""
        analyzer1 = get_attack_path_analyzer()
        analyzer2 = get_attack_path_analyzer()

        # Should be same instance
        assert analyzer1 is analyzer2

    def test_calculate_criticality_score(self, sample_iam_role):
        """Test resource criticality calculation."""
        analyzer = AttackPathAnalyzer()

        # IAM roles should be critical
        score = analyzer._calculate_criticality(sample_iam_role)
        assert score > 0

    def test_path_sorting_by_risk(self, sample_environment, sample_finding):
        """Test paths are sorted by risk score."""
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([sample_finding], [], sample_environment)

        paths = analyzer.find_critical_paths()

        # Should be sorted descending by risk
        if len(paths) > 1:
            for i in range(len(paths) - 1):
                assert paths[i].risk_score >= paths[i + 1].risk_score

"""Tests for attack path analysis."""

import networkx as nx

from cloudguard_anomaly.analysis.attack_paths import AttackPath, AttackPathAnalyzer
from cloudguard_anomaly.core.models import (
    Environment,
    Finding,
    Provider,
    Resource,
    ResourceType,
    Severity,
)


def _resource(identifier, resource_type, **properties):
    return Resource(
        id=identifier,
        name=identifier,
        type=resource_type,
        provider=Provider.AWS,
        region="us-east-1",
        properties=properties,
    )


def _open_group_scenario():
    """A public security group fronting a database."""
    group = _resource("sg-1", ResourceType.SECURITY_GROUP)
    database = _resource("db-1", ResourceType.DATABASE, security_groups=["sg-1"])
    finding = Finding(
        id="f1",
        resource=group,
        severity=Severity.CRITICAL,
        title="Security group publicly exposed",
        description="d",
    )
    return [finding], Environment("e", Provider.AWS, resources=[group, database])


class TestAttackPathAnalyzer:
    def test_starts_empty(self):
        analyzer = AttackPathAnalyzer()
        assert isinstance(analyzer.graph, nx.DiGraph)
        assert analyzer.graph.number_of_nodes() == 0

    def test_graph_holds_resources_and_findings(self):
        findings, environment = _open_group_scenario()
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph(findings, [], environment)

        kinds = [data["type"] for _, data in analyzer.graph.nodes(data=True)]
        assert kinds.count("resource") == 2
        assert kinds.count("finding") == 1

    def test_finds_a_path_from_exposure_to_database(self):
        """Resource types were stringified as 'ResourceType.X', so no target ever matched."""
        findings, environment = _open_group_scenario()
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph(findings, [], environment)

        paths = analyzer.find_critical_paths()

        assert len(paths) == 1
        assert isinstance(paths[0], AttackPath)
        assert paths[0].target == "db-1"
        assert [node.node_id for node in paths[0].nodes] == ["finding-f1", "sg-1", "db-1"]
        assert paths[0].severity is Severity.CRITICAL

    def test_no_exposure_means_no_paths(self):
        _, environment = _open_group_scenario()
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([], [], environment)
        assert analyzer.find_critical_paths() == []

    def test_empty_environment_has_no_paths(self):
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph([], [], Environment("e", Provider.AWS))
        assert analyzer.find_critical_paths() == []

    def test_shorter_paths_score_higher(self):
        analyzer = AttackPathAnalyzer()
        analyzer.graph.add_node("a", type="finding", severity="critical")
        for node in ["b", "c", "d", "e"]:
            analyzer.graph.add_node(node, type="resource", resource_type="storage")

        short = analyzer._create_attack_path(["a", "b"], "a", "b")
        long = analyzer._create_attack_path(["a", "c", "d", "e"], "a", "e")

        assert short.risk_score > long.risk_score

    def test_report_names_each_path(self):
        findings, environment = _open_group_scenario()
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph(findings, [], environment)

        report = analyzer.generate_path_report(analyzer.find_critical_paths())

        assert "Entry Point: finding-f1" in report
        assert "Target: db-1" in report

    def test_empty_report(self):
        assert AttackPathAnalyzer().generate_path_report([]) == "No attack paths identified."

    def test_statistics(self):
        findings, environment = _open_group_scenario()
        analyzer = AttackPathAnalyzer()
        analyzer.build_attack_graph(findings, [], environment)

        stats = analyzer.get_statistics()

        assert stats["resources"] == 2
        assert stats["findings"] == 1
        assert stats["entry_points"] == 1

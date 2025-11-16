"""
Attack Path Analysis for CloudGuard-Anomaly.

Uses graph-based analysis to identify potential attack chains and prioritize
remediation based on actual exploit paths rather than individual severity.
"""

import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from cloudguard_anomaly.core.models import Finding, Anomaly, Environment, Resource, Severity

logger = logging.getLogger(__name__)


@dataclass
class AttackNode:
    """Node in the attack graph."""

    node_id: str
    node_type: str  # 'resource', 'finding', 'vulnerability'
    severity: str
    description: str
    resource_id: Optional[str] = None
    finding_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Represents a potential attack path."""

    path_id: str
    nodes: List[AttackNode]
    risk_score: float
    description: str
    entry_point: str  # First node (usually public-facing)
    target: str  # Final node (usually critical resource)
    length: int  # Number of hops
    severity: Severity
    remediation_priority: int  # 1-10, higher = more urgent


class AttackPathAnalyzer:
    """
    Analyzes security findings to identify exploit chains.

    Uses NetworkX to build a directed graph of resources, findings, and
    their relationships, then identifies paths from public entry points
    to critical assets.
    """

    def __init__(self):
        """Initialize attack path analyzer."""
        if not NETWORKX_AVAILABLE:
            raise ImportError(
                "NetworkX is required for attack path analysis. "
                "Install with: pip install networkx"
            )

        self.graph: nx.DiGraph = nx.DiGraph()
        logger.info("Attack path analyzer initialized")

    def build_attack_graph(
        self,
        findings: List[Finding],
        anomalies: List[Anomaly],
        environment: Environment
    ) -> nx.DiGraph:
        """
        Build directed graph of potential attack paths.

        Args:
            findings: Security findings
            anomalies: Configuration anomalies
            environment: Environment being analyzed

        Returns:
            Directed graph representing attack surface
        """
        self.graph.clear()

        # Add resources as nodes
        for resource in environment.resources:
            node_data = {
                'type': 'resource',
                'resource_type': str(resource.type),
                'provider': str(resource.provider),
                'region': resource.region,
                'properties': resource.properties,
            }
            self.graph.add_node(resource.id, **node_data)

        # Add findings as nodes and connect to resources
        for finding in findings:
            finding_node_id = f"finding-{finding.id}"
            node_data = {
                'type': 'finding',
                'severity': finding.severity.value,
                'title': finding.title,
                'description': finding.description,
            }
            self.graph.add_node(finding_node_id, **node_data)

            # Connect finding to affected resource
            if finding.resource:
                self.graph.add_edge(finding.resource.id, finding_node_id, relationship='has_finding')

        # Add edges based on resource relationships
        self._add_resource_relationships(environment.resources)

        # Add edges based on security implications
        self._add_security_edges(findings, environment.resources)

        logger.info(
            f"Built attack graph: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

        return self.graph

    def _add_resource_relationships(self, resources: List[Resource]):
        """Add edges based on resource relationships."""
        # Map resources for quick lookup
        resource_map = {r.id: r for r in resources}

        for resource in resources:
            props = resource.properties

            # S3 bucket to IAM roles (if bucket policy grants access)
            if 'bucket_policy' in props:
                policy = props.get('bucket_policy', {})
                statements = policy.get('Statement', [])
                for stmt in statements:
                    principals = stmt.get('Principal', {})
                    if isinstance(principals, dict):
                        arns = principals.get('AWS', [])
                        if isinstance(arns, str):
                            arns = [arns]
                        for arn in arns:
                            # Extract role name from ARN
                            if ':role/' in arn:
                                role_name = arn.split(':role/')[-1]
                                # Find matching role resource
                                for r in resources:
                                    if role_name in r.id:
                                        self.graph.add_edge(
                                            resource.id,
                                            r.id,
                                            relationship='grants_access'
                                        )

            # Security group to instances
            if 'security_groups' in props:
                sg_ids = props.get('security_groups', [])
                for sg_id in sg_ids:
                    if sg_id in resource_map:
                        self.graph.add_edge(
                            sg_id,
                            resource.id,
                            relationship='protects'
                        )

            # VPC relationships
            if 'vpc_id' in props:
                vpc_id = props['vpc_id']
                if vpc_id in resource_map:
                    self.graph.add_edge(
                        vpc_id,
                        resource.id,
                        relationship='contains'
                    )

    def _add_security_edges(self, findings: List[Finding], resources: List[Resource]):
        """Add edges based on security findings."""
        # Connect public-facing resources to findings
        for finding in findings:
            if not finding.resource:
                continue

            # Public access findings create entry points
            if 'public' in finding.title.lower() or 'exposed' in finding.title.lower():
                finding_node = f"finding-{finding.id}"
                # This finding represents a potential entry point
                self.graph.nodes[finding_node]['entry_point'] = True

            # IAM findings may lead to privilege escalation
            if 'iam' in finding.title.lower() or 'permission' in finding.title.lower():
                finding_node = f"finding-{finding.id}"
                self.graph.nodes[finding_node]['escalation_risk'] = True

    def find_critical_paths(self) -> List[AttackPath]:
        """
        Identify critical attack paths from entry points to critical resources.

        Returns:
            List of attack paths sorted by risk score
        """
        if not self.graph:
            logger.warning("No attack graph built - call build_attack_graph() first")
            return []

        # Identify entry points (public-facing/exposed resources)
        entry_points = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('entry_point') or
               ('public' in str(data.get('title', '')).lower()) or
               (data.get('type') == 'resource' and
                data.get('properties', {}).get('public_access'))
        ]

        # Identify critical targets (databases, storage with sensitive data)
        critical_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('type') == 'resource' and
               data.get('resource_type') in ['database', 'storage']
        ]

        paths = []

        # Find paths from entry points to critical resources
        for entry in entry_points:
            for target in critical_nodes:
                if entry == target:
                    continue

                try:
                    if nx.has_path(self.graph, entry, target):
                        # Find shortest path
                        path = nx.shortest_path(self.graph, entry, target)

                        # Create AttackPath object
                        attack_path = self._create_attack_path(path, entry, target)
                        if attack_path:
                            paths.append(attack_path)

                except nx.NetworkXNoPath:
                    continue

        # Sort by risk score
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        logger.info(f"Identified {len(paths)} potential attack paths")
        return paths

    def _create_attack_path(
        self,
        path: List[str],
        entry: str,
        target: str
    ) -> Optional[AttackPath]:
        """Create AttackPath object from node path."""
        nodes = []

        for node_id in path:
            node_data = self.graph.nodes[node_id]

            attack_node = AttackNode(
                node_id=node_id,
                node_type=node_data.get('type', 'unknown'),
                severity=node_data.get('severity', 'info'),
                description=node_data.get('title') or node_data.get('resource_type', ''),
                resource_id=node_id if node_data.get('type') == 'resource' else None,
                finding_id=node_id.replace('finding-', '') if node_data.get('type') == 'finding' else None,
                metadata=node_data
            )
            nodes.append(attack_node)

        # Calculate risk score
        risk_score = self._calculate_path_risk(nodes)

        # Determine overall severity
        severities = [n.severity for n in nodes if n.severity]
        if 'critical' in severities:
            severity = Severity.CRITICAL
        elif 'high' in severities:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        # Generate description
        description = f"Attack path from {entry} to {target} via {len(path)-2} intermediate steps"

        # Calculate remediation priority (1-10)
        priority = min(10, int(risk_score / 10) + len(path))

        return AttackPath(
            path_id=f"path-{entry}-{target}",
            nodes=nodes,
            risk_score=risk_score,
            description=description,
            entry_point=entry,
            target=target,
            length=len(path),
            severity=severity,
            remediation_priority=priority
        )

    def _calculate_path_risk(self, nodes: List[AttackNode]) -> float:
        """
        Calculate risk score for an attack path.

        Args:
            nodes: Nodes in the path

        Returns:
            Risk score (0-100)
        """
        risk_score = 0.0

        # Severity weights
        severity_weights = {
            'critical': 40,
            'high': 25,
            'medium': 15,
            'low': 5,
            'info': 1
        }

        # Add severity scores
        for node in nodes:
            severity = node.severity.lower() if node.severity else 'info'
            risk_score += severity_weights.get(severity, 0)

        # Penalty for path length (longer = easier)
        path_length_penalty = len(nodes) * 2

        # Bonus for entry point + escalation + critical target
        has_entry = any(n.metadata.get('entry_point') for n in nodes)
        has_escalation = any(n.metadata.get('escalation_risk') for n in nodes)
        has_critical_target = nodes[-1].metadata.get('resource_type') == 'database'

        if has_entry:
            risk_score += 15
        if has_escalation:
            risk_score += 10
        if has_critical_target:
            risk_score += 20

        total_risk = risk_score + path_length_penalty

        return min(100.0, total_risk)

    def generate_path_report(self, paths: List[AttackPath]) -> str:
        """
        Generate human-readable report of attack paths.

        Args:
            paths: Attack paths to report

        Returns:
            Formatted report string
        """
        if not paths:
            return "No attack paths identified."

        report = []
        report.append("=" * 80)
        report.append("ATTACK PATH ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nIdentified {len(paths)} potential attack paths\n")

        for i, path in enumerate(paths[:10], 1):  # Top 10
            report.append(f"\n{'='*80}")
            report.append(f"PATH #{i} - Risk Score: {path.risk_score:.1f}/100 - Priority: {path.remediation_priority}/10")
            report.append(f"{'='*80}")
            report.append(f"Entry Point: {path.entry_point}")
            report.append(f"Target: {path.target}")
            report.append(f"Path Length: {path.length} hops")
            report.append(f"Severity: {path.severity.value.upper()}\n")

            report.append("Attack Chain:")
            for j, node in enumerate(path.nodes, 1):
                icon = "🔓" if node.metadata.get('entry_point') else "➜"
                report.append(f"  {icon} Step {j}: {node.description}")
                if node.severity:
                    report.append(f"    Severity: {node.severity.upper()}")

            report.append(f"\nDescription: {path.description}\n")

        return "\n".join(report)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the attack graph.

        Returns:
            Dictionary with graph statistics
        """
        if not self.graph:
            return {}

        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'resources': len([n for n, d in self.graph.nodes(data=True) if d.get('type') == 'resource']),
            'findings': len([n for n, d in self.graph.nodes(data=True) if d.get('type') == 'finding']),
            'entry_points': len([n for n, d in self.graph.nodes(data=True) if d.get('entry_point')]),
            'is_connected': nx.is_weakly_connected(self.graph) if self.graph.number_of_nodes() > 0 else False,
        }

"""
Advanced Attack Path Analysis for CloudGuard-Anomaly v2.

Provides sophisticated graph-based threat modeling with:
- Multi-dimensional risk scoring
- MITRE ATT&CK technique mapping
- Blast radius calculation
- Centrality analysis for critical nodes
- Interactive graph visualization
- Advanced pathfinding algorithms
"""

import logging
import json
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
from enum import Enum

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from cloudguard_anomaly.core.models import Finding, Anomaly, Environment, Resource, Severity

logger = logging.getLogger(__name__)


class AttackTechnique(Enum):
    """MITRE ATT&CK technique categories."""
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class ThreatIntelligence:
    """Threat intelligence context for a node."""
    cve_ids: List[str] = field(default_factory=list)
    exploit_availability: str = "unknown"  # none, poc, weaponized
    attack_techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    threat_actor_groups: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0  # 0-10


@dataclass
class AdvancedAttackNode:
    """Enhanced node with advanced threat context."""
    node_id: str
    node_type: str
    severity: str
    description: str
    resource_id: Optional[str] = None
    finding_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Optional[ThreatIntelligence] = None
    centrality_score: float = 0.0
    blast_radius: int = 0
    is_critical_chokepoint: bool = False


@dataclass
class AdvancedAttackPath:
    """Enhanced attack path with advanced analytics."""
    path_id: str
    nodes: List[AdvancedAttackNode]
    risk_score: float
    cvss_score: float
    description: str
    entry_point: str
    target: str
    length: int
    severity: Severity
    remediation_priority: int
    attack_techniques: List[str] = field(default_factory=list)
    estimated_time_to_compromise: str = "unknown"  # hours, days, weeks
    likelihood: str = "medium"  # low, medium, high, critical
    impact: str = "medium"  # low, medium, high, critical
    mitigation_steps: List[str] = field(default_factory=list)
    assets_at_risk: int = 0


@dataclass
class BlastRadiusAnalysis:
    """Analysis of potential impact scope."""
    source_node: str
    directly_affected: List[str]
    indirectly_affected: List[str]
    total_affected: int
    affected_by_severity: Dict[str, int]
    affected_by_type: Dict[str, int]
    estimated_cost: float = 0.0


class AdvancedAttackPathAnalyzer:
    """
    Advanced attack path analysis with sophisticated threat modeling.

    Features:
    - Graph centrality analysis to identify critical nodes
    - MITRE ATT&CK technique mapping
    - Blast radius calculation
    - Multi-factor risk scoring
    - Interactive graph visualization export
    - Choke point identification
    """

    def __init__(self):
        """Initialize advanced attack path analyzer."""
        if not NETWORKX_AVAILABLE:
            raise ImportError(
                "NetworkX is required for attack path analysis. "
                "Install with: pip install networkx"
            )

        self.graph: nx.DiGraph = nx.DiGraph()
        self.centrality_scores: Dict[str, float] = {}
        self.betweenness_scores: Dict[str, float] = {}
        self.pagerank_scores: Dict[str, float] = {}

        # MITRE ATT&CK mapping for common cloud misconfigurations
        self.attack_technique_map = self._initialize_attack_technique_map()

        logger.info("Advanced attack path analyzer initialized")

    def _initialize_attack_technique_map(self) -> Dict[str, List[str]]:
        """Map common security findings to MITRE ATT&CK techniques."""
        return {
            "public_s3": ["T1530", "T1567"],  # Data from Cloud Storage, Exfiltration
            "public_rds": ["T1530", "T1213"],  # Data from Information Repositories
            "ssh_open": ["T1078", "T1133"],  # Valid Accounts, External Remote Services
            "rdp_open": ["T1078", "T1133"],
            "overprivileged_iam": ["T1078", "T1098"],  # Account Manipulation
            "missing_mfa": ["T1078", "T1556"],  # Modify Authentication Process
            "public_snapshot": ["T1530"],
            "unencrypted_storage": ["T1530", "T1005"],  # Data from Local System
            "logging_disabled": ["T1562"],  # Impair Defenses
            "wildcard_permissions": ["T1098", "T1548"],  # Abuse Elevation Control
        }

    def build_advanced_attack_graph(
        self,
        findings: List[Finding],
        anomalies: List[Anomaly],
        environment: Environment
    ) -> nx.DiGraph:
        """
        Build advanced attack graph with enhanced node attributes.

        Args:
            findings: Security findings
            anomalies: Configuration anomalies
            environment: Environment being analyzed

        Returns:
            Enhanced directed graph with threat intelligence
        """
        self.graph.clear()

        # Add resources as nodes with enhanced metadata
        for resource in environment.resources:
            node_data = {
                'type': 'resource',
                'resource_type': str(resource.type),
                'provider': str(resource.provider),
                'region': resource.region,
                'properties': resource.properties,
                'criticality': self._assess_resource_criticality(resource),
                'exposure': self._assess_resource_exposure(resource),
            }
            self.graph.add_node(resource.id, **node_data)

        # Add findings with threat intelligence
        for finding in findings:
            finding_node_id = f"finding-{finding.id}"

            # Map to MITRE ATT&CK techniques
            techniques = self._map_to_attack_techniques(finding)

            node_data = {
                'type': 'finding',
                'severity': finding.severity.value,
                'title': finding.title,
                'description': finding.description,
                'attack_techniques': techniques,
                'exploitability': self._assess_exploitability(finding),
            }
            self.graph.add_node(finding_node_id, **node_data)

            # Connect finding to affected resource
            if finding.resource:
                self.graph.add_edge(
                    finding.resource.id,
                    finding_node_id,
                    relationship='has_finding',
                    weight=self._get_edge_weight(finding.severity)
                )

        # Add comprehensive resource relationships
        self._add_comprehensive_relationships(environment.resources)

        # Calculate centrality metrics
        self._calculate_centrality_metrics()

        logger.info(
            f"Built advanced attack graph: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

        return self.graph

    def _assess_resource_criticality(self, resource: Resource) -> str:
        """Assess resource criticality level."""
        critical_types = {'database', 'key_management', 'secrets_manager'}
        high_types = {'storage', 'compute', 'container'}

        if resource.type in critical_types:
            return 'critical'
        elif resource.type in high_types:
            return 'high'
        else:
            return 'medium'

    def _assess_resource_exposure(self, resource: Resource) -> str:
        """Assess resource exposure level."""
        props = resource.properties

        # Check for public exposure indicators
        if props.get('public_access') or props.get('public_ip'):
            return 'public'
        elif props.get('vpc_id') and not props.get('internet_gateway'):
            return 'private'
        else:
            return 'internal'

    def _map_to_attack_techniques(self, finding: Finding) -> List[str]:
        """Map finding to MITRE ATT&CK techniques."""
        techniques = []
        title_lower = finding.title.lower()

        for pattern, techs in self.attack_technique_map.items():
            if pattern.replace('_', ' ') in title_lower:
                techniques.extend(techs)

        return list(set(techniques))

    def _assess_exploitability(self, finding: Finding) -> float:
        """Assess exploitability score (0-10)."""
        score = 0.0
        title_lower = finding.title.lower()

        # High exploitability indicators
        if 'public' in title_lower:
            score += 4.0
        if 'ssh' in title_lower or 'rdp' in title_lower:
            score += 3.0
        if 'default' in title_lower or 'weak' in title_lower:
            score += 2.0
        if 'admin' in title_lower or 'root' in title_lower:
            score += 1.0

        # Severity multiplier
        severity_multipliers = {
            Severity.CRITICAL: 1.5,
            Severity.HIGH: 1.3,
            Severity.MEDIUM: 1.1,
            Severity.LOW: 1.0,
        }
        score *= severity_multipliers.get(finding.severity, 1.0)

        return min(10.0, score)

    def _get_edge_weight(self, severity: Severity) -> float:
        """Get edge weight based on severity."""
        weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        return weights.get(severity, 0.5)

    def _add_comprehensive_relationships(self, resources: List[Resource]):
        """Add comprehensive resource relationships."""
        resource_map = {r.id: r for r in resources}

        for resource in resources:
            props = resource.properties

            # IAM relationships
            if 'policies' in props:
                for policy in props.get('policies', []):
                    if isinstance(policy, dict):
                        for resource_arn in policy.get('resources', []):
                            # Link IAM to resources it can access
                            self.graph.add_edge(
                                resource.id,
                                resource_arn,
                                relationship='can_access',
                                weight=0.9
                            )

            # Network relationships
            if 'security_groups' in props:
                for sg_id in props.get('security_groups', []):
                    if sg_id in resource_map:
                        self.graph.add_edge(
                            sg_id,
                            resource.id,
                            relationship='protects',
                            weight=0.7
                        )

            # VPC/Network containment
            if 'vpc_id' in props:
                vpc_id = props['vpc_id']
                if vpc_id in resource_map:
                    self.graph.add_edge(
                        vpc_id,
                        resource.id,
                        relationship='contains',
                        weight=0.6
                    )

            # Storage to compute relationships
            if 'volumes' in props:
                for volume_id in props.get('volumes', []):
                    if volume_id in resource_map:
                        self.graph.add_edge(
                            volume_id,
                            resource.id,
                            relationship='attached_to',
                            weight=0.8
                        )

            # Database to application relationships
            if 'database_connections' in props:
                for db_id in props.get('database_connections', []):
                    if db_id in resource_map:
                        self.graph.add_edge(
                            resource.id,
                            db_id,
                            relationship='connects_to',
                            weight=0.85
                        )

    def _calculate_centrality_metrics(self):
        """Calculate various centrality metrics for all nodes."""
        if self.graph.number_of_nodes() == 0:
            return

        try:
            # Degree centrality - nodes with many connections
            self.centrality_scores = nx.degree_centrality(self.graph)

            # Betweenness centrality - nodes that act as bridges
            self.betweenness_scores = nx.betweenness_centrality(self.graph)

            # PageRank - importance based on incoming connections
            self.pagerank_scores = nx.pagerank(self.graph, weight='weight')

            logger.info("Calculated centrality metrics for all nodes")
        except Exception as e:
            logger.error(f"Error calculating centrality metrics: {e}")

    def find_advanced_attack_paths(
        self,
        max_paths: int = 100,
        min_risk_score: float = 30.0
    ) -> List[AdvancedAttackPath]:
        """
        Find attack paths with advanced risk analysis.

        Args:
            max_paths: Maximum number of paths to return
            min_risk_score: Minimum risk score threshold

        Returns:
            List of advanced attack paths
        """
        if not self.graph:
            logger.warning("No attack graph built")
            return []

        # Identify entry points
        entry_points = self._identify_entry_points()

        # Identify critical targets
        critical_nodes = self._identify_critical_targets()

        paths = []

        # Find paths with weighted shortest path algorithms
        for entry in entry_points:
            for target in critical_nodes:
                if entry == target:
                    continue

                try:
                    # Use Dijkstra for weighted paths
                    if nx.has_path(self.graph, entry, target):
                        path = nx.shortest_path(
                            self.graph,
                            entry,
                            target,
                            weight=lambda u, v, d: 1.0 / d.get('weight', 0.5)
                        )

                        attack_path = self._create_advanced_attack_path(path, entry, target)

                        if attack_path and attack_path.risk_score >= min_risk_score:
                            paths.append(attack_path)

                except (nx.NetworkXNoPath, nx.NetworkXError) as e:
                    continue

        # Sort by risk score
        paths.sort(key=lambda p: (p.risk_score, p.cvss_score), reverse=True)

        logger.info(f"Identified {len(paths)} advanced attack paths")
        return paths[:max_paths]

    def _identify_entry_points(self) -> List[str]:
        """Identify potential attack entry points."""
        entry_points = []

        for node, data in self.graph.nodes(data=True):
            # Public-facing resources
            if data.get('exposure') == 'public':
                entry_points.append(node)

            # Findings indicating entry points
            if data.get('type') == 'finding':
                title_lower = data.get('title', '').lower()
                if any(keyword in title_lower for keyword in ['public', 'exposed', 'ssh', 'rdp', 'open']):
                    entry_points.append(node)

        return entry_points

    def _identify_critical_targets(self) -> List[str]:
        """Identify critical assets as attack targets."""
        critical_nodes = []

        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'resource':
                # Critical resource types
                if data.get('criticality') in ['critical', 'high']:
                    critical_nodes.append(node)

                # Resources with sensitive data indicators
                props = data.get('properties', {})
                if props.get('encryption') is False or props.get('sensitive_data'):
                    critical_nodes.append(node)

        return critical_nodes

    def _create_advanced_attack_path(
        self,
        path: List[str],
        entry: str,
        target: str
    ) -> Optional[AdvancedAttackPath]:
        """Create advanced attack path with comprehensive analysis."""
        nodes = []
        all_techniques = []

        for node_id in path:
            node_data = self.graph.nodes[node_id]

            # Get centrality and blast radius
            centrality = self.betweenness_scores.get(node_id, 0.0)
            blast_radius = self.calculate_blast_radius_for_node(node_id).total_affected

            attack_node = AdvancedAttackNode(
                node_id=node_id,
                node_type=node_data.get('type', 'unknown'),
                severity=node_data.get('severity', 'info'),
                description=node_data.get('title') or node_data.get('resource_type', ''),
                resource_id=node_id if node_data.get('type') == 'resource' else None,
                finding_id=node_id.replace('finding-', '') if node_data.get('type') == 'finding' else None,
                metadata=node_data,
                centrality_score=centrality,
                blast_radius=blast_radius,
                is_critical_chokepoint=centrality > 0.1
            )
            nodes.append(attack_node)

            # Collect attack techniques
            techniques = node_data.get('attack_techniques', [])
            all_techniques.extend(techniques)

        # Calculate risk scores
        risk_score = self._calculate_advanced_risk_score(nodes, path)
        cvss_score = self._calculate_cvss_score(nodes)

        # Determine severity
        severity = self._determine_path_severity(nodes)

        # Estimate time to compromise
        ttc = self._estimate_time_to_compromise(len(path), risk_score)

        # Calculate likelihood and impact
        likelihood = self._calculate_likelihood(nodes)
        impact = self._calculate_impact(nodes)

        # Generate mitigation steps
        mitigation_steps = self._generate_mitigation_steps(nodes)

        # Count assets at risk
        assets_at_risk = len(set(n.resource_id for n in nodes if n.resource_id))

        description = (
            f"Attack path from {entry} to {target} via {len(path)-2} intermediate steps. "
            f"Exploits {len(set(all_techniques))} MITRE ATT&CK techniques."
        )

        priority = min(10, int(risk_score / 10) + (2 if likelihood == 'high' else 0))

        return AdvancedAttackPath(
            path_id=f"adv-path-{entry[:8]}-{target[:8]}",
            nodes=nodes,
            risk_score=risk_score,
            cvss_score=cvss_score,
            description=description,
            entry_point=entry,
            target=target,
            length=len(path),
            severity=severity,
            remediation_priority=priority,
            attack_techniques=list(set(all_techniques)),
            estimated_time_to_compromise=ttc,
            likelihood=likelihood,
            impact=impact,
            mitigation_steps=mitigation_steps,
            assets_at_risk=assets_at_risk
        )

    def _calculate_advanced_risk_score(
        self,
        nodes: List[AdvancedAttackNode],
        path: List[str]
    ) -> float:
        """Calculate comprehensive risk score."""
        risk = 0.0

        # Severity contribution
        severity_weights = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5, 'info': 1}
        for node in nodes:
            severity = node.severity.lower() if node.severity else 'info'
            risk += severity_weights.get(severity, 0)

        # Centrality contribution (critical choke points increase risk)
        centrality_bonus = sum(n.centrality_score * 20 for n in nodes)
        risk += centrality_bonus

        # Blast radius contribution
        blast_radius_bonus = sum(min(n.blast_radius, 10) for n in nodes)
        risk += blast_radius_bonus

        # Path length (shorter = more critical)
        if len(nodes) <= 3:
            risk += 20
        elif len(nodes) <= 5:
            risk += 10

        # Entry point and target bonuses
        if nodes[0].metadata.get('exposure') == 'public':
            risk += 15
        if nodes[-1].metadata.get('criticality') == 'critical':
            risk += 25

        return min(100.0, risk)

    def _calculate_cvss_score(self, nodes: List[AdvancedAttackNode]) -> float:
        """Calculate CVSS-like score for the path."""
        # Simplified CVSS calculation
        # Base score components
        attack_vector = 3.9  # Network
        attack_complexity = 0.77  # Low (path exists)
        privileges_required = 0.85  # None (public entry)
        user_interaction = 0.85  # None

        # Impact metrics
        confidentiality = 0.56  # High
        integrity = 0.56  # High
        availability = 0.22  # Low

        impact = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
        exploitability = attack_vector * attack_complexity * privileges_required * user_interaction

        if impact <= 0:
            return 0.0

        base_score = min(10.0, ((impact + exploitability - 1.5) * 1.5))

        return round(base_score, 1)

    def _determine_path_severity(self, nodes: List[AdvancedAttackNode]) -> Severity:
        """Determine overall path severity."""
        severities = [n.severity for n in nodes if n.severity]

        if 'critical' in severities:
            return Severity.CRITICAL
        elif 'high' in severities:
            return Severity.HIGH
        elif 'medium' in severities:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _estimate_time_to_compromise(self, path_length: int, risk_score: float) -> str:
        """Estimate time an attacker would need."""
        if risk_score > 80 and path_length <= 3:
            return "minutes"
        elif risk_score > 60 and path_length <= 5:
            return "hours"
        elif risk_score > 40:
            return "days"
        else:
            return "weeks"

    def _calculate_likelihood(self, nodes: List[AdvancedAttackNode]) -> str:
        """Calculate likelihood of exploitation."""
        exploitability_avg = sum(
            n.metadata.get('exploitability', 0) for n in nodes
        ) / max(len(nodes), 1)

        if exploitability_avg > 7:
            return "critical"
        elif exploitability_avg > 5:
            return "high"
        elif exploitability_avg > 3:
            return "medium"
        else:
            return "low"

    def _calculate_impact(self, nodes: List[AdvancedAttackNode]) -> str:
        """Calculate potential impact."""
        has_critical = any(n.metadata.get('criticality') == 'critical' for n in nodes)
        max_blast_radius = max((n.blast_radius for n in nodes), default=0)

        if has_critical and max_blast_radius > 10:
            return "critical"
        elif has_critical or max_blast_radius > 5:
            return "high"
        elif max_blast_radius > 2:
            return "medium"
        else:
            return "low"

    def _generate_mitigation_steps(self, nodes: List[AdvancedAttackNode]) -> List[str]:
        """Generate prioritized mitigation recommendations."""
        steps = []

        for node in nodes:
            if node.is_critical_chokepoint:
                steps.append(f"Secure critical choke point: {node.description}")

            if node.metadata.get('exposure') == 'public':
                steps.append(f"Restrict public access to: {node.description}")

            if 'ssh' in node.description.lower() or 'rdp' in node.description.lower():
                steps.append("Implement VPN/bastion host for remote access")

        return steps[:5]  # Top 5 steps

    def calculate_blast_radius_for_node(self, node_id: str) -> BlastRadiusAnalysis:
        """Calculate blast radius if a node is compromised."""
        if node_id not in self.graph:
            return BlastRadiusAnalysis(
                source_node=node_id,
                directly_affected=[],
                indirectly_affected=[],
                total_affected=0,
                affected_by_severity={},
                affected_by_type={}
            )

        # Direct descendants (1 hop)
        directly_affected = list(self.graph.successors(node_id))

        # Indirect descendants (2+ hops)
        all_reachable = nx.descendants(self.graph, node_id)
        indirectly_affected = list(all_reachable - set(directly_affected))

        # Categorize by severity and type
        affected_by_severity = defaultdict(int)
        affected_by_type = defaultdict(int)

        for affected_node in all_reachable:
            node_data = self.graph.nodes[affected_node]
            severity = node_data.get('severity', 'info')
            node_type = node_data.get('type', 'unknown')

            affected_by_severity[severity] += 1
            affected_by_type[node_type] += 1

        return BlastRadiusAnalysis(
            source_node=node_id,
            directly_affected=directly_affected,
            indirectly_affected=indirectly_affected,
            total_affected=len(all_reachable),
            affected_by_severity=dict(affected_by_severity),
            affected_by_type=dict(affected_by_type)
        )

    def identify_critical_choke_points(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Identify critical choke points in the attack graph.

        Nodes with high betweenness centrality that, if secured,
        would break many attack paths.

        Args:
            top_n: Number of top choke points to return

        Returns:
            List of (node_id, betweenness_score) tuples
        """
        if not self.betweenness_scores:
            self._calculate_centrality_metrics()

        sorted_nodes = sorted(
            self.betweenness_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_nodes[:top_n]

    def export_graph_visualization(self, output_path: str) -> Dict[str, Any]:
        """
        Export graph data for visualization.

        Args:
            output_path: Path to save visualization data

        Returns:
            Dictionary with graph data in D3.js compatible format
        """
        nodes_data = []
        links_data = []

        # Export nodes
        for node_id, node_data in self.graph.nodes(data=True):
            nodes_data.append({
                'id': node_id,
                'type': node_data.get('type'),
                'severity': node_data.get('severity'),
                'label': node_data.get('title') or node_data.get('resource_type', ''),
                'centrality': self.centrality_scores.get(node_id, 0),
                'pagerank': self.pagerank_scores.get(node_id, 0),
            })

        # Export edges
        for source, target, edge_data in self.graph.edges(data=True):
            links_data.append({
                'source': source,
                'target': target,
                'relationship': edge_data.get('relationship'),
                'weight': edge_data.get('weight', 0.5),
            })

        viz_data = {
            'nodes': nodes_data,
            'links': links_data,
            'metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'total_nodes': len(nodes_data),
                'total_edges': len(links_data),
            }
        }

        # Save to file
        with open(output_path, 'w') as f:
            json.dump(viz_data, f, indent=2)

        logger.info(f"Exported graph visualization to {output_path}")
        return viz_data

    def generate_advanced_report(self, paths: List[AdvancedAttackPath]) -> str:
        """Generate comprehensive attack path analysis report."""
        if not paths:
            return "No attack paths identified."

        report = []
        report.append("=" * 100)
        report.append("ADVANCED ATTACK PATH ANALYSIS REPORT")
        report.append("=" * 100)
        report.append(f"\nGenerated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Attack Paths Identified: {len(paths)}\n")

        # Executive summary
        critical_paths = len([p for p in paths if p.severity == Severity.CRITICAL])
        high_paths = len([p for p in paths if p.severity == Severity.HIGH])

        report.append("\nEXECUTIVE SUMMARY")
        report.append("-" * 100)
        report.append(f"Critical Risk Paths: {critical_paths}")
        report.append(f"High Risk Paths: {high_paths}")
        report.append(f"Average Risk Score: {sum(p.risk_score for p in paths) / len(paths):.1f}/100")
        report.append(f"Average CVSS Score: {sum(p.cvss_score for p in paths) / len(paths):.1f}/10")

        # Top choke points
        choke_points = self.identify_critical_choke_points(5)
        if choke_points:
            report.append("\nTOP CRITICAL CHOKE POINTS (Secure These First)")
            report.append("-" * 100)
            for node_id, score in choke_points:
                node_data = self.graph.nodes.get(node_id, {})
                label = node_data.get('title') or node_data.get('resource_type', node_id)
                report.append(f"  • {label} (Betweenness: {score:.3f})")

        # Detailed paths
        report.append(f"\n\nDETAILED ATTACK PATH ANALYSIS (Top {min(10, len(paths))} Paths)")
        report.append("=" * 100)

        for i, path in enumerate(paths[:10], 1):
            report.append(f"\n{'='*100}")
            report.append(f"PATH #{i} - {path.severity.value.upper()}")
            report.append(f"{'='*100}")
            report.append(f"Risk Score: {path.risk_score:.1f}/100 | CVSS: {path.cvss_score}/10 | Priority: {path.remediation_priority}/10")
            report.append(f"Likelihood: {path.likelihood.upper()} | Impact: {path.impact.upper()}")
            report.append(f"Time to Compromise: {path.estimated_time_to_compromise}")
            report.append(f"Assets at Risk: {path.assets_at_risk}")

            if path.attack_techniques:
                report.append(f"\nMITRE ATT&CK Techniques: {', '.join(path.attack_techniques)}")

            report.append(f"\nAttack Chain ({path.length} steps):")
            for j, node in enumerate(path.nodes, 1):
                icon = "🔓" if node.metadata.get('exposure') == 'public' else "🔐" if node.is_critical_chokepoint else "➜"
                report.append(f"  {icon} Step {j}: {node.description}")
                if node.severity:
                    report.append(f"     Severity: {node.severity.upper()} | Blast Radius: {node.blast_radius}")
                if node.is_critical_chokepoint:
                    report.append(f"     ⚠️  CRITICAL CHOKE POINT")

            if path.mitigation_steps:
                report.append(f"\nRecommended Mitigations:")
                for step in path.mitigation_steps:
                    report.append(f"  • {step}")

            report.append("")

        return "\n".join(report)

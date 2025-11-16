"""
Cost Analysis Module for CloudGuard-Anomaly.

Analyzes the cost impact of security findings and provides cost optimization recommendations.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

from cloudguard_anomaly.core.models import Resource, Finding, Environment, Provider


class CostCategory(Enum):
    """Cost categories."""

    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    SECURITY = "security"
    OTHER = "other"


@dataclass
class CostEstimate:
    """Cost estimate for a resource."""

    resource_id: str
    resource_type: str
    category: CostCategory
    monthly_cost: float
    currency: str = "USD"
    provider: str = ""
    region: str = ""
    breakdown: Dict[str, float] = None

    def __post_init__(self):
        if self.breakdown is None:
            self.breakdown = {}


@dataclass
class CostImpact:
    """Cost impact of a security finding."""

    finding_id: str
    finding_title: str
    current_monthly_cost: float
    potential_savings: float
    implementation_cost: float
    roi_months: float
    recommendations: List[str] = None

    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []


class CostAnalyzer:
    """Analyzes cloud costs and security cost impacts."""

    # Simplified cost estimates (monthly USD)
    # In production, integrate with AWS Cost Explorer, Azure Cost Management, etc.
    BASE_COSTS = {
        # AWS
        "ec2.t3.micro": 8.0,
        "ec2.t3.small": 16.0,
        "ec2.t3.medium": 32.0,
        "ec2.m5.large": 70.0,
        "ec2.m5.xlarge": 140.0,
        "rds.db.t3.micro": 15.0,
        "rds.db.t3.small": 30.0,
        "rds.db.m5.large": 130.0,
        "s3.standard": 0.023,  # per GB
        "ebs.gp3": 0.08,  # per GB
        "lambda.requests": 0.20,  # per million requests
        # Azure
        "vm.b1s": 7.0,
        "vm.b2s": 30.0,
        "vm.d2s_v3": 96.0,
        "sql.basic": 5.0,
        "sql.s0": 15.0,
        "storage.standard": 0.018,  # per GB
        # GCP
        "compute.e2-micro": 6.0,
        "compute.e2-small": 12.0,
        "compute.n1-standard-1": 25.0,
        "sql.db-f1-micro": 7.0,
        "storage.standard": 0.020,  # per GB
    }

    def __init__(self):
        """Initialize cost analyzer."""
        pass

    def estimate_resource_cost(self, resource: Resource) -> CostEstimate:
        """
        Estimate monthly cost for a resource.

        Args:
            resource: Resource to analyze

        Returns:
            CostEstimate object
        """
        category = self._get_cost_category(resource)
        monthly_cost = self._calculate_base_cost(resource)

        # Add additional costs based on configuration
        additional_costs = self._calculate_additional_costs(resource)

        breakdown = {
            "base": monthly_cost,
            **additional_costs,
        }

        total_cost = sum(breakdown.values())

        return CostEstimate(
            resource_id=resource.id,
            resource_type=str(resource.type),
            category=category,
            monthly_cost=total_cost,
            provider=str(resource.provider),
            region=resource.region,
            breakdown=breakdown,
        )

    def _get_cost_category(self, resource: Resource) -> CostCategory:
        """Determine cost category for resource."""
        type_str = str(resource.type).lower()

        if "compute" in type_str or "vm" in type_str or "instance" in type_str:
            return CostCategory.COMPUTE
        elif "storage" in type_str or "bucket" in type_str or "blob" in type_str:
            return CostCategory.STORAGE
        elif "database" in type_str or "sql" in type_str or "db" in type_str:
            return CostCategory.DATABASE
        elif "network" in type_str or "vpc" in type_str or "subnet" in type_str:
            return CostCategory.NETWORK
        elif (
            "security_group" in type_str
            or "firewall" in type_str
            or "waf" in type_str
        ):
            return CostCategory.SECURITY
        else:
            return CostCategory.OTHER

    def _calculate_base_cost(self, resource: Resource) -> float:
        """Calculate base cost for resource."""
        # Try to match instance type or resource configuration
        props = resource.properties

        # AWS EC2
        if resource.provider == Provider.AWS and "compute" in str(resource.type).lower():
            instance_type = props.get("instance_type", "t3.micro")
            cost_key = f"ec2.{instance_type}"
            return self.BASE_COSTS.get(cost_key, 10.0)

        # AWS RDS
        if resource.provider == Provider.AWS and "database" in str(resource.type).lower():
            db_instance_class = props.get("db_instance_class", "db.t3.micro")
            cost_key = f"rds.{db_instance_class}"
            return self.BASE_COSTS.get(cost_key, 15.0)

        # AWS S3
        if resource.provider == Provider.AWS and "storage" in str(resource.type).lower():
            size_gb = props.get("size_gb", 100)
            return size_gb * self.BASE_COSTS.get("s3.standard", 0.023)

        # Azure VM
        if resource.provider == Provider.AZURE and "compute" in str(
            resource.type
        ).lower():
            vm_size = props.get("vm_size", "b1s")
            cost_key = f"vm.{vm_size}"
            return self.BASE_COSTS.get(cost_key, 10.0)

        # GCP Compute
        if resource.provider == Provider.GCP and "compute" in str(resource.type).lower():
            machine_type = props.get("machine_type", "e2-micro")
            cost_key = f"compute.{machine_type}"
            return self.BASE_COSTS.get(cost_key, 6.0)

        # Default
        return 10.0

    def _calculate_additional_costs(self, resource: Resource) -> Dict[str, float]:
        """Calculate additional costs (network, storage, etc.)."""
        costs = {}
        props = resource.properties

        # Network egress
        if props.get("public_ip"):
            costs["network_egress"] = 5.0

        # Additional storage
        if "volume_size" in props:
            volume_gb = props.get("volume_size", 0)
            costs["storage"] = volume_gb * 0.08

        # Backup costs
        if props.get("backup_enabled"):
            costs["backup"] = 10.0

        # Encryption costs (KMS keys)
        if props.get("encryption_enabled"):
            costs["kms"] = 1.0

        return costs

    def analyze_finding_cost_impact(self, finding: Finding, resource: Resource) -> CostImpact:
        """
        Analyze cost impact of a security finding.

        Args:
            finding: Security finding
            resource: Related resource

        Returns:
            CostImpact object
        """
        current_cost = self.estimate_resource_cost(resource).monthly_cost

        # Analyze potential savings based on finding type
        savings = 0.0
        implementation_cost = 0.0
        recommendations = []

        finding_type = finding.type.lower()

        if "public" in finding_type or "exposed" in finding_type:
            # Public resources may have unnecessary egress costs
            savings = 5.0  # Estimated monthly savings
            implementation_cost = 0.0  # No cost to restrict access
            recommendations.append(
                "Restrict public access to reduce data transfer costs"
            )

        elif "unencrypted" in finding_type or "encryption" in finding_type:
            # Enabling encryption has minimal cost
            savings = 0.0
            implementation_cost = 1.0  # Monthly KMS cost
            recommendations.append(
                "Enable encryption (minimal cost increase: ~$1/month)"
            )

        elif "unused" in finding_type or "idle" in finding_type:
            # Unused resources can be deleted
            savings = current_cost * 0.9  # Save 90% of cost
            implementation_cost = 0.0
            recommendations.append(f"Delete unused resource to save ${savings:.2f}/month")

        elif "oversized" in finding_type or "right-sizing" in finding_type:
            # Oversized instances
            savings = current_cost * 0.3  # Save 30% by right-sizing
            implementation_cost = 0.0
            recommendations.append(f"Right-size instance to save ${savings:.2f}/month")

        elif "backup" in finding_type and "missing" in finding_type:
            # Missing backups
            savings = 0.0
            implementation_cost = current_cost * 0.2  # 20% of resource cost
            recommendations.append(
                f"Enable backups (cost increase: ~${implementation_cost:.2f}/month)"
            )

        elif "logging" in finding_type and "disabled" in finding_type:
            # Missing logging
            savings = 0.0
            implementation_cost = 5.0  # CloudWatch/monitoring cost
            recommendations.append("Enable logging (cost increase: ~$5/month)")

        # Calculate ROI
        roi_months = (
            implementation_cost / savings if savings > 0 else float("inf")
        )

        return CostImpact(
            finding_id=finding.id,
            finding_title=finding.title,
            current_monthly_cost=current_cost,
            potential_savings=savings,
            implementation_cost=implementation_cost,
            roi_months=roi_months,
            recommendations=recommendations,
        )

    def analyze_environment_costs(
        self, environment: Environment, findings: List[Finding] = None
    ) -> Dict[str, Any]:
        """
        Analyze total costs for an environment.

        Args:
            environment: Environment to analyze
            findings: Optional list of findings

        Returns:
            Cost analysis summary
        """
        resource_costs = []
        total_cost = 0.0
        category_costs = {cat: 0.0 for cat in CostCategory}

        for resource in environment.resources:
            cost_estimate = self.estimate_resource_cost(resource)
            resource_costs.append(cost_estimate)
            total_cost += cost_estimate.monthly_cost
            category_costs[cost_estimate.category] += cost_estimate.monthly_cost

        # Analyze finding impacts
        finding_impacts = []
        total_potential_savings = 0.0

        if findings:
            for finding in findings:
                # Find related resource
                resource = next(
                    (r for r in environment.resources if r.id == finding.resource.id),
                    None,
                )
                if resource:
                    impact = self.analyze_finding_cost_impact(finding, resource)
                    finding_impacts.append(impact)
                    total_potential_savings += impact.potential_savings

        return {
            "environment_name": environment.name,
            "total_monthly_cost": total_cost,
            "category_breakdown": {
                cat.value: cost for cat, cost in category_costs.items()
            },
            "resource_count": len(environment.resources),
            "resource_costs": [
                {
                    "resource_id": c.resource_id,
                    "type": c.resource_type,
                    "monthly_cost": c.monthly_cost,
                    "category": c.category.value,
                }
                for c in resource_costs
            ],
            "finding_impacts": [
                {
                    "finding_id": f.finding_id,
                    "title": f.finding_title,
                    "current_cost": f.current_monthly_cost,
                    "potential_savings": f.potential_savings,
                    "roi_months": f.roi_months,
                    "recommendations": f.recommendations,
                }
                for f in finding_impacts
            ],
            "total_potential_savings": total_potential_savings,
            "optimized_cost": total_cost - total_potential_savings,
        }

    def generate_cost_optimization_report(
        self, environment: Environment, findings: List[Finding]
    ) -> str:
        """Generate human-readable cost optimization report."""
        analysis = self.analyze_environment_costs(environment, findings)

        report = []
        report.append("=" * 80)
        report.append("COST OPTIMIZATION REPORT")
        report.append("=" * 80)
        report.append(f"\nEnvironment: {analysis['environment_name']}")
        report.append(f"Current Monthly Cost: ${analysis['total_monthly_cost']:.2f}")
        report.append(
            f"Potential Savings: ${analysis['total_potential_savings']:.2f}"
        )
        report.append(f"Optimized Cost: ${analysis['optimized_cost']:.2f}")
        report.append(f"\nCost Breakdown by Category:")

        for category, cost in analysis["category_breakdown"].items():
            if cost > 0:
                report.append(f"  {category.upper()}: ${cost:.2f}")

        if analysis["finding_impacts"]:
            report.append(f"\nCost Optimization Opportunities:")
            for impact in analysis["finding_impacts"]:
                if impact["potential_savings"] > 0:
                    report.append(f"\n  • {impact['title']}")
                    report.append(f"    Savings: ${impact['potential_savings']:.2f}/month")
                    for rec in impact["recommendations"]:
                        report.append(f"    → {rec}")

        return "\n".join(report)

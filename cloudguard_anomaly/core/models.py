"""
Core data models for CloudGuard-Anomaly framework.

This module defines the fundamental data structures used throughout the framework
for representing cloud resources, policies, findings, and anomalies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for findings and anomalies."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric order of the level; higher is more severe."""
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class ResourceType(str, Enum):
    """Common cloud resource types across providers."""

    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY_GROUP = "security_group"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    LOAD_BALANCER = "load_balancer"
    API_GATEWAY = "api_gateway"
    FUNCTION = "function"
    QUEUE = "queue"
    TOPIC = "topic"
    SECRET = "secret"
    KEY = "key"
    UNKNOWN = "unknown"


class Provider(str, Enum):
    """Supported cloud providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    MULTI = "multi"


class FindingType(str, Enum):
    """Types of security findings."""

    MISCONFIGURATION = "misconfiguration"
    DRIFT = "drift"
    IDENTITY_RISK = "identity_risk"
    NETWORK_EXPOSURE = "network_exposure"
    COMPLIANCE_VIOLATION = "compliance_violation"
    ANOMALY = "anomaly"


@dataclass
class Resource:
    """
    Represents a cloud resource in the environment.

    Attributes:
        id: Unique identifier for the resource
        name: Human-readable name
        type: Type of resource (compute, storage, etc.)
        provider: Cloud provider (AWS, Azure, GCP)
        region: Cloud region
        properties: Resource-specific configuration properties
        tags: Resource tags/labels
        metadata: Additional metadata
    """

    id: str
    name: str
    type: ResourceType
    provider: Provider
    region: str
    properties: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert resource to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "provider": self.provider.value,
            "region": self.region,
            "properties": self.properties,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Resource":
        """Rebuild a resource from its :meth:`to_dict` form."""
        return cls(
            id=data["id"],
            name=data["name"],
            type=ResourceType(data["type"]),
            provider=Provider(data["provider"]),
            region=data.get("region", "global"),
            properties=data.get("properties", {}),
            tags=data.get("tags", {}),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Policy:
    """
    Represents a security policy or rule.

    Attributes:
        id: Unique policy identifier
        name: Policy name
        description: Human-readable description
        severity: Severity level for violations
        provider: Target provider (or MULTI for cross-cloud)
        resource_types: Applicable resource types
        condition: Policy condition logic
        remediation: Remediation guidance
        references: External references (CIS benchmarks, etc.)
    """

    id: str
    name: str
    description: str
    severity: Severity
    provider: Provider
    resource_types: list[ResourceType]
    condition: dict[str, Any]
    remediation: str
    references: list[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert policy to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "provider": self.provider.value,
            "resource_types": [rt.value for rt in self.resource_types],
            "condition": self.condition,
            "remediation": self.remediation,
            "references": self.references,
            "enabled": self.enabled,
        }


@dataclass
class Finding:
    """
    Represents a security finding discovered during analysis.

    Attributes:
        id: Unique finding identifier
        type: Type of finding
        severity: Severity level
        title: Short title/summary
        description: Detailed description
        resource: Affected resource
        policy: Policy that triggered the finding
        evidence: Supporting evidence
        remediation: Remediation steps
        timestamp: When finding was detected
    """

    id: str
    type: FindingType
    severity: Severity
    title: str
    description: str
    resource: Resource
    policy: Policy | None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "resource": self.resource.to_dict(),
            "policy": self.policy.to_dict() if self.policy else None,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Rebuild a finding from its :meth:`to_dict` form, without its policy object."""
        return cls(
            id=data["id"],
            type=FindingType(data["type"]),
            severity=Severity(data["severity"]),
            title=data["title"],
            description=data["description"],
            resource=Resource.from_dict(data["resource"]),
            policy=None,
            evidence=data.get("evidence", {}),
            remediation=data.get("remediation", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


@dataclass
class Anomaly:
    """
    Represents a detected anomaly or drift in configuration.

    Attributes:
        id: Unique anomaly identifier
        type: Type of anomaly
        severity: Severity level
        resource: Affected resource
        baseline: Baseline configuration
        current: Current configuration
        changes: Detected changes
        impact: Impact assessment
        timestamp: When anomaly was detected
    """

    id: str
    type: str
    severity: Severity
    resource: Resource
    baseline: dict[str, Any]
    current: dict[str, Any]
    changes: list[dict[str, Any]]
    impact: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert anomaly to dictionary representation."""
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity.value,
            "resource": self.resource.to_dict(),
            "baseline": self.baseline,
            "current": self.current,
            "changes": self.changes,
            "impact": self.impact,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Environment:
    """
    Represents a cloud environment to be analyzed.

    Attributes:
        name: Environment name
        provider: Primary cloud provider
        resources: List of resources in the environment
        baseline_resources: Baseline resource configurations
        metadata: Environment metadata
    """

    name: str
    provider: Provider
    resources: list[Resource] = field(default_factory=list)
    baseline_resources: list[Resource] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert environment to dictionary representation."""
        return {
            "name": self.name,
            "provider": self.provider.value,
            "resources": [r.to_dict() for r in self.resources],
            "baseline_resources": (
                [r.to_dict() for r in self.baseline_resources] if self.baseline_resources else None
            ),
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """
    Represents the complete results of a security scan.

    Attributes:
        environment: Scanned environment
        findings: List of findings
        anomalies: List of anomalies
        summary: Summary statistics
        narratives: Human-readable narratives
        timestamp: Scan timestamp
    """

    environment: Environment
    findings: list[Finding] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    narratives: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary representation."""
        return {
            "environment": self.environment.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "summary": self.summary,
            "narratives": self.narratives,
            "timestamp": self.timestamp.isoformat(),
        }

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> list[Finding]:
        """Get all critical findings."""
        return self.get_findings_by_severity(Severity.CRITICAL)

    def get_high_findings(self) -> list[Finding]:
        """Get all high severity findings."""
        return self.get_findings_by_severity(Severity.HIGH)

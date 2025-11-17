"""
Data Security Posture Management (DSPM) for CloudGuard-Anomaly v2.

Comprehensive data security analysis:
- Sensitive data discovery and classification
- Data exposure analysis
- Data encryption status
- Data access patterns
- Data lifecycle management
- PII/PHI/PCI detection
- Data residency compliance
"""

import logging
import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data sensitivity classification."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # PII, PHI, PCI


class DataType(Enum):
    """Types of sensitive data."""
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Industry data
    CREDENTIALS = "credentials"
    INTELLECTUAL_PROPERTY = "ip"
    FINANCIAL = "financial"


@dataclass
class SensitiveDataFinding:
    """Sensitive data discovery finding."""
    finding_id: str
    data_type: DataType
    classification: DataClassification
    location: str  # S3 bucket, database, etc.
    resource_id: str
    sample_matches: List[str]  # Redacted samples
    total_matches: int
    encrypted: bool
    public_access: bool
    risk_score: float
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DataStore:
    """Data storage resource."""
    store_id: str
    store_type: str  # s3, rds, dynamodb, etc.
    classification: DataClassification
    contains_sensitive_data: bool
    sensitive_data_types: List[DataType]
    encryption_at_rest: bool
    encryption_in_transit: bool
    access_logging: bool
    versioning_enabled: bool
    backup_enabled: bool
    public_access: bool
    cross_region_replication: bool
    data_residency_region: str
    last_accessed: Optional[datetime] = None


class DataSecurityScanner:
    """
    Data Security Posture Management scanner.

    Discovers and classifies sensitive data across cloud storage,
    databases, and data warehouses. Assesses data security controls
    and compliance with data protection regulations.
    """

    def __init__(self):
        """Initialize DSPM scanner."""
        self.findings: List[SensitiveDataFinding] = []
        self.data_patterns = self._load_data_patterns()
        logger.info("DSPM scanner initialized")

    def _load_data_patterns(self) -> Dict[DataType, List[str]]:
        """Load regex patterns for sensitive data detection."""
        return {
            DataType.PII: [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Z]{2}\d{6,8}\b',  # Passport
                r'\b\d{3}-\d{3}-\d{4}\b',  # Phone
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            ],
            DataType.PCI: [
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',  # Credit card
                r'\b\d{3,4}\b',  # CVV
            ],
            DataType.PHI: [
                r'\b(?:patient|medical|diagnosis|prescription)\b',
                r'\bICD-\d+\b',  # ICD codes
            ],
            DataType.CREDENTIALS: [
                r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']+',
                r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[^\s"\']+',
                r'(?i)(?:secret|token)\s*[:=]\s*["\']?[^\s"\']+',
                r'(?:AKIA|ASIA)[0-9A-Z]{16}',  # AWS access keys
            ],
            DataType.FINANCIAL: [
                r'\b(?:account|routing)[_-]?(?:number|num)\b',
                r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',  # IBAN
                r'\b\d{9}\b',  # Routing number
            ],
        }

    def scan_data_store(
        self,
        data_store: DataStore,
        sample_data: Optional[List[str]] = None
    ) -> List[SensitiveDataFinding]:
        """
        Scan a data store for sensitive data.

        Args:
            data_store: Data store to scan
            sample_data: Sample data for scanning (optional)

        Returns:
            List of sensitive data findings
        """
        logger.info(f"Scanning data store: {data_store.store_id}")

        findings = []

        # Scan sample data if provided
        if sample_data:
            for data_type, patterns in self.data_patterns.items():
                matches = self._scan_with_patterns(sample_data, patterns)

                if matches:
                    classification = self._classify_data(data_type)
                    risk_score = self._calculate_risk(
                        data_type,
                        data_store,
                        len(matches)
                    )

                    finding = SensitiveDataFinding(
                        finding_id=f"dspm-{data_store.store_id}-{data_type.value}",
                        data_type=data_type,
                        classification=classification,
                        location=data_store.store_id,
                        resource_id=data_store.store_id,
                        sample_matches=self._redact_samples(matches[:5]),
                        total_matches=len(matches),
                        encrypted=data_store.encryption_at_rest,
                        public_access=data_store.public_access,
                        risk_score=risk_score,
                        recommendations=self._generate_recommendations(
                            data_type,
                            data_store
                        )
                    )
                    findings.append(finding)

        # Check security controls
        control_findings = self._check_security_controls(data_store)
        findings.extend(control_findings)

        self.findings.extend(findings)
        return findings

    def _scan_with_patterns(
        self,
        data: List[str],
        patterns: List[str]
    ) -> List[str]:
        """Scan data with regex patterns."""
        matches = []

        for text in data:
            for pattern in patterns:
                found = re.findall(pattern, text, re.IGNORECASE)
                matches.extend(found)

        return matches

    def _classify_data(self, data_type: DataType) -> DataClassification:
        """Classify data sensitivity level."""
        if data_type in [DataType.PII, DataType.PHI, DataType.PCI, DataType.CREDENTIALS]:
            return DataClassification.RESTRICTED
        elif data_type in [DataType.FINANCIAL, DataType.INTELLECTUAL_PROPERTY]:
            return DataClassification.CONFIDENTIAL
        else:
            return DataClassification.INTERNAL

    def _calculate_risk(
        self,
        data_type: DataType,
        data_store: DataStore,
        match_count: int
    ) -> float:
        """Calculate risk score for sensitive data finding."""
        risk = 0.0

        # Base risk by data type
        type_risk = {
            DataType.PII: 30,
            DataType.PHI: 40,
            DataType.PCI: 50,
            DataType.CREDENTIALS: 60,
            DataType.FINANCIAL: 35,
            DataType.INTELLECTUAL_PROPERTY: 25,
        }
        risk += type_risk.get(data_type, 20)

        # Risk factors
        if data_store.public_access:
            risk += 30  # Critical risk

        if not data_store.encryption_at_rest:
            risk += 20

        if not data_store.access_logging:
            risk += 10

        if match_count > 1000:
            risk += 10  # Large data exposure

        return min(100.0, risk)

    def _redact_samples(self, samples: List[str]) -> List[str]:
        """Redact sensitive samples for reporting."""
        redacted = []

        for sample in samples:
            if len(sample) > 10:
                # Show first 2 and last 2 characters
                redacted_sample = sample[:2] + '*' * (len(sample) - 4) + sample[-2:]
            else:
                redacted_sample = '*' * len(sample)

            redacted.append(redacted_sample)

        return redacted

    def _generate_recommendations(
        self,
        data_type: DataType,
        data_store: DataStore
    ) -> List[str]:
        """Generate recommendations for data protection."""
        recommendations = []

        if data_store.public_access:
            recommendations.append("URGENT: Remove public access to data containing sensitive information")

        if not data_store.encryption_at_rest:
            recommendations.append("Enable encryption at rest")

        if not data_store.encryption_in_transit:
            recommendations.append("Enable encryption in transit (TLS/SSL)")

        if not data_store.access_logging:
            recommendations.append("Enable access logging for audit trail")

        if not data_store.versioning_enabled and data_store.store_type in ['s3', 'blob']:
            recommendations.append("Enable versioning for data recovery")

        if not data_store.backup_enabled:
            recommendations.append("Enable automated backups")

        if data_type in [DataType.PII, DataType.PHI, DataType.PCI]:
            recommendations.append(f"Implement data masking/tokenization for {data_type.value.upper()}")
            recommendations.append("Review data retention policies")
            recommendations.append("Implement access controls and monitoring")

        return recommendations

    def _check_security_controls(self, data_store: DataStore) -> List[SensitiveDataFinding]:
        """Check security controls on data store."""
        findings = []

        # Check for unencrypted sensitive data
        if data_store.contains_sensitive_data and not data_store.encryption_at_rest:
            finding = SensitiveDataFinding(
                finding_id=f"dspm-control-encryption-{data_store.store_id}",
                data_type=DataType.PII,  # Generic
                classification=DataClassification.RESTRICTED,
                location=data_store.store_id,
                resource_id=data_store.store_id,
                sample_matches=[],
                total_matches=0,
                encrypted=False,
                public_access=data_store.public_access,
                risk_score=80.0 if data_store.public_access else 60.0,
                recommendations=[
                    "Enable encryption at rest immediately",
                    "Rotate encryption keys regularly",
                ]
            )
            findings.append(finding)

        # Check for public access to sensitive data
        if data_store.contains_sensitive_data and data_store.public_access:
            finding = SensitiveDataFinding(
                finding_id=f"dspm-control-public-{data_store.store_id}",
                data_type=DataType.PII,
                classification=DataClassification.RESTRICTED,
                location=data_store.store_id,
                resource_id=data_store.store_id,
                sample_matches=[],
                total_matches=0,
                encrypted=data_store.encryption_at_rest,
                public_access=True,
                risk_score=95.0,
                recommendations=[
                    "CRITICAL: Remove public access immediately",
                    "Implement IP whitelisting or VPN access",
                    "Review and revoke unnecessary permissions",
                ]
            )
            findings.append(finding)

        return findings

    def generate_dspm_report(self) -> str:
        """Generate DSPM analysis report."""
        report = []
        report.append("=" * 80)
        report.append("DATA SECURITY POSTURE MANAGEMENT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Findings: {len(self.findings)}\n")

        # Summary by data type
        by_type = {}
        for finding in self.findings:
            data_type = finding.data_type.value
            by_type[data_type] = by_type.get(data_type, 0) + 1

        report.append("SENSITIVE DATA TYPES DISCOVERED")
        report.append("-" * 80)
        for data_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            report.append(f"{data_type.upper()}: {count} findings")

        # High risk findings
        high_risk = [f for f in self.findings if f.risk_score >= 70]

        if high_risk:
            report.append(f"\n\nHIGH RISK DATA EXPOSURES ({len(high_risk)})")
            report.append("=" * 80)

            for finding in high_risk[:10]:  # Top 10
                report.append(f"\n[RISK: {finding.risk_score:.0f}/100] {finding.data_type.value.upper()}")
                report.append(f"Location: {finding.location}")
                report.append(f"Classification: {finding.classification.value.upper()}")
                report.append(f"Total Matches: {finding.total_matches}")
                report.append(f"Encrypted: {'Yes' if finding.encrypted else 'NO'}")
                report.append(f"Public Access: {'YES - CRITICAL!' if finding.public_access else 'No'}")

                if finding.recommendations:
                    report.append("Recommendations:")
                    for rec in finding.recommendations:
                        report.append(f"  • {rec}")

                report.append("-" * 80)

        return "\n".join(report)

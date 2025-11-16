"""
Database storage layer for CloudGuard-Anomaly.

Provides persistent storage for scan results, findings, and historical data
to enable trend analysis, compliance tracking, and reporting.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    DateTime,
    Float,
    Boolean,
    JSON,
    Index,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from cloudguard_anomaly.core.models import ScanResult, Finding, Anomaly

logger = logging.getLogger(__name__)

Base = declarative_base()


class ScanRecord(Base):
    """Database model for scan results."""

    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    environment_name = Column(String, index=True, nullable=False)
    provider = Column(String, index=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    risk_score = Column(Integer)
    findings_count = Column(Integer)
    anomalies_count = Column(Integer)
    critical_count = Column(Integer)
    high_count = Column(Integer)
    medium_count = Column(Integer)
    low_count = Column(Integer)
    data = Column(JSON)  # Full scan result

    __table_args__ = (
        Index("idx_env_timestamp", "environment_name", "timestamp"),
        Index("idx_risk_score", "risk_score"),
    )


class FindingRecord(Base):
    """Database model for individual findings."""

    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, index=True, nullable=False)
    environment_name = Column(String, index=True)
    severity = Column(String, index=True)
    type = Column(String, index=True)
    resource_id = Column(String, index=True)
    resource_type = Column(String, index=True)
    title = Column(String)
    description = Column(String)
    timestamp = Column(DateTime, index=True)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    data = Column(JSON)

    __table_args__ = (
        Index("idx_severity_type", "severity", "type"),
        Index("idx_resource", "resource_id", "resource_type"),
    )


class AnomalyRecord(Base):
    """Database model for configuration anomalies."""

    __tablename__ = "anomalies"

    id = Column(String, primary_key=True)
    scan_id = Column(String, index=True, nullable=False)
    environment_name = Column(String, index=True)
    type = Column(String, index=True)
    severity = Column(String, index=True)
    resource_id = Column(String, index=True)
    timestamp = Column(DateTime, index=True)
    data = Column(JSON)


class ComplianceRecord(Base):
    """Database model for compliance assessments."""

    __tablename__ = "compliance"

    id = Column(String, primary_key=True)
    scan_id = Column(String, index=True, nullable=False)
    environment_name = Column(String, index=True)
    framework = Column(String, index=True)
    compliance_score = Column(Float)
    passed_controls = Column(Integer)
    failed_controls = Column(Integer)
    total_controls = Column(Integer)
    timestamp = Column(DateTime, index=True)
    data = Column(JSON)


class DatabaseStorage:
    """Persistent storage for CloudGuard-Anomaly data."""

    def __init__(self, database_url: str = "sqlite:///cloudguard.db"):
        """
        Initialize database storage.

        Args:
            database_url: SQLAlchemy database URL
        """
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            echo=False,
            pool_pre_ping=True,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

        logger.info(f"Initialized database storage: {database_url}")

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def save_scan(self, scan_result: ScanResult) -> str:
        """
        Save scan result to database.

        Args:
            scan_result: Scan result to save

        Returns:
            Scan ID
        """
        session = self.get_session()
        scan_id = str(uuid.uuid4())

        try:
            severity_counts = scan_result.summary.get("severity_counts", {})

            # Create scan record
            scan_record = ScanRecord(
                id=scan_id,
                environment_name=scan_result.environment.name,
                provider=scan_result.environment.provider.value,
                timestamp=scan_result.timestamp,
                risk_score=scan_result.summary.get("risk_score", 0),
                findings_count=len(scan_result.findings),
                anomalies_count=len(scan_result.anomalies),
                critical_count=severity_counts.get("critical", 0),
                high_count=severity_counts.get("high", 0),
                medium_count=severity_counts.get("medium", 0),
                low_count=severity_counts.get("low", 0),
                data=scan_result.to_dict(),
            )
            session.add(scan_record)

            # Save individual findings
            for finding in scan_result.findings:
                finding_record = FindingRecord(
                    id=finding.id,
                    scan_id=scan_id,
                    environment_name=scan_result.environment.name,
                    severity=finding.severity.value,
                    type=finding.type.value,
                    resource_id=finding.resource.id,
                    resource_type=finding.resource.type.value,
                    title=finding.title,
                    description=finding.description,
                    timestamp=finding.timestamp,
                    data=finding.to_dict(),
                )
                session.add(finding_record)

            # Save anomalies
            for anomaly in scan_result.anomalies:
                anomaly_record = AnomalyRecord(
                    id=anomaly.id,
                    scan_id=scan_id,
                    environment_name=scan_result.environment.name,
                    type=anomaly.type,
                    severity=anomaly.severity.value,
                    resource_id=anomaly.resource.id,
                    timestamp=anomaly.timestamp,
                    data=anomaly.to_dict(),
                )
                session.add(anomaly_record)

            session.commit()
            logger.info(f"Saved scan {scan_id} for environment {scan_result.environment.name}")

            return scan_id

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save scan: {e}")
            raise
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Get scan by ID."""
        session = self.get_session()
        try:
            return session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        finally:
            session.close()

    def get_latest_scan(self, environment_name: str) -> Optional[ScanRecord]:
        """Get latest scan for an environment."""
        session = self.get_session()
        try:
            return (
                session.query(ScanRecord)
                .filter(ScanRecord.environment_name == environment_name)
                .order_by(ScanRecord.timestamp.desc())
                .first()
            )
        finally:
            session.close()

    def get_scans(
        self,
        environment_name: Optional[str] = None,
        days: int = 30,
        limit: int = 100,
    ) -> List[ScanRecord]:
        """
        Get recent scans.

        Args:
            environment_name: Filter by environment
            days: Number of days to look back
            limit: Maximum number of scans

        Returns:
            List of scan records
        """
        session = self.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            query = session.query(ScanRecord).filter(ScanRecord.timestamp >= cutoff)

            if environment_name:
                query = query.filter(ScanRecord.environment_name == environment_name)

            return query.order_by(ScanRecord.timestamp.desc()).limit(limit).all()

        finally:
            session.close()

    def get_trend_data(
        self, environment_name: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get trend data for an environment.

        Args:
            environment_name: Environment name
            days: Number of days to analyze

        Returns:
            List of trend data points
        """
        scans = self.get_scans(environment_name=environment_name, days=days)

        trend_data = []
        for scan in scans:
            trend_data.append(
                {
                    "timestamp": scan.timestamp.isoformat(),
                    "risk_score": scan.risk_score,
                    "findings_count": scan.findings_count,
                    "critical_count": scan.critical_count,
                    "high_count": scan.high_count,
                }
            )

        return trend_data

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        environment_name: Optional[str] = None,
        severity: Optional[str] = None,
        unresolved_only: bool = False,
        limit: int = 100,
    ) -> List[FindingRecord]:
        """
        Query findings with filters.

        Args:
            scan_id: Filter by scan ID
            environment_name: Filter by environment
            severity: Filter by severity
            unresolved_only: Only unresolved findings
            limit: Maximum results

        Returns:
            List of finding records
        """
        session = self.get_session()
        try:
            query = session.query(FindingRecord)

            if scan_id:
                query = query.filter(FindingRecord.scan_id == scan_id)

            if environment_name:
                query = query.filter(FindingRecord.environment_name == environment_name)

            if severity:
                query = query.filter(FindingRecord.severity == severity)

            if unresolved_only:
                query = query.filter(FindingRecord.resolved == False)

            return query.order_by(FindingRecord.timestamp.desc()).limit(limit).all()

        finally:
            session.close()

    def mark_finding_resolved(self, finding_id: str):
        """Mark a finding as resolved."""
        session = self.get_session()
        try:
            finding = (
                session.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
            )

            if finding:
                finding.resolved = True
                finding.resolved_at = datetime.utcnow()
                session.commit()
                logger.info(f"Marked finding {finding_id} as resolved")
            else:
                logger.warning(f"Finding {finding_id} not found")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to mark finding as resolved: {e}")
            raise
        finally:
            session.close()

    def get_statistics(self, environment_name: str, days: int = 30) -> Dict[str, Any]:
        """
        Get statistics for an environment.

        Args:
            environment_name: Environment name
            days: Analysis period

        Returns:
            Statistics dictionary
        """
        session = self.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            # Get scan count
            scan_count = (
                session.query(ScanRecord)
                .filter(
                    ScanRecord.environment_name == environment_name,
                    ScanRecord.timestamp >= cutoff,
                )
                .count()
            )

            # Get average risk score
            avg_risk = (
                session.query(ScanRecord.risk_score)
                .filter(
                    ScanRecord.environment_name == environment_name,
                    ScanRecord.timestamp >= cutoff,
                )
                .all()
            )
            avg_risk_score = (
                sum(r[0] for r in avg_risk) / len(avg_risk) if avg_risk else 0
            )

            # Get unresolved findings count
            unresolved_count = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.environment_name == environment_name,
                    FindingRecord.resolved == False,
                )
                .count()
            )

            return {
                "scan_count": scan_count,
                "average_risk_score": round(avg_risk_score, 2),
                "unresolved_findings": unresolved_count,
            }

        finally:
            session.close()

    def cleanup_old_data(self, days: int = 90):
        """
        Clean up data older than specified days.

        Args:
            days: Delete data older than this many days
        """
        session = self.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            # Delete old scans
            deleted_scans = (
                session.query(ScanRecord)
                .filter(ScanRecord.timestamp < cutoff)
                .delete()
            )

            # Delete orphaned findings
            deleted_findings = (
                session.query(FindingRecord)
                .filter(FindingRecord.timestamp < cutoff)
                .delete()
            )

            session.commit()
            logger.info(
                f"Cleaned up {deleted_scans} scans and {deleted_findings} findings"
            )

        except Exception as e:
            session.rollback()
            logger.error(f"Cleanup failed: {e}")
            raise
        finally:
            session.close()

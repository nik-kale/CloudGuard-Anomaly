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


class PolicyRecord(Base):
    """Database model for security policies."""

    __tablename__ = "policies"

    id = Column(String, primary_key=True)
    name = Column(String, index=True, nullable=False)
    description = Column(String)
    severity = Column(String, index=True)
    provider = Column(String, index=True)
    enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String)  # User ID who created the policy
    data = Column(JSON)  # Full policy data (resource_types, condition, remediation, etc.)

    __table_args__ = (
        Index("idx_provider_enabled", "provider", "enabled"),
        Index("idx_severity", "severity"),
    )


class AuditLog(Base):
    """Database model for audit logging."""

    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, index=True, nullable=False, default=datetime.utcnow)
    user_id = Column(String, index=True)  # User who performed the action
    username = Column(String)  # Username for quick reference
    action = Column(String, index=True, nullable=False)  # create, update, delete, login, logout, etc.
    resource_type = Column(String, index=True)  # user, role, policy, scan, finding, etc.
    resource_id = Column(String, index=True)  # ID of affected resource
    status = Column(String, index=True)  # success, failure, error
    ip_address = Column(String)  # Client IP address
    user_agent = Column(String)  # Client user agent
    details = Column(JSON)  # Additional context (changes made, error details, etc.)

    __table_args__ = (
        Index("idx_user_timestamp", "user_id", "timestamp"),
        Index("idx_action_status", "action", "status"),
        Index("idx_resource", "resource_type", "resource_id"),
    )


class DatabaseStorage:
    """Persistent storage for CloudGuard-Anomaly data."""

    def __init__(self, database_url: str = "sqlite:///cloudguard.db"):
        """
        Initialize database storage with connection pooling.

        Args:
            database_url: SQLAlchemy database URL
        """
        from cloudguard_anomaly.config import get_config
        config = get_config()

        self.database_url = database_url

        # Configure engine with connection pooling
        engine_kwargs = {
            'echo': False,
            'pool_pre_ping': True,  # Verify connections before using
        }

        # Add pooling only for non-SQLite databases
        if not database_url.startswith('sqlite'):
            from sqlalchemy.pool import QueuePool
            engine_kwargs.update({
                'poolclass': QueuePool,
                'pool_size': config.database_pool_size,
                'max_overflow': config.database_max_overflow,
                'pool_recycle': 3600,  # Recycle connections after 1 hour
                'pool_timeout': 30,  # Wait up to 30 seconds for a connection
            })
            logger.info(
                f"Connection pooling enabled: pool_size={config.database_pool_size}, "
                f"max_overflow={config.database_max_overflow}"
            )

        self.engine = create_engine(database_url, **engine_kwargs)
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

    def get_compliance_results(
        self,
        framework: Optional[str] = None,
        environment_name: Optional[str] = None,
        days: int = 30,
        limit: int = 50,
    ) -> List[ComplianceRecord]:
        """
        Query compliance results from database.

        Args:
            framework: Filter by compliance framework (e.g., 'soc2', 'pci_dss')
            environment_name: Filter by environment name
            days: Look back this many days
            limit: Maximum number of results

        Returns:
            List of ComplianceRecord objects
        """
        session = self.get_session()
        try:
            query = session.query(ComplianceRecord)

            if framework:
                query = query.filter(ComplianceRecord.framework == framework)

            if environment_name:
                query = query.filter(ComplianceRecord.environment_name == environment_name)

            if days:
                since = datetime.utcnow() - timedelta(days=days)
                query = query.filter(ComplianceRecord.timestamp >= since)

            return query.order_by(ComplianceRecord.timestamp.desc()).limit(limit).all()

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

    # Policy CRUD operations

    def create_policy(
        self,
        name: str,
        description: str,
        severity: str,
        provider: str,
        resource_types: List[str],
        condition: Dict[str, Any],
        remediation: str,
        references: Optional[List[str]] = None,
        enabled: bool = True,
        created_by: Optional[str] = None
    ) -> PolicyRecord:
        """
        Create a new security policy.

        Args:
            name: Policy name
            description: Policy description
            severity: Severity level
            provider: Target cloud provider
            resource_types: Applicable resource types
            condition: Policy condition logic
            remediation: Remediation guidance
            references: External references
            enabled: Whether policy is enabled
            created_by: User ID who created the policy

        Returns:
            Created policy record
        """
        session = self.get_session()
        try:
            policy = PolicyRecord(
                id=str(uuid.uuid4()),
                name=name,
                description=description,
                severity=severity,
                provider=provider,
                enabled=enabled,
                created_by=created_by,
                data={
                    "resource_types": resource_types,
                    "condition": condition,
                    "remediation": remediation,
                    "references": references or []
                }
            )

            session.add(policy)
            session.commit()
            logger.info(f"Created policy: {name} (ID: {policy.id})")
            return policy

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create policy: {e}")
            raise
        finally:
            session.close()

    def get_policy(self, policy_id: str) -> Optional[PolicyRecord]:
        """
        Get policy by ID.

        Args:
            policy_id: Policy ID

        Returns:
            Policy record or None if not found
        """
        session = self.get_session()
        try:
            return session.query(PolicyRecord).filter(PolicyRecord.id == policy_id).first()
        finally:
            session.close()

    def list_policies(
        self,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> List[PolicyRecord]:
        """
        List policies with filtering.

        Args:
            provider: Filter by provider
            severity: Filter by severity
            enabled_only: Only return enabled policies
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of policy records
        """
        session = self.get_session()
        try:
            query = session.query(PolicyRecord)

            if provider:
                query = query.filter(PolicyRecord.provider == provider)

            if severity:
                query = query.filter(PolicyRecord.severity == severity)

            if enabled_only:
                query = query.filter(PolicyRecord.enabled == True)

            return query.order_by(PolicyRecord.created_at.desc()).limit(limit).offset(offset).all()

        finally:
            session.close()

    def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        provider: Optional[str] = None,
        resource_types: Optional[List[str]] = None,
        condition: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        enabled: Optional[bool] = None
    ) -> Optional[PolicyRecord]:
        """
        Update an existing policy.

        Args:
            policy_id: Policy ID
            name: New policy name
            description: New description
            severity: New severity
            provider: New provider
            resource_types: New resource types
            condition: New condition
            remediation: New remediation
            references: New references
            enabled: New enabled status

        Returns:
            Updated policy record or None if not found
        """
        session = self.get_session()
        try:
            policy = session.query(PolicyRecord).filter(PolicyRecord.id == policy_id).first()

            if not policy:
                return None

            # Update basic fields
            if name is not None:
                policy.name = name
            if description is not None:
                policy.description = description
            if severity is not None:
                policy.severity = severity
            if provider is not None:
                policy.provider = provider
            if enabled is not None:
                policy.enabled = enabled

            # Update data field
            if any([resource_types, condition, remediation, references]):
                data = policy.data or {}
                if resource_types is not None:
                    data['resource_types'] = resource_types
                if condition is not None:
                    data['condition'] = condition
                if remediation is not None:
                    data['remediation'] = remediation
                if references is not None:
                    data['references'] = references
                policy.data = data

            policy.updated_at = datetime.utcnow()

            session.commit()
            logger.info(f"Updated policy: {policy_id}")
            return policy

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update policy: {e}")
            raise
        finally:
            session.close()

    def delete_policy(self, policy_id: str) -> bool:
        """
        Delete a policy.

        Args:
            policy_id: Policy ID

        Returns:
            True if deleted, False if not found
        """
        session = self.get_session()
        try:
            policy = session.query(PolicyRecord).filter(PolicyRecord.id == policy_id).first()

            if not policy:
                return False

            session.delete(policy)
            session.commit()
            logger.info(f"Deleted policy: {policy_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete policy: {e}")
            raise
        finally:
            session.close()

    # Audit logging operations

    def log_audit_event(
        self,
        action: str,
        resource_type: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: str = "success",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """
        Log an audit event.

        Args:
            action: Action performed (create, update, delete, login, logout, etc.)
            resource_type: Type of resource (user, role, policy, scan, finding, etc.)
            user_id: User ID who performed the action
            username: Username for quick reference
            resource_id: ID of affected resource
            status: Status (success, failure, error)
            ip_address: Client IP address
            user_agent: Client user agent
            details: Additional context as dict

        Returns:
            Created audit log record
        """
        session = self.get_session()
        try:
            audit_log = AuditLog(
                id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                user_id=user_id,
                username=username,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details or {}
            )

            session.add(audit_log)
            session.commit()

            logger.debug(
                f"Audit log: {action} {resource_type} "
                f"by {username or user_id or 'system'} - {status}"
            )

            return audit_log

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create audit log: {e}")
            # Don't raise - audit logging failure shouldn't break the application
            return None
        finally:
            session.close()

    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        """
        Query audit logs with filtering.

        Args:
            user_id: Filter by user ID
            action: Filter by action
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            status: Filter by status
            start_time: Filter logs after this time
            end_time: Filter logs before this time
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of audit log records
        """
        session = self.get_session()
        try:
            query = session.query(AuditLog)

            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            if action:
                query = query.filter(AuditLog.action == action)
            if resource_type:
                query = query.filter(AuditLog.resource_type == resource_type)
            if resource_id:
                query = query.filter(AuditLog.resource_id == resource_id)
            if status:
                query = query.filter(AuditLog.status == status)
            if start_time:
                query = query.filter(AuditLog.timestamp >= start_time)
            if end_time:
                query = query.filter(AuditLog.timestamp <= end_time)

            return query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()

        finally:
            session.close()

    def get_user_activity(self, user_id: str, days: int = 30) -> List[AuditLog]:
        """
        Get recent activity for a specific user.

        Args:
            user_id: User ID
            days: Number of days to look back

        Returns:
            List of audit log records for the user
        """
        start_time = datetime.utcnow() - timedelta(days=days)
        return self.get_audit_logs(
            user_id=user_id,
            start_time=start_time,
            limit=1000
        )

    def cleanup_old_audit_logs(self, days: int = 365):
        """
        Clean up audit logs older than specified days.

        Args:
            days: Delete logs older than this many days
        """
        session = self.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            deleted_count = (
                session.query(AuditLog)
                .filter(AuditLog.timestamp < cutoff)
                .delete()
            )

            session.commit()
            logger.info(f"Cleaned up {deleted_count} old audit logs")

        except Exception as e:
            session.rollback()
            logger.error(f"Audit log cleanup failed: {e}")
            raise
        finally:
            session.close()

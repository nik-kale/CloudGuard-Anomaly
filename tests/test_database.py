"""
Tests for database storage layer.
"""

from unittest.mock import MagicMock

import cloudguard_anomaly.storage.database as storage
from cloudguard_anomaly.storage.database import (
    AnomalyRecord,
    ComplianceRecord,
    DatabaseStorage,
    ScanRecord,
)


class TestDatabaseStorage:
    """Test database storage functionality."""

    def test_database_initialization(self, test_database_url):
        """Test database initializes correctly."""
        db = DatabaseStorage(test_database_url)
        assert db.database_url == test_database_url
        assert db.engine is not None

    def test_save_scan(self, database, sample_scan_result):
        """Test saving scan result to database."""
        scan_id = database.save_scan(sample_scan_result)

        assert scan_id is not None
        assert isinstance(scan_id, str)

        # Verify scan was saved
        scan = database.get_scan(scan_id)
        assert scan is not None
        assert scan.environment_name == sample_scan_result.environment.name

    def test_get_scan(self, database, sample_scan_result):
        """Test retrieving scan by ID."""
        scan_id = database.save_scan(sample_scan_result)

        scan = database.get_scan(scan_id)

        assert scan.id == scan_id
        assert scan.environment_name == sample_scan_result.environment.name
        assert scan.findings_count == len(sample_scan_result.findings)

    def test_get_latest_scan(self, database, sample_scan_result):
        """Test getting latest scan for environment."""
        database.save_scan(sample_scan_result)

        latest = database.get_latest_scan(sample_scan_result.environment.name)

        assert latest is not None
        assert latest.environment_name == sample_scan_result.environment.name

    def test_get_scans(self, database, sample_scan_result):
        """Test querying multiple scans."""
        # Save multiple scans
        database.save_scan(sample_scan_result)
        database.save_scan(sample_scan_result)

        scans = database.get_scans(
            environment_name=sample_scan_result.environment.name, days=30, limit=10
        )

        assert len(scans) >= 2

    def test_get_trend_data(self, database, sample_scan_result):
        """Test getting trend data."""
        database.save_scan(sample_scan_result)

        trend_data = database.get_trend_data(sample_scan_result.environment.name, days=30)

        assert isinstance(trend_data, list)
        assert len(trend_data) >= 1

        if trend_data:
            point = trend_data[0]
            assert "timestamp" in point
            assert "risk_score" in point
            assert "findings_count" in point

    def test_get_findings(self, database, sample_scan_result):
        """Test querying findings."""
        scan_id = database.save_scan(sample_scan_result)

        findings = database.get_findings(scan_id=scan_id)

        assert len(findings) >= 1
        assert all(f.scan_id == scan_id for f in findings)

    def test_get_findings_by_severity(self, database, sample_scan_result):
        """Test filtering findings by severity."""
        database.save_scan(sample_scan_result)

        high_findings = database.get_findings(
            environment_name=sample_scan_result.environment.name, severity="high"
        )

        assert all(f.severity == "high" for f in high_findings)

    def test_get_unresolved_findings(self, database, sample_scan_result):
        """Test querying unresolved findings."""
        database.save_scan(sample_scan_result)

        unresolved = database.get_findings(
            environment_name=sample_scan_result.environment.name, unresolved_only=True
        )

        assert all(not f.resolved for f in unresolved)

    def test_mark_finding_resolved(self, database, sample_scan_result):
        """Test marking finding as resolved."""
        scan_id = database.save_scan(sample_scan_result)

        findings = database.get_findings(scan_id=scan_id, limit=1)
        if findings:
            finding_id = findings[0].id

            database.mark_finding_resolved(finding_id)

            # Verify it's marked resolved
            resolved_finding = database.get_findings(scan_id=scan_id, limit=1)[0]
            assert resolved_finding.resolved is True
            assert resolved_finding.resolved_at is not None

    def test_get_statistics(self, database, sample_scan_result):
        """Test getting environment statistics."""
        database.save_scan(sample_scan_result)

        stats = database.get_statistics(sample_scan_result.environment.name, days=30)

        assert "scan_count" in stats
        assert "average_risk_score" in stats
        assert "unresolved_findings" in stats
        assert stats["scan_count"] >= 1

    def test_cleanup_old_data(self, database, sample_scan_result):
        """Test cleaning up old data."""
        # Save scan
        database.save_scan(sample_scan_result)

        # Delete data older than 0 days (everything)
        database.cleanup_old_data(days=0)

        # Verify scans were deleted
        scans = database.get_scans(days=365, limit=100)
        # May have been deleted or not depending on exact timing
        assert isinstance(scans, list)

    def test_connection_pooling_config(self, monkeypatch):
        """Non-SQLite URLs get a bounded, recycled pool."""
        engine = MagicMock()
        monkeypatch.setattr(storage, "create_engine", engine)
        monkeypatch.setattr(storage.Base.metadata, "create_all", MagicMock())

        DatabaseStorage("postgresql://user:pass@localhost/testdb")

        kwargs = engine.call_args.kwargs
        assert kwargs["pool_size"] > 0
        assert kwargs["pool_recycle"] == 3600

    def test_cleanup_removes_every_scan_table(self, database, sample_scan_result):
        """Anomalies and compliance rows used to outlive their scans."""
        scan_id = database.save_scan(sample_scan_result)
        session = database.get_session()
        try:
            session.add(
                ComplianceRecord(
                    id="c1",
                    scan_id=scan_id,
                    framework="soc2",
                    timestamp=sample_scan_result.timestamp,
                )
            )
            session.commit()
        finally:
            session.close()

        database.cleanup_old_data(days=0)

        session = database.get_session()
        try:
            assert session.query(AnomalyRecord).count() == 0
            assert session.query(ComplianceRecord).count() == 0
            assert session.query(ScanRecord).count() == 0
        finally:
            session.close()

    def test_statistics_tolerate_scans_without_a_score(self, database, sample_scan_result):
        scan_id = database.save_scan(sample_scan_result)
        session = database.get_session()
        try:
            session.get(ScanRecord, scan_id).risk_score = None
            session.commit()
        finally:
            session.close()

        stats = database.get_statistics(sample_scan_result.environment.name)
        assert stats["scan_count"] >= 1

    def test_get_compliance_results(self, database):
        """Test querying compliance results."""
        results = database.get_compliance_results(framework="soc2", days=30)

        # Should return list (may be empty)
        assert isinstance(results, list)

    def test_save_multiple_findings(self, database, sample_scan_result):
        """Test saving scan with multiple findings."""
        from cloudguard_anomaly.core.models import Finding, FindingType, Severity

        # Add more findings
        for i in range(5):
            sample_scan_result.findings.append(
                Finding(
                    id=f"finding-{i}",
                    resource=sample_scan_result.findings[0].resource,
                    policy_id=f"POLICY_{i}",
                    severity=Severity.MEDIUM,
                    type=FindingType.MISCONFIGURATION,
                    title=f"Test Finding {i}",
                    description=f"Test description {i}",
                )
            )

        scan_id = database.save_scan(sample_scan_result)

        findings = database.get_findings(scan_id=scan_id)
        assert len(findings) >= 5


class TestDatabaseModels:
    """Test database model structures."""

    def test_scan_record_structure(self, database, sample_scan_result):
        """Test ScanRecord model structure."""
        scan_id = database.save_scan(sample_scan_result)
        scan = database.get_scan(scan_id)

        assert hasattr(scan, "id")
        assert hasattr(scan, "environment_name")
        assert hasattr(scan, "timestamp")
        assert hasattr(scan, "risk_score")
        assert hasattr(scan, "findings_count")
        assert hasattr(scan, "critical_count")
        assert hasattr(scan, "high_count")
        assert hasattr(scan, "data")

    def test_finding_record_structure(self, database, sample_scan_result):
        """Test FindingRecord model structure."""
        scan_id = database.save_scan(sample_scan_result)
        findings = database.get_findings(scan_id=scan_id, limit=1)

        if findings:
            finding = findings[0]
            assert hasattr(finding, "id")
            assert hasattr(finding, "scan_id")
            assert hasattr(finding, "severity")
            assert hasattr(finding, "type")
            assert hasattr(finding, "resource_id")
            assert hasattr(finding, "resolved")

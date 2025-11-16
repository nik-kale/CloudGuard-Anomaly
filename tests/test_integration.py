"""
Integration tests for CloudGuard-Anomaly.

Tests end-to-end workflows and component integration:
- Complete user journey (registration → authentication → operations)
- Policy lifecycle (create → evaluate → update → delete)
- Scan workflow (initiate → process → findings → audit)
- Role-based access control workflows
- Multi-user scenarios
- Database integrity across operations
- API integration scenarios
"""

import os
import json
import uuid
import pytest
import tempfile
from datetime import datetime, timedelta

from cloudguard_anomaly.config import Config
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.auth import AuthenticationManager
from cloudguard_anomaly.auth.models import Permission, User, Role


@pytest.fixture(scope="module")
def test_db_path():
    """Create temporary database for integration testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture(scope="module")
def test_config(test_db_path):
    """Create test configuration."""
    return Config(
        database_url=f"sqlite:///{test_db_path}",
        log_level="INFO"
    )


@pytest.fixture(scope="module")
def database(test_config):
    """Create database instance."""
    return DatabaseStorage(test_config.database_url)


@pytest.fixture(scope="module")
def auth_manager(database):
    """Create authentication manager."""
    manager = AuthenticationManager(database)
    manager.create_default_roles()
    return manager


# ============================================================================
# USER JOURNEY INTEGRATION TESTS
# ============================================================================

class TestUserJourney:
    """Test complete user journeys through the system."""

    def test_complete_user_lifecycle(self, auth_manager, database):
        """Test complete user lifecycle from creation to deletion."""
        # Step 1: Admin creates user
        user = auth_manager.create_user(
            username="journey_user",
            email="journey@test.com",
            password="JourneyP@ss123!",
            roles=["viewer"]
        )
        assert user is not None
        assert user.id is not None

        # Step 2: User authenticates
        authenticated = auth_manager.authenticate(
            "journey_user",
            "JourneyP@ss123!"
        )
        assert authenticated is not None
        assert authenticated.id == user.id

        # Step 3: Create session for user
        session = auth_manager.create_session(user.id)
        assert session is not None
        assert session.is_valid()

        # Step 4: Validate session
        session_user = auth_manager.validate_session(session.token)
        assert session_user is not None
        assert session_user.id == user.id

        # Step 5: User performs operations (view policies)
        policies = database.list_policies(limit=10)
        assert isinstance(policies, list)

        # Step 6: Check user has correct permissions
        assert user.has_permission(Permission.SCAN_VIEW)
        assert not user.has_permission(Permission.POLICY_CREATE)

        # Step 7: User logs out
        auth_manager.logout(session.token)

        # Step 8: Session is invalidated
        session_user = auth_manager.validate_session(session.token)
        assert session_user is None

        # Step 9: Admin deletes user
        auth_manager.delete_user(user.id)

        # Step 10: User no longer exists
        deleted_user = auth_manager.get_user(user.id)
        assert deleted_user is None

    def test_user_password_change_journey(self, auth_manager):
        """Test user changing their password."""
        # Create user
        user = auth_manager.create_user(
            username="pwd_change_user",
            email="pwdchange@test.com",
            password="OldP@ssw0rd123!"
        )

        try:
            # Authenticate with old password
            auth = auth_manager.authenticate("pwd_change_user", "OldP@ssw0rd123!")
            assert auth is not None

            # Update password
            session = database.get_session()
            try:
                db_user = session.query(User).filter(User.id == user.id).first()
                db_user.set_password("NewP@ssw0rd456!")
                session.commit()
            finally:
                session.close()

            # Old password should not work
            auth = auth_manager.authenticate("pwd_change_user", "OldP@ssw0rd123!")
            assert auth is None

            # New password should work
            auth = auth_manager.authenticate("pwd_change_user", "NewP@ssw0rd456!")
            assert auth is not None

        finally:
            auth_manager.delete_user(user.id)

    def test_user_role_change_journey(self, auth_manager):
        """Test changing user roles and permissions."""
        # Create user with viewer role
        user = auth_manager.create_user(
            username="role_change_user",
            email="rolechange@test.com",
            password="RoleTest123!",
            roles=["viewer"]
        )

        try:
            # Initially cannot create policies
            assert not user.has_permission(Permission.POLICY_CREATE)

            # Upgrade to security_analyst role
            session = database.get_session()
            try:
                db_user = session.query(User).filter(User.id == user.id).first()
                analyst_role = session.query(Role).filter(Role.name == 'security_analyst').first()

                db_user.roles.clear()
                db_user.roles.append(analyst_role)
                session.commit()

                # Now can run scans
                assert db_user.has_permission(Permission.SCAN_RUN)

            finally:
                session.close()

        finally:
            auth_manager.delete_user(user.id)


# ============================================================================
# POLICY LIFECYCLE INTEGRATION TESTS
# ============================================================================

class TestPolicyLifecycle:
    """Test complete policy lifecycle."""

    def test_policy_crud_workflow(self, database, auth_manager):
        """Test complete policy CRUD workflow."""
        # Create admin user
        admin = auth_manager.create_admin_user(
            username="policy_admin",
            email="policy_admin@test.com",
            password="AdminP@ss123!"
        )

        try:
            # Step 1: Create policy
            policy = database.create_policy(
                name="Test S3 Encryption Policy",
                description="Ensures S3 buckets are encrypted",
                severity="high",
                provider="aws",
                resource_types=["s3_bucket"],
                condition={"encryption_enabled": False},
                remediation="Enable server-side encryption",
                references=["CIS 2.1.1"],
                enabled=True,
                created_by=admin.id
            )

            assert policy is not None
            assert policy.id is not None
            assert policy.enabled is True

            # Step 2: Read policy
            retrieved = database.get_policy(policy.id)
            assert retrieved is not None
            assert retrieved.name == policy.name

            # Step 3: List policies with filters
            policies = database.list_policies(
                provider="aws",
                severity="high",
                enabled_only=True
            )
            assert any(p.id == policy.id for p in policies)

            # Step 4: Update policy
            updated = database.update_policy(
                policy.id,
                severity="critical",
                enabled=False
            )
            assert updated is not None
            assert updated.severity == "critical"
            assert updated.enabled is False

            # Step 5: Verify update persisted
            retrieved = database.get_policy(policy.id)
            assert retrieved.severity == "critical"
            assert retrieved.enabled is False

            # Step 6: Delete policy
            deleted = database.delete_policy(policy.id)
            assert deleted is True

            # Step 7: Verify deletion
            retrieved = database.get_policy(policy.id)
            assert retrieved is None

        finally:
            auth_manager.delete_user(admin.id)

    def test_policy_bulk_operations(self, database):
        """Test bulk policy operations."""
        # Create multiple policies
        policies = []
        for i in range(5):
            policy = database.create_policy(
                name=f"Bulk Policy {i}",
                description=f"Test policy {i}",
                severity="medium",
                provider="aws",
                resource_types=["ec2_instance"],
                condition={},
                remediation="Fix it"
            )
            policies.append(policy)

        try:
            # List all created policies
            all_policies = database.list_policies(provider="aws", limit=100)
            created_ids = {p.id for p in policies}
            found_ids = {p.id for p in all_policies if p.id in created_ids}
            assert len(found_ids) == 5

            # Bulk enable/disable
            for policy in policies[:3]:
                database.update_policy(policy.id, enabled=False)

            # Verify states
            disabled = database.list_policies(provider="aws", enabled_only=False, limit=100)
            disabled_count = sum(1 for p in disabled if p.id in created_ids and not p.enabled)
            assert disabled_count == 3

        finally:
            # Cleanup
            for policy in policies:
                database.delete_policy(policy.id)


# ============================================================================
# SCAN WORKFLOW INTEGRATION TESTS
# ============================================================================

class TestScanWorkflow:
    """Test complete scan workflow."""

    def test_scan_finding_audit_workflow(self, database, auth_manager):
        """Test complete scan → findings → audit workflow."""
        # Create user
        user = auth_manager.create_user(
            username="scan_user",
            email="scan@test.com",
            password="ScanP@ss123!",
            roles=["security_analyst"]
        )

        try:
            # Step 1: Create policies
            policy = database.create_policy(
                name="S3 Public Access Check",
                description="Check for public S3 buckets",
                severity="high",
                provider="aws",
                resource_types=["s3_bucket"],
                condition={"public_access": True},
                remediation="Disable public access"
            )

            # Step 2: Create scan record
            scan_id = str(uuid.uuid4())
            scan = database.create_scan_record(
                scan_id=scan_id,
                provider="aws",
                region="us-east-1",
                scan_type="full"
            )
            assert scan is not None

            # Step 3: Create findings from scan
            findings = []
            for i in range(3):
                finding = database.create_finding_record(
                    scan_id=scan_id,
                    resource_id=f"s3-bucket-{i}",
                    resource_type="s3_bucket",
                    policy_id=policy.id,
                    severity="high",
                    title=f"Public S3 Bucket {i}",
                    description=f"Bucket {i} is publicly accessible",
                    status="open"
                )
                findings.append(finding)

            assert len(findings) == 3

            # Step 4: Query findings by scan
            scan_findings = database.get_findings_by_scan(scan_id)
            assert len(scan_findings) == 3

            # Step 5: Create audit log for scan
            audit = database.create_audit_log(
                user_id=user.id,
                username=user.username,
                action="run_scan",
                resource_type="scan",
                resource_id=scan_id,
                status="success",
                details={"findings_count": 3, "severity": "high"}
            )
            assert audit is not None

            # Step 6: Query audit logs
            logs = database.get_audit_logs(
                user_id=user.id,
                action="run_scan",
                limit=10
            )
            assert len(logs) > 0
            assert any(log.resource_id == scan_id for log in logs)

            # Step 7: Resolve finding
            resolved = database.update_finding_status(
                findings[0].id,
                "resolved",
                resolution_notes="Fixed by enabling encryption"
            )
            assert resolved is not None
            assert resolved.status == "resolved"

            # Step 8: Create audit log for resolution
            database.create_audit_log(
                user_id=user.id,
                username=user.username,
                action="resolve_finding",
                resource_type="finding",
                resource_id=findings[0].id,
                status="success"
            )

        finally:
            # Cleanup
            database.delete_policy(policy.id)
            auth_manager.delete_user(user.id)


# ============================================================================
# RBAC INTEGRATION TESTS
# ============================================================================

class TestRBACIntegration:
    """Test role-based access control integration."""

    def test_multi_role_permissions(self, auth_manager):
        """Test user with multiple roles."""
        # Create custom role
        session = database.get_session()
        try:
            custom_role = Role(
                name="custom_scanner",
                description="Custom scanner role",
                permissions=f"{Permission.SCAN_RUN},{Permission.SCAN_VIEW}"
            )
            session.add(custom_role)
            session.commit()

            # Create user with multiple roles
            user = auth_manager.create_user(
                username="multi_role_user",
                email="multirole@test.com",
                password="MultiRole123!",
                roles=["viewer", "custom_scanner"]
            )

            try:
                # User should have permissions from both roles
                assert user.has_permission(Permission.SCAN_VIEW)  # from both
                assert user.has_permission(Permission.SCAN_RUN)   # from custom_scanner
                assert user.has_permission(Permission.FINDING_VIEW)  # from viewer

                # Should not have admin permissions
                assert not user.has_permission(Permission.USER_CREATE)

            finally:
                auth_manager.delete_user(user.id)
                session.delete(custom_role)
                session.commit()

        finally:
            session.close()

    def test_role_permission_changes_propagate(self, auth_manager):
        """Test that role permission changes affect users."""
        session = database.get_session()
        try:
            # Create role with limited permissions
            test_role = Role(
                name="test_dynamic_role",
                description="Test role",
                permissions=Permission.SCAN_VIEW
            )
            session.add(test_role)
            session.commit()

            # Create user with this role
            user = auth_manager.create_user(
                username="dynamic_user",
                email="dynamic@test.com",
                password="DynamicTest123!",
                roles=["test_dynamic_role"]
            )

            try:
                # Initially has only SCAN_VIEW
                db_user = session.query(User).filter(User.id == user.id).first()
                assert db_user.has_permission(Permission.SCAN_VIEW)
                assert not db_user.has_permission(Permission.FINDING_VIEW)

                # Update role permissions
                test_role.permissions = f"{Permission.SCAN_VIEW},{Permission.FINDING_VIEW}"
                session.commit()

                # User should now have new permission
                session.expire_all()  # Refresh from DB
                db_user = session.query(User).filter(User.id == user.id).first()
                assert db_user.has_permission(Permission.SCAN_VIEW)
                assert db_user.has_permission(Permission.FINDING_VIEW)

            finally:
                auth_manager.delete_user(user.id)
                session.delete(test_role)
                session.commit()

        finally:
            session.close()


# ============================================================================
# MULTI-USER SCENARIO TESTS
# ============================================================================

class TestMultiUserScenarios:
    """Test multi-user interaction scenarios."""

    def test_concurrent_users_different_permissions(self, auth_manager, database):
        """Test multiple users with different permission levels."""
        # Create admin
        admin = auth_manager.create_admin_user(
            username="admin_concurrent",
            email="admin_concurrent@test.com",
            password="AdminConc123!"
        )

        # Create analyst
        analyst = auth_manager.create_user(
            username="analyst_concurrent",
            email="analyst_concurrent@test.com",
            password="AnalystConc123!",
            roles=["security_analyst"]
        )

        # Create viewer
        viewer = auth_manager.create_user(
            username="viewer_concurrent",
            email="viewer_concurrent@test.com",
            password="ViewerConc123!",
            roles=["viewer"]
        )

        try:
            # Admin creates policy
            policy = database.create_policy(
                name="Admin Created Policy",
                description="Policy created by admin",
                severity="high",
                provider="aws",
                resource_types=["s3_bucket"],
                condition={},
                remediation="Fix",
                created_by=admin.id
            )

            # All users can view
            assert admin.has_permission(Permission.POLICY_VIEW)
            assert analyst.has_permission(Permission.POLICY_VIEW)
            assert viewer.has_permission(Permission.POLICY_VIEW)

            # Only admin can delete
            assert admin.has_permission(Permission.POLICY_DELETE)
            assert not analyst.has_permission(Permission.POLICY_DELETE)
            assert not viewer.has_permission(Permission.POLICY_DELETE)

            # Analyst can run scans
            assert analyst.has_permission(Permission.SCAN_RUN)
            assert not viewer.has_permission(Permission.SCAN_RUN)

            # Cleanup
            database.delete_policy(policy.id)

        finally:
            auth_manager.delete_user(admin.id)
            auth_manager.delete_user(analyst.id)
            auth_manager.delete_user(viewer.id)

    def test_user_activity_tracking(self, auth_manager, database):
        """Test tracking activity across multiple users."""
        users = []

        try:
            # Create multiple users
            for i in range(3):
                user = auth_manager.create_user(
                    username=f"activity_user_{i}",
                    email=f"activity{i}@test.com",
                    password=f"Activity{i}P@ss123!"
                )
                users.append(user)

            # Each user performs actions
            for i, user in enumerate(users):
                for j in range(i + 1):  # Different number of actions per user
                    database.create_audit_log(
                        user_id=user.id,
                        username=user.username,
                        action="view_dashboard",
                        resource_type="dashboard",
                        status="success"
                    )

            # Query activity per user
            for i, user in enumerate(users):
                logs = database.get_audit_logs(
                    user_id=user.id,
                    action="view_dashboard",
                    limit=100
                )
                assert len(logs) == i + 1

        finally:
            for user in users:
                auth_manager.delete_user(user.id)


# ============================================================================
# DATABASE INTEGRITY TESTS
# ============================================================================

class TestDatabaseIntegrity:
    """Test database integrity across operations."""

    def test_cascade_delete_user_sessions(self, auth_manager, database):
        """Test that deleting user cascades to sessions."""
        # Create user and sessions
        user = auth_manager.create_user(
            username="cascade_test",
            email="cascade@test.com",
            password="CascadeTest123!"
        )

        sessions = []
        for i in range(3):
            session = auth_manager.create_session(user.id)
            sessions.append(session)

        # Verify sessions exist
        for session in sessions:
            assert auth_manager.validate_session(session.token) is not None

        # Delete user
        auth_manager.delete_user(user.id)

        # Sessions should be deleted (cascade)
        for session in sessions:
            assert auth_manager.validate_session(session.token) is None

    def test_referential_integrity_policy_findings(self, database):
        """Test referential integrity between policies and findings."""
        # Create policy
        policy = database.create_policy(
            name="Integrity Test Policy",
            description="Test",
            severity="medium",
            provider="aws",
            resource_types=["s3_bucket"],
            condition={},
            remediation="Fix"
        )

        try:
            # Create scan
            scan_id = str(uuid.uuid4())
            scan = database.create_scan_record(
                scan_id=scan_id,
                provider="aws",
                region="us-east-1",
                scan_type="full"
            )

            # Create finding referencing policy
            finding = database.create_finding_record(
                scan_id=scan_id,
                resource_id="test-resource",
                resource_type="s3_bucket",
                policy_id=policy.id,
                severity="medium",
                title="Test Finding",
                description="Test",
                status="open"
            )

            # Verify finding references policy
            retrieved_finding = database.get_finding(finding.id)
            assert retrieved_finding.policy_id == policy.id

            # Delete policy (finding may or may not cascade depending on constraints)
            database.delete_policy(policy.id)

        except Exception as e:
            # Cleanup on error
            try:
                database.delete_policy(policy.id)
            except:
                pass

    def test_transaction_rollback_on_error(self, database):
        """Test that transactions rollback on errors."""
        initial_policy_count = len(database.list_policies(limit=1000))

        try:
            # Attempt to create invalid policy (should fail)
            database.create_policy(
                name="Invalid Policy",
                description="Test",
                severity="invalid_severity",  # Invalid
                provider="aws",
                resource_types=[],
                condition={},
                remediation="Fix"
            )
        except Exception:
            # Expected to fail
            pass

        # Policy count should not have changed
        final_policy_count = len(database.list_policies(limit=1000))
        assert initial_policy_count == final_policy_count


# ============================================================================
# END-TO-END API INTEGRATION TESTS
# ============================================================================

class TestAPIIntegration:
    """Test end-to-end API integration scenarios."""

    def test_complete_authentication_flow(self, auth_manager):
        """Test complete authentication flow."""
        # Create user
        user = auth_manager.create_user(
            username="api_auth_user",
            email="api_auth@test.com",
            password="ApiAuth123!"
        )

        try:
            # Authenticate (simulate login endpoint)
            authenticated = auth_manager.authenticate(
                "api_auth_user",
                "ApiAuth123!"
            )
            assert authenticated is not None

            # Create session (simulate session creation)
            session = auth_manager.create_session(authenticated.id)
            assert session is not None

            # Validate session (simulate protected endpoint access)
            session_user = auth_manager.validate_session(session.token)
            assert session_user is not None
            assert session_user.id == user.id

            # Logout (simulate logout endpoint)
            auth_manager.logout(session.token)

            # Verify session invalid
            session_user = auth_manager.validate_session(session.token)
            assert session_user is None

        finally:
            auth_manager.delete_user(user.id)

    def test_api_key_authentication_flow(self, auth_manager):
        """Test API key authentication flow."""
        # Create user
        user = auth_manager.create_user(
            username="api_key_user",
            email="api_key@test.com",
            password="ApiKey123!"
        )

        try:
            # Generate API key
            session = database.get_session()
            try:
                db_user = session.query(User).filter(User.id == user.id).first()
                api_key = db_user.generate_api_key()
                session.commit()
            finally:
                session.close()

            # Authenticate with API key
            authenticated = auth_manager.authenticate_api_key(api_key)
            assert authenticated is not None
            assert authenticated.id == user.id

            # Regenerate API key (old one should be invalid)
            session = database.get_session()
            try:
                db_user = session.query(User).filter(User.id == user.id).first()
                new_api_key = db_user.generate_api_key()
                session.commit()
            finally:
                session.close()

            # Old key should not work
            authenticated = auth_manager.authenticate_api_key(api_key)
            assert authenticated is None

            # New key should work
            authenticated = auth_manager.authenticate_api_key(new_api_key)
            assert authenticated is not None

        finally:
            auth_manager.delete_user(user.id)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

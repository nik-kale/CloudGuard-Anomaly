"""
Comprehensive API tests for CloudGuard-Anomaly v1 endpoints.

Tests cover:
- Policy management (CRUD + filtering)
- User management (CRUD + authentication)
- Role management (CRUD + permissions)
- Audit log queries (filtering + statistics)
- Authentication and authorization
- Input validation and error handling
"""

import os
import json
import uuid
import pytest
import tempfile
from datetime import datetime, timedelta
from flask import Flask

from cloudguard_anomaly.config import get_config, Config
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.auth import AuthenticationManager
from cloudguard_anomaly.auth.models import Permission, User, Role, Session
from cloudguard_anomaly.dashboard.app import create_app


@pytest.fixture(scope="session")
def test_db_path():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture(scope="session")
def test_config(test_db_path):
    """Create test configuration."""
    config = Config(
        database_url=f"sqlite:///{test_db_path}",
        log_level="DEBUG",
        log_format="text"
    )
    return config


@pytest.fixture(scope="session")
def database(test_config):
    """Create database instance for testing."""
    db = DatabaseStorage(test_config.database_url)
    yield db


@pytest.fixture(scope="session")
def auth_manager(database):
    """Create authentication manager."""
    manager = AuthenticationManager(database)
    manager.create_default_roles()
    yield manager


@pytest.fixture(scope="session")
def app(test_config, database, auth_manager):
    """Create Flask app for testing."""
    # Set test config
    os.environ['DATABASE_URL'] = test_config.database_url
    os.environ['LOG_LEVEL'] = 'DEBUG'

    app = create_app()
    app.config['TESTING'] = True

    yield app


@pytest.fixture(scope="session")
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def admin_user(auth_manager):
    """Create admin user for testing."""
    try:
        user = auth_manager.create_admin_user(
            username="test_admin",
            email="admin@test.com",
            password="AdminP@ssw0rd123!"
        )
        yield user
    finally:
        # Cleanup
        try:
            auth_manager.delete_user(user.id)
        except:
            pass


@pytest.fixture
def regular_user(auth_manager):
    """Create regular user for testing."""
    try:
        user = auth_manager.create_user(
            username="test_user",
            email="user@test.com",
            password="UserP@ssw0rd123!",
            roles=["viewer"]
        )
        yield user
    finally:
        # Cleanup
        try:
            auth_manager.delete_user(user.id)
        except:
            pass


@pytest.fixture
def admin_token(auth_manager, admin_user):
    """Create admin session token."""
    session = auth_manager.create_session(admin_user.id)
    return session.token


@pytest.fixture
def user_token(auth_manager, regular_user):
    """Create regular user session token."""
    session = auth_manager.create_session(regular_user.id)
    return session.token


@pytest.fixture
def admin_headers(admin_token):
    """Headers with admin authentication."""
    return {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }


@pytest.fixture
def user_headers(user_token):
    """Headers with user authentication."""
    return {
        'Authorization': f'Bearer {user_token}',
        'Content-Type': 'application/json'
    }


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

class TestAuthentication:
    """Test authentication and authorization."""

    def test_unauthenticated_request_fails(self, client):
        """Test that unauthenticated requests are rejected."""
        response = client.get('/api/v1/policies')
        assert response.status_code == 401

    def test_invalid_token_fails(self, client):
        """Test that invalid tokens are rejected."""
        headers = {'Authorization': 'Bearer invalid-token-12345'}
        response = client.get('/api/v1/policies', headers=headers)
        assert response.status_code == 401

    def test_expired_token_fails(self, client, auth_manager, admin_user):
        """Test that expired tokens are rejected."""
        # Create session with negative TTL (already expired)
        session = Session.create_session(admin_user.id, ttl_hours=-1)
        headers = {'Authorization': f'Bearer {session.token}'}
        response = client.get('/api/v1/policies', headers=headers)
        assert response.status_code == 401

    def test_valid_token_succeeds(self, client, admin_headers):
        """Test that valid tokens are accepted."""
        response = client.get('/api/v1/policies', headers=admin_headers)
        assert response.status_code in [200, 403]  # 403 if no permission

    def test_permission_denied(self, client, user_headers):
        """Test that insufficient permissions return 403."""
        # Try to create policy without permission
        response = client.post(
            '/api/v1/policies',
            headers=user_headers,
            json={'name': 'test', 'description': 'test'}
        )
        assert response.status_code == 403


# ============================================================================
# POLICY API TESTS
# ============================================================================

class TestPolicyAPI:
    """Test policy management endpoints."""

    def test_list_policies_success(self, client, admin_headers, database):
        """Test listing policies."""
        # Create a test policy first
        database.create_policy(
            name="Test Policy",
            description="Test description",
            severity="high",
            provider="aws",
            resource_types=["s3_bucket"],
            condition={"encryption": False},
            remediation="Enable encryption",
            enabled=True
        )

        response = client.get('/api/v1/policies', headers=admin_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'policies' in data
        assert 'count' in data
        assert isinstance(data['policies'], list)

    def test_list_policies_with_filters(self, client, admin_headers):
        """Test listing policies with filters."""
        response = client.get(
            '/api/v1/policies?provider=aws&severity=high&enabled=true',
            headers=admin_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert 'policies' in data

    def test_list_policies_pagination(self, client, admin_headers):
        """Test policy pagination."""
        response = client.get(
            '/api/v1/policies?limit=10&offset=0',
            headers=admin_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['limit'] == 10
        assert data['offset'] == 0

    def test_get_policy_success(self, client, admin_headers, database):
        """Test getting a specific policy."""
        # Create policy
        policy = database.create_policy(
            name="Get Test Policy",
            description="Test",
            severity="medium",
            provider="aws",
            resource_types=["ec2_instance"],
            condition={},
            remediation="Fix it"
        )

        response = client.get(f'/api/v1/policies/{policy.id}', headers=admin_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert data['id'] == policy.id
        assert data['name'] == "Get Test Policy"

    def test_get_policy_not_found(self, client, admin_headers):
        """Test getting non-existent policy."""
        fake_id = str(uuid.uuid4())
        response = client.get(f'/api/v1/policies/{fake_id}', headers=admin_headers)
        assert response.status_code == 404

    def test_get_policy_invalid_id(self, client, admin_headers):
        """Test getting policy with invalid ID."""
        response = client.get('/api/v1/policies/invalid-id', headers=admin_headers)
        assert response.status_code == 400

    def test_create_policy_success(self, client, admin_headers):
        """Test creating a new policy."""
        policy_data = {
            "name": "Test S3 Encryption Policy",
            "description": "Ensures S3 buckets are encrypted",
            "severity": "high",
            "provider": "aws",
            "resource_types": ["s3_bucket"],
            "condition": {"encryption_enabled": False},
            "remediation": "Enable S3 bucket encryption",
            "references": ["CIS 2.1.1"],
            "enabled": True
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )
        assert response.status_code == 201

        data = response.get_json()
        assert 'id' in data
        assert data['name'] == policy_data['name']
        assert data['severity'] == policy_data['severity']

    def test_create_policy_missing_fields(self, client, admin_headers):
        """Test creating policy with missing required fields."""
        policy_data = {
            "name": "Incomplete Policy"
            # Missing required fields
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )
        assert response.status_code == 400
        assert 'error' in response.get_json()

    def test_create_policy_invalid_severity(self, client, admin_headers):
        """Test creating policy with invalid severity."""
        policy_data = {
            "name": "Test Policy",
            "description": "Test",
            "severity": "invalid",  # Invalid severity
            "provider": "aws",
            "resource_types": ["s3_bucket"],
            "condition": {},
            "remediation": "Fix"
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )
        assert response.status_code == 400

    def test_create_policy_invalid_provider(self, client, admin_headers):
        """Test creating policy with invalid provider."""
        policy_data = {
            "name": "Test Policy",
            "description": "Test",
            "severity": "high",
            "provider": "invalid_provider",  # Invalid
            "resource_types": ["s3_bucket"],
            "condition": {},
            "remediation": "Fix"
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )
        assert response.status_code == 400

    def test_update_policy_success(self, client, admin_headers, database):
        """Test updating a policy."""
        # Create policy
        policy = database.create_policy(
            name="Original Name",
            description="Original",
            severity="low",
            provider="aws",
            resource_types=["s3_bucket"],
            condition={},
            remediation="Fix"
        )

        update_data = {
            "name": "Updated Name",
            "severity": "high"
        }

        response = client.put(
            f'/api/v1/policies/{policy.id}',
            headers=admin_headers,
            json=update_data
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['name'] == "Updated Name"
        assert data['severity'] == "high"

    def test_update_policy_not_found(self, client, admin_headers):
        """Test updating non-existent policy."""
        fake_id = str(uuid.uuid4())
        response = client.put(
            f'/api/v1/policies/{fake_id}',
            headers=admin_headers,
            json={"name": "Updated"}
        )
        assert response.status_code == 404

    def test_delete_policy_success(self, client, admin_headers, database):
        """Test deleting a policy."""
        # Create policy
        policy = database.create_policy(
            name="To Delete",
            description="Test",
            severity="low",
            provider="aws",
            resource_types=["s3_bucket"],
            condition={},
            remediation="Fix"
        )

        response = client.delete(
            f'/api/v1/policies/{policy.id}',
            headers=admin_headers
        )
        assert response.status_code == 204

        # Verify deleted
        get_response = client.get(
            f'/api/v1/policies/{policy.id}',
            headers=admin_headers
        )
        assert get_response.status_code == 404

    def test_delete_policy_not_found(self, client, admin_headers):
        """Test deleting non-existent policy."""
        fake_id = str(uuid.uuid4())
        response = client.delete(
            f'/api/v1/policies/{fake_id}',
            headers=admin_headers
        )
        assert response.status_code == 404


# ============================================================================
# USER API TESTS
# ============================================================================

class TestUserAPI:
    """Test user management endpoints."""

    def test_list_users_admin_only(self, client, user_headers):
        """Test that only admins can list users."""
        response = client.get('/api/v1/users', headers=user_headers)
        assert response.status_code == 403

    def test_list_users_success(self, client, admin_headers):
        """Test listing users as admin."""
        response = client.get('/api/v1/users', headers=admin_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'users' in data
        assert isinstance(data['users'], list)

    def test_get_user_self(self, client, user_headers, regular_user):
        """Test users can view their own profile."""
        response = client.get(
            f'/api/v1/users/{regular_user.id}',
            headers=user_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['id'] == regular_user.id
        assert data['username'] == regular_user.username
        # Ensure sensitive fields are not exposed
        assert 'password_hash' not in data
        assert 'api_key' not in data

    def test_get_user_other_forbidden(self, client, user_headers, admin_user):
        """Test users cannot view other user profiles."""
        response = client.get(
            f'/api/v1/users/{admin_user.id}',
            headers=user_headers
        )
        assert response.status_code == 403

    def test_get_user_admin_can_view_any(self, client, admin_headers, regular_user):
        """Test admins can view any user."""
        response = client.get(
            f'/api/v1/users/{regular_user.id}',
            headers=admin_headers
        )
        assert response.status_code == 200

    def test_create_user_success(self, client, admin_headers, auth_manager):
        """Test creating a new user."""
        user_data = {
            "username": "new_user",
            "email": "newuser@test.com",
            "password": "NewUserP@ss123!",
            "roles": ["viewer"],
            "is_admin": False
        }

        response = client.post(
            '/api/v1/users',
            headers=admin_headers,
            json=user_data
        )
        assert response.status_code == 201

        data = response.get_json()
        assert data['username'] == "new_user"
        assert data['email'] == "newuser@test.com"
        assert 'viewer' in data['roles']

        # Cleanup
        try:
            auth_manager.delete_user(data['id'])
        except:
            pass

    def test_create_user_missing_fields(self, client, admin_headers):
        """Test creating user with missing required fields."""
        user_data = {
            "username": "incomplete_user"
            # Missing email and password
        }

        response = client.post(
            '/api/v1/users',
            headers=admin_headers,
            json=user_data
        )
        assert response.status_code == 400

    def test_create_user_weak_password(self, client, admin_headers):
        """Test creating user with weak password."""
        user_data = {
            "username": "weak_pass_user",
            "email": "weak@test.com",
            "password": "weak"  # Weak password
        }

        response = client.post(
            '/api/v1/users',
            headers=admin_headers,
            json=user_data
        )
        assert response.status_code == 400
        assert 'error' in response.get_json()

    def test_create_user_invalid_email(self, client, admin_headers):
        """Test creating user with invalid email."""
        user_data = {
            "username": "test_user_email",
            "email": "invalid-email",  # Invalid format
            "password": "ValidP@ss123!"
        }

        response = client.post(
            '/api/v1/users',
            headers=admin_headers,
            json=user_data
        )
        assert response.status_code == 400

    def test_create_user_duplicate_username(self, client, admin_headers, regular_user):
        """Test creating user with duplicate username."""
        user_data = {
            "username": regular_user.username,  # Duplicate
            "email": "different@test.com",
            "password": "ValidP@ss123!"
        }

        response = client.post(
            '/api/v1/users',
            headers=admin_headers,
            json=user_data
        )
        assert response.status_code == 400

    def test_update_user_self(self, client, user_headers, regular_user):
        """Test users can update their own profile."""
        update_data = {
            "email": "newemail@test.com",
            "password": "NewP@ssw0rd123!"
        }

        response = client.put(
            f'/api/v1/users/{regular_user.id}',
            headers=user_headers,
            json=update_data
        )
        assert response.status_code == 200

    def test_update_user_cannot_change_own_admin_status(self, client, user_headers, regular_user):
        """Test users cannot make themselves admin."""
        update_data = {"is_admin": True}

        response = client.put(
            f'/api/v1/users/{regular_user.id}',
            headers=user_headers,
            json=update_data
        )
        assert response.status_code == 200

        # Verify they're still not admin
        get_response = client.get(
            f'/api/v1/users/{regular_user.id}',
            headers=user_headers
        )
        data = get_response.get_json()
        assert data['is_admin'] == False

    def test_update_user_admin_can_change_admin_status(self, client, admin_headers, regular_user):
        """Test admins can change user admin status."""
        update_data = {"is_admin": True}

        response = client.put(
            f'/api/v1/users/{regular_user.id}',
            headers=admin_headers,
            json=update_data
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['is_admin'] == True

    def test_delete_user_success(self, client, admin_headers, auth_manager):
        """Test deleting a user."""
        # Create user to delete
        user = auth_manager.create_user(
            username="to_delete",
            email="delete@test.com",
            password="DeleteP@ss123!"
        )

        response = client.delete(
            f'/api/v1/users/{user.id}',
            headers=admin_headers
        )
        assert response.status_code == 204

    def test_delete_user_cannot_delete_self(self, client, admin_headers, admin_user):
        """Test admin cannot delete their own account."""
        response = client.delete(
            f'/api/v1/users/{admin_user.id}',
            headers=admin_headers
        )
        assert response.status_code == 400

    def test_regenerate_api_key_self(self, client, user_headers, regular_user):
        """Test users can regenerate their own API key."""
        response = client.post(
            f'/api/v1/users/{regular_user.id}/regenerate-api-key',
            headers=user_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert 'api_key' in data
        assert data['api_key'].startswith('cgak_')

    def test_regenerate_api_key_admin_for_other(self, client, admin_headers, regular_user):
        """Test admins can regenerate API keys for other users."""
        response = client.post(
            f'/api/v1/users/{regular_user.id}/regenerate-api-key',
            headers=admin_headers
        )
        assert response.status_code == 200


# ============================================================================
# ROLE API TESTS
# ============================================================================

class TestRoleAPI:
    """Test role management endpoints."""

    def test_list_roles_admin_only(self, client, user_headers):
        """Test that only admins can list roles."""
        response = client.get('/api/v1/roles', headers=user_headers)
        assert response.status_code == 403

    def test_list_roles_success(self, client, admin_headers):
        """Test listing roles as admin."""
        response = client.get('/api/v1/roles', headers=admin_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'roles' in data
        assert len(data['roles']) >= 4  # Default roles

    def test_get_role_success(self, client, admin_headers, database):
        """Test getting a specific role."""
        # Get admin role
        session = database.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            role = session.query(Role).filter(Role.name == 'admin').first()

            response = client.get(
                f'/api/v1/roles/{role.id}',
                headers=admin_headers
            )
            assert response.status_code == 200

            data = response.get_json()
            assert data['name'] == 'admin'
            assert 'permissions' in data
        finally:
            session.close()

    def test_create_role_success(self, client, admin_headers):
        """Test creating a new role."""
        role_data = {
            "name": "custom_analyst",
            "description": "Custom security analyst role",
            "permissions": [
                "scan:view",
                "finding:view",
                "compliance:view"
            ]
        }

        response = client.post(
            '/api/v1/roles',
            headers=admin_headers,
            json=role_data
        )
        assert response.status_code == 201

        data = response.get_json()
        assert data['name'] == "custom_analyst"
        assert len(data['permissions']) == 3

    def test_create_role_invalid_name_format(self, client, admin_headers):
        """Test creating role with invalid name format."""
        role_data = {
            "name": "Invalid-Name!",  # Should be lowercase with underscores
            "description": "Test",
            "permissions": []
        }

        response = client.post(
            '/api/v1/roles',
            headers=admin_headers,
            json=role_data
        )
        assert response.status_code == 400

    def test_create_role_invalid_permission(self, client, admin_headers):
        """Test creating role with invalid permission."""
        role_data = {
            "name": "test_role",
            "description": "Test",
            "permissions": ["invalid:permission"]  # Invalid
        }

        response = client.post(
            '/api/v1/roles',
            headers=admin_headers,
            json=role_data
        )
        assert response.status_code == 400

    def test_update_role_success(self, client, admin_headers, database):
        """Test updating a role."""
        # Create role first
        session = database.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            role = Role(
                name="update_test_role",
                description="Original description",
                permissions="scan:view"
            )
            session.add(role)
            session.commit()

            update_data = {
                "description": "Updated description",
                "permissions": ["scan:view", "finding:view"]
            }

            response = client.put(
                f'/api/v1/roles/{role.id}',
                headers=admin_headers,
                json=update_data
            )
            assert response.status_code == 200

            data = response.get_json()
            assert data['description'] == "Updated description"
            assert len(data['permissions']) == 2
        finally:
            session.close()

    def test_delete_role_success(self, client, admin_headers, database):
        """Test deleting a custom role."""
        # Create role first
        session = database.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            role = Role(
                name="delete_test_role",
                description="To be deleted",
                permissions=""
            )
            session.add(role)
            session.commit()

            response = client.delete(
                f'/api/v1/roles/{role.id}',
                headers=admin_headers
            )
            assert response.status_code == 204
        finally:
            session.close()

    def test_delete_default_role_forbidden(self, client, admin_headers, database):
        """Test that default roles cannot be deleted."""
        # Try to delete admin role
        session = database.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            role = session.query(Role).filter(Role.name == 'admin').first()

            response = client.delete(
                f'/api/v1/roles/{role.id}',
                headers=admin_headers
            )
            assert response.status_code == 400
        finally:
            session.close()

    def test_list_permissions(self, client, admin_headers):
        """Test listing all available permissions."""
        response = client.get(
            '/api/v1/roles/permissions',
            headers=admin_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert 'permissions' in data
        assert len(data['permissions']) > 0
        # Should include common permissions
        assert any('scan:view' in p for p in data['permissions'])


# ============================================================================
# AUDIT LOG API TESTS
# ============================================================================

class TestAuditLogAPI:
    """Test audit log endpoints."""

    def test_list_audit_logs_requires_permission(self, client, user_headers):
        """Test that audit log access requires permission."""
        response = client.get('/api/v1/audit-logs', headers=user_headers)
        # Regular viewer role doesn't have audit:view permission
        assert response.status_code == 403

    def test_list_audit_logs_success(self, client, admin_headers, database):
        """Test listing audit logs."""
        # Create some audit logs
        database.create_audit_log(
            user_id="test-user",
            username="test",
            action="create",
            resource_type="policy",
            resource_id="test-policy-id",
            status="success"
        )

        response = client.get('/api/v1/audit-logs', headers=admin_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'audit_logs' in data
        assert isinstance(data['audit_logs'], list)

    def test_list_audit_logs_with_filters(self, client, admin_headers):
        """Test filtering audit logs."""
        response = client.get(
            '/api/v1/audit-logs?action=create&status=success&days=7',
            headers=admin_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert 'audit_logs' in data

    def test_list_audit_logs_with_time_range(self, client, admin_headers):
        """Test filtering audit logs by time range."""
        start_time = (datetime.utcnow() - timedelta(days=7)).isoformat()
        end_time = datetime.utcnow().isoformat()

        response = client.get(
            f'/api/v1/audit-logs?start_time={start_time}&end_time={end_time}',
            headers=admin_headers
        )
        assert response.status_code == 200

    def test_list_audit_logs_invalid_time_format(self, client, admin_headers):
        """Test that invalid time format returns error."""
        response = client.get(
            '/api/v1/audit-logs?start_time=invalid',
            headers=admin_headers
        )
        assert response.status_code == 400

    def test_get_user_activity_self(self, client, user_headers, regular_user, database):
        """Test users can view their own activity."""
        # Create audit log for user
        database.create_audit_log(
            user_id=regular_user.id,
            username=regular_user.username,
            action="login",
            resource_type="session",
            status="success"
        )

        response = client.get(
            f'/api/v1/audit-logs/user/{regular_user.id}',
            headers=user_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['user_id'] == regular_user.id
        assert 'audit_logs' in data

    def test_get_user_activity_other_forbidden(self, client, user_headers, admin_user):
        """Test users cannot view other users' activity."""
        response = client.get(
            f'/api/v1/audit-logs/user/{admin_user.id}',
            headers=user_headers
        )
        assert response.status_code == 403

    def test_get_user_activity_admin_can_view_any(self, client, admin_headers, regular_user):
        """Test admins can view any user's activity."""
        response = client.get(
            f'/api/v1/audit-logs/user/{regular_user.id}',
            headers=admin_headers
        )
        assert response.status_code == 200

    def test_get_audit_stats(self, client, admin_headers, database):
        """Test getting audit log statistics."""
        # Create various audit logs
        database.create_audit_log(
            user_id="test-1",
            username="test1",
            action="create",
            resource_type="policy",
            status="success"
        )
        database.create_audit_log(
            user_id="test-2",
            username="test2",
            action="delete",
            resource_type="user",
            status="success"
        )

        response = client.get('/api/v1/audit-logs/stats', headers=admin_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'total_events' in data
        assert 'by_action' in data
        assert 'by_status' in data
        assert 'by_resource_type' in data
        assert 'top_users' in data


# ============================================================================
# INPUT VALIDATION TESTS
# ============================================================================

class TestInputValidation:
    """Test input validation across all endpoints."""

    def test_sql_injection_prevention(self, client, admin_headers):
        """Test that SQL injection attempts are handled safely."""
        malicious_input = "'; DROP TABLE users; --"

        response = client.get(
            f'/api/v1/policies?provider={malicious_input}',
            headers=admin_headers
        )
        # Should not crash, should return empty or error
        assert response.status_code in [200, 400]

    def test_xss_prevention(self, client, admin_headers):
        """Test that XSS attempts are sanitized."""
        xss_input = "<script>alert('XSS')</script>"

        policy_data = {
            "name": xss_input,
            "description": xss_input,
            "severity": "high",
            "provider": "aws",
            "resource_types": ["s3_bucket"],
            "condition": {},
            "remediation": "Fix"
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )

        # XSS should be sanitized or rejected
        if response.status_code == 201:
            data = response.get_json()
            # Scripts should be stripped
            assert '<script>' not in data['name']

    def test_large_payload_handling(self, client, admin_headers):
        """Test handling of excessively large payloads."""
        large_string = "A" * 100000  # 100KB string

        policy_data = {
            "name": "Test",
            "description": large_string,
            "severity": "high",
            "provider": "aws",
            "resource_types": ["s3_bucket"],
            "condition": {},
            "remediation": "Fix"
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )
        # Should be rejected or truncated
        assert response.status_code in [400, 413, 500]

    def test_null_byte_injection(self, client, admin_headers):
        """Test handling of null byte injection."""
        null_input = "test\x00malicious"

        response = client.get(
            f'/api/v1/policies?provider={null_input}',
            headers=admin_headers
        )
        assert response.status_code in [200, 400]

    def test_unicode_handling(self, client, admin_headers):
        """Test proper handling of unicode characters."""
        unicode_input = "测试 🔒 Тест"

        policy_data = {
            "name": unicode_input,
            "description": "Unicode test",
            "severity": "high",
            "provider": "aws",
            "resource_types": ["s3_bucket"],
            "condition": {},
            "remediation": "Fix"
        }

        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            json=policy_data
        )
        # Should handle unicode gracefully
        assert response.status_code in [200, 201, 400]


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """Test error handling across all endpoints."""

    def test_invalid_json(self, client, admin_headers):
        """Test handling of invalid JSON."""
        response = client.post(
            '/api/v1/policies',
            headers=admin_headers,
            data='{"invalid": json}'  # Invalid JSON
        )
        assert response.status_code in [400, 500]

    def test_missing_content_type(self, client, admin_token):
        """Test handling of missing Content-Type header."""
        headers = {'Authorization': f'Bearer {admin_token}'}  # No Content-Type

        response = client.post(
            '/api/v1/policies',
            headers=headers,
            data='{"name": "test"}'
        )
        assert response.status_code in [400, 415]

    def test_method_not_allowed(self, client, admin_headers):
        """Test that unsupported HTTP methods return 405."""
        response = client.patch('/api/v1/policies', headers=admin_headers)
        assert response.status_code == 405

    def test_not_found_endpoint(self, client, admin_headers):
        """Test that non-existent endpoints return 404."""
        response = client.get('/api/v1/nonexistent', headers=admin_headers)
        assert response.status_code == 404


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

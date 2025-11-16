"""
Role-Based Access Control (RBAC) for CloudGuard-Anomaly.

Provides multi-tenancy and access control for enterprise deployments.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Set, Dict, Any, Optional
import uuid


class Role(Enum):
    """User roles."""

    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    DEVELOPER = "developer"


class Permission(Enum):
    """Granular permissions."""

    # Scan permissions
    SCAN_RUN = "scan:run"
    SCAN_VIEW = "scan:view"
    SCAN_DELETE = "scan:delete"

    # Finding permissions
    FINDING_VIEW = "finding:view"
    FINDING_RESOLVE = "finding:resolve"
    FINDING_SUPPRESS = "finding:suppress"

    # Remediation permissions
    REMEDIATE_VIEW = "remediate:view"
    REMEDIATE_EXECUTE = "remediate:execute"

    # Policy permissions
    POLICY_VIEW = "policy:view"
    POLICY_CREATE = "policy:create"
    POLICY_UPDATE = "policy:update"
    POLICY_DELETE = "policy:delete"

    # Environment permissions
    ENVIRONMENT_VIEW = "environment:view"
    ENVIRONMENT_CREATE = "environment:create"
    ENVIRONMENT_UPDATE = "environment:update"
    ENVIRONMENT_DELETE = "environment:delete"

    # User management
    USER_VIEW = "user:view"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

    # Settings
    SETTINGS_VIEW = "settings:view"
    SETTINGS_UPDATE = "settings:update"


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        # Full access
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
        Permission.SCAN_DELETE,
        Permission.FINDING_VIEW,
        Permission.FINDING_RESOLVE,
        Permission.FINDING_SUPPRESS,
        Permission.REMEDIATE_VIEW,
        Permission.REMEDIATE_EXECUTE,
        Permission.POLICY_VIEW,
        Permission.POLICY_CREATE,
        Permission.POLICY_UPDATE,
        Permission.POLICY_DELETE,
        Permission.ENVIRONMENT_VIEW,
        Permission.ENVIRONMENT_CREATE,
        Permission.ENVIRONMENT_UPDATE,
        Permission.ENVIRONMENT_DELETE,
        Permission.USER_VIEW,
        Permission.USER_CREATE,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_UPDATE,
    },
    Role.SECURITY_ANALYST: {
        # Can run scans, view/resolve findings, execute remediation
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
        Permission.FINDING_VIEW,
        Permission.FINDING_RESOLVE,
        Permission.FINDING_SUPPRESS,
        Permission.REMEDIATE_VIEW,
        Permission.REMEDIATE_EXECUTE,
        Permission.POLICY_VIEW,
        Permission.ENVIRONMENT_VIEW,
        Permission.ENVIRONMENT_UPDATE,
        Permission.SETTINGS_VIEW,
    },
    Role.AUDITOR: {
        # Read-only access to everything
        Permission.SCAN_VIEW,
        Permission.FINDING_VIEW,
        Permission.REMEDIATE_VIEW,
        Permission.POLICY_VIEW,
        Permission.ENVIRONMENT_VIEW,
        Permission.USER_VIEW,
        Permission.SETTINGS_VIEW,
    },
    Role.VIEWER: {
        # Limited read access
        Permission.SCAN_VIEW,
        Permission.FINDING_VIEW,
        Permission.ENVIRONMENT_VIEW,
    },
    Role.DEVELOPER: {
        # Can manage policies and environments
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
        Permission.FINDING_VIEW,
        Permission.POLICY_VIEW,
        Permission.POLICY_CREATE,
        Permission.POLICY_UPDATE,
        Permission.ENVIRONMENT_VIEW,
        Permission.ENVIRONMENT_CREATE,
        Permission.ENVIRONMENT_UPDATE,
    },
}


@dataclass
class User:
    """User account."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    email: str = ""
    role: Role = Role.VIEWER
    organizations: List[str] = field(default_factory=list)
    custom_permissions: Set[Permission] = field(default_factory=set)
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        if not self.is_active:
            return False

        # Check custom permissions
        if permission in self.custom_permissions:
            return True

        # Check role-based permissions
        return permission in ROLE_PERMISSIONS.get(self.role, set())

    def get_all_permissions(self) -> Set[Permission]:
        """Get all permissions for this user."""
        if not self.is_active:
            return set()

        base_perms = ROLE_PERMISSIONS.get(self.role, set())
        return base_perms | self.custom_permissions


@dataclass
class Organization:
    """Multi-tenant organization."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    is_active: bool = True
    environment_ids: List[str] = field(default_factory=list)
    settings: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


class RBACManager:
    """Manages RBAC and multi-tenancy."""

    def __init__(self):
        self.users: Dict[str, User] = {}
        self.organizations: Dict[str, Organization] = {}

    def create_user(
        self, username: str, email: str, role: Role, organizations: List[str] = None
    ) -> User:
        """Create a new user."""
        user = User(
            username=username,
            email=email,
            role=role,
            organizations=organizations or [],
        )
        self.users[user.id] = user
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)

    def update_user_role(self, user_id: str, role: Role) -> bool:
        """Update user's role."""
        user = self.users.get(user_id)
        if user:
            user.role = role
            return True
        return False

    def grant_permission(self, user_id: str, permission: Permission) -> bool:
        """Grant custom permission to user."""
        user = self.users.get(user_id)
        if user:
            user.custom_permissions.add(permission)
            return True
        return False

    def revoke_permission(self, user_id: str, permission: Permission) -> bool:
        """Revoke custom permission from user."""
        user = self.users.get(user_id)
        if user:
            user.custom_permissions.discard(permission)
            return True
        return False

    def create_organization(self, name: str, description: str = "") -> Organization:
        """Create a new organization."""
        org = Organization(name=name, description=description)
        self.organizations[org.id] = org
        return org

    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID."""
        return self.organizations.get(org_id)

    def add_user_to_org(self, user_id: str, org_id: str) -> bool:
        """Add user to organization."""
        user = self.users.get(user_id)
        org = self.organizations.get(org_id)

        if user and org and org_id not in user.organizations:
            user.organizations.append(org_id)
            return True
        return False

    def remove_user_from_org(self, user_id: str, org_id: str) -> bool:
        """Remove user from organization."""
        user = self.users.get(user_id)

        if user and org_id in user.organizations:
            user.organizations.remove(org_id)
            return True
        return False

    def check_access(
        self, user_id: str, permission: Permission, org_id: Optional[str] = None
    ) -> bool:
        """
        Check if user has permission.

        Args:
            user_id: User ID
            permission: Required permission
            org_id: Optional organization ID for multi-tenant check

        Returns:
            True if user has permission
        """
        user = self.users.get(user_id)
        if not user or not user.is_active:
            return False

        # Check organization membership if required
        if org_id and org_id not in user.organizations:
            return False

        return user.has_permission(permission)

    def get_user_environments(self, user_id: str) -> List[str]:
        """Get all environment IDs accessible to user."""
        user = self.users.get(user_id)
        if not user:
            return []

        environment_ids = []
        for org_id in user.organizations:
            org = self.organizations.get(org_id)
            if org and org.is_active:
                environment_ids.extend(org.environment_ids)

        return environment_ids

    def audit_log(
        self, user_id: str, action: str, resource_type: str, resource_id: str
    ) -> Dict[str, Any]:
        """Log user action for audit trail."""
        user = self.users.get(user_id)

        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "username": user.username if user else "unknown",
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
        }

        # In production, persist to database or logging system
        return log_entry

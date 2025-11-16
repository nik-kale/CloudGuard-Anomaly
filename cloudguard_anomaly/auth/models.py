"""
Authentication and user models for CloudGuard-Anomaly.

Provides user management, authentication, and session handling.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
from dataclasses import dataclass, field

from sqlalchemy import Column, String, DateTime, Boolean, Table, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from cloudguard_anomaly.storage.database import Base

# Association table for many-to-many relationship between users and roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', String, ForeignKey('users.id')),
    Column('role_id', String, ForeignKey('roles.id'))
)


class User(Base):
    """User model for authentication."""

    __tablename__ = 'users'

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    api_key_hash = Column(String, unique=True, nullable=True, index=True)  # Hashed API key
    api_key_prefix = Column(String, nullable=True)  # First 8 chars for identification
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"

    def set_password(self, password: str):
        """Hash and set user password."""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        self.password_hash = f"{salt}${password_hash.hex()}"

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        try:
            salt, stored_hash = self.password_hash.split('$')
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return password_hash.hex() == stored_hash
        except (ValueError, AttributeError):
            return False

    def generate_api_key(self) -> str:
        """
        Generate new API key for user.

        Returns the plaintext API key (only shown once).
        Stores hashed version in database.
        """
        # Generate secure random API key
        api_key = f"cgak_{secrets.token_urlsafe(32)}"

        # Store prefix for identification (first 8 chars)
        self.api_key_prefix = api_key[:8]

        # Hash the API key before storing
        salt = secrets.token_hex(16)
        key_hash = hashlib.pbkdf2_hmac(
            'sha256',
            api_key.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        self.api_key_hash = f"{salt}${key_hash.hex()}"

        # Return plaintext key (only shown once)
        return api_key

    def verify_api_key(self, api_key: str) -> bool:
        """
        Verify an API key against stored hash.

        Args:
            api_key: Plaintext API key to verify

        Returns:
            True if API key matches, False otherwise
        """
        if not self.api_key_hash:
            return False

        try:
            salt, stored_hash = self.api_key_hash.split('$')
            key_hash = hashlib.pbkdf2_hmac(
                'sha256',
                api_key.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return key_hash.hex() == stored_hash
        except (ValueError, AttributeError):
            return False

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role."""
        return any(role.name == role_name for role in self.roles)

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        for role in self.roles:
            if permission in role.permissions:
                return True
        return False


class Role(Base):
    """Role model for RBAC."""

    __tablename__ = 'roles'

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(String, nullable=True)
    permissions = Column(String, nullable=False, default='')  # JSON or comma-separated
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')

    def __repr__(self):
        return f"<Role(name='{self.name}')>"

    def add_permission(self, permission: str):
        """Add permission to role."""
        perms = set(self.permissions.split(',')) if self.permissions else set()
        perms.add(permission)
        self.permissions = ','.join(sorted(perms))

    def remove_permission(self, permission: str):
        """Remove permission from role."""
        perms = set(self.permissions.split(',')) if self.permissions else set()
        perms.discard(permission)
        self.permissions = ','.join(sorted(perms))

    def get_permissions(self) -> List[str]:
        """Get list of permissions."""
        return [p for p in self.permissions.split(',') if p]


class Session(Base):
    """User session model."""

    __tablename__ = 'sessions'

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey('users.id'), nullable=False, index=True)
    token = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    # Relationships
    user = relationship('User', back_populates='sessions')

    def __repr__(self):
        return f"<Session(user_id='{self.user_id}', expires={self.expires_at})>"

    @classmethod
    def create_session(cls, user_id: str, ttl_hours: int = 24) -> 'Session':
        """Create new session for user."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)

        return cls(
            user_id=user_id,
            token=token,
            expires_at=expires_at
        )

    def is_valid(self) -> bool:
        """Check if session is still valid."""
        return datetime.utcnow() < self.expires_at

    def extend(self, hours: int = 24):
        """Extend session expiration."""
        self.expires_at = datetime.utcnow() + timedelta(hours=hours)


# Permission constants
class Permission:
    """Standard permissions for CloudGuard-Anomaly."""

    # Scan permissions
    SCAN_VIEW = 'scan:view'
    SCAN_RUN = 'scan:run'
    SCAN_DELETE = 'scan:delete'

    # Finding permissions
    FINDING_VIEW = 'finding:view'
    FINDING_RESOLVE = 'finding:resolve'
    FINDING_DELETE = 'finding:delete'

    # Compliance permissions
    COMPLIANCE_VIEW = 'compliance:view'
    COMPLIANCE_RUN = 'compliance:run'

    # Policy permissions
    POLICY_VIEW = 'policy:view'
    POLICY_CREATE = 'policy:create'
    POLICY_UPDATE = 'policy:update'
    POLICY_DELETE = 'policy:delete'

    # User management
    USER_VIEW = 'user:view'
    USER_CREATE = 'user:create'
    USER_UPDATE = 'user:update'
    USER_DELETE = 'user:delete'

    # Role management
    ROLE_VIEW = 'role:view'
    ROLE_CREATE = 'role:create'
    ROLE_UPDATE = 'role:update'
    ROLE_DELETE = 'role:delete'

    # Admin
    ADMIN_ALL = 'admin:*'


# Default roles
DEFAULT_ROLES = {
    'admin': {
        'description': 'Full system access',
        'permissions': [Permission.ADMIN_ALL]
    },
    'security_analyst': {
        'description': 'Can view and resolve findings',
        'permissions': [
            Permission.SCAN_VIEW,
            Permission.SCAN_RUN,
            Permission.FINDING_VIEW,
            Permission.FINDING_RESOLVE,
            Permission.COMPLIANCE_VIEW,
            Permission.POLICY_VIEW,
        ]
    },
    'auditor': {
        'description': 'Read-only access to scans and findings',
        'permissions': [
            Permission.SCAN_VIEW,
            Permission.FINDING_VIEW,
            Permission.COMPLIANCE_VIEW,
            Permission.POLICY_VIEW,
        ]
    },
    'viewer': {
        'description': 'Read-only dashboard access',
        'permissions': [
            Permission.SCAN_VIEW,
            Permission.FINDING_VIEW,
        ]
    }
}

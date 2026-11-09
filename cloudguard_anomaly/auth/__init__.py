"""
Authentication and authorization for CloudGuard-Anomaly.

Provides user management, session handling, and RBAC.
"""

import logging
from datetime import datetime

from cloudguard_anomaly.auth.models import (
    DEFAULT_ROLES,
    Role,
    Session,
    User,
    burn_password_hash,
)
from cloudguard_anomaly.auth.password import PasswordValidationError, validate_password_strength
from cloudguard_anomaly.storage.database import DatabaseStorage, get_database

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """
    Manages user authentication and authorization.

    Handles login, logout, session management, and RBAC.
    """

    def __init__(self, database: DatabaseStorage):
        """
        Initialize authentication manager.

        Args:
            database: Database storage instance
        """
        self.database = database
        logger.info("Authentication manager initialized")

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: list[str] | None = None,
        is_admin: bool = False,
    ) -> User:
        """
        Create new user.

        Args:
            username: Username
            email: Email address
            password: Password (will be hashed)
            roles: List of role names
            is_admin: Admin flag

        Returns:
            Created user

        Raises:
            ValueError: If user already exists
            PasswordValidationError: If password doesn't meet complexity requirements
        """
        session = self.database.get_session()

        try:
            # Validate password strength
            try:
                validate_password_strength(password, username=username)
            except PasswordValidationError as e:
                raise ValueError(f"Password validation failed: {e}")

            # Check if user exists
            existing = (
                session.query(User)
                .filter((User.username == username) | (User.email == email))
                .first()
            )

            if existing:
                raise ValueError(
                    f"User with username '{username}' or email '{email}' already exists"
                )

            # Create user
            user = User(username=username, email=email, is_admin=is_admin)
            user.set_password(password)
            user.generate_api_key()

            # Assign roles
            if roles:
                for role_name in roles:
                    role = session.query(Role).filter(Role.name == role_name).first()
                    if role:
                        user.roles.append(role)
                    else:
                        logger.warning(f"Role '{role_name}' not found")

            session.add(user)
            session.commit()
            session.refresh(user)

            logger.info(f"Created user: {username}")
            return user

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create user: {e}")
            raise
        finally:
            session.close()

    def authenticate(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User | None:
        """
        Authenticate user with username and password.

        Args:
            username: Username or email
            password: Password
            ip_address: Client address, recorded in the audit log
            user_agent: Client user agent, recorded in the audit log

        Returns:
            User if authentication successful, None otherwise
        """
        session = self.database.get_session()

        try:
            user = (
                session.query(User)
                .filter((User.username == username) | (User.email == username))
                .first()
            )

            failure = None
            if not user:
                burn_password_hash(password)
                failure = "unknown user"
            elif not user.check_password(password):
                failure = "invalid password"
            elif not user.is_active:
                failure = "inactive user"

            if failure is None:
                user.last_login = datetime.utcnow()
                session.commit()

            self.database.log_audit_event(
                action="login",
                resource_type="session",
                user_id=user.id if user else None,
                username=username[:128],
                status="failure" if failure else "success",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": failure} if failure else None,
            )

            if failure:
                logger.warning(f"Authentication failed for {username[:128]!r}: {failure}")
                return None

            logger.info(f"User authenticated: {username}")
            return user

        finally:
            session.close()

    def authenticate_api_key(self, api_key: str) -> User | None:
        """
        Authenticate using API key.

        Args:
            api_key: API key

        Returns:
            User if valid, None otherwise
        """
        session = self.database.get_session()

        try:
            # Get prefix for faster lookup
            prefix = api_key[:8] if len(api_key) >= 8 else api_key

            # Find user by prefix (narrows down candidates)
            users = session.query(User).filter(User.api_key_prefix == prefix).all()

            # Verify against each candidate
            for user in users:
                if user.verify_api_key(api_key):
                    if not user.is_active:
                        logger.warning(f"Authentication failed: user '{user.username}' is inactive")
                        return None

                    logger.info(f"API key authenticated: {user.username}")
                    return user

            logger.warning("Authentication failed: invalid API key")
            return None

        finally:
            session.close()

    def create_session(self, user_id: str, ttl_hours: int = 24) -> Session:
        """
        Create new session for user.

        Args:
            user_id: User ID
            ttl_hours: Session TTL in hours

        Returns:
            Created session
        """
        db_session = self.database.get_session()

        try:
            session = Session.create_session(user_id, ttl_hours)
            db_session.add(session)
            db_session.commit()

            logger.info(f"Created session for user {user_id}")
            return session

        except Exception as e:
            db_session.rollback()
            logger.error(f"Failed to create session: {e}")
            raise
        finally:
            db_session.close()

    def validate_session(self, token: str) -> User | None:
        """
        Validate session token and return user.

        Args:
            token: Session token

        Returns:
            User if session valid, None otherwise
        """
        db_session = self.database.get_session()

        try:
            session = db_session.query(Session).filter(Session.token == token).first()

            if not session:
                return None

            if not session.is_valid():
                # Session expired
                db_session.delete(session)
                db_session.commit()
                return None

            # Get user
            user = db_session.query(User).filter(User.id == session.user_id).first()

            if not user or not user.is_active:
                return None

            # Extend session
            session.extend()
            db_session.commit()

            return user

        finally:
            db_session.close()

    def logout(self, token: str):
        """
        Logout user by deleting session.

        Args:
            token: Session token
        """
        db_session = self.database.get_session()

        try:
            session = db_session.query(Session).filter(Session.token == token).first()

            if session:
                db_session.delete(session)
                db_session.commit()
                logger.info(f"User logged out: {session.user_id}")

        except Exception as e:
            db_session.rollback()
            logger.error(f"Failed to logout: {e}")
        finally:
            db_session.close()

    def create_default_roles(self):
        """Create default roles if they don't exist."""
        db_session = self.database.get_session()

        try:
            for role_name, role_data in DEFAULT_ROLES.items():
                existing = db_session.query(Role).filter(Role.name == role_name).first()

                if not existing:
                    role = Role(
                        name=role_name,
                        description=role_data["description"],
                        permissions=",".join(role_data["permissions"]),
                    )
                    db_session.add(role)
                    logger.info(f"Created default role: {role_name}")

            db_session.commit()

        except Exception as e:
            db_session.rollback()
            logger.error(f"Failed to create default roles: {e}")
            raise
        finally:
            db_session.close()

    def create_admin_user(self, username: str, email: str, password: str) -> User:
        """
        Create admin user with all permissions.

        Args:
            username: Username
            email: Email
            password: Password

        Returns:
            Created admin user
        """
        return self.create_user(
            username=username, email=email, password=password, roles=["admin"], is_admin=True
        )

    def get_user(self, user_id: str) -> User | None:
        """Get user by ID."""
        session = self.database.get_session()
        try:
            return session.query(User).filter(User.id == user_id).first()
        finally:
            session.close()

    def list_users(self) -> list[User]:
        """List all users."""
        session = self.database.get_session()
        try:
            return session.query(User).all()
        finally:
            session.close()

    def delete_user(self, user_id: str):
        """Delete user."""
        session = self.database.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                session.delete(user)
                session.commit()
                logger.info(f"Deleted user: {user.username}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete user: {e}")
            raise
        finally:
            session.close()


# Global authentication manager instance
_auth_manager: AuthenticationManager | None = None


def get_auth_manager(database: DatabaseStorage | None = None) -> AuthenticationManager:
    """Get the authentication manager bound to ``database`` or the shared handle."""
    global _auth_manager

    database = database or get_database()
    if _auth_manager is None or _auth_manager.database is not database:
        _auth_manager = AuthenticationManager(database)
        _auth_manager.create_default_roles()

    return _auth_manager

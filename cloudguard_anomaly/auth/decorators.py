"""
Flask decorators for authentication and authorization.
"""

import functools
import logging
from typing import Callable, Optional, List

from flask import request, jsonify, session as flask_session, redirect, url_for

from cloudguard_anomaly.auth import get_auth_manager

logger = logging.getLogger(__name__)


def login_required(f: Callable) -> Callable:
    """
    Decorator to require authentication for route.

    Checks session token or API key in headers.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        auth_manager = get_auth_manager()

        # Check session token
        session_token = flask_session.get('token')
        if session_token:
            user = auth_manager.validate_session(session_token)
            if user:
                request.current_user = user
                return f(*args, **kwargs)

        # Check API key in Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            parts = auth_header.split(' ', 1)  # Split only on first space
            if len(parts) == 2 and parts[1].strip():  # Validate token exists and not empty
                api_key = parts[1].strip()
                user = auth_manager.authenticate_api_key(api_key)
                if user:
                    request.current_user = user
                    return f(*args, **kwargs)

        # Check API key in X-API-Key header
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = auth_manager.authenticate_api_key(api_key)
            if user:
                request.current_user = user
                return f(*args, **kwargs)

        # Not authenticated
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        else:
            return redirect(url_for('login'))

    return decorated_function


def permission_required(permission: str) -> Callable:
    """
    Decorator to require specific permission for route.

    Args:
        permission: Permission string (e.g., 'scan:run')
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = getattr(request, 'current_user', None)

            if not user:
                return jsonify({'error': 'Authentication required'}), 401

            # Admin has all permissions
            if user.is_admin:
                return f(*args, **kwargs)

            # Check permission
            if user.has_permission(permission) or user.has_permission('admin:*'):
                return f(*args, **kwargs)

            logger.warning(
                f"Permission denied: {user.username} lacks '{permission}'"
            )

            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': f"Permission required: {permission}"}), 403
            else:
                return "Forbidden: Insufficient permissions", 403

        return decorated_function
    return decorator


def role_required(role_name: str) -> Callable:
    """
    Decorator to require specific role for route.

    Args:
        role_name: Role name (e.g., 'admin', 'security_analyst')
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = getattr(request, 'current_user', None)

            if not user:
                return jsonify({'error': 'Authentication required'}), 401

            # Check role
            if user.has_role(role_name):
                return f(*args, **kwargs)

            logger.warning(
                f"Role check failed: {user.username} lacks role '{role_name}'"
            )

            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': f"Role required: {role_name}"}), 403
            else:
                return "Forbidden: Insufficient role", 403

        return decorated_function
    return decorator


def admin_required(f: Callable) -> Callable:
    """
    Decorator to require admin access for route.
    """
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user = getattr(request, 'current_user', None)

        if not user:
            return jsonify({'error': 'Authentication required'}), 401

        if not user.is_admin:
            logger.warning(
                f"Admin check failed: {user.username} is not admin"
            )

            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access required'}), 403
            else:
                return "Forbidden: Admin access required", 403

        return f(*args, **kwargs)

    return decorated_function


def optional_auth(f: Callable) -> Callable:
    """
    Decorator to optionally authenticate user.

    Does not require authentication but sets current_user if available.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        auth_manager = get_auth_manager()

        # Try session token
        session_token = flask_session.get('token')
        if session_token:
            user = auth_manager.validate_session(session_token)
            if user:
                request.current_user = user
                return f(*args, **kwargs)

        # Try API key
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            parts = auth_header.split(' ', 1)  # Split only on first space
            if len(parts) == 2 and parts[1].strip():  # Validate token exists and not empty
                api_key = parts[1].strip()
                user = auth_manager.authenticate_api_key(api_key)
                if user:
                    request.current_user = user
                    return f(*args, **kwargs)

        # No authentication - continue anyway
        request.current_user = None
        return f(*args, **kwargs)

    return decorated_function

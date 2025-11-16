"""
User management API endpoints.

Provides RESTful CRUD operations for user accounts.
"""

import logging
from typing import Dict, Any

from flask import request, jsonify

from cloudguard_anomaly.api.v1 import api_v1
from cloudguard_anomaly.auth.decorators import login_required, admin_required
from cloudguard_anomaly.auth import get_auth_manager
from cloudguard_anomaly.auth.password import validate_password_strength, PasswordValidationError
from cloudguard_anomaly.api.validation import (
    validate_limit,
    validate_scan_id,
    sanitize_string,
    safe_error_message,
    get_pagination_params,
)

logger = logging.getLogger(__name__)

# Get auth manager
auth_manager = get_auth_manager()


def user_to_dict(user) -> Dict[str, Any]:
    """Convert User model to API response dictionary."""
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'roles': [role.name for role in user.roles] if user.roles else [],
        # Never expose password_hash or api_key in API responses
    }


@api_v1.route('/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    """
    List all users (admin only).

    Returns:
        JSON array of user objects
    """
    try:
        users = auth_manager.list_users()
        result = [user_to_dict(u) for u in users]

        return jsonify({
            'users': result,
            'count': len(result)
        }), 200

    except Exception as e:
        logger.error(f"Error listing users: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to list users')}), 500


@api_v1.route('/users/<user_id>', methods=['GET'])
@login_required
def get_user(user_id: str):
    """
    Get a specific user by ID.

    Users can view their own profile, admins can view any user.

    Args:
        user_id: User UUID

    Returns:
        JSON user object or 404 if not found
    """
    # Validate user ID
    user_id = validate_scan_id(user_id)
    if not user_id:
        return jsonify({'error': 'Invalid user ID'}), 400

    try:
        current_user = getattr(request, 'current_user', None)
        
        # Check permission: user can view self, admin can view anyone
        if current_user.id != user_id and not current_user.is_admin:
            return jsonify({'error': 'Permission denied'}), 403

        user = auth_manager.get_user(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify(user_to_dict(user)), 200

    except Exception as e:
        logger.error(f"Error getting user {user_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve user')}), 500


@api_v1.route('/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    """
    Create a new user (admin only).

    Request Body (JSON):
        {
            "username": "john.doe",
            "email": "john@example.com",
            "password": "SecureP@ss123!",
            "roles": ["viewer"],
            "is_admin": false
        }

    Returns:
        JSON user object with 201 status or error
    """
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'email', 'password']
        missing_fields = [f for f in required_fields if f not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        # Validate and sanitize inputs
        username = sanitize_string(data['username'], max_length=128)
        email = sanitize_string(data['email'], max_length=256)
        password = data['password']  # Don't sanitize password, validate it
        roles = data.get('roles', [])
        is_admin = data.get('is_admin', False)

        if not all([username, email, password]):
            return jsonify({'error': 'Invalid input values'}), 400

        # Validate email format
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Create user (password validation happens in auth manager)
        try:
            user = auth_manager.create_user(
                username=username,
                email=email,
                password=password,
                roles=roles if isinstance(roles, list) else [],
                is_admin=bool(is_admin)
            )
        except ValueError as e:
            # Password validation or duplicate user error
            return jsonify({'error': str(e)}), 400

        current_user = getattr(request, 'current_user', None)
        current_user_id = current_user.id if current_user else 'unknown'
        logger.info(f"User created: {user.id} ({username}) by {current_user_id}")

        return jsonify(user_to_dict(user)), 201

    except Exception as e:
        logger.error(f"Error creating user: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to create user')}), 500


@api_v1.route('/users/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id: str):
    """
    Update an existing user.

    Users can update their own profile (except roles/admin).
    Admins can update any user.

    Args:
        user_id: User UUID

    Request Body (JSON):
        Any subset of: email, password, roles, is_admin, is_active

    Returns:
        JSON updated user object or 404 if not found
    """
    # Validate user ID
    user_id = validate_scan_id(user_id)
    if not user_id:
        return jsonify({'error': 'Invalid user ID'}), 400

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        current_user = getattr(request, 'current_user', None)
        
        # Check permission
        is_self_update = current_user.id == user_id
        is_admin = current_user.is_admin

        if not is_self_update and not is_admin:
            return jsonify({'error': 'Permission denied'}), 403

        data = request.get_json()

        # Get user from database
        from cloudguard_anomaly.storage.database import DatabaseStorage
        from cloudguard_anomaly.config import get_config
        config = get_config()
        db = DatabaseStorage(config.database_url)
        session = db.get_session()

        try:
            from cloudguard_anomaly.auth.models import User
            user = session.query(User).filter(User.id == user_id).first()

            if not user:
                return jsonify({'error': 'User not found'}), 404

            # Update email
            if 'email' in data:
                email = sanitize_string(data['email'], max_length=256)
                if email:
                    import re
                    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                    if not re.match(email_pattern, email):
                        return jsonify({'error': 'Invalid email format'}), 400
                    user.email = email

            # Update password
            if 'password' in data:
                password = data['password']
                try:
                    validate_password_strength(password, username=user.username)
                    user.set_password(password)
                except PasswordValidationError as e:
                    return jsonify({'error': f'Password validation failed: {e}'}), 400

            # Admin-only updates
            if is_admin:
                if 'is_admin' in data:
                    user.is_admin = bool(data['is_admin'])
                
                if 'is_active' in data:
                    user.is_active = bool(data['is_active'])

                if 'roles' in data and isinstance(data['roles'], list):
                    # Update roles
                    from cloudguard_anomaly.auth.models import Role
                    user.roles.clear()
                    for role_name in data['roles']:
                        role = session.query(Role).filter(Role.name == role_name).first()
                        if role:
                            user.roles.append(role)

            session.commit()
            logger.info(f"User updated: {user_id} by {current_user.id}")

            result = user_to_dict(user)

            return jsonify(result), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to update user')}), 500


@api_v1.route('/users/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id: str):
    """
    Delete a user (admin only).

    Args:
        user_id: User UUID

    Returns:
        204 No Content on success or 404 if not found
    """
    # Validate user ID
    user_id = validate_scan_id(user_id)
    if not user_id:
        return jsonify({'error': 'Invalid user ID'}), 400

    try:
        current_user = getattr(request, 'current_user', None)
        
        # Prevent self-deletion
        if current_user.id == user_id:
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Check if user exists
        user = auth_manager.get_user(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Delete user
        auth_manager.delete_user(user_id)

        logger.info(f"User deleted: {user_id} by {current_user.id}")

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to delete user')}), 500


@api_v1.route('/users/<user_id>/regenerate-api-key', methods=['POST'])
@login_required
def regenerate_api_key(user_id: str):
    """
    Regenerate API key for a user.

    Users can regenerate their own key, admins can regenerate any key.

    Args:
        user_id: User UUID

    Returns:
        JSON with new API key
    """
    # Validate user ID
    user_id = validate_scan_id(user_id)
    if not user_id:
        return jsonify({'error': 'Invalid user ID'}), 400

    try:
        current_user = getattr(request, 'current_user', None)
        
        # Check permission
        if current_user.id != user_id and not current_user.is_admin:
            return jsonify({'error': 'Permission denied'}), 403

        # Get user and regenerate API key
        from cloudguard_anomaly.storage.database import DatabaseStorage
        from cloudguard_anomaly.config import get_config
        config = get_config()
        db = DatabaseStorage(config.database_url)
        session = db.get_session()

        try:
            from cloudguard_anomaly.auth.models import User
            user = session.query(User).filter(User.id == user_id).first()

            if not user:
                return jsonify({'error': 'User not found'}), 404

            # Generate new API key
            user.generate_api_key()
            session.commit()

            logger.info(f"API key regenerated for user: {user_id} by {current_user.id}")

            return jsonify({
                'api_key': user.api_key,
                'message': 'API key regenerated successfully. Store it securely - it will not be shown again.'
            }), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error regenerating API key for user {user_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to regenerate API key')}), 500

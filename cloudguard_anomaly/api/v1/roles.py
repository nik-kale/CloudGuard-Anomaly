"""
Role management API endpoints.

Provides RESTful CRUD operations for user roles and permissions.
"""

import logging
from typing import Dict, Any

from flask import request, jsonify

from cloudguard_anomaly.api.v1 import api_v1
from cloudguard_anomaly.auth.decorators import login_required, admin_required
from cloudguard_anomaly.api.validation import (
    validate_scan_id,
    sanitize_string,
    safe_error_message,
)
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.config import get_config

logger = logging.getLogger(__name__)

# Initialize database
config = get_config()
db = DatabaseStorage(config.database_url)


def role_to_dict(role) -> Dict[str, Any]:
    """Convert Role model to API response dictionary."""
    return {
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'permissions': role.permissions.split(',') if role.permissions else [],
        'created_at': role.created_at.isoformat() if role.created_at else None,
    }


@api_v1.route('/roles', methods=['GET'])
@login_required
@admin_required
def list_roles():
    """
    List all roles (admin only).

    Returns:
        JSON array of role objects
    """
    try:
        session = db.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            roles = session.query(Role).all()
            result = [role_to_dict(r) for r in roles]

            return jsonify({
                'roles': result,
                'count': len(result)
            }), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error listing roles: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to list roles')}), 500


@api_v1.route('/roles/<role_id>', methods=['GET'])
@login_required
@admin_required
def get_role(role_id: str):
    """
    Get a specific role by ID (admin only).

    Args:
        role_id: Role UUID

    Returns:
        JSON role object or 404 if not found
    """
    # Validate role ID
    role_id = validate_scan_id(role_id)
    if not role_id:
        return jsonify({'error': 'Invalid role ID'}), 400

    try:
        session = db.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            role = session.query(Role).filter(Role.id == role_id).first()

            if not role:
                return jsonify({'error': 'Role not found'}), 404

            return jsonify(role_to_dict(role)), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting role {role_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve role')}), 500


@api_v1.route('/roles', methods=['POST'])
@login_required
@admin_required
def create_role():
    """
    Create a new role (admin only).

    Request Body (JSON):
        {
            "name": "custom_analyst",
            "description": "Custom security analyst role",
            "permissions": ["scan:view", "finding:view", "compliance:view"]
        }

    Returns:
        JSON role object with 201 status or error
    """
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['name', 'description', 'permissions']
        missing_fields = [f for f in required_fields if f not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        # Validate and sanitize inputs
        name = sanitize_string(data['name'], max_length=128)
        description = sanitize_string(data['description'], max_length=512)
        permissions = data['permissions'] if isinstance(data['permissions'], list) else []

        if not all([name, description]):
            return jsonify({'error': 'Invalid input values'}), 400

        # Validate role name format (lowercase, underscores only)
        import re
        if not re.match(r'^[a-z_]+$', name):
            return jsonify({'error': 'Role name must be lowercase with underscores only'}), 400

        session = db.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role, Permission
            import uuid

            # Check if role already exists
            existing = session.query(Role).filter(Role.name == name).first()
            if existing:
                return jsonify({'error': f'Role with name "{name}" already exists'}), 400

            # Validate permissions
            valid_permissions = {p for p in dir(Permission) if not p.startswith('_')}
            permission_values = [getattr(Permission, p) for p in dir(Permission) if not p.startswith('_') and isinstance(getattr(Permission, p), str)]
            
            for perm in permissions:
                if perm not in permission_values:
                    return jsonify({'error': f'Invalid permission: {perm}'}), 400

            # Create role
            role = Role(
                id=str(uuid.uuid4()),
                name=name,
                description=description,
                permissions=','.join(permissions)
            )

            session.add(role)
            session.commit()

            current_user = getattr(request, 'current_user', None)
            current_user_id = current_user.id if current_user else 'unknown'
            logger.info(f"Role created: {role.id} ({name}) by {current_user_id}")

            return jsonify(role_to_dict(role)), 201

        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error creating role: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to create role')}), 500


@api_v1.route('/roles/<role_id>', methods=['PUT'])
@login_required
@admin_required
def update_role(role_id: str):
    """
    Update an existing role (admin only).

    Args:
        role_id: Role UUID

    Request Body (JSON):
        Any subset of: description, permissions

    Returns:
        JSON updated role object or 404 if not found
    """
    # Validate role ID
    role_id = validate_scan_id(role_id)
    if not role_id:
        return jsonify({'error': 'Invalid role ID'}), 400

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()

        session = db.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role, Permission
            role = session.query(Role).filter(Role.id == role_id).first()

            if not role:
                return jsonify({'error': 'Role not found'}), 404

            # Update description
            if 'description' in data:
                description = sanitize_string(data['description'], max_length=512)
                if description:
                    role.description = description

            # Update permissions
            if 'permissions' in data:
                permissions = data['permissions'] if isinstance(data['permissions'], list) else []
                
                # Validate permissions
                permission_values = [getattr(Permission, p) for p in dir(Permission) if not p.startswith('_') and isinstance(getattr(Permission, p), str)]
                
                for perm in permissions:
                    if perm not in permission_values:
                        return jsonify({'error': f'Invalid permission: {perm}'}), 400

                role.permissions = ','.join(permissions)

            session.commit()

            current_user = getattr(request, 'current_user', None)
            current_user_id = current_user.id if current_user else 'unknown'
            logger.info(f"Role updated: {role_id} by {current_user_id}")

            return jsonify(role_to_dict(role)), 200

        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error updating role {role_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to update role')}), 500


@api_v1.route('/roles/<role_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_role(role_id: str):
    """
    Delete a role (admin only).

    Cannot delete default roles (admin, security_analyst, viewer, auditor).

    Args:
        role_id: Role UUID

    Returns:
        204 No Content on success or 404 if not found
    """
    # Validate role ID
    role_id = validate_scan_id(role_id)
    if not role_id:
        return jsonify({'error': 'Invalid role ID'}), 400

    try:
        session = db.get_session()
        try:
            from cloudguard_anomaly.auth.models import Role
            role = session.query(Role).filter(Role.id == role_id).first()

            if not role:
                return jsonify({'error': 'Role not found'}), 404

            # Prevent deletion of default roles
            default_roles = ['admin', 'security_analyst', 'viewer', 'auditor']
            if role.name in default_roles:
                return jsonify({'error': f'Cannot delete default role: {role.name}'}), 400

            session.delete(role)
            session.commit()

            current_user = getattr(request, 'current_user', None)
            current_user_id = current_user.id if current_user else 'unknown'
            logger.info(f"Role deleted: {role_id} ({role.name}) by {current_user_id}")

            return '', 204

        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error deleting role {role_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to delete role')}), 500


@api_v1.route('/roles/permissions', methods=['GET'])
@login_required
@admin_required
def list_permissions():
    """
    List all available permissions (admin only).

    Returns:
        JSON array of permission strings
    """
    try:
        from cloudguard_anomaly.auth.models import Permission
        
        # Get all permission constants
        permissions = [
            getattr(Permission, p) 
            for p in dir(Permission) 
            if not p.startswith('_') and isinstance(getattr(Permission, p), str)
        ]

        return jsonify({
            'permissions': sorted(permissions),
            'count': len(permissions)
        }), 200

    except Exception as e:
        logger.error(f"Error listing permissions: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to list permissions')}), 500

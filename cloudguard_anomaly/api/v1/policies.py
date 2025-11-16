"""
Policy management API endpoints.

Provides RESTful CRUD operations for security policies.
"""

import logging
from typing import Dict, Any, List

from flask import request, jsonify

from cloudguard_anomaly.api.v1 import api_v1
from cloudguard_anomaly.auth.decorators import login_required, permission_required
from cloudguard_anomaly.auth.models import Permission
from cloudguard_anomaly.api.validation import (
    validate_severity,
    validate_limit,
    validate_provider,
    validate_scan_id,
    sanitize_string,
    safe_error_message,
    get_pagination_params,
)
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.config import get_config

logger = logging.getLogger(__name__)

# Initialize database
config = get_config()
db = DatabaseStorage(config.database_url)


def policy_record_to_dict(policy) -> Dict[str, Any]:
    """Convert PolicyRecord to API response dictionary."""
    data = policy.data or {}
    return {
        'id': policy.id,
        'name': policy.name,
        'description': policy.description,
        'severity': policy.severity,
        'provider': policy.provider,
        'enabled': policy.enabled,
        'resource_types': data.get('resource_types', []),
        'condition': data.get('condition', {}),
        'remediation': data.get('remediation', ''),
        'references': data.get('references', []),
        'created_at': policy.created_at.isoformat() if policy.created_at else None,
        'updated_at': policy.updated_at.isoformat() if policy.updated_at else None,
        'created_by': policy.created_by
    }


@api_v1.route('/policies', methods=['GET'])
@login_required
@permission_required(Permission.POLICY_VIEW)
def list_policies():
    """
    List all policies with optional filtering.

    Query Parameters:
        - provider: Filter by cloud provider
        - severity: Filter by severity level
        - enabled: Filter by enabled status (true/false)
        - limit: Maximum number of results (default: 100, max: 1000)
        - offset: Number of results to skip (default: 0)

    Returns:
        JSON array of policy objects
    """
    try:
        # Validate and extract query parameters
        provider = validate_provider(request.args.get('provider'))
        severity = validate_severity(request.args.get('severity'))
        enabled_param = request.args.get('enabled', '').lower()
        enabled_only = enabled_param == 'true' if enabled_param else False
        limit, offset = get_pagination_params(request)

        # Get policies from database
        policies = db.list_policies(
            provider=provider,
            severity=severity,
            enabled_only=enabled_only,
            limit=limit,
            offset=offset
        )

        # Convert to API response format
        result = [policy_record_to_dict(p) for p in policies]

        return jsonify({
            'policies': result,
            'count': len(result),
            'limit': limit,
            'offset': offset
        }), 200

    except Exception as e:
        logger.error(f"Error listing policies: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to list policies')}), 500


@api_v1.route('/policies/<policy_id>', methods=['GET'])
@login_required
@permission_required(Permission.POLICY_VIEW)
def get_policy(policy_id: str):
    """
    Get a specific policy by ID.

    Args:
        policy_id: Policy UUID

    Returns:
        JSON policy object or 404 if not found
    """
    # Validate policy ID
    policy_id = validate_scan_id(policy_id)
    if not policy_id:
        return jsonify({'error': 'Invalid policy ID'}), 400

    try:
        policy = db.get_policy(policy_id)

        if not policy:
            return jsonify({'error': 'Policy not found'}), 404

        return jsonify(policy_record_to_dict(policy)), 200

    except Exception as e:
        logger.error(f"Error getting policy {policy_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve policy')}), 500


@api_v1.route('/policies', methods=['POST'])
@login_required
@permission_required(Permission.POLICY_CREATE)
def create_policy():
    """
    Create a new security policy.

    Request Body (JSON):
        {
            "name": "Policy Name",
            "description": "Policy description",
            "severity": "high",
            "provider": "aws",
            "resource_types": ["s3_bucket"],
            "condition": {...},
            "remediation": "How to fix",
            "references": ["CIS 2.1.1"],
            "enabled": true
        }

    Returns:
        JSON policy object with 201 status or error
    """
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['name', 'description', 'severity', 'provider', 'resource_types', 'condition', 'remediation']
        missing_fields = [f for f in required_fields if f not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        # Validate and sanitize inputs
        name = sanitize_string(data['name'], max_length=256)
        description = sanitize_string(data['description'], max_length=1000)
        severity = validate_severity(data['severity'])
        provider = validate_provider(data['provider'])

        if not all([name, description, severity, provider]):
            return jsonify({'error': 'Invalid input values'}), 400

        # Extract optional fields
        resource_types = data['resource_types'] if isinstance(data['resource_types'], list) else []
        condition = data['condition'] if isinstance(data['condition'], dict) else {}
        remediation = sanitize_string(data['remediation'], max_length=2000)
        references = data.get('references', []) if isinstance(data.get('references'), list) else []
        enabled = data.get('enabled', True)

        # Get current user
        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else None

        # Create policy
        policy = db.create_policy(
            name=name,
            description=description,
            severity=severity,
            provider=provider,
            resource_types=resource_types,
            condition=condition,
            remediation=remediation,
            references=references,
            enabled=enabled,
            created_by=user_id
        )

        logger.info(f"Policy created: {policy.id} by user {user_id}")

        return jsonify(policy_record_to_dict(policy)), 201

    except Exception as e:
        logger.error(f"Error creating policy: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to create policy')}), 500


@api_v1.route('/policies/<policy_id>', methods=['PUT'])
@login_required
@permission_required(Permission.POLICY_UPDATE)
def update_policy(policy_id: str):
    """
    Update an existing policy.

    Args:
        policy_id: Policy UUID

    Request Body (JSON):
        Any subset of policy fields to update

    Returns:
        JSON updated policy object or 404 if not found
    """
    # Validate policy ID
    policy_id = validate_scan_id(policy_id)
    if not policy_id:
        return jsonify({'error': 'Invalid policy ID'}), 400

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()

        # Validate and sanitize inputs
        update_args = {}

        if 'name' in data:
            update_args['name'] = sanitize_string(data['name'], max_length=256)
        if 'description' in data:
            update_args['description'] = sanitize_string(data['description'], max_length=1000)
        if 'severity' in data:
            update_args['severity'] = validate_severity(data['severity'])
        if 'provider' in data:
            update_args['provider'] = validate_provider(data['provider'])
        if 'resource_types' in data:
            update_args['resource_types'] = data['resource_types']
        if 'condition' in data:
            update_args['condition'] = data['condition']
        if 'remediation' in data:
            update_args['remediation'] = sanitize_string(data['remediation'], max_length=2000)
        if 'references' in data:
            update_args['references'] = data['references']
        if 'enabled' in data:
            update_args['enabled'] = bool(data['enabled'])

        # Update policy
        policy = db.update_policy(policy_id, **update_args)

        if not policy:
            return jsonify({'error': 'Policy not found'}), 404

        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else 'unknown'
        logger.info(f"Policy updated: {policy_id} by user {user_id}")

        return jsonify(policy_record_to_dict(policy)), 200

    except Exception as e:
        logger.error(f"Error updating policy {policy_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to update policy')}), 500


@api_v1.route('/policies/<policy_id>', methods=['DELETE'])
@login_required
@permission_required(Permission.POLICY_DELETE)
def delete_policy(policy_id: str):
    """
    Delete a policy.

    Args:
        policy_id: Policy UUID

    Returns:
        204 No Content on success or 404 if not found
    """
    # Validate policy ID
    policy_id = validate_scan_id(policy_id)
    if not policy_id:
        return jsonify({'error': 'Invalid policy ID'}), 400

    try:
        deleted = db.delete_policy(policy_id)

        if not deleted:
            return jsonify({'error': 'Policy not found'}), 404

        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else 'unknown'
        logger.info(f"Policy deleted: {policy_id} by user {user_id}")

        return '', 204

    except Exception as e:
        logger.error(f"Error deleting policy {policy_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to delete policy')}), 500

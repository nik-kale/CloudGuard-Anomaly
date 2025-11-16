"""
Audit log API endpoints.

Provides read-only access to audit logs for security monitoring.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from flask import request, jsonify

from cloudguard_anomaly.api.v1 import api_v1
from cloudguard_anomaly.auth.decorators import login_required, permission_required
from cloudguard_anomaly.auth.models import Permission
from cloudguard_anomaly.api.validation import (
    validate_limit,
    validate_scan_id,
    safe_error_message,
    get_pagination_params,
)
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.config import get_config

logger = logging.getLogger(__name__)

# Initialize database
config = get_config()
db = DatabaseStorage(config.database_url)


def audit_log_to_dict(log) -> Dict[str, Any]:
    """Convert AuditLog to API response dictionary."""
    return {
        'id': log.id,
        'timestamp': log.timestamp.isoformat() if log.timestamp else None,
        'user_id': log.user_id,
        'username': log.username,
        'action': log.action,
        'resource_type': log.resource_type,
        'resource_id': log.resource_id,
        'status': log.status,
        'ip_address': log.ip_address,
        'user_agent': log.user_agent,
        'details': log.details or {}
    }


@api_v1.route('/audit-logs', methods=['GET'])
@login_required
@permission_required(Permission.AUDIT_VIEW)
def list_audit_logs():
    """
    List audit logs with filtering (requires audit:view permission).

    Query Parameters:
        - user_id: Filter by user ID
        - action: Filter by action (create, update, delete, login, etc.)
        - resource_type: Filter by resource type (user, role, policy, etc.)
        - resource_id: Filter by specific resource ID
        - status: Filter by status (success, failure, error)
        - start_time: Filter logs after this time (ISO format)
        - end_time: Filter logs before this time (ISO format)
        - days: Alternative to start_time - logs from last N days
        - limit: Maximum number of results (default: 100, max: 1000)
        - offset: Number of results to skip (default: 0)

    Returns:
        JSON array of audit log objects
    """
    try:
        # Extract query parameters
        user_id = request.args.get('user_id')
        action = request.args.get('action')
        resource_type = request.args.get('resource_type')
        resource_id = request.args.get('resource_id')
        status = request.args.get('status')
        
        # Parse time filters
        start_time = None
        end_time = None
        
        if request.args.get('days'):
            try:
                days = int(request.args.get('days'))
                if days > 0 and days <= 365:
                    start_time = datetime.utcnow() - timedelta(days=days)
            except ValueError:
                pass
        
        if request.args.get('start_time'):
            try:
                start_time = datetime.fromisoformat(request.args.get('start_time'))
            except ValueError:
                return jsonify({'error': 'Invalid start_time format. Use ISO format.'}), 400
        
        if request.args.get('end_time'):
            try:
                end_time = datetime.fromisoformat(request.args.get('end_time'))
            except ValueError:
                return jsonify({'error': 'Invalid end_time format. Use ISO format.'}), 400

        limit, offset = get_pagination_params(request)

        # Get audit logs from database
        logs = db.get_audit_logs(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset
        )

        # Convert to API response format
        result = [audit_log_to_dict(log) for log in logs]

        return jsonify({
            'audit_logs': result,
            'count': len(result),
            'limit': limit,
            'offset': offset
        }), 200

    except Exception as e:
        logger.error(f"Error listing audit logs: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to list audit logs')}), 500


@api_v1.route('/audit-logs/<log_id>', methods=['GET'])
@login_required
@permission_required(Permission.AUDIT_VIEW)
def get_audit_log(log_id: str):
    """
    Get a specific audit log by ID (requires audit:view permission).

    Args:
        log_id: Audit log UUID

    Returns:
        JSON audit log object or 404 if not found
    """
    # Validate log ID
    log_id = validate_scan_id(log_id)
    if not log_id:
        return jsonify({'error': 'Invalid audit log ID'}), 400

    try:
        session = db.get_session()
        try:
            from cloudguard_anomaly.storage.database import AuditLog
            log = session.query(AuditLog).filter(AuditLog.id == log_id).first()

            if not log:
                return jsonify({'error': 'Audit log not found'}), 404

            return jsonify(audit_log_to_dict(log)), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting audit log {log_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve audit log')}), 500


@api_v1.route('/audit-logs/user/<user_id>', methods=['GET'])
@login_required
def get_user_activity(user_id: str):
    """
    Get activity logs for a specific user.

    Users can view their own activity, admins can view any user's activity.

    Args:
        user_id: User UUID

    Query Parameters:
        - days: Number of days to look back (default: 30, max: 365)

    Returns:
        JSON array of audit log objects
    """
    # Validate user ID
    user_id = validate_scan_id(user_id)
    if not user_id:
        return jsonify({'error': 'Invalid user ID'}), 400

    try:
        current_user = getattr(request, 'current_user', None)
        
        # Check permission: user can view own activity, admin can view anyone's
        if current_user.id != user_id and not current_user.is_admin:
            return jsonify({'error': 'Permission denied'}), 403

        # Parse days parameter
        days = 30  # default
        if request.args.get('days'):
            try:
                days = int(request.args.get('days'))
                if days < 1 or days > 365:
                    days = 30
            except ValueError:
                days = 30

        # Get user activity
        logs = db.get_user_activity(user_id=user_id, days=days)

        # Convert to API response format
        result = [audit_log_to_dict(log) for log in logs]

        return jsonify({
            'user_id': user_id,
            'days': days,
            'audit_logs': result,
            'count': len(result)
        }), 200

    except Exception as e:
        logger.error(f"Error getting user activity for {user_id}: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve user activity')}), 500


@api_v1.route('/audit-logs/stats', methods=['GET'])
@login_required
@permission_required(Permission.AUDIT_VIEW)
def get_audit_stats():
    """
    Get audit log statistics (requires audit:view permission).

    Query Parameters:
        - days: Number of days to analyze (default: 30, max: 365)

    Returns:
        JSON statistics object
    """
    try:
        # Parse days parameter
        days = 30  # default
        if request.args.get('days'):
            try:
                days = int(request.args.get('days'))
                if days < 1 or days > 365:
                    days = 30
            except ValueError:
                days = 30

        start_time = datetime.utcnow() - timedelta(days=days)

        session = db.get_session()
        try:
            from cloudguard_anomaly.storage.database import AuditLog
            from sqlalchemy import func

            # Total events
            total_events = session.query(func.count(AuditLog.id)).filter(
                AuditLog.timestamp >= start_time
            ).scalar()

            # Events by action
            by_action = session.query(
                AuditLog.action,
                func.count(AuditLog.id).label('count')
            ).filter(
                AuditLog.timestamp >= start_time
            ).group_by(AuditLog.action).all()

            # Events by status
            by_status = session.query(
                AuditLog.status,
                func.count(AuditLog.id).label('count')
            ).filter(
                AuditLog.timestamp >= start_time
            ).group_by(AuditLog.status).all()

            # Events by resource type
            by_resource_type = session.query(
                AuditLog.resource_type,
                func.count(AuditLog.id).label('count')
            ).filter(
                AuditLog.timestamp >= start_time
            ).group_by(AuditLog.resource_type).all()

            # Most active users
            by_user = session.query(
                AuditLog.user_id,
                AuditLog.username,
                func.count(AuditLog.id).label('count')
            ).filter(
                AuditLog.timestamp >= start_time
            ).group_by(AuditLog.user_id, AuditLog.username).order_by(
                func.count(AuditLog.id).desc()
            ).limit(10).all()

            return jsonify({
                'period_days': days,
                'start_time': start_time.isoformat(),
                'total_events': total_events,
                'by_action': {action: count for action, count in by_action},
                'by_status': {status: count for status, count in by_status},
                'by_resource_type': {rt: count for rt, count in by_resource_type if rt},
                'top_users': [
                    {'user_id': uid, 'username': uname, 'event_count': count}
                    for uid, uname, count in by_user if uid
                ]
            }), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting audit stats: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve audit statistics')}), 500

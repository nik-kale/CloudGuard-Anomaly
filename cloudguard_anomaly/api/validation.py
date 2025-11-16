"""
Input validation utilities for CloudGuard-Anomaly API.

Provides request validation, sanitization, and security checks.
"""

import re
from typing import Optional, List, Any, Dict
from enum import Enum

from flask import request, jsonify
from functools import wraps


class ValidSeverity(str, Enum):
    """Valid severity levels."""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'


class ValidStatus(str, Enum):
    """Valid finding status."""
    OPEN = 'open'
    RESOLVED = 'resolved'
    ALL = 'all'


class ValidFramework(str, Enum):
    """Valid compliance frameworks."""
    SOC2 = 'soc2'
    PCI_DSS = 'pci-dss'
    HIPAA = 'hipaa'
    GDPR = 'gdpr'
    ISO27001 = 'iso27001'
    NIST = 'nist'


def validate_severity(severity: Optional[str]) -> Optional[str]:
    """Validate severity parameter."""
    if severity is None:
        return None

    severity = severity.lower().strip()

    try:
        ValidSeverity(severity)
        return severity
    except ValueError:
        return None


def validate_status(status: Optional[str]) -> Optional[str]:
    """Validate status parameter."""
    if status is None:
        return None

    status = status.lower().strip()

    try:
        ValidStatus(status)
        return status
    except ValueError:
        return None


def validate_framework(framework: Optional[str]) -> Optional[str]:
    """Validate framework parameter."""
    if framework is None:
        return None

    framework = framework.lower().strip()

    try:
        ValidFramework(framework)
        return framework
    except ValueError:
        return None


def validate_limit(limit: Optional[int], max_limit: int = 1000) -> int:
    """Validate and cap limit parameter."""
    if limit is None:
        return 100  # Default

    if not isinstance(limit, int):
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            return 100

    # Cap at max_limit
    if limit < 1:
        return 1
    if limit > max_limit:
        return max_limit

    return limit


def validate_days(days: Optional[int], max_days: int = 365) -> int:
    """Validate days parameter."""
    if days is None:
        return 30  # Default

    if not isinstance(days, int):
        try:
            days = int(days)
        except (ValueError, TypeError):
            return 30

    if days < 1:
        return 1
    if days > max_days:
        return max_days

    return days


def validate_environment_name(env_name: Optional[str]) -> Optional[str]:
    """Validate environment name (alphanumeric, hyphens, underscores only)."""
    if env_name is None:
        return None

    env_name = env_name.strip()

    # Must be alphanumeric with hyphens/underscores, 1-64 chars
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', env_name):
        return None

    return env_name


def validate_scan_id(scan_id: Optional[str]) -> Optional[str]:
    """Validate scan ID format."""
    if scan_id is None:
        return None

    scan_id = scan_id.strip()

    # UUID or alphanumeric with hyphens, 1-128 chars
    if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', scan_id):
        return None

    return scan_id


def sanitize_string(value: Optional[str], max_length: int = 256) -> Optional[str]:
    """Sanitize string input."""
    if value is None:
        return None

    # Strip whitespace
    value = value.strip()

    # Limit length
    if len(value) > max_length:
        value = value[:max_length]

    # Remove control characters
    value = ''.join(char for char in value if char.isprintable() or char in '\n\r\t')

    return value if value else None


def validate_request_json(required_fields: List[str]):
    """
    Decorator to validate JSON request has required fields.

    Usage:
        @validate_request_json(['username', 'password'])
        def my_endpoint():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400

            data = request.get_json()

            missing_fields = [field for field in required_fields if field not in data]

            if missing_fields:
                return jsonify({
                    'error': 'Missing required fields',
                    'missing': missing_fields
                }), 400

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def safe_error_message(exception: Exception, user_facing: str = 'An error occurred') -> str:
    """
    Generate safe error message that doesn't leak sensitive data.

    Args:
        exception: The exception that occurred
        user_facing: User-facing error message

    Returns:
        Safe error message for client
    """
    # In production, never expose raw exception details
    # Log the actual error internally, return generic message to client
    return user_facing


class PaginationParams:
    """Pagination parameters with cursor support."""

    def __init__(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[str] = None
    ):
        self.limit = validate_limit(limit, max_limit=1000)
        self.offset = max(0, offset or 0)
        self.cursor = cursor  # For future cursor-based pagination

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'limit': self.limit,
            'offset': self.offset,
            'cursor': self.cursor
        }


def get_pagination_params() -> PaginationParams:
    """Extract and validate pagination parameters from request."""
    limit = request.args.get('limit', type=int)
    offset = request.args.get('offset', type=int, default=0)
    cursor = request.args.get('cursor')

    return PaginationParams(limit=limit, offset=offset, cursor=cursor)

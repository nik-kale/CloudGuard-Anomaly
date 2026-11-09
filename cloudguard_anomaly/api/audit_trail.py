"""Audit-log helper shared by the API routes."""

from typing import Any

from flask import request

from cloudguard_anomaly.storage.database import get_database


def record_audit_event(
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    status: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    """Record an API action against the authenticated caller of the current request."""
    user = getattr(request, "current_user", None)
    get_database().log_audit_event(
        action=action,
        resource_type=resource_type,
        user_id=user.id if user else None,
        username=user.username if user else None,
        resource_id=resource_id,
        status=status,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string or None,
        details=details,
    )

"""
CloudGuard-Anomaly API v1.

Complete REST API with authentication, RBAC, and full CRUD operations.
"""

from flask import Blueprint

# Create API v1 blueprint
api_v1_blueprint = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# Import all route modules to register them
from cloudguard_anomaly.api.v1 import (
    scans,
    findings,
    policies,
    users,
    roles,
    audit,
    compliance,
    health
)

__all__ = ['api_v1_blueprint']

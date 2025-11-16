"""
CloudGuard-Anomaly API v1.

RESTful API endpoints for CloudGuard-Anomaly.
"""

from flask import Blueprint

# Create v1 blueprint
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# Import routes to register them with the blueprint
from cloudguard_anomaly.api.v1 import policies, users, roles, audit

__all__ = ['api_v1']

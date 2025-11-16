"""
CloudGuard-Anomaly REST API.

Provides versioned REST API for all CloudGuard functionality.
"""

from cloudguard_anomaly.api.validation import *
from cloudguard_anomaly.api.v1 import api_v1_blueprint

__all__ = ['api_v1_blueprint']

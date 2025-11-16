"""
Prometheus metrics for CloudGuard-Anomaly.

Provides application-level metrics for monitoring and alerting.
"""

import time
import functools
from typing import Callable, Optional
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Info,
    generate_latest,
    REGISTRY,
    CONTENT_TYPE_LATEST
)


# Application info
app_info = Info('cloudguard_anomaly_app', 'CloudGuard-Anomaly application information')
app_info.info({
    'version': '3.0',
    'service': 'cloudguard-anomaly'
})

# HTTP request metrics
http_requests_total = Counter(
    'cloudguard_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'cloudguard_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
)

http_requests_in_progress = Gauge(
    'cloudguard_http_requests_in_progress',
    'HTTP requests currently being processed',
    ['method', 'endpoint']
)

# Authentication metrics
auth_attempts_total = Counter(
    'cloudguard_auth_attempts_total',
    'Total authentication attempts',
    ['method', 'status']  # method: password/api_key, status: success/failure
)

active_sessions = Gauge(
    'cloudguard_active_sessions',
    'Number of active user sessions'
)

# Scan metrics
scans_total = Counter(
    'cloudguard_scans_total',
    'Total number of scans performed',
    ['provider', 'status']  # status: success/failure/error
)

scan_duration_seconds = Histogram(
    'cloudguard_scan_duration_seconds',
    'Scan duration in seconds',
    ['provider'],
    buckets=[10, 30, 60, 120, 300, 600, 1800, 3600]
)

scans_in_progress = Gauge(
    'cloudguard_scans_in_progress',
    'Number of scans currently running',
    ['provider']
)

# Finding metrics
findings_total = Counter(
    'cloudguard_findings_total',
    'Total number of findings discovered',
    ['severity', 'provider', 'finding_type']
)

findings_open = Gauge(
    'cloudguard_findings_open',
    'Number of open findings',
    ['severity', 'provider']
)

findings_resolved = Counter(
    'cloudguard_findings_resolved_total',
    'Total number of findings resolved',
    ['severity', 'provider']
)

# Anomaly detection metrics
anomalies_detected_total = Counter(
    'cloudguard_anomalies_detected_total',
    'Total number of anomalies detected',
    ['type', 'severity']
)

ml_model_predictions_total = Counter(
    'cloudguard_ml_predictions_total',
    'Total number of ML model predictions',
    ['model', 'result']  # result: anomaly/normal
)

ml_model_accuracy = Gauge(
    'cloudguard_ml_model_accuracy',
    'ML model accuracy score',
    ['model']
)

# Policy metrics
policies_evaluated_total = Counter(
    'cloudguard_policies_evaluated_total',
    'Total number of policy evaluations',
    ['policy_id', 'result']  # result: pass/fail
)

policies_total = Gauge(
    'cloudguard_policies_total',
    'Total number of policies',
    ['provider', 'enabled']
)

# Database metrics
db_connections_total = Gauge(
    'cloudguard_db_connections_total',
    'Total number of database connections',
    ['state']  # state: active/idle
)

db_query_duration_seconds = Histogram(
    'cloudguard_db_query_duration_seconds',
    'Database query duration in seconds',
    ['operation'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
)

# Cache metrics
cache_hits_total = Counter(
    'cloudguard_cache_hits_total',
    'Total number of cache hits',
    ['cache_name']
)

cache_misses_total = Counter(
    'cloudguard_cache_misses_total',
    'Total number of cache misses',
    ['cache_name']
)

# Audit log metrics
audit_events_total = Counter(
    'cloudguard_audit_events_total',
    'Total number of audit events',
    ['action', 'resource_type', 'status']
)

# Error metrics
errors_total = Counter(
    'cloudguard_errors_total',
    'Total number of errors',
    ['error_type', 'component']
)

# API metrics
api_calls_total = Counter(
    'cloudguard_api_calls_total',
    'Total API calls to external services',
    ['service', 'status']  # service: aws/azure/gcp/anthropic/openai
)

api_call_duration_seconds = Histogram(
    'cloudguard_api_call_duration_seconds',
    'External API call duration in seconds',
    ['service'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)


class MetricsCollector:
    """
    Central metrics collector for CloudGuard-Anomaly.
    """

    def track_http_request(self, method: str, endpoint: str, status: int, duration: float):
        """Track HTTP request metrics."""
        http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

    def track_auth_attempt(self, method: str, success: bool):
        """Track authentication attempt."""
        status = 'success' if success else 'failure'
        auth_attempts_total.labels(method=method, status=status).inc()

    def track_scan(self, provider: str, duration: float, success: bool):
        """Track scan completion."""
        status = 'success' if success else 'failure'
        scans_total.labels(provider=provider, status=status).inc()
        scan_duration_seconds.labels(provider=provider).observe(duration)

    def track_finding(self, severity: str, provider: str, finding_type: str):
        """Track finding discovery."""
        findings_total.labels(
            severity=severity,
            provider=provider,
            finding_type=finding_type
        ).inc()

    def track_anomaly(self, anomaly_type: str, severity: str):
        """Track anomaly detection."""
        anomalies_detected_total.labels(type=anomaly_type, severity=severity).inc()

    def track_policy_evaluation(self, policy_id: str, passed: bool):
        """Track policy evaluation."""
        result = 'pass' if passed else 'fail'
        policies_evaluated_total.labels(policy_id=policy_id, result=result).inc()

    def track_audit_event(self, action: str, resource_type: str, status: str):
        """Track audit event."""
        audit_events_total.labels(
            action=action,
            resource_type=resource_type,
            status=status
        ).inc()

    def track_error(self, error_type: str, component: str):
        """Track error occurrence."""
        errors_total.labels(error_type=error_type, component=component).inc()

    def track_api_call(self, service: str, duration: float, status: str):
        """Track external API call."""
        api_calls_total.labels(service=service, status=status).inc()
        api_call_duration_seconds.labels(service=service).observe(duration)


# Global metrics collector instance
metrics = MetricsCollector()


def track_request(endpoint: Optional[str] = None):
    """
    Decorator to track HTTP request metrics.

    Args:
        endpoint: Custom endpoint name (defaults to function name)

    Example:
        @track_request('create_policy')
        def create_policy():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request

            endpoint_name = endpoint or func.__name__
            method = request.method

            # Track request in progress
            http_requests_in_progress.labels(method=method, endpoint=endpoint_name).inc()

            start_time = time.time()
            try:
                result = func(*args, **kwargs)

                # Get status code
                if isinstance(result, tuple):
                    status = result[1] if len(result) > 1 else 200
                else:
                    status = 200

                duration = time.time() - start_time
                metrics.track_http_request(method, endpoint_name, status, duration)

                return result

            except Exception as e:
                duration = time.time() - start_time
                metrics.track_http_request(method, endpoint_name, 500, duration)
                raise

            finally:
                http_requests_in_progress.labels(method=method, endpoint=endpoint_name).dec()

        return wrapper
    return decorator


def track_scan(provider: str):
    """
    Decorator to track scan metrics.

    Args:
        provider: Cloud provider name

    Example:
        @track_scan('aws')
        def scan_aws_environment():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            scans_in_progress.labels(provider=provider).inc()

            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                metrics.track_scan(provider, duration, True)
                return result

            except Exception as e:
                duration = time.time() - start_time
                metrics.track_scan(provider, duration, False)
                raise

            finally:
                scans_in_progress.labels(provider=provider).dec()

        return wrapper
    return decorator


def get_metrics():
    """
    Generate Prometheus metrics in text format.

    Returns:
        Metrics in Prometheus exposition format
    """
    return generate_latest(REGISTRY)


def get_metrics_content_type():
    """
    Get the content type for Prometheus metrics.

    Returns:
        Content-Type header value
    """
    return CONTENT_TYPE_LATEST

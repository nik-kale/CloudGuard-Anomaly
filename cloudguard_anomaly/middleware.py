"""
Middleware for CloudGuard-Anomaly Flask application.

Provides request/response logging, metrics, and correlation IDs.
"""

import time
import uuid
import logging
from flask import Flask, request, g
from typing import Any

from cloudguard_anomaly.observability.metrics import metrics

logger = logging.getLogger(__name__)


def setup_middleware(app: Flask):
    """
    Set up middleware for the Flask application.

    Args:
        app: Flask application instance
    """

    @app.before_request
    def before_request():
        """Execute before each request."""
        # Generate request ID for tracing
        request.request_id = str(uuid.uuid4())
        g.request_id = request.request_id
        g.start_time = time.time()

        # Add user ID if authenticated
        if hasattr(request, 'current_user') and request.current_user:
            request.user_id = request.current_user.id
            g.user_id = request.current_user.id
        else:
            request.user_id = None
            g.user_id = None

        # Log request
        logger.info(
            "Request started",
            extra={
                'request_id': request.request_id,
                'user_id': request.user_id,
                'method': request.method,
                'path': request.path,
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string if request.user_agent else None
            }
        )

    @app.after_request
    def after_request(response):
        """Execute after each request."""
        # Calculate request duration
        duration = time.time() - g.get('start_time', time.time())

        # Track metrics
        endpoint = request.endpoint or 'unknown'
        metrics.track_http_request(
            method=request.method,
            endpoint=endpoint,
            status=response.status_code,
            duration=duration
        )

        # Add custom headers
        response.headers['X-Request-ID'] = g.get('request_id', 'unknown')
        response.headers['X-Response-Time'] = f"{duration:.3f}s"

        # ===================================================================
        # SECURITY HEADERS - OWASP Best Practices
        # ===================================================================

        # Content Security Policy - Prevent XSS attacks
        # Restricts sources for scripts, styles, images, etc.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # X-Frame-Options - Prevent clickjacking attacks
        # Denies embedding in iframes from other domains
        response.headers['X-Frame-Options'] = 'DENY'

        # X-Content-Type-Options - Prevent MIME sniffing
        # Forces browser to respect declared content type
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # X-XSS-Protection - Enable browser XSS protection
        # Legacy header, but still useful for older browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Strict-Transport-Security (HSTS) - Enforce HTTPS
        # Forces browser to use HTTPS for 1 year
        # Include subdomains and allow preloading
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload'
        )

        # Referrer-Policy - Control referrer information
        # Limits referrer header to same-origin only
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions-Policy - Control browser features
        # Disables potentially dangerous features
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=(), '
            'magnetometer=(), '
            'gyroscope=(), '
            'accelerometer=()'
        )

        # X-Permitted-Cross-Domain-Policies - Restrict cross-domain access
        # Prevents Adobe Flash/PDF from loading cross-domain content
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'

        # X-Download-Options - Prevent file execution in IE
        response.headers['X-Download-Options'] = 'noopen'

        # X-DNS-Prefetch-Control - Control DNS prefetching
        # Disable to prevent privacy leakage
        response.headers['X-DNS-Prefetch-Control'] = 'off'

        # Cache-Control for sensitive endpoints
        if '/api/' in request.path:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        # Log response
        logger.info(
            "Request completed",
            extra={
                'request_id': g.get('request_id'),
                'user_id': g.get('user_id'),
                'method': request.method,
                'path': request.path,
                'status': response.status_code,
                'duration': duration,
                'response_size': response.content_length
            }
        )

        return response

    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle uncaught exceptions."""
        # Track error metrics
        error_type = type(error).__name__
        metrics.track_error(error_type, 'application')

        # Log error with full context
        logger.error(
            f"Unhandled exception: {error}",
            extra={
                'request_id': g.get('request_id'),
                'user_id': g.get('user_id'),
                'method': request.method,
                'path': request.path,
                'error_type': error_type
            },
            exc_info=True
        )

        # Return generic error response
        from flask import jsonify
        return jsonify({
            'error': 'An internal server error occurred',
            'request_id': g.get('request_id')
        }), 500

    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 errors."""
        logger.warning(
            "Resource not found",
            extra={
                'request_id': g.get('request_id'),
                'user_id': g.get('user_id'),
                'method': request.method,
                'path': request.path
            }
        )

        from flask import jsonify
        return jsonify({
            'error': 'Resource not found',
            'request_id': g.get('request_id')
        }), 404

    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle 500 errors."""
        metrics.track_error('internal_server_error', 'application')

        logger.error(
            "Internal server error",
            extra={
                'request_id': g.get('request_id'),
                'user_id': g.get('user_id'),
                'method': request.method,
                'path': request.path
            },
            exc_info=True
        )

        from flask import jsonify
        return jsonify({
            'error': 'Internal server error',
            'request_id': g.get('request_id')
        }), 500

    logger.info("Middleware configured successfully")

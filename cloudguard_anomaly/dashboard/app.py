"""
CloudGuard-Anomaly Web Dashboard.

Flask-based real-time security monitoring dashboard.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from flask import Flask, render_template, jsonify, request, send_from_directory, session, redirect, url_for
from flask_socketio import SocketIO, emit

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

try:
    from flask_caching import Cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False

from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.core.models import Severity
from cloudguard_anomaly.config import get_config
from cloudguard_anomaly.auth import get_auth_manager
from cloudguard_anomaly.auth.decorators import login_required, permission_required, admin_required, optional_auth
from cloudguard_anomaly.auth.models import Permission
from cloudguard_anomaly.api.validation import (
    validate_severity,
    validate_status,
    validate_framework,
    validate_limit,
    validate_days,
    validate_environment_name,
    validate_scan_id,
    safe_error_message,
    get_pagination_params,
)

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Load configuration
config = get_config()
app.config['SECRET_KEY'] = config.dashboard_secret_key or 'dev-key-change-in-production'

# Initialize extensions
# WebSocket CORS - use configured origins or disable in production
allowed_origins = config.cors_origins.split(',') if config.cors_origins else []
socketio = SocketIO(app, cors_allowed_origins=allowed_origins or ["http://localhost:5000"])

# CORS support - use configured origins
if CORS_AVAILABLE:
    cors_origins_list = config.cors_origins.split(',') if config.cors_origins else ["http://localhost:5000"]
    CORS(app, resources={r"/api/*": {"origins": cors_origins_list}})

# Rate limiting
limiter: Optional[Limiter] = None
if LIMITER_AVAILABLE and config.rate_limit_enabled:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[config.rate_limit_default],
        storage_uri=config.redis_url if config.cache_backend == "redis" else None
    )
    logger.info(f"Rate limiting enabled: {config.rate_limit_default}")

# Caching
cache: Optional[Cache] = None
if CACHE_AVAILABLE:
    cache_config = {
        'CACHE_TYPE': config.cache_backend,
    }
    if config.cache_backend == 'redis':
        cache_config['CACHE_REDIS_URL'] = config.redis_url

    cache = Cache(app, config=cache_config)
    logger.info(f"Caching enabled: {config.cache_backend}")

# Global database instance
db = None


def init_dashboard(database_url: str):
    """Initialize dashboard with database connection."""
    global db
    db = DatabaseStorage(database_url)
    logger.info(f"Dashboard initialized with database: {database_url}")


# =============================================================================
# HEALTH CHECK ENDPOINTS
# =============================================================================

@app.route('/health')
def health():
    """
    Health check endpoint.

    Returns 200 if service is running.
    """
    return jsonify({
        'status': 'healthy',
        'service': 'cloudguard-anomaly-dashboard',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '3.0.0'
    })


@app.route('/ready')
def ready():
    """
    Readiness check endpoint.

    Returns 200 if service is ready to accept requests (database connected).
    """
    if not db:
        return jsonify({
            'status': 'not ready',
            'reason': 'Database not initialized'
        }), 503

    # Try to query database
    try:
        db.get_scans(days=1, limit=1)
        return jsonify({
            'status': 'ready',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return jsonify({
            'status': 'not ready',
            'reason': 'Database connection failed',
            'error': str(e)
        }), 503


@app.route('/metrics')
def metrics():
    """
    Metrics endpoint for monitoring.

    Returns basic performance and usage metrics.
    """
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    try:
        # Get basic metrics
        recent_scans = db.get_scans(days=7, limit=1000)

        return jsonify({
            'scans_last_7_days': len(recent_scans),
            'database_healthy': True,
            'cache_backend': config.cache_backend,
            'rate_limiting_enabled': config.rate_limit_enabled,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        return jsonify({
            'error': str(e),
            'database_healthy': False,
            'timestamp': datetime.utcnow().isoformat()
        }), 500


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login endpoint.

    GET: Show login page
    POST: Authenticate user
    """
    # Apply rate limiting for POST requests (login attempts)
    if request.method == 'POST' and limiter:
        # Check rate limit: 5 attempts per minute
        try:
            limiter.check()
        except Exception:
            return jsonify({'error': 'Too many login attempts. Please try again later.'}), 429

    if request.method == 'GET':
        return render_template('login.html')

    # POST - authenticate
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        if request.is_json:
            return jsonify({'error': 'Username and password required'}), 400
        return render_template('login.html', error='Username and password required')

    auth_manager = get_auth_manager(db)
    user = auth_manager.authenticate(username, password)

    if not user:
        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        return render_template('login.html', error='Invalid username or password')

    # Create session
    user_session = auth_manager.create_session(user.id)
    session['token'] = user_session.token
    session['user_id'] = user.id
    session['username'] = user.username

    logger.info(f"User logged in: {user.username}")

    if request.is_json:
        return jsonify({
            'success': True,
            'token': user_session.token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        })

    return redirect(url_for('index'))


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    """User logout endpoint."""
    token = session.get('token')

    if token:
        auth_manager = get_auth_manager(db)
        auth_manager.logout(token)

    session.clear()

    if request.is_json:
        return jsonify({'success': True})

    return redirect(url_for('login'))


@app.route('/api/auth/me')
@login_required
def get_current_user():
    """Get current authenticated user info."""
    user = getattr(request, 'current_user', None)

    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'roles': [role.name for role in user.roles],
        'api_key': user.api_key if user.api_key else None
    })


@app.route('/api/auth/generate-api-key', methods=['POST'])
@login_required
def generate_api_key():
    """Generate new API key for current user."""
    user = getattr(request, 'current_user', None)

    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    api_key = user.generate_api_key()

    # Save to database
    session_obj = db.get_session()
    try:
        session_obj.merge(user)
        session_obj.commit()
    finally:
        session_obj.close()

    return jsonify({
        'success': True,
        'api_key': api_key
    })


# =============================================================================
# MAIN ROUTES
# =============================================================================

@app.route('/')
@optional_auth
def index():
    """Dashboard home page."""
    user = getattr(request, 'current_user', None)

    if config.enable_auth and not user:
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user)


@app.route('/api/overview')
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_overview():
    """Get overview statistics."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    # Apply caching if available
    cache_key = 'overview_stats'
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)

    try:
        # Get recent scans with validated parameters
        days = validate_days(request.args.get('days', type=int), max_days=365)
        recent_scans = db.get_scans(days=days, limit=100)

        # Calculate statistics
        total_scans = len(recent_scans)
        total_findings = sum(len(scan.data.get('findings', [])) for scan in recent_scans)

        # Get severity breakdown
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for scan in recent_scans:
            for finding in scan.data.get('findings', []):
                severity = finding.get('severity', 'info').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Get environments
        environments = list(set(scan.environment_name for scan in recent_scans))

        # Calculate risk score average
        risk_scores = [scan.data.get('summary', {}).get('risk_score', 0) for scan in recent_scans]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        result = {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'environments': len(environments),
            'avg_risk_score': round(avg_risk_score, 1),
            'severity_counts': severity_counts,
            'last_scan': recent_scans[0].timestamp.isoformat() if recent_scans else None
        }

        # Cache result for 5 minutes
        if cache:
            cache.set(cache_key, result, timeout=300)

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting overview: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve overview')}), 500


@app.route('/api/scans')
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_scans():
    """Get list of scans."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    try:
        # Validate input parameters
        days = validate_days(request.args.get('days', type=int))
        limit = validate_limit(request.args.get('limit', type=int))
        environment = validate_environment_name(request.args.get('environment'))

        scans = db.get_scans(days=days, limit=limit)

        scan_list = []
        for scan in scans:
            summary = scan.data.get('summary', {})
            scan_list.append({
                'id': scan.id,
                'environment': scan.environment_name,
                'provider': scan.provider,
                'timestamp': scan.timestamp.isoformat(),
                'findings_count': len(scan.data.get('findings', [])),
                'risk_score': summary.get('risk_score', 0),
                'severity_counts': summary.get('severity_counts', {})
            })

        return jsonify({'scans': scan_list})
    except Exception as e:
        logger.error(f"Error getting scans: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve scans')}), 500


@app.route('/api/scans/<scan_id>')
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_scan_details(scan_id: str):
    """Get detailed scan information."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    # Validate scan ID
    scan_id = validate_scan_id(scan_id)
    if not scan_id:
        return jsonify({'error': 'Invalid scan ID'}), 400

    try:
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify({
            'id': scan.id,
            'environment': scan.environment_name,
            'provider': scan.provider,
            'timestamp': scan.timestamp.isoformat(),
            'findings': scan.data.get('findings', []),
            'anomalies': scan.data.get('anomalies', []),
            'summary': scan.data.get('summary', {}),
            'narratives': scan.data.get('narratives', {})
        })
    except Exception as e:
        logger.error(f"Error getting scan details: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve scan')}), 500


@app.route('/api/trends')
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_trends():
    """Get trend data for charts."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    try:
        # Validate parameters
        environment = validate_environment_name(request.args.get('environment'))
        days = validate_days(request.args.get('days', type=int))

        if not environment:
            # Get list of environments
            scans = db.get_scans(days=days, limit=100)
            environments = list(set(scan.environment_name for scan in scans))
            if not environments:
                return jsonify({'error': 'No environments found'}), 404
            environment = environments[0]

        trend_data = db.get_trend_data(environment, days=days)

        return jsonify({
            'environment': environment,
            'trends': trend_data
        })
    except Exception as e:
        logger.error(f"Error getting trends: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve trends')}), 500


@app.route('/api/findings')
@login_required
@permission_required(Permission.FINDING_VIEW)
def get_findings():
    """Get findings with filtering."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    try:
        # Validate all input parameters
        severity = validate_severity(request.args.get('severity'))
        status = validate_status(request.args.get('status')) or 'open'
        limit = validate_limit(request.args.get('limit', type=int))

        findings = db.get_findings(
            severity=severity,
            unresolved_only=(status == 'open'),
            limit=limit
        )

        finding_list = []
        for finding in findings:
            finding_list.append({
                'id': finding.id,
                'scan_id': finding.scan_id,
                'type': finding.type,
                'severity': finding.severity,
                'title': finding.title,
                'description': finding.description,
                'resource_id': finding.resource_id,
                'status': 'open' if not finding.resolved else 'resolved',
                'created_at': finding.timestamp.isoformat()
            })

        return jsonify({'findings': finding_list})
    except Exception as e:
        logger.error(f"Error getting findings: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve findings')}), 500


@app.route('/api/findings/<finding_id>/resolve', methods=['POST'])
@login_required
@permission_required(Permission.FINDING_RESOLVE)
def resolve_finding(finding_id: str):
    """Mark a finding as resolved."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    # Validate finding ID
    finding_id = validate_scan_id(finding_id)  # Uses same validation as scan_id
    if not finding_id:
        return jsonify({'error': 'Invalid finding ID'}), 400

    try:
        db.mark_finding_resolved(finding_id)
        logger.info(f"Finding {finding_id} marked as resolved by user {getattr(request, 'current_user', 'unknown')}")
        return jsonify({'success': True, 'message': 'Finding resolved'})
    except Exception as e:
        logger.error(f"Error resolving finding: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to resolve finding')}), 500


@app.route('/api/compliance')
@login_required
@permission_required(Permission.COMPLIANCE_VIEW)
def get_compliance():
    """Get compliance status."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({'error': safe_error_message(None, 'Service unavailable')}), 500

    try:
        # Validate parameters
        framework = validate_framework(request.args.get('framework'))
        days = validate_days(request.args.get('days', type=int))

        compliance_records = db.get_compliance_results(
            framework=framework,
            days=days,
            limit=50
        )

        compliance_list = []
        for record in compliance_records:
            compliance_list.append({
                'id': record.id,
                'scan_id': record.scan_id,
                'framework': record.framework,
                'score': record.compliance_score,
                'passed': record.passed_controls,
                'failed': record.failed_controls,
                'created_at': record.timestamp.isoformat()
            })

        return jsonify({'compliance': compliance_list})
    except Exception as e:
        logger.error(f"Error getting compliance: {e}", exc_info=True)
        return jsonify({'error': safe_error_message(e, 'Failed to retrieve compliance data')}), 500


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.info('Client connected to dashboard')
    emit('connection_response', {'status': 'connected'})


@socketio.on('subscribe_scans')
def handle_subscribe_scans(data):
    """Subscribe to scan updates."""
    logger.info(f"Client subscribed to scan updates: {data}")
    # In production, implement real-time scan notifications


def broadcast_scan_update(scan_result):
    """Broadcast scan update to all connected clients."""
    socketio.emit('scan_update', {
        'environment': scan_result.environment.name,
        'findings_count': len(scan_result.findings),
        'risk_score': scan_result.summary.get('risk_score', 0),
        'timestamp': datetime.utcnow().isoformat()
    })


def run_dashboard(database_url: str, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
    """Run the dashboard application.

    Args:
        database_url: Database connection URL
        host: Host to bind to
        port: Port to listen on
        debug: Enable debug mode
    """
    init_dashboard(database_url)
    logger.info(f"Starting dashboard on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)


if __name__ == '__main__':
    # Example: Run with SQLite database
    run_dashboard('sqlite:///cloudguard.db', debug=True)

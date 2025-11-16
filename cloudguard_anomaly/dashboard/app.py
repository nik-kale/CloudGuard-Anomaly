"""
CloudGuard-Anomaly Web Dashboard.

Flask-based real-time security monitoring dashboard.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from flask import Flask, render_template, jsonify, request, send_from_directory
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

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Load configuration
config = get_config()
app.config['SECRET_KEY'] = config.dashboard_secret_key or 'dev-key-change-in-production'

# Initialize extensions
socketio = SocketIO(app, cors_allowed_origins="*")

# CORS support
if CORS_AVAILABLE:
    CORS(app, resources={r"/api/*": {"origins": "*"}})

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
# MAIN ROUTES
# =============================================================================

@app.route('/')
def index():
    """Dashboard home page."""
    return render_template('dashboard.html')


@app.route('/api/overview')
def get_overview():
    """Get overview statistics."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    # Apply caching if available
    cache_key = 'overview_stats'
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)

    try:
        # Get recent scans
        recent_scans = db.get_scans(days=30, limit=100)

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
        logger.error(f"Error getting overview: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans')
def get_scans():
    """Get list of scans."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    try:
        days = request.args.get('days', default=30, type=int)
        limit = request.args.get('limit', default=50, type=int)

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
        logger.error(f"Error getting scans: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>')
def get_scan_details(scan_id: str):
    """Get detailed scan information."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

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
        logger.error(f"Error getting scan details: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/trends')
def get_trends():
    """Get trend data for charts."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    try:
        environment = request.args.get('environment')
        days = request.args.get('days', default=30, type=int)

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
        logger.error(f"Error getting trends: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/findings')
def get_findings():
    """Get findings with filtering."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    try:
        severity = request.args.get('severity')
        status = request.args.get('status', default='open')
        limit = request.args.get('limit', default=100, type=int)

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
        logger.error(f"Error getting findings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/findings/<finding_id>/resolve', methods=['POST'])
def resolve_finding(finding_id: str):
    """Mark a finding as resolved."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    try:
        db.mark_finding_resolved(finding_id)
        return jsonify({'success': True, 'message': 'Finding resolved'})
    except Exception as e:
        logger.error(f"Error resolving finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/compliance')
def get_compliance():
    """Get compliance status."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

    try:
        framework = request.args.get('framework')
        days = request.args.get('days', default=30, type=int)

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
        logger.error(f"Error getting compliance: {e}")
        return jsonify({'error': str(e)}), 500


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

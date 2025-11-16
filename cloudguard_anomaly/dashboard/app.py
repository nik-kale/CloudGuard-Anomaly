"""
CloudGuard-Anomaly Web Dashboard.

Flask-based real-time security monitoring dashboard.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.core.models import Severity

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'cloudguard-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global database instance
db = None


def init_dashboard(database_url: str):
    """Initialize dashboard with database connection."""
    global db
    db = DatabaseStorage(database_url)
    logger.info(f"Dashboard initialized with database: {database_url}")


@app.route('/')
def index():
    """Dashboard home page."""
    return render_template('dashboard.html')


@app.route('/api/overview')
def get_overview():
    """Get overview statistics."""
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500

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

        return jsonify({
            'total_scans': total_scans,
            'total_findings': total_findings,
            'environments': len(environments),
            'avg_risk_score': round(avg_risk_score, 1),
            'severity_counts': severity_counts,
            'last_scan': recent_scans[0].created_at.isoformat() if recent_scans else None
        })
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
                'timestamp': scan.created_at.isoformat(),
                'findings_count': len(scan.data.get('findings', [])),
                'risk_score': summary.get('risk_score', 0),
                'severity_counts': summary.get('severity_counts', {}),
                'status': scan.status
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
            'timestamp': scan.created_at.isoformat(),
            'findings': scan.data.get('findings', []),
            'anomalies': scan.data.get('anomalies', []),
            'summary': scan.data.get('summary', {}),
            'narratives': scan.data.get('narratives', {}),
            'status': scan.status
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
            status=status,
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
                'status': finding.status,
                'created_at': finding.created_at.isoformat()
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
                'score': record.score,
                'passed': record.passed,
                'failed': record.failed,
                'created_at': record.created_at.isoformat()
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

"""
CloudGuard-Anomaly Web Dashboard.

Flask-based real-time security monitoring dashboard.
"""

import logging
from datetime import datetime

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
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

try:
    from flask_wtf.csrf import CSRFProtect

    CSRF_AVAILABLE = True
except ImportError:
    CSRF_AVAILABLE = False

from cloudguard_anomaly.api.validation import (
    safe_error_message,
    validate_days,
    validate_environment_name,
    validate_framework,
    validate_limit,
    validate_scan_id,
    validate_severity,
    validate_status,
)
from cloudguard_anomaly.auth import get_auth_manager
from cloudguard_anomaly.auth.decorators import (
    login_required,
    optional_auth,
    permission_required,
)
from cloudguard_anomaly.auth.models import Permission
from cloudguard_anomaly.config import get_config, redact_database_url
from cloudguard_anomaly.middleware import setup_middleware
from cloudguard_anomaly.observability.logging import setup_logging
from cloudguard_anomaly.observability.metrics import get_metrics, get_metrics_content_type
from cloudguard_anomaly.storage.database import DatabaseStorage, get_database, set_database

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")

# Load configuration
config = get_config()

# Every route takes small JSON bodies; refuse anything larger before parsing it
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

# Keep the session cookie off cross-site requests
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Initialize observability
setup_logging(log_level=config.log_level, log_format=getattr(config, "log_format", "json"))
setup_middleware(app)

# Initialize extensions
# WebSocket CORS - use configured origins or disable in production
allowed_origins = config.cors_origins.split(",") if config.cors_origins else []
socketio = SocketIO(app, cors_allowed_origins=allowed_origins or ["http://localhost:5000"])

# CORS support - use configured origins
if CORS_AVAILABLE:
    cors_origins_list = (
        config.cors_origins.split(",") if config.cors_origins else ["http://localhost:5000"]
    )
    CORS(app, resources={r"/api/*": {"origins": cors_origins_list}})

# CSRF protection
csrf: CSRFProtect | None = None
if CSRF_AVAILABLE:
    # Checked in enforce_csrf below: the built-in check cannot distinguish a browser
    # relying on its session cookie from a client sending its own credentials.
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    csrf = CSRFProtect(app)
    logger.info("CSRF protection enabled")

    @app.before_request
    def enforce_csrf():
        """Require a CSRF token on cookie-authenticated state changes."""
        if request.method not in app.config["WTF_CSRF_METHODS"] or not request.endpoint:
            return
        # Browsers cannot attach these headers (or a JSON body) to a cross-site form post
        if request.headers.get("Authorization") or request.headers.get("X-API-Key"):
            return
        if request.endpoint == "login" and request.is_json:
            return
        csrf.protect()


# Rate limiting
limiter: Limiter | None = None
if LIMITER_AVAILABLE and config.rate_limit_enabled:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[config.rate_limit_default],
        storage_uri=config.redis_url if config.cache_backend == "redis" else None,
    )
    logger.info(f"Rate limiting enabled: {config.rate_limit_default}")

# Caching
cache: Cache | None = None
if CACHE_AVAILABLE:
    # flask-caching resolves CACHE_TYPE to a backend class name
    cache_backends = {"simple": "SimpleCache", "redis": "RedisCache"}
    cache_config = {
        "CACHE_TYPE": cache_backends.get(config.cache_backend, config.cache_backend),
    }
    if config.cache_backend == "redis":
        cache_config["CACHE_REDIS_URL"] = config.redis_url

    cache = Cache(app, config=cache_config)
    logger.info(f"Caching enabled: {config.cache_backend}")

# Global database instance
db = None

# Register API v1 blueprint
from cloudguard_anomaly.api.v1 import api_v1

app.register_blueprint(api_v1)
logger.info("Registered API v1 blueprint at /api/v1")


def init_dashboard(database_url: str):
    """Initialize dashboard with database connection."""
    global db
    db = DatabaseStorage(database_url)
    set_database(db)
    logger.info(f"Dashboard initialized with database: {redact_database_url(database_url)}")


def create_app(database_url: str | None = None) -> Flask:
    """
    Configure the dashboard application.

    Args:
        database_url: Database URL (defaults to the configured one)

    Returns:
        The ready-to-serve Flask application

    Raises:
        ValueError: If no session secret is configured outside debug mode
    """
    app.config["SECRET_KEY"] = config.require_dashboard_secret()
    init_dashboard(database_url or config.database_url)
    return app


# =============================================================================
# HEALTH CHECK ENDPOINTS
# =============================================================================


@app.route("/health")
def health():
    """
    Health check endpoint for Kubernetes probes.

    Returns:
        JSON response with health status
    """
    try:
        # Check database connection
        if db:
            session_obj = db.get_session()
            try:
                from sqlalchemy import text

                session_obj.execute(text("SELECT 1"))
                db_status = "healthy"
            except Exception:
                logger.exception("Database health check failed")
                db_status = "unhealthy"
            finally:
                session_obj.close()
        else:
            db_status = "not initialized"

        # Overall health
        is_healthy = db_status == "healthy"

        return jsonify(
            {
                "status": "healthy" if is_healthy else "unhealthy",
                "components": {"database": db_status, "application": "healthy"},
                "version": "3.0",
                "timestamp": datetime.utcnow().isoformat(),
            }
        ), (200 if is_healthy else 503)

    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return (
            jsonify({"status": "unhealthy", "timestamp": datetime.utcnow().isoformat()}),
            503,
        )


@app.route("/metrics")
def metrics_endpoint():
    """
    Prometheus metrics endpoint.

    Returns:
        Metrics in Prometheus exposition format
    """
    return Response(get_metrics(), mimetype=get_metrics_content_type())


@app.route("/ready")
def ready():
    """
    Readiness check endpoint.

    Returns 200 if service is ready to accept requests (database connected).
    """
    if not db:
        return jsonify({"status": "not ready", "reason": "Database not initialized"}), 503

    # Try to query database
    try:
        db.get_scans(days=1, limit=1)
        return jsonify(
            {"status": "ready", "database": "connected", "timestamp": datetime.utcnow().isoformat()}
        )
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return (
            jsonify({"status": "not ready", "reason": "Database connection failed"}),
            503,
        )


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================


def rate_limit(rule: str):
    """Apply a per-route POST limit when rate limiting is enabled."""
    if limiter:
        return limiter.limit(rule, methods=["POST"])
    return lambda view: view


@app.route("/login", methods=["GET", "POST"])
@rate_limit("5 per minute")
def login():
    """
    User login endpoint.

    GET: Show login page
    POST: Authenticate user
    """
    if request.method == "GET":
        return render_template("login.html")

    # POST - authenticate
    data = request.get_json() or request.form
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        if request.is_json:
            return jsonify({"error": "Username and password required"}), 400
        return render_template("login.html", error="Username and password required")

    auth_manager = get_auth_manager(db)
    user = auth_manager.authenticate(
        username,
        password,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string or None,
    )

    if not user:
        if request.is_json:
            return jsonify({"error": "Invalid credentials"}), 401
        return render_template("login.html", error="Invalid username or password")

    # Create session
    user_session = auth_manager.create_session(user.id)
    session["token"] = user_session.token
    session["user_id"] = user.id
    session["username"] = user.username

    logger.info(f"User logged in: {user.username}")

    if request.is_json:
        return jsonify(
            {
                "success": True,
                "token": user_session.token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                },
            }
        )

    return redirect(url_for("index"))


@app.route("/logout", methods=["POST", "GET"])
def logout():
    """User logout endpoint."""
    token = session.get("token")

    if token:
        auth_manager = get_auth_manager(db)
        auth_manager.logout(token)

    session.clear()

    if request.is_json:
        return jsonify({"success": True})

    return redirect(url_for("login"))


@app.route("/api/auth/me")
@login_required
def get_current_user():
    """Get current authenticated user info."""
    user = getattr(request, "current_user", None)

    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "roles": [role.name for role in user.roles],
            "api_key_prefix": user.api_key_prefix,
        }
    )


@app.route("/api/auth/generate-api-key", methods=["POST"])
@rate_limit("3 per hour")
@login_required
def generate_api_key():
    """Generate new API key for current user."""
    user = getattr(request, "current_user", None)

    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    api_key = user.generate_api_key()

    # Save to database
    session_obj = get_database().get_session()
    try:
        session_obj.merge(user)
        session_obj.commit()
    finally:
        session_obj.close()

    return jsonify({"success": True, "api_key": api_key})


# =============================================================================
# MAIN ROUTES
# =============================================================================


@app.route("/")
@optional_auth
def index():
    """Dashboard home page."""
    user = getattr(request, "current_user", None)

    if config.enable_auth and not user:
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


@app.route("/api/overview")
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_overview():
    """Get overview statistics."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    days = validate_days(request.args.get("days", type=int), max_days=365)

    # Apply caching if available
    cache_key = f"overview_stats:{days}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)

    try:
        # Get recent scans with validated parameters
        recent_scans = db.get_scans(days=days, limit=100)

        # Calculate statistics
        total_scans = len(recent_scans)
        total_findings = sum(len(scan.data.get("findings", [])) for scan in recent_scans)

        # Get severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for scan in recent_scans:
            for finding in scan.data.get("findings", []):
                severity = finding.get("severity", "info").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Get environments
        environments = list(set(scan.environment_name for scan in recent_scans))

        # Calculate risk score average
        risk_scores = [scan.data.get("summary", {}).get("risk_score", 0) for scan in recent_scans]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        result = {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "environments": len(environments),
            "avg_risk_score": round(avg_risk_score, 1),
            "severity_counts": severity_counts,
            "last_scan": recent_scans[0].timestamp.isoformat() if recent_scans else None,
        }

        # Cache result for 5 minutes
        if cache:
            cache.set(cache_key, result, timeout=300)

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting overview: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to retrieve overview")}), 500


@app.route("/api/scans")
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_scans():
    """Get list of scans."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    try:
        # Validate input parameters
        days = validate_days(request.args.get("days", type=int))
        limit = validate_limit(request.args.get("limit", type=int))
        environment = validate_environment_name(request.args.get("environment"))

        scans = db.get_scans(environment_name=environment, days=days, limit=limit)

        scan_list = []
        for scan in scans:
            summary = scan.data.get("summary", {})
            scan_list.append(
                {
                    "id": scan.id,
                    "environment": scan.environment_name,
                    "provider": scan.provider,
                    "timestamp": scan.timestamp.isoformat(),
                    "findings_count": len(scan.data.get("findings", [])),
                    "risk_score": summary.get("risk_score", 0),
                    "severity_counts": summary.get("severity_counts", {}),
                }
            )

        return jsonify({"scans": scan_list})
    except Exception as e:
        logger.error(f"Error getting scans: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to retrieve scans")}), 500


@app.route("/api/scans/<scan_id>")
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_scan_details(scan_id: str):
    """Get detailed scan information."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    # Validate scan ID
    scan_id = validate_scan_id(scan_id)
    if not scan_id:
        return jsonify({"error": "Invalid scan ID"}), 400

    try:
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404

        return jsonify(
            {
                "id": scan.id,
                "environment": scan.environment_name,
                "provider": scan.provider,
                "timestamp": scan.timestamp.isoformat(),
                "findings": scan.data.get("findings", []),
                "anomalies": scan.data.get("anomalies", []),
                "summary": scan.data.get("summary", {}),
                "narratives": scan.data.get("narratives", {}),
            }
        )
    except Exception as e:
        logger.error(f"Error getting scan details: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to retrieve scan")}), 500


@app.route("/api/trends")
@login_required
@permission_required(Permission.SCAN_VIEW)
def get_trends():
    """Get trend data for charts."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    try:
        # Validate parameters
        environment = validate_environment_name(request.args.get("environment"))
        days = validate_days(request.args.get("days", type=int))

        if not environment:
            # Get list of environments
            scans = db.get_scans(days=days, limit=100)
            environments = list(set(scan.environment_name for scan in scans))
            if not environments:
                return jsonify({"error": "No environments found"}), 404
            environment = environments[0]

        trend_data = db.get_trend_data(environment, days=days)

        return jsonify({"environment": environment, "trends": trend_data})
    except Exception as e:
        logger.error(f"Error getting trends: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to retrieve trends")}), 500


@app.route("/api/findings")
@login_required
@permission_required(Permission.FINDING_VIEW)
def get_findings():
    """Get findings with filtering."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    try:
        # Validate all input parameters
        severity = validate_severity(request.args.get("severity"))
        status = validate_status(request.args.get("status")) or "open"
        limit = validate_limit(request.args.get("limit", type=int))

        findings = db.get_findings(
            severity=severity, unresolved_only=(status == "open"), limit=limit
        )

        finding_list = []
        for finding in findings:
            finding_list.append(
                {
                    "id": finding.id,
                    "scan_id": finding.scan_id,
                    "type": finding.type,
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "resource_id": finding.resource_id,
                    "status": "open" if not finding.resolved else "resolved",
                    "created_at": finding.timestamp.isoformat(),
                }
            )

        return jsonify({"findings": finding_list})
    except Exception as e:
        logger.error(f"Error getting findings: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to retrieve findings")}), 500


@app.route("/api/findings/<finding_id>/resolve", methods=["POST"])
@login_required
@permission_required(Permission.FINDING_RESOLVE)
def resolve_finding(finding_id: str):
    """Mark a finding as resolved."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    # Validate finding ID
    finding_id = validate_scan_id(finding_id)  # Uses same validation as scan_id
    if not finding_id:
        return jsonify({"error": "Invalid finding ID"}), 400

    try:
        db.mark_finding_resolved(finding_id)
        logger.info(
            f"Finding {finding_id} marked as resolved by user {getattr(request, 'current_user', 'unknown')}"
        )
        return jsonify({"success": True, "message": "Finding resolved"})
    except Exception as e:
        logger.error(f"Error resolving finding: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to resolve finding")}), 500


@app.route("/api/compliance")
@login_required
@permission_required(Permission.COMPLIANCE_VIEW)
def get_compliance():
    """Get compliance status."""
    if not db:
        logger.error("Database not initialized")
        return jsonify({"error": safe_error_message(None, "Service unavailable")}), 500

    try:
        # Validate parameters
        framework = validate_framework(request.args.get("framework"))
        days = validate_days(request.args.get("days", type=int))

        compliance_records = db.get_compliance_results(framework=framework, days=days, limit=50)

        compliance_list = []
        for record in compliance_records:
            compliance_list.append(
                {
                    "id": record.id,
                    "scan_id": record.scan_id,
                    "framework": record.framework,
                    "score": record.compliance_score,
                    "passed": record.passed_controls,
                    "failed": record.failed_controls,
                    "created_at": record.timestamp.isoformat(),
                }
            )

        return jsonify({"compliance": compliance_list})
    except Exception as e:
        logger.error(f"Error getting compliance: {e}", exc_info=True)
        return jsonify({"error": safe_error_message(e, "Failed to retrieve compliance data")}), 500


@socketio.on("connect")
def handle_connect():
    """Handle WebSocket connection."""
    logger.info("Client connected to dashboard")
    emit("connection_response", {"status": "connected"})


@socketio.on("subscribe_scans")
def handle_subscribe_scans(data):
    """Subscribe to scan updates."""
    logger.info(f"Client subscribed to scan updates: {data}")
    # In production, implement real-time scan notifications


def broadcast_scan_update(scan_result):
    """Broadcast scan update to all connected clients."""
    socketio.emit(
        "scan_update",
        {
            "environment": scan_result.environment.name,
            "findings_count": len(scan_result.findings),
            "risk_score": scan_result.summary.get("risk_score", 0),
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


def run_dashboard(
    database_url: str, host: str = "127.0.0.1", port: int = 5000, debug: bool = False
):
    """Run the dashboard application.

    Args:
        database_url: Database connection URL
        host: Host to bind to
        port: Port to listen on
        debug: Enable debug mode
    """
    create_app(database_url)
    logger.info(f"Starting dashboard on {host}:{port}")
    # Flask-SocketIO refuses to start on Werkzeug outside debug mode unless told to;
    # requirements.txt ships no eventlet/gevent server for it to choose instead.
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    run_dashboard(
        config.database_url,
        host=config.dashboard_host,
        port=config.dashboard_port,
        debug=config.dashboard_debug,
    )

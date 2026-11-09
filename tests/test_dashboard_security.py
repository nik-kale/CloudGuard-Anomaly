"""Security regression tests for the dashboard entry points and rendering."""

import inspect
import logging
import runpy
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import cloudguard_anomaly.storage.database as storage
from cloudguard_anomaly.auth import AuthenticationManager
from cloudguard_anomaly.config import Config, redact_database_url, set_config
from cloudguard_anomaly.dashboard import app as dashboard

TEMPLATES = Path(dashboard.__file__).parent / "templates"
PASSWORD = "Dashb0ard#Secure!"


@pytest.fixture(autouse=True)
def restore_shared_handles():
    """The app and storage handles are process-wide; keep tests from leaking them."""
    previous_db, previous_shared = dashboard.db, storage._database
    yield
    dashboard.db, storage._database = previous_db, previous_shared


@pytest.fixture
def flask_app(tmp_path):
    application = dashboard.create_app(f"sqlite:///{tmp_path}/dash.db")
    application.config["TESTING"] = True
    if dashboard.limiter:
        dashboard.limiter.reset()
    return application


@pytest.fixture
def user(flask_app):
    manager = AuthenticationManager(dashboard.db)
    manager.create_default_roles()
    return manager.create_user("dash_user", "dash@test.com", PASSWORD, roles=["viewer"])


class TestEntryPoints:
    def test_dashboard_binds_to_loopback_by_default(self, monkeypatch):
        monkeypatch.delenv("DASHBOARD_HOST", raising=False)
        assert Config().dashboard_host == "127.0.0.1"
        assert inspect.signature(dashboard.run_dashboard).parameters["host"].default == "127.0.0.1"

    def test_cli_dashboard_binds_to_loopback_by_default(self):
        from cloudguard_anomaly.cli.main import dashboard as command

        host = next(p for p in command.params if p.name == "host")
        assert host.default == "127.0.0.1"

    def test_module_entry_point_follows_configuration(self, monkeypatch, tmp_path):
        """The container runs this entry point; it must not force debug or SQLite."""
        database_url = f"sqlite:///{tmp_path}/configured.db"
        configured = Config(
            database_url=database_url,
            dashboard_secret_key="k" * 32,
            dashboard_host="10.0.0.5",
            dashboard_port=8123,
            dashboard_debug=False,
        )
        set_config(configured)
        monkeypatch.setattr("cloudguard_anomaly.config._config", configured)
        captured = {}
        monkeypatch.setattr(
            "flask_socketio.SocketIO.run", lambda _self, _app, **kwargs: captured.update(kwargs)
        )

        runpy.run_module("cloudguard_anomaly.dashboard.app", run_name="__main__")

        assert captured["debug"] is False
        assert captured["host"] == "10.0.0.5"
        assert captured["port"] == 8123
        assert storage.get_database().database_url == database_url


class TestSecretsStayOutOfOutput:
    def test_redact_database_url_removes_password(self):
        redacted = redact_database_url("postgresql://svc:hunter2@db:5432/cg")
        assert "hunter2" not in redacted
        assert redacted == "postgresql://svc:***@db:5432/cg"

    def test_redact_leaves_passwordless_urls_alone(self):
        assert redact_database_url("sqlite:///cloudguard.db") == "sqlite:///cloudguard.db"

    def test_storage_does_not_log_the_database_password(self, monkeypatch, caplog):
        monkeypatch.setattr(storage, "create_engine", MagicMock())
        monkeypatch.setattr(storage.Base.metadata, "create_all", MagicMock())
        with caplog.at_level(logging.DEBUG):
            storage.DatabaseStorage("postgresql://svc:hunter2@db:5432/cg")
        assert "hunter2" not in caplog.text

    def test_dashboard_init_does_not_log_the_database_password(self, monkeypatch, caplog):
        monkeypatch.setattr(dashboard, "DatabaseStorage", MagicMock())
        with caplog.at_level(logging.DEBUG):
            dashboard.init_dashboard("postgresql://svc:hunter2@db:5432/cg")
        assert "hunter2" not in caplog.text

    def test_health_does_not_echo_database_errors(self, flask_app, monkeypatch):
        monkeypatch.setattr(
            dashboard.db,
            "get_session",
            MagicMock(side_effect=RuntimeError("connect to postgresql://svc:hunter2@db failed")),
        )
        response = flask_app.test_client().get("/health")
        assert response.status_code == 503
        assert "hunter2" not in response.get_data(as_text=True)

    def test_ready_does_not_echo_database_errors(self, flask_app, monkeypatch):
        monkeypatch.setattr(
            dashboard.db, "get_scans", MagicMock(side_effect=RuntimeError("hunter2"))
        )
        response = flask_app.test_client().get("/ready")
        assert response.status_code == 503
        assert "hunter2" not in response.get_data(as_text=True)


class TestLoginProtection:
    def test_login_form_carries_a_csrf_token(self, flask_app):
        assert 'name="csrf_token"' in flask_app.test_client().get("/login").get_data(as_text=True)

    def test_form_login_without_csrf_token_is_refused(self, flask_app, user):
        response = flask_app.test_client().post(
            "/login", data={"username": "dash_user", "password": PASSWORD}
        )
        assert response.status_code == 400

    def test_login_attempts_are_rate_limited(self, flask_app):
        assert dashboard.limiter is not None
        client = flask_app.test_client()
        codes = [
            client.post("/login", json={"username": "x", "password": "y"}).status_code
            for _ in range(6)
        ]
        assert codes == [401] * 5 + [429]

    def test_session_cookie_is_same_site(self, flask_app):
        assert flask_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


class TestCookieAuthenticatedWrites:
    def test_cookie_session_cannot_post_without_csrf_token(self, flask_app, user):
        client = flask_app.test_client()
        login = client.post("/login", json={"username": "dash_user", "password": PASSWORD})
        assert login.status_code == 200
        response = client.post("/api/findings/abc/resolve")
        assert response.status_code == 400


class TestRendering:
    def test_findings_are_not_interpolated_into_html(self):
        template = (TEMPLATES / "dashboard.html").read_text()
        assert "row.innerHTML" not in template
        assert "textContent = text" in template

    def test_trend_chart_reads_the_field_the_api_returns(self):
        assert "new Date(t.timestamp)" in (TEMPLATES / "dashboard.html").read_text()

    def test_csp_allows_the_scripts_the_dashboard_loads(self, flask_app):
        csp = flask_app.test_client().get("/login").headers["Content-Security-Policy"]
        assert "https://cdn.jsdelivr.net" in csp
        assert "https://cdn.socket.io" in csp
        assert "'unsafe-eval'" not in csp


class TestFilters:
    def _save(self, name, sample_scan_result):
        sample_scan_result.environment.name = name
        return dashboard.db.save_scan(sample_scan_result)

    def test_scan_list_honours_environment_filter(self, flask_app, user, sample_scan_result):
        self._save("env-a", sample_scan_result)
        self._save("env-b", sample_scan_result)
        client = flask_app.test_client()
        client.post("/login", json={"username": "dash_user", "password": PASSWORD})

        scans = client.get("/api/scans?environment=env-a").get_json()["scans"]

        assert {scan["environment"] for scan in scans} == {"env-a"}

    def test_overview_cache_is_per_time_window(self, flask_app, user, sample_scan_result):
        dashboard.cache.clear()
        self._save("env-a", sample_scan_result)
        client = flask_app.test_client()
        client.post("/login", json={"username": "dash_user", "password": PASSWORD})

        assert client.get("/api/overview?days=30").get_json()["total_scans"] == 1
        recorded = dashboard.db.get_scans(days=30, limit=1)[0]
        session = dashboard.db.get_session()
        try:
            stored = session.get(type(recorded), recorded.id)
            stored.timestamp = stored.timestamp.replace(year=stored.timestamp.year - 1)
            session.commit()
        finally:
            session.close()

        assert client.get("/api/overview?days=7").get_json()["total_scans"] == 0

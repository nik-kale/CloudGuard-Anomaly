"""Regression tests for package import, schema creation and migrations."""

import importlib
import os
import pkgutil
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory

import cloudguard_anomaly
from cloudguard_anomaly.auth.models import Permission
from cloudguard_anomaly.config import Config
from cloudguard_anomaly.storage.database import DatabaseStorage

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_every_module_imports():
    """A broken import anywhere takes the dashboard or CLI down with it."""
    failures = {}
    for module in pkgutil.walk_packages(cloudguard_anomaly.__path__, "cloudguard_anomaly."):
        try:
            importlib.import_module(module.name)
        except Exception as exc:  # noqa: BLE001 - collecting every failure for the report
            failures[module.name] = repr(exc)
    assert failures == {}


def test_validation_module_imports_without_starting_the_api():
    """Input validators must not drag route modules and a database along."""
    code = (
        "import sys; import cloudguard_anomaly.api.validation; "
        "sys.exit('cloudguard_anomaly.api.v1' in sys.modules)"
    )
    env = {k: v for k, v in os.environ.items() if k != "DASHBOARD_SECRET_KEY"}
    result = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, env=env, check=False)
    assert result.returncode == 0


def test_audit_permission_exists():
    assert Permission.AUDIT_VIEW == "audit:view"


def test_schema_builds_on_a_fresh_database(tmp_path):
    """Index names are schema-wide, so two tables cannot share one."""
    database = DatabaseStorage(f"sqlite:///{tmp_path}/fresh.db")
    assert database.get_session() is not None


def test_migrations_have_a_single_head():
    script = ScriptDirectory.from_config(AlembicConfig(str(REPO_ROOT / "alembic.ini")))
    assert len(script.get_heads()) == 1


def test_migrations_apply_on_sqlite_without_a_dashboard_secret(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "DASHBOARD_SECRET_KEY"}
    env["DATABASE_URL"] = f"sqlite:///{tmp_path}/migrated.db"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]


class TestDashboardSecret:
    def test_config_does_not_demand_a_dashboard_secret(self, monkeypatch):
        """CLI scans and migrations never touch the dashboard secret."""
        monkeypatch.delenv("DASHBOARD_SECRET_KEY", raising=False)
        monkeypatch.delenv("DASHBOARD_DEBUG", raising=False)
        assert Config().dashboard_secret_key == ""

    def test_starting_the_dashboard_still_requires_one(self, monkeypatch):
        monkeypatch.delenv("DASHBOARD_SECRET_KEY", raising=False)
        monkeypatch.delenv("DASHBOARD_DEBUG", raising=False)
        with pytest.raises(ValueError, match="DASHBOARD_SECRET_KEY"):
            Config().require_dashboard_secret()

    def test_debug_mode_gets_a_random_key_not_a_fixed_one(self, monkeypatch):
        monkeypatch.delenv("DASHBOARD_SECRET_KEY", raising=False)
        monkeypatch.setenv("DASHBOARD_DEBUG", "true")
        first = Config().require_dashboard_secret()
        second = Config().require_dashboard_secret()
        assert first != second
        assert len(first) >= 32

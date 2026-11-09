"""Guards for packaging metadata."""

import ast
import sys
import tomllib
from pathlib import Path

import pytest

import cloudguard_anomaly

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
REQUIREMENTS = (REPO_ROOT / "requirements.txt").read_text().lower()

# Import name -> distribution name, where they differ
DISTRIBUTIONS = {
    "alembic": "alembic",
    "azure": "azure-",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "flask_caching": "flask-caching",
    "flask_cors": "flask-cors",
    "flask_limiter": "flask-limiter",
    "flask_socketio": "flask-socketio",
    "flask_wtf": "flask-wtf",
    "google": "google-cloud-",
    "hcl2": "python-hcl2",
    "prometheus_client": "prometheus-client",
    "pythonjsonlogger": "python-json-logger",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
}
BUNDLED_WITH_OTHERS = {"botocore", "werkzeug"}  # installed by boto3 and flask


def _third_party_imports():
    package = Path(cloudguard_anomaly.__file__).parent
    names = set()
    for path in package.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names - set(sys.stdlib_module_names) - {"cloudguard_anomaly"} - BUNDLED_WITH_OTHERS


@pytest.mark.parametrize("module", sorted(_third_party_imports()))
def test_imported_packages_are_declared(module):
    assert DISTRIBUTIONS.get(module, module).lower() in REQUIREMENTS


def test_extras_cover_the_dashboard():
    assert any(
        "flask-socketio" in dep
        for dep in PYPROJECT["project"]["optional-dependencies"]["dashboard"]
    )


def test_policies_and_templates_ship_in_the_package():
    package_data = PYPROJECT["tool"]["setuptools"]["package-data"]["cloudguard_anomaly"]
    assert "policies/*.yaml" in package_data
    assert "dashboard/templates/*.html" in package_data


def test_project_urls_point_at_the_real_repository():
    for url in PYPROJECT["project"]["urls"].values():
        assert url.startswith("https://github.com/nik-kale/CloudGuard-Anomaly")

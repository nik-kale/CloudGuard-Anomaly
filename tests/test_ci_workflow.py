"""Guards for how the CI pipeline is wired."""

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci-cd.yml"
JOBS = yaml.safe_load(WORKFLOW.read_text())["jobs"]


def _step(job, name):
    return next(step for step in JOBS[job]["steps"] if step.get("name") == name)


def test_lint_tools_are_pinned():
    command = _step("lint", "Install linting tools")["run"]
    assert all(f"{tool}==" in command for tool in ("black", "ruff", "mypy"))


def test_dependency_scanners_audit_the_application():
    """A bare pip-audit inspects the job's own tooling and fails on its dependencies."""
    assert "-r requirements.txt" in _step("security", "Run pip-audit")["run"]
    assert "-r requirements.txt" in _step("security", "Run Safety dependency check")["run"]


def test_docker_job_lowercases_the_image_name():
    names = [step.get("name") for step in JOBS["docker"]["steps"]]
    assert names.index("Lowercase image name") < names.index("Build Docker image")


def test_docker_job_can_upload_scan_results():
    assert JOBS["docker"]["permissions"]["security-events"] == "write"

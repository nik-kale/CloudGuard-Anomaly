"""Regression tests for report generation and CLI behaviour."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from cloudguard_anomaly.cli.commands.scan import execute_scan
from cloudguard_anomaly.cli.main import cli
from cloudguard_anomaly.core.engine import AnalysisEngine
from cloudguard_anomaly.core.evaluator import PolicyEvaluator
from cloudguard_anomaly.core.loader import ConfigLoader
from cloudguard_anomaly.core.models import (
    Environment,
    Finding,
    FindingType,
    Policy,
    Provider,
    Resource,
    ResourceType,
    Severity,
)
from cloudguard_anomaly.integrations.aws_live import AWSLiveIntegration
from cloudguard_anomaly.integrations.aws_multi_account import AWSAccount, AWSMultiAccountScanner
from cloudguard_anomaly.reports import HTMLReporter, JSONReporter, MarkdownReporter, PDFReporter
from cloudguard_anomaly.reports.common import safe_report_name
from cloudguard_anomaly.security.secrets import SecretsManager
from cloudguard_anomaly.storage.database import DatabaseStorage

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_ENV = REPO_ROOT / "examples" / "environments" / "env_aws_small"
HOSTILE = "<img src=x onerror=alert(1)>"


def _hostile_result(result):
    result.environment.name = HOSTILE
    result.findings[0].title = HOSTILE
    result.findings[0].description = f"desc {HOSTILE}"
    result.findings[0].remediation = f"fix {HOSTILE}"
    return result


class TestReporters:
    def test_json_report_is_the_full_scan_result(self, sample_scan_result, tmp_path):
        path = tmp_path / "report.json"
        JSONReporter().save_report(sample_scan_result, path)
        data = json.loads(path.read_text())
        assert data["environment"]["name"] == sample_scan_result.environment.name
        assert data["findings"][0]["id"] == "finding-001"

    def test_markdown_report_lists_findings(self, sample_scan_result, tmp_path):
        path = tmp_path / "report.md"
        MarkdownReporter().save_report(sample_scan_result, path)
        text = path.read_text()
        assert sample_scan_result.environment.name in text
        assert "S3 Bucket Not Encrypted" in text
        assert "Enable server-side encryption" in text

    def test_html_report_escapes_scanned_values(self, sample_scan_result, tmp_path):
        path = tmp_path / "report.html"
        HTMLReporter().save_report(_hostile_result(sample_scan_result), path)
        text = path.read_text()
        assert "<img src=x" not in text
        assert "&lt;img src=x" in text

    def test_pdf_report_accepts_markup_in_scanned_values(self, sample_scan_result, tmp_path):
        """ReportLab parses Paragraph text as XML, so raw '<' aborts the report."""
        path = tmp_path / "report.pdf"
        PDFReporter().generate_report(
            _hostile_result(sample_scan_result), str(path), company_name="A & <B>"
        )
        assert path.stat().st_size > 0

    def test_pdf_finding_row_reads_scan_result_fields(self, sample_scan_result):
        data = PDFReporter()._prepare(sample_scan_result)
        finding = data["findings"][0]
        assert finding["resource_id"] == sample_scan_result.findings[0].resource.id
        assert finding["finding_type"] == "misconfiguration"


class TestSafeReportName:
    @pytest.mark.parametrize(
        "name",
        ["../../../../etc/cron.d/x", "..", "", "/absolute/path", "a\\..\\b", "bad\nname"],
    )
    def test_never_escapes_the_output_directory(self, name, tmp_path):
        safe = safe_report_name(name)
        assert safe
        assert (tmp_path / f"{safe}_report.json").resolve().parent == tmp_path.resolve()

    def test_keeps_ordinary_names_readable(self):
        assert safe_report_name("Prod AWS-1") == "prod_aws-1"


class TestLoader:
    def test_example_environment_loads_its_resources(self):
        """Native type names were rejected, so scans reported an empty, clean estate."""
        environment = ConfigLoader.load_environment(EXAMPLE_ENV)
        types = {resource.type for resource in environment.resources}
        assert ResourceType.STORAGE in types
        assert ResourceType.IAM_ROLE in types
        assert ResourceType.UNKNOWN not in types

    def test_unrecognized_type_is_kept_as_unknown(self):
        resource = ConfigLoader.parse_resource({"id": "x", "type": "made_up"}, Provider.AWS)
        assert resource.type is ResourceType.UNKNOWN


class TestScanCommand:
    def test_scan_writes_every_report(self, tmp_path):
        execute_scan(EXAMPLE_ENV, output_dir=tmp_path, enable_agents=False)
        written = {p.suffix for p in tmp_path.iterdir()}
        assert written == {".json", ".md", ".html", ".pdf"}
        data = json.loads(next(tmp_path.glob("*.json")).read_text())
        assert data["summary"]["total_findings"] > 0

    def test_environment_name_cannot_redirect_reports(self, tmp_path):
        """environment.yaml is scanned input and must not choose the output path."""
        env_dir = tmp_path / "env"
        (env_dir / "runtime_snapshot").mkdir(parents=True)
        (env_dir / "environment.yaml").write_text(
            yaml.safe_dump({"name": "../../escaped", "provider": "aws"})
        )
        output = tmp_path / "a" / "b" / "reports"

        execute_scan(env_dir, output_dir=output, output_format="json", enable_agents=False)

        assert list(tmp_path.rglob("*_report.json")) == [output / "escaped_report.json"]


class TestCliModuleEntryPoint:
    @pytest.mark.parametrize(
        "command", ["live-scan", "compliance", "remediate", "train-ml", "dashboard"]
    )
    def test_commands_exist_when_run_as_a_module(self, command):
        """The container runs ``python -m cloudguard_anomaly.cli.main``."""
        result = subprocess.run(
            [sys.executable, "-m", "cloudguard_anomaly.cli.main", command, "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr[-500:]


def _finding(severity, title):
    resource = Resource(
        id="b1",
        name="bucket",
        type=ResourceType.STORAGE,
        provider=Provider.AWS,
        region="us-east-1",
    )
    return Finding(
        id=f"f-{severity.value}",
        type=FindingType.MISCONFIGURATION,
        severity=severity,
        title=title,
        description="d",
        resource=resource,
        policy=None,
    )


class TestRemediateCommand:
    @pytest.fixture
    def scan_id(self, tmp_path, sample_scan_result):
        self.url = f"sqlite:///{tmp_path}/r.db"
        sample_scan_result.findings = [
            _finding(Severity.CRITICAL, "Public S3 Bucket"),
            _finding(Severity.HIGH, "Public Storage Access"),
            _finding(Severity.LOW, "Public S3 Bucket"),
        ]
        return DatabaseStorage(self.url).save_scan(sample_scan_result)

    def _run(self, scan_id, *args):
        return CliRunner().invoke(
            cli, ["remediate", "--scan-id", scan_id, "--database-url", self.url, *args]
        )

    def test_dry_run_can_be_disabled(self):
        from cloudguard_anomaly.cli.main import remediate as command

        option = next(p for p in command.params if p.name == "dry_run")
        assert option.secondary_opts == ["--no-dry-run"]
        assert option.default is True

    def test_severity_is_a_minimum_not_alphabetical(self, scan_id):
        result = self._run(scan_id, "--severity", "high")
        assert result.exit_code == 0, result.output
        assert "Total: 2" in result.output

    def test_dry_run_remediates_rebuilt_findings(self, scan_id):
        result = self._run(scan_id)
        assert "Remediated: 3" in result.output
        assert "Failed: 0" in result.output


def test_train_ml_uses_stored_resources(tmp_path, sample_scan_result):
    url = f"sqlite:///{tmp_path}/t.db"
    DatabaseStorage(url).save_scan(sample_scan_result)
    result = CliRunner().invoke(cli, ["train-ml", "--database-url", url])
    assert result.exit_code == 0, result.output
    assert "Model trained" in result.output


class TestContainerScanCommand:
    def _run(self, summary):
        scanner = MagicMock()
        scanner.scan_image.return_value = MagicMock(summary=summary)
        scanner.generate_report.return_value = "report"
        with patch("cloudguard_anomaly.cli.commands.container_scan.DockerScanner") as cls:
            cls.return_value = scanner
            return CliRunner().invoke(cli, ["container-scan", "--image", "nginx:1"])

    def test_clean_scan_exits_zero(self):
        result = self._run({"total_vulnerabilities": 0, "total_findings": 0})
        assert result.exit_code == 0
        assert "failed" not in result.output.lower()

    def test_critical_issues_exit_two(self):
        result = self._run({"total_vulnerabilities": 1, "total_findings": 0, "critical": 1})
        assert result.exit_code == 2


class TestContainerEntrypoint:
    @pytest.fixture
    def fake_python(self, tmp_path):
        script = tmp_path / "python"
        script.write_text(
            '#!/bin/bash\nprintf "%s\\n" "$@" > "$CAPTURE"\ncat >> "$CAPTURE" <<<""\n'
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return tmp_path

    def _run(self, fake_python, *args, **env):
        capture = fake_python / "captured"
        process_env = {
            **os.environ,
            "PATH": f"{fake_python}:{os.environ['PATH']}",
            "CAPTURE": str(capture),
            "SKIP_MIGRATIONS": "true",
            **env,
        }
        process_env.pop("DATABASE_URL", None)
        subprocess.run(
            ["bash", str(REPO_ROOT / "docker-entrypoint.sh"), *args],
            env=process_env,
            capture_output=True,
            text=True,
            check=False,
        )
        return capture.read_text() if capture.exists() else ""

    def test_scan_mode_does_not_repeat_the_subcommand(self, fake_python):
        lines = self._run(fake_python, "scan", "--env", "x").split("\n")
        assert lines[:5] == ["-m", "cloudguard_anomaly.cli.main", "scan", "--env", "x"]

    def test_admin_password_is_not_spliced_into_python_source(self, fake_python):
        secret = "pa'ss\"word"
        output = self._run(fake_python, "shell", CREATE_ADMIN="true", ADMIN_PASSWORD=secret)
        assert secret not in output

    def test_no_default_admin_password(self):
        assert "changeme123" not in (REPO_ROOT / "docker-entrypoint.sh").read_text()


def test_image_does_not_install_packages_under_root_home():
    """The container runs as a non-root user that cannot read /root/.local."""
    assert "/root/.local" not in (REPO_ROOT / "Dockerfile").read_text()


def test_image_installs_entrypoint_before_dropping_root():
    """chmod on the root-owned /usr/local/bin fails the build once USER has switched."""
    lines = [line.strip() for line in (REPO_ROOT / "Dockerfile").read_text().splitlines()]
    chmod_line = next(i for i, line in enumerate(lines) if "chmod +x /usr/local/bin" in line)
    assert chmod_line < lines.index("USER cloudguard")


def test_jobs_exporting_a_build_cache_set_up_buildx():
    """The default docker driver cannot export a gha cache, so those jobs need Buildx."""
    workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/ci-cd.yml").read_text())
    exporting = {
        name: job["steps"]
        for name, job in workflow["jobs"].items()
        if any("cache-to" in step.get("with", {}) for step in job["steps"])
    }
    assert exporting
    for name, steps in exporting.items():
        uses = [step.get("uses", "") for step in steps]
        assert any(u.startswith("docker/setup-buildx-action") for u in uses), name


class TestCoreRegressions:
    def _policy_finding(self, resource_type, check, **properties):
        resource = Resource(
            id="r",
            name="r",
            type=resource_type,
            provider=Provider.AWS,
            region="x",
            properties=properties,
        )
        policy = Policy(
            id="P",
            name="n",
            description="d",
            severity=Severity.HIGH,
            provider=Provider.MULTI,
            resource_types=[resource_type],
            condition={"custom": {"type": check}},
            remediation="r",
        )
        return PolicyEvaluator([policy]).evaluate_resource(resource)

    def test_encrypted_resource_is_not_flagged(self):
        """Every encryption key had to be present, so nothing could ever pass."""
        assert self._policy_finding(ResourceType.STORAGE, "encryption", encrypted=True) == []

    def test_unencrypted_resource_is_flagged(self):
        assert len(self._policy_finding(ResourceType.STORAGE, "encryption", encrypted=False)) == 1

    def test_logging_enabled_resource_is_not_flagged(self):
        assert self._policy_finding(ResourceType.STORAGE, "logging", logging_enabled=True) == []

    def test_disabled_settings_block_counts_as_off(self):
        findings = self._policy_finding(
            ResourceType.STORAGE, "encryption", encryption={"enabled": False}
        )
        assert len(findings) == 1

    def test_yml_files_are_loaded(self, tmp_path):
        (tmp_path / "res.yml").write_text(
            yaml.safe_dump({"resources": [{"id": "a", "name": "a", "type": "storage"}]})
        )
        assert len(ConfigLoader._load_resources_from_dir(tmp_path, Provider.AWS)) == 1

    def test_scan_does_not_warn_about_missing_agents(self, caplog, sample_environment):
        engine = AnalysisEngine(enable_agents=True)
        engine.scan_environment(sample_environment)
        assert "Could not initialize LLM agents" not in caplog.text

    def test_aws_secret_stored_as_a_bare_string(self):
        manager = SecretsManager("env")
        manager.client = MagicMock()
        manager.client.exceptions.ResourceNotFoundException = KeyError
        manager.client.get_secret_value.return_value = {"SecretString": "not-json"}
        assert manager._get_aws_secret("path", None) == "not-json"

    def test_multi_account_scan_uses_the_assumed_session(self):
        """Region scans passed arguments the integration never accepted."""
        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": "1"}
        environment = Environment("live", Provider.AWS, resources=[])
        scanner = AWSMultiAccountScanner.__new__(AWSMultiAccountScanner)
        account = AWSAccount(account_id="1", account_name="prod")

        with patch.object(AWSLiveIntegration, "discover_all_resources", return_value=environment):
            result = scanner._scan_single_region(session, "eu-west-1", account, None)

        assert result.name == "prod-eu-west-1"
        assert result.metadata["region"] == "eu-west-1"


def test_drift_scenario_reads_its_current_state():
    """The README's drift example has baseline/ and current/ but no runtime_snapshot/."""
    scenario = REPO_ROOT / "examples" / "drift_scenarios" / "public_bucket_after_change"
    environment = ConfigLoader.load_environment(scenario)
    assert environment.resources
    assert environment.baseline_resources

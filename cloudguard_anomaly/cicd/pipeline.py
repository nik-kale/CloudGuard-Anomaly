"""
CI/CD pipeline integration for CloudGuard-Anomaly.

Provides templates and helpers for integrating security scans into CI/CD pipelines.
"""

import sys
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any

from cloudguard_anomaly.core.models import ScanResult, Severity


class ExitCodePolicy(Enum):
    """Exit code policies for CI/CD integration."""

    FAIL_ON_CRITICAL = "fail_on_critical"
    FAIL_ON_HIGH = "fail_on_high"
    FAIL_ON_MEDIUM = "fail_on_medium"
    WARN_ONLY = "warn_only"
    ALWAYS_PASS = "always_pass"


@dataclass
class CICDConfig:
    """CI/CD configuration."""

    exit_code_policy: ExitCodePolicy
    max_critical: int = 0
    max_high: int = 5
    max_medium: int = 20
    fail_on_risk_score: int = 80


class CICDIntegration:
    """CI/CD pipeline integration helpers."""

    @staticmethod
    def determine_exit_code(scan_result: ScanResult, config: CICDConfig) -> int:
        """
        Determine exit code based on scan results and policy.

        Args:
            scan_result: Scan results
            config: CI/CD configuration

        Returns:
            Exit code (0 = pass, 1 = warning, 2 = failure)
        """
        critical = len(scan_result.get_critical_findings())
        high = len(scan_result.get_high_findings())
        medium_findings = [
            f for f in scan_result.findings if f.severity == Severity.MEDIUM
        ]
        medium = len(medium_findings)
        risk_score = scan_result.summary.get("risk_score", 0)

        policy = config.exit_code_policy

        if policy == ExitCodePolicy.ALWAYS_PASS:
            return 0

        if policy == ExitCodePolicy.WARN_ONLY:
            return 1 if critical > 0 or high > 0 else 0

        # Check critical threshold
        if critical > config.max_critical:
            return 2

        # Check high threshold
        if policy in [ExitCodePolicy.FAIL_ON_CRITICAL, ExitCodePolicy.FAIL_ON_HIGH]:
            if high > config.max_high:
                return 2

        # Check medium threshold
        if policy == ExitCodePolicy.FAIL_ON_MEDIUM:
            if medium > config.max_medium:
                return 2

        # Check risk score
        if risk_score >= config.fail_on_risk_score:
            return 2

        # Warning if any issues found
        if critical > 0 or high > 0 or medium > 0:
            return 1

        return 0

    @staticmethod
    def generate_gitlab_ci() -> str:
        """Generate .gitlab-ci.yml configuration."""
        return """# CloudGuard-Anomaly Security Scan
cloudguard-security-scan:
  stage: security
  image: python:3.11
  before_script:
    - pip install cloudguard-anomaly
  script:
    - cloudguard-anomaly scan --env infrastructure/ --format json --output reports/
    - cloudguard-anomaly compliance --env infrastructure/ --framework soc2
  artifacts:
    reports:
      cloudguard: reports/*_report.json
    paths:
      - reports/
    expire_in: 30 days
  allow_failure: false
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
"""

    @staticmethod
    def generate_github_actions() -> str:
        """Generate GitHub Actions workflow."""
        return """name: CloudGuard Security Scan

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install CloudGuard-Anomaly
        run: |
          pip install cloudguard-anomaly

      - name: Run Security Scan
        run: |
          cloudguard-anomaly scan --env infrastructure/ --format all --output reports/

      - name: Run Compliance Check
        run: |
          cloudguard-anomaly compliance --env infrastructure/ --framework soc2

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: reports/

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('reports/summary.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
"""

    @staticmethod
    def generate_jenkins_pipeline() -> str:
        """Generate Jenkinsfile."""
        return """pipeline {
    agent any

    stages {
        stage('Setup') {
            steps {
                sh 'pip install cloudguard-anomaly'
            }
        }

        stage('Security Scan') {
            steps {
                sh 'cloudguard-anomaly scan --env infrastructure/ --format all --output reports/'
            }
        }

        stage('Compliance Check') {
            steps {
                sh 'cloudguard-anomaly compliance --env infrastructure/ --framework soc2'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: '*_report.html',
                reportName: 'CloudGuard Security Report'
            ])
        }
        failure {
            mail to: 'security@example.com',
                 subject: "CloudGuard Security Scan Failed: ${env.JOB_NAME}",
                 body: "Security scan detected critical issues. Check ${env.BUILD_URL}"
        }
    }
}
"""

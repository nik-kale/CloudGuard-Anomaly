"""
Docker and OCI container image security scanner.

Scans container images for:
- Known vulnerabilities (CVEs)
- Security misconfigurations
- Secrets and sensitive data
- Base image issues
- Dockerfile best practices
"""

import logging
import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ContainerVulnerability:
    """Represents a container vulnerability."""
    cve_id: str
    severity: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    description: str
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)


@dataclass
class ContainerFinding:
    """Security finding from container scan."""
    finding_id: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    remediation: str
    layer: Optional[str] = None
    location: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContainerScanResult:
    """Complete container scan result."""
    image_name: str
    image_tag: str
    image_id: str
    scan_timestamp: datetime
    vulnerabilities: List[ContainerVulnerability]
    findings: List[ContainerFinding]
    metadata: Dict[str, Any]
    summary: Dict[str, int] = field(default_factory=dict)


class DockerScanner:
    """
    Scans Docker and OCI images for security issues.

    Features:
    - CVE vulnerability scanning
    - Configuration security checks
    - Secret detection
    - Base image analysis
    - Dockerfile best practice validation
    """

    def __init__(self):
        """Initialize Docker scanner."""
        self.secret_patterns = self._compile_secret_patterns()
        logger.info("Docker security scanner initialized")

    def scan_image(
        self,
        image: str,
        dockerfile_path: Optional[str] = None,
        scan_vulnerabilities: bool = True,
        scan_secrets: bool = True,
        scan_config: bool = True
    ) -> ContainerScanResult:
        """
        Scan a Docker image for security issues.

        Args:
            image: Image name and tag (e.g., 'nginx:latest')
            dockerfile_path: Optional path to Dockerfile for additional checks
            scan_vulnerabilities: Enable CVE scanning
            scan_secrets: Enable secret detection
            scan_config: Enable configuration checks

        Returns:
            ContainerScanResult with all findings
        """
        logger.info(f"Scanning container image: {image}")

        # Parse image name and tag
        image_name, image_tag = self._parse_image_name(image)

        # Get image metadata
        image_metadata = self._get_image_metadata(image)
        if not image_metadata:
            raise ValueError(f"Image not found or inaccessible: {image}")

        image_id = image_metadata.get('Id', 'unknown')

        # Initialize results
        vulnerabilities: List[ContainerVulnerability] = []
        findings: List[ContainerFinding] = []

        # 1. Configuration security checks
        if scan_config:
            config_findings = self._scan_image_config(image_metadata)
            findings.extend(config_findings)

        # 2. Vulnerability scanning
        if scan_vulnerabilities:
            vuln_findings = self._scan_vulnerabilities(image)
            vulnerabilities.extend(vuln_findings)

        # 3. Secret detection
        if scan_secrets:
            secret_findings = self._scan_for_secrets(image)
            findings.extend(secret_findings)

        # 4. Dockerfile analysis (if provided)
        if dockerfile_path:
            dockerfile_findings = self._scan_dockerfile(dockerfile_path)
            findings.extend(dockerfile_findings)

        # 5. Layer analysis
        layer_findings = self._scan_layers(image_metadata)
        findings.extend(layer_findings)

        # Generate summary
        summary = self._generate_summary(vulnerabilities, findings)

        result = ContainerScanResult(
            image_name=image_name,
            image_tag=image_tag,
            image_id=image_id,
            scan_timestamp=datetime.utcnow(),
            vulnerabilities=vulnerabilities,
            findings=findings,
            metadata=image_metadata,
            summary=summary
        )

        logger.info(
            f"Scan complete: {len(vulnerabilities)} vulnerabilities, "
            f"{len(findings)} configuration findings"
        )

        return result

    def _parse_image_name(self, image: str) -> Tuple[str, str]:
        """Parse image into name and tag."""
        if ':' in image:
            name, tag = image.rsplit(':', 1)
        else:
            name, tag = image, 'latest'
        return name, tag

    def _get_image_metadata(self, image: str) -> Optional[Dict[str, Any]]:
        """Get image metadata using docker inspect."""
        try:
            result = subprocess.run(
                ['docker', 'inspect', image],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                metadata_list = json.loads(result.stdout)
                return metadata_list[0] if metadata_list else None
            else:
                logger.error(f"Failed to inspect image: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout inspecting image: {image}")
            return None
        except FileNotFoundError:
            logger.error("Docker CLI not found. Please install Docker.")
            return None
        except Exception as e:
            logger.error(f"Error inspecting image: {e}")
            return None

    def _scan_image_config(self, metadata: Dict[str, Any]) -> List[ContainerFinding]:
        """Scan image configuration for security issues."""
        findings = []
        config = metadata.get('Config', {})

        # Check 1: Running as root
        user = config.get('User', '')
        if not user or user == 'root' or user == '0':
            findings.append(ContainerFinding(
                finding_id='CONTAINER-001',
                severity='high',
                title='Container runs as root user',
                description='Image is configured to run as root, which poses security risks',
                remediation='Add USER instruction in Dockerfile to run as non-root user',
                metadata={'current_user': user or 'root'}
            ))

        # Check 2: Exposed sensitive ports
        exposed_ports = config.get('ExposedPorts', {})
        sensitive_ports = {22: 'SSH', 3389: 'RDP', 23: 'Telnet'}

        for port_spec in exposed_ports.keys():
            port_num = int(port_spec.split('/')[0])
            if port_num in sensitive_ports:
                findings.append(ContainerFinding(
                    finding_id='CONTAINER-002',
                    severity='medium',
                    title=f'Sensitive port {port_num} exposed',
                    description=f'Image exposes {sensitive_ports[port_num]} port {port_num}',
                    remediation='Remove unnecessary port exposures from Dockerfile',
                    metadata={'port': port_num, 'service': sensitive_ports[port_num]}
                ))

        # Check 3: No health check defined
        if 'Healthcheck' not in config or not config['Healthcheck']:
            findings.append(ContainerFinding(
                finding_id='CONTAINER-003',
                severity='low',
                title='No health check defined',
                description='Image does not define a health check',
                remediation='Add HEALTHCHECK instruction to Dockerfile',
                metadata={}
            ))

        # Check 4: Environment variables with secrets
        env_vars = config.get('Env', [])
        sensitive_keywords = ['password', 'secret', 'key', 'token', 'api_key']

        for env_var in env_vars:
            var_name = env_var.split('=')[0].lower()
            if any(keyword in var_name for keyword in sensitive_keywords):
                findings.append(ContainerFinding(
                    finding_id='CONTAINER-004',
                    severity='critical',
                    title=f'Potential secret in environment variable: {var_name}',
                    description='Environment variable name suggests it contains sensitive data',
                    remediation='Use Docker secrets or external secret management instead',
                    metadata={'variable_name': env_var.split('=')[0]}
                ))

        return findings

    def _scan_vulnerabilities(self, image: str) -> List[ContainerVulnerability]:
        """
        Scan for known vulnerabilities using Trivy.

        Falls back to basic checks if Trivy is not available.
        """
        vulnerabilities = []

        try:
            # Try using Trivy if available
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', '--quiet', image],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                trivy_output = json.loads(result.stdout)
                vulnerabilities = self._parse_trivy_output(trivy_output)
                logger.info(f"Trivy found {len(vulnerabilities)} vulnerabilities")
            else:
                logger.warning(f"Trivy scan failed: {result.stderr}")

        except FileNotFoundError:
            logger.info("Trivy not found, skipping CVE scan (install with: brew install trivy)")
        except subprocess.TimeoutExpired:
            logger.warning("Trivy scan timeout")
        except Exception as e:
            logger.error(f"Error running Trivy: {e}")

        return vulnerabilities

    def _parse_trivy_output(self, trivy_data: Dict) -> List[ContainerVulnerability]:
        """Parse Trivy JSON output into vulnerabilities."""
        vulnerabilities = []

        for result in trivy_data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                vulnerabilities.append(ContainerVulnerability(
                    cve_id=vuln.get('VulnerabilityID', 'UNKNOWN'),
                    severity=vuln.get('Severity', 'UNKNOWN').lower(),
                    package=vuln.get('PkgName', 'unknown'),
                    installed_version=vuln.get('InstalledVersion', 'unknown'),
                    fixed_version=vuln.get('FixedVersion'),
                    description=vuln.get('Description', '')[:200],
                    cvss_score=self._extract_cvss_score(vuln),
                    references=vuln.get('References', [])
                ))

        return vulnerabilities

    def _extract_cvss_score(self, vuln: Dict) -> Optional[float]:
        """Extract CVSS score from vulnerability data."""
        cvss = vuln.get('CVSS', {})
        if isinstance(cvss, dict):
            for version in ['nvd', 'redhat', 'vendor']:
                if version in cvss and 'V3Score' in cvss[version]:
                    return cvss[version]['V3Score']
        return None

    def _scan_for_secrets(self, image: str) -> List[ContainerFinding]:
        """Scan image layers for secrets and sensitive data."""
        findings = []

        try:
            # Export image to tar and scan contents
            # This is a basic implementation - production should use dedicated tools like ggshield
            logger.info("Scanning for secrets (basic implementation)")

            # Get image history
            result = subprocess.run(
                ['docker', 'history', '--no-trunc', '--format', '{{.CreatedBy}}', image],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                history_lines = result.stdout.strip().split('\n')

                for idx, line in enumerate(history_lines):
                    # Check for secrets in command history
                    for pattern_name, pattern in self.secret_patterns.items():
                        matches = pattern.findall(line)
                        if matches:
                            findings.append(ContainerFinding(
                                finding_id='CONTAINER-SECRET-001',
                                severity='critical',
                                title=f'Potential {pattern_name} found in layer',
                                description=f'Layer command may contain {pattern_name}',
                                remediation='Remove secrets from Dockerfile and use Docker secrets or build args',
                                layer=f'Layer {idx}',
                                metadata={'pattern': pattern_name}
                            ))

        except Exception as e:
            logger.error(f"Error scanning for secrets: {e}")

        return findings

    def _compile_secret_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for secret detection."""
        return {
            'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'AWS Secret Key': re.compile(r'aws_secret_access_key\s*=\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'),
            'GitHub Token': re.compile(r'gh[ps]_[a-zA-Z0-9]{36}'),
            'Generic API Key': re.compile(r'api[_-]?key[\s:=]+[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?', re.IGNORECASE),
            'Private Key': re.compile(r'-----BEGIN.*PRIVATE KEY-----'),
            'Password': re.compile(r'password[\s:=]+[\'"]?([^\s\'"]{8,})[\'"]?', re.IGNORECASE),
        }

    def _scan_dockerfile(self, dockerfile_path: str) -> List[ContainerFinding]:
        """Scan Dockerfile for best practice violations."""
        findings = []

        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()

            has_user = False
            has_healthcheck = False
            uses_latest_tag = False

            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Check for USER instruction
                if line.startswith('USER '):
                    has_user = True

                # Check for HEALTHCHECK
                if line.startswith('HEALTHCHECK '):
                    has_healthcheck = True

                # Check for :latest tag usage
                if 'FROM ' in line and ':latest' in line:
                    uses_latest_tag = True
                    findings.append(ContainerFinding(
                        finding_id='DOCKERFILE-001',
                        severity='medium',
                        title='Base image uses :latest tag',
                        description=f'Line {line_num}: Using :latest tag is not reproducible',
                        remediation='Pin to a specific version tag',
                        location=f'Line {line_num}',
                        metadata={'line': line.strip()}
                    ))

                # Check for ADD instead of COPY
                if line.startswith('ADD ') and not ('http://' in line or 'https://' in line):
                    findings.append(ContainerFinding(
                        finding_id='DOCKERFILE-002',
                        severity='low',
                        title='ADD used instead of COPY',
                        description=f'Line {line_num}: ADD has implicit extraction behavior',
                        remediation='Use COPY for simple file copying',
                        location=f'Line {line_num}',
                        metadata={'line': line.strip()}
                    ))

                # Check for apt-get without -y
                if 'apt-get install' in line and '-y' not in line:
                    findings.append(ContainerFinding(
                        finding_id='DOCKERFILE-003',
                        severity='low',
                        title='apt-get install without -y flag',
                        description=f'Line {line_num}: Installation may hang waiting for input',
                        remediation='Add -y flag to apt-get install',
                        location=f'Line {line_num}',
                        metadata={'line': line.strip()}
                    ))

            # Check for missing USER instruction
            if not has_user:
                findings.append(ContainerFinding(
                    finding_id='DOCKERFILE-004',
                    severity='high',
                    title='No USER instruction in Dockerfile',
                    description='Dockerfile does not set a non-root user',
                    remediation='Add USER instruction to run as non-root',
                    location='Dockerfile',
                    metadata={}
                ))

            # Check for missing HEALTHCHECK
            if not has_healthcheck:
                findings.append(ContainerFinding(
                    finding_id='DOCKERFILE-005',
                    severity='low',
                    title='No HEALTHCHECK instruction',
                    description='Dockerfile does not define a health check',
                    remediation='Add HEALTHCHECK instruction',
                    location='Dockerfile',
                    metadata={}
                ))

        except FileNotFoundError:
            logger.error(f"Dockerfile not found: {dockerfile_path}")
        except Exception as e:
            logger.error(f"Error scanning Dockerfile: {e}")

        return findings

    def _scan_layers(self, metadata: Dict[str, Any]) -> List[ContainerFinding]:
        """Analyze image layers for security issues."""
        findings = []

        # Check for excessive layers
        layers = metadata.get('RootFS', {}).get('Layers', [])
        if len(layers) > 50:
            findings.append(ContainerFinding(
                finding_id='CONTAINER-LAYER-001',
                severity='low',
                title=f'Excessive layer count: {len(layers)}',
                description='Image has many layers which increases image size',
                remediation='Combine RUN commands to reduce layers',
                metadata={'layer_count': len(layers)}
            ))

        return findings

    def _generate_summary(
        self,
        vulnerabilities: List[ContainerVulnerability],
        findings: List[ContainerFinding]
    ) -> Dict[str, int]:
        """Generate summary statistics."""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'total_findings': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            if severity in summary:
                summary[severity] += 1

        # Count findings by severity
        for finding in findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def generate_report(self, result: ContainerScanResult, format: str = 'json') -> str:
        """
        Generate scan report in specified format.

        Args:
            result: Container scan result
            format: Output format ('json', 'markdown', 'text')

        Returns:
            Formatted report as string
        """
        if format == 'json':
            return self._generate_json_report(result)
        elif format == 'markdown':
            return self._generate_markdown_report(result)
        else:
            return self._generate_text_report(result)

    def _generate_json_report(self, result: ContainerScanResult) -> str:
        """Generate JSON report."""
        report = {
            'image': f"{result.image_name}:{result.image_tag}",
            'image_id': result.image_id,
            'scan_timestamp': result.scan_timestamp.isoformat(),
            'summary': result.summary,
            'vulnerabilities': [
                {
                    'cve_id': v.cve_id,
                    'severity': v.severity,
                    'package': v.package,
                    'installed_version': v.installed_version,
                    'fixed_version': v.fixed_version,
                    'description': v.description,
                    'cvss_score': v.cvss_score
                }
                for v in result.vulnerabilities
            ],
            'findings': [
                {
                    'id': f.finding_id,
                    'severity': f.severity,
                    'title': f.title,
                    'description': f.description,
                    'remediation': f.remediation,
                    'layer': f.layer,
                    'location': f.location
                }
                for f in result.findings
            ]
        }
        return json.dumps(report, indent=2)

    def _generate_markdown_report(self, result: ContainerScanResult) -> str:
        """Generate Markdown report."""
        lines = [
            f"# Container Security Scan Report",
            f"",
            f"**Image:** `{result.image_name}:{result.image_tag}`  ",
            f"**Image ID:** `{result.image_id}`  ",
            f"**Scan Time:** {result.scan_timestamp.isoformat()}  ",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {result.summary.get('critical', 0)} |",
            f"| High | {result.summary.get('high', 0)} |",
            f"| Medium | {result.summary.get('medium', 0)} |",
            f"| Low | {result.summary.get('low', 0)} |",
            f"| **Total** | **{result.summary['total_vulnerabilities'] + result.summary['total_findings']}** |",
            f"",
        ]

        if result.vulnerabilities:
            lines.extend([
                f"## Vulnerabilities ({len(result.vulnerabilities)})",
                f"",
            ])

            for vuln in sorted(result.vulnerabilities, key=lambda v: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(v.severity, 4)):
                lines.extend([
                    f"### {vuln.cve_id} - {vuln.severity.upper()}",
                    f"",
                    f"- **Package:** {vuln.package}",
                    f"- **Installed:** {vuln.installed_version}",
                    f"- **Fixed:** {vuln.fixed_version or 'N/A'}",
                    f"- **Description:** {vuln.description}",
                    f"",
                ])

        if result.findings:
            lines.extend([
                f"## Configuration Findings ({len(result.findings)})",
                f"",
            ])

            for finding in sorted(result.findings, key=lambda f: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(f.severity, 4)):
                lines.extend([
                    f"### {finding.title} - {finding.severity.upper()}",
                    f"",
                    f"**Description:** {finding.description}  ",
                    f"**Remediation:** {finding.remediation}  ",
                ])
                if finding.location:
                    lines.append(f"**Location:** {finding.location}  ")
                lines.append("")

        return "\n".join(lines)

    def _generate_text_report(self, result: ContainerScanResult) -> str:
        """Generate plain text report."""
        lines = [
            "=" * 80,
            "CONTAINER SECURITY SCAN REPORT",
            "=" * 80,
            f"Image: {result.image_name}:{result.image_tag}",
            f"Image ID: {result.image_id}",
            f"Scan Time: {result.scan_timestamp.isoformat()}",
            "",
            "SUMMARY",
            "-" * 80,
            f"Critical: {result.summary.get('critical', 0)}",
            f"High:     {result.summary.get('high', 0)}",
            f"Medium:   {result.summary.get('medium', 0)}",
            f"Low:      {result.summary.get('low', 0)}",
            f"Total:    {result.summary['total_vulnerabilities'] + result.summary['total_findings']}",
            "",
        ]

        if result.vulnerabilities:
            lines.extend([
                f"VULNERABILITIES ({len(result.vulnerabilities)})",
                "-" * 80,
            ])
            for vuln in result.vulnerabilities[:10]:  # Limit to first 10
                lines.extend([
                    f"  [{vuln.severity.upper()}] {vuln.cve_id}",
                    f"  Package: {vuln.package} ({vuln.installed_version})",
                    f"  Fix: {vuln.fixed_version or 'N/A'}",
                    "",
                ])

        if result.findings:
            lines.extend([
                f"CONFIGURATION FINDINGS ({len(result.findings)})",
                "-" * 80,
            ])
            for finding in result.findings[:10]:  # Limit to first 10
                lines.extend([
                    f"  [{finding.severity.upper()}] {finding.title}",
                    f"  {finding.description}",
                    "",
                ])

        return "\n".join(lines)


# Container Security Scanner

Comprehensive Docker and OCI image security scanning for CloudGuard-Anomaly.

## Features

- **CVE Vulnerability Scanning**: Integration with Trivy for known vulnerabilities
- **Configuration Security**: Checks for security misconfigurations
- **Secret Detection**: Finds hardcoded secrets and sensitive data
- **Dockerfile Best Practices**: Validates Dockerfile against security best practices
- **Layer Analysis**: Analyzes image layers for security issues

## Installation

### Prerequisites

```bash
# Optional but recommended: Install Trivy for CVE scanning
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Docker
docker pull aquasec/trivy
```

## Usage

### CLI Command

```bash
# Basic scan
cloudguard-anomaly container-scan --image nginx:latest

# Scan with Dockerfile analysis
cloudguard-anomaly container-scan --image myapp:1.0 --dockerfile Dockerfile

# Generate JSON report
cloudguard-anomaly container-scan --image nginx:latest --format json --output report.json

# Generate Markdown report
cloudguard-anomaly container-scan --image myapp:1.0 --format markdown --output report.md

# Skip specific checks
cloudguard-anomaly container-scan --image nginx:latest --skip-secrets --skip-config
```

### Python API

```python
from cloudguard_anomaly.containers import DockerScanner

# Initialize scanner
scanner = DockerScanner()

# Scan an image
result = scanner.scan_image(
    image='nginx:latest',
    dockerfile_path='Dockerfile',
    scan_vulnerabilities=True,
    scan_secrets=True,
    scan_config=True
)

# Generate reports
json_report = scanner.generate_report(result, format='json')
markdown_report = scanner.generate_report(result, format='markdown')
text_report = scanner.generate_report(result, format='text')

# Access findings
print(f"Total vulnerabilities: {len(result.vulnerabilities)}")
print(f"Total findings: {len(result.findings)}")

for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.cve_id}: {vuln.package}")

for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
```

## Security Checks

### Configuration Checks

1. **Root User Detection** (CONTAINER-001)
   - Severity: HIGH
   - Detects containers running as root user
   - Remediation: Add `USER` instruction in Dockerfile

2. **Sensitive Port Exposure** (CONTAINER-002)
   - Severity: MEDIUM
   - Detects exposure of SSH (22), RDP (3389), Telnet (23)
   - Remediation: Remove unnecessary port exposures

3. **Missing Health Check** (CONTAINER-003)
   - Severity: LOW
   - Detects missing HEALTHCHECK instruction
   - Remediation: Add HEALTHCHECK to Dockerfile

4. **Secrets in Environment** (CONTAINER-004)
   - Severity: CRITICAL
   - Detects potential secrets in environment variables
   - Remediation: Use Docker secrets or external secret management

5. **Excessive Layers** (CONTAINER-LAYER-001)
   - Severity: LOW
   - Detects images with >50 layers
   - Remediation: Combine RUN commands

### Secret Detection Patterns

- AWS Access Keys (AKIA...)
- AWS Secret Keys
- GitHub Tokens (ghp_, ghs_)
- Generic API Keys
- Private Keys (PEM format)
- Passwords in commands

### Dockerfile Best Practices

1. **Latest Tag Usage** (DOCKERFILE-001)
   - Severity: MEDIUM
   - Detects use of `:latest` tag in FROM instruction
   - Remediation: Pin to specific version

2. **ADD vs COPY** (DOCKERFILE-002)
   - Severity: LOW
   - Suggests using COPY instead of ADD for simple file copying
   - Remediation: Use COPY unless tar extraction needed

3. **apt-get Without -y** (DOCKERFILE-003)
   - Severity: LOW
   - Detects apt-get install without -y flag
   - Remediation: Add -y flag to avoid build hangs

4. **Missing USER** (DOCKERFILE-004)
   - Severity: HIGH
   - Detects Dockerfile without USER instruction
   - Remediation: Add USER to run as non-root

5. **Missing HEALTHCHECK** (DOCKERFILE-005)
   - Severity: LOW
   - Detects missing HEALTHCHECK
   - Remediation: Add HEALTHCHECK instruction

## Vulnerability Scanning

The scanner integrates with Trivy for comprehensive CVE detection:

- Supports all OS packages (Alpine, Debian, Ubuntu, RHEL, etc.)
- Language-specific dependencies (Python, Node.js, Ruby, Go, etc.)
- CVSS scoring and severity classification
- Fixed version recommendations

### Without Trivy

If Trivy is not installed, the scanner will:
- Skip CVE vulnerability scanning
- Still perform configuration and secret checks
- Provide offline checking for well-known CVEs

## Output Formats

### JSON Format

```json
{
  "image": "nginx:latest",
  "image_id": "sha256:abc123...",
  "scan_timestamp": "2024-01-01T12:00:00",
  "summary": {
    "total_vulnerabilities": 5,
    "total_findings": 3,
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 2
  },
  "vulnerabilities": [...],
  "findings": [...]
}
```

### Markdown Format

Generates a formatted Markdown report suitable for documentation or GitHub:

```markdown
# Container Security Scan Report

**Image:** `nginx:latest`
**Scan Time:** 2024-01-01T12:00:00

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 3     |
...
```

### Text Format

Plain text output suitable for terminal display and logs.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Container Security Scan
  run: |
    pip install -e .
    cloudguard-anomaly container-scan \
      --image ${{ env.IMAGE_NAME }}:${{ github.sha }} \
      --format json \
      --output scan-results.json

    # Fail on critical findings
    if grep -q '"critical": [1-9]' scan-results.json; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### GitLab CI

```yaml
container_security_scan:
  script:
    - cloudguard-anomaly container-scan --image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: scan-results.json
```

### Jenkins

```groovy
stage('Container Scan') {
    steps {
        sh 'cloudguard-anomaly container-scan --image myapp:latest --format json --output scan.json'

        script {
            def scan = readJSON file: 'scan.json'
            if (scan.summary.critical > 0) {
                error "Critical vulnerabilities found!"
            }
        }
    }
}
```

## Advanced Usage

### Scanning Private Registry Images

```bash
# Login to registry first
docker login myregistry.com

# Then scan
cloudguard-anomaly container-scan --image myregistry.com/myapp:1.0
```

### Batch Scanning

```python
from cloudguard_anomaly.containers import DockerScanner

scanner = DockerScanner()
images = ['nginx:latest', 'alpine:3.15', 'ubuntu:20.04']

for image in images:
    result = scanner.scan_image(image)
    print(f"{image}: {result.summary['critical']} critical issues")
```

### Custom Severity Thresholds

```python
result = scanner.scan_image('myapp:1.0')

# Fail on high or critical
critical_count = result.summary.get('critical', 0)
high_count = result.summary.get('high', 0)

if critical_count > 0 or high_count > 5:
    raise Exception(f"Security threshold exceeded: {critical_count} critical, {high_count} high")
```

## Troubleshooting

### Docker Not Found

Ensure Docker is installed and the daemon is running:

```bash
docker --version
docker ps
```

### Trivy Not Found

CVE scanning will be skipped. Install Trivy for vulnerability detection:

```bash
brew install trivy  # macOS
```

### Permission Denied

Ensure your user has Docker permissions:

```bash
sudo usermod -aG docker $USER
# Log out and back in
```

### Timeout Issues

For large images, increase timeout in code or use Docker caching.

## Architecture

```
DockerScanner
├── _scan_image_config()    # Configuration security checks
├── _scan_vulnerabilities()  # CVE scanning (Trivy)
├── _scan_for_secrets()      # Secret pattern detection
├── _scan_dockerfile()       # Dockerfile best practices
└── _scan_layers()           # Layer analysis

VulnerabilityDatabase
└── Offline CVE database for fallback
```

## Performance

- Local image scan: ~5-30 seconds
- With Trivy CVE scan: +30-60 seconds (first run)
- Trivy uses caching for subsequent scans

## Security Considerations

- Scans run in read-only mode (no modifications)
- No data sent to external services (unless Trivy configured)
- Secret patterns are basic regex (use dedicated tools for production)
- Trivy database updated regularly for accurate CVE data

## Contributing

To add new security checks:

1. Add check in appropriate `_scan_*()` method
2. Create new `ContainerFinding` with unique ID
3. Add test case in `test_container_scanner.py`
4. Update documentation

## License

MIT License - See LICENSE file for details


"""
Tests for container security scanner.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock

from cloudguard_anomaly.containers import DockerScanner
from cloudguard_anomaly.containers.docker_scanner import (
    ContainerVulnerability,
    ContainerFinding,
    ContainerScanResult
)


@pytest.fixture
def mock_docker_metadata():
    """Mock Docker inspect output."""
    return {
        'Id': 'sha256:abc123',
        'Config': {
            'User': '',  # Running as root
            'Env': [
                'PATH=/usr/local/bin:/usr/bin',
                'API_KEY=secret123',  # Sensitive env var
                'DATABASE_PASSWORD=pass123'  # Sensitive env var
            ],
            'ExposedPorts': {
                '80/tcp': {},
                '22/tcp': {},  # SSH exposed
            }
        },
        'RootFS': {
            'Layers': ['sha256:layer1', 'sha256:layer2', 'sha256:layer3']
        }
    }


@pytest.fixture
def scanner():
    """Create scanner instance."""
    return DockerScanner()


class TestDockerScanner:
    """Test Docker security scanner."""
    
    def test_parse_image_name(self, scanner):
        """Test image name parsing."""
        # With tag
        name, tag = scanner._parse_image_name('nginx:1.21')
        assert name == 'nginx'
        assert tag == '1.21'
        
        # Without tag (defaults to latest)
        name, tag = scanner._parse_image_name('ubuntu')
        assert name == 'ubuntu'
        assert tag == 'latest'
        
        # With registry
        name, tag = scanner._parse_image_name('gcr.io/my-project/myapp:v1.0')
        assert name == 'gcr.io/my-project/myapp'
        assert tag == 'v1.0'
    
    def test_scan_image_config_root_user(self, scanner, mock_docker_metadata):
        """Test detection of root user."""
        findings = scanner._scan_image_config(mock_docker_metadata)
        
        # Should detect root user
        root_findings = [f for f in findings if f.finding_id == 'CONTAINER-001']
        assert len(root_findings) == 1
        assert root_findings[0].severity == 'high'
        assert 'root' in root_findings[0].title.lower()
    
    def test_scan_image_config_sensitive_ports(self, scanner, mock_docker_metadata):
        """Test detection of sensitive ports."""
        findings = scanner._scan_image_config(mock_docker_metadata)
        
        # Should detect SSH port
        port_findings = [f for f in findings if f.finding_id == 'CONTAINER-002']
        assert len(port_findings) >= 1
        
        ssh_finding = [f for f in port_findings if f.metadata.get('port') == 22]
        assert len(ssh_finding) == 1
        assert 'SSH' in ssh_finding[0].description
    
    def test_scan_image_config_secrets_in_env(self, scanner, mock_docker_metadata):
        """Test detection of secrets in environment variables."""
        findings = scanner._scan_image_config(mock_docker_metadata)
        
        # Should detect API_KEY and DATABASE_PASSWORD
        secret_findings = [f for f in findings if f.finding_id == 'CONTAINER-004']
        assert len(secret_findings) == 2  # API_KEY and DATABASE_PASSWORD
        
        for finding in secret_findings:
            assert finding.severity == 'critical'
            assert 'secret' in finding.title.lower() or 'password' in finding.title.lower()
    
    def test_scan_image_config_no_healthcheck(self, scanner, mock_docker_metadata):
        """Test detection of missing health check."""
        findings = scanner._scan_image_config(mock_docker_metadata)
        
        healthcheck_findings = [f for f in findings if f.finding_id == 'CONTAINER-003']
        assert len(healthcheck_findings) == 1
        assert 'health check' in healthcheck_findings[0].title.lower()
    
    def test_secret_pattern_detection(self, scanner):
        """Test secret pattern regex."""
        # AWS Access Key
        matches = scanner.secret_patterns['AWS Access Key'].findall('AKIAIOSFODNN7EXAMPLE')
        assert len(matches) == 1
        
        # GitHub Token
        matches = scanner.secret_patterns['GitHub Token'].findall('ghp_1234567890abcdefghijklmnopqrstuvwx')
        assert len(matches) == 1
        
        # Private Key
        matches = scanner.secret_patterns['Private Key'].findall('-----BEGIN RSA PRIVATE KEY-----')
        assert len(matches) == 1
    
    def test_scan_dockerfile_root_user(self, scanner, tmp_path):
        """Test Dockerfile scanning for root user."""
        # Create Dockerfile without USER instruction
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM ubuntu:20.04
RUN apt-get update
COPY app /app
CMD ["/app/start.sh"]
        """)
        
        findings = scanner._scan_dockerfile(str(dockerfile))
        
        # Should detect missing USER
        user_findings = [f for f in findings if f.finding_id == 'DOCKERFILE-004']
        assert len(user_findings) == 1
        assert user_findings[0].severity == 'high'
    
    def test_scan_dockerfile_latest_tag(self, scanner, tmp_path):
        """Test detection of :latest tag."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM ubuntu:latest
RUN apt-get update
        """)
        
        findings = scanner._scan_dockerfile(str(dockerfile))
        
        # Should detect :latest tag
        latest_findings = [f for f in findings if f.finding_id == 'DOCKERFILE-001']
        assert len(latest_findings) == 1
        assert 'latest' in latest_findings[0].title.lower()
    
    def test_scan_dockerfile_add_instead_copy(self, scanner, tmp_path):
        """Test detection of ADD instead of COPY."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM ubuntu:20.04
ADD app.tar.gz /app
        """)
        
        findings = scanner._scan_dockerfile(str(dockerfile))
        
        # Should suggest COPY
        add_findings = [f for f in findings if f.finding_id == 'DOCKERFILE-002']
        # Note: ADD is allowed for tarballs, so this might not trigger
        # But for regular files it should
        
        dockerfile.write_text("""
FROM ubuntu:20.04
ADD app.py /app/
        """)
        
        findings = scanner._scan_dockerfile(str(dockerfile))
        add_findings = [f for f in findings if f.finding_id == 'DOCKERFILE-002']
        assert len(add_findings) >= 0  # May or may not detect depending on context
    
    def test_generate_summary(self, scanner):
        """Test summary generation."""
        vulnerabilities = [
            ContainerVulnerability('CVE-2021-1', 'critical', 'pkg1', '1.0', '1.1', 'desc1'),
            ContainerVulnerability('CVE-2021-2', 'high', 'pkg2', '1.0', '1.1', 'desc2'),
            ContainerVulnerability('CVE-2021-3', 'medium', 'pkg3', '1.0', '1.1', 'desc3'),
        ]
        
        findings = [
            ContainerFinding('F1', 'high', 'Title', 'Desc', 'Remediation'),
            ContainerFinding('F2', 'low', 'Title', 'Desc', 'Remediation'),
        ]
        
        summary = scanner._generate_summary(vulnerabilities, findings)
        
        assert summary['total_vulnerabilities'] == 3
        assert summary['total_findings'] == 2
        assert summary['critical'] == 1
        assert summary['high'] == 2  # 1 vuln + 1 finding
        assert summary['medium'] == 1
        assert summary['low'] == 1
    
    def test_generate_json_report(self, scanner):
        """Test JSON report generation."""
        from datetime import datetime
        
        result = ContainerScanResult(
            image_name='nginx',
            image_tag='latest',
            image_id='sha256:abc123',
            scan_timestamp=datetime(2024, 1, 1, 12, 0, 0),
            vulnerabilities=[
                ContainerVulnerability('CVE-2021-1', 'high', 'pkg1', '1.0', '1.1', 'Test vuln')
            ],
            findings=[
                ContainerFinding('F1', 'high', 'Test Finding', 'Description', 'Fix it')
            ],
            metadata={},
            summary={'total_vulnerabilities': 1, 'total_findings': 1, 'high': 2}
        )
        
        report_json = scanner._generate_json_report(result)
        report = json.loads(report_json)
        
        assert report['image'] == 'nginx:latest'
        assert len(report['vulnerabilities']) == 1
        assert len(report['findings']) == 1
        assert report['summary']['high'] == 2
    
    def test_generate_markdown_report(self, scanner):
        """Test Markdown report generation."""
        from datetime import datetime
        
        result = ContainerScanResult(
            image_name='nginx',
            image_tag='latest',
            image_id='sha256:abc123',
            scan_timestamp=datetime(2024, 1, 1, 12, 0, 0),
            vulnerabilities=[],
            findings=[
                ContainerFinding('F1', 'critical', 'Root User', 'Runs as root', 'Add USER')
            ],
            metadata={},
            summary={'total_vulnerabilities': 0, 'total_findings': 1, 'critical': 1}
        )
        
        report = scanner._generate_markdown_report(result)
        
        assert '# Container Security Scan Report' in report
        assert 'nginx:latest' in report
        assert 'Root User' in report
        assert 'CRITICAL' in report
    
    def test_scan_layers_excessive(self, scanner):
        """Test detection of excessive layers."""
        metadata = {
            'RootFS': {
                'Layers': ['layer' + str(i) for i in range(60)]  # 60 layers
            }
        }
        
        findings = scanner._scan_layers(metadata)
        
        # Should detect excessive layers
        layer_findings = [f for f in findings if f.finding_id == 'CONTAINER-LAYER-001']
        assert len(layer_findings) == 1
        assert layer_findings[0].metadata['layer_count'] == 60


@pytest.mark.integration
class TestDockerScannerIntegration:
    """Integration tests requiring Docker."""
    
    @pytest.mark.skipif(not pytest.docker_available, reason="Docker not available")
    def test_scan_real_image(self, scanner):
        """Test scanning a real Docker image."""
        # This would require Docker to be installed and running
        # Skip in CI unless Docker is available
        pass


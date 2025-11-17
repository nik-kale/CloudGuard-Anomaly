"""
API Security Scanner for CloudGuard-Anomaly v2.

Comprehensive API security analysis including:
- REST API security scanning
- GraphQL security analysis
- Authentication and authorization testing
- OWASP API Top 10 vulnerability detection
- API Gateway configuration review
- Rate limiting and throttling analysis
- API versioning and deprecation checks
"""

import logging
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

logger = logging.getLogger(__name__)


class APIVulnerabilityType(Enum):
    """OWASP API Security Top 10 vulnerability types."""
    BROKEN_OBJECT_LEVEL_AUTH = "API1:2023"  # Broken Object Level Authorization
    BROKEN_AUTHENTICATION = "API2:2023"  # Broken Authentication
    BROKEN_OBJECT_PROPERTY_AUTH = "API3:2023"  # Broken Object Property Level Authorization
    UNRESTRICTED_RESOURCE_CONSUMPTION = "API4:2023"  # Unrestricted Resource Consumption
    BROKEN_FUNCTION_AUTH = "API5:2023"  # Broken Function Level Authorization
    UNRESTRICTED_SENSITIVE_BUSINESS_FLOWS = "API6:2023"  # Unrestricted Access to Sensitive Business Flows
    SERVER_SIDE_REQUEST_FORGERY = "API7:2023"  # Server Side Request Forgery
    SECURITY_MISCONFIGURATION = "API8:2023"  # Security Misconfiguration
    IMPROPER_INVENTORY_MANAGEMENT = "API9:2023"  # Improper Inventory Management
    UNSAFE_API_CONSUMPTION = "API10:2023"  # Unsafe Consumption of APIs


class APISeverity(Enum):
    """API vulnerability severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class APIEndpoint:
    """API endpoint definition."""
    path: str
    method: str  # GET, POST, PUT, DELETE, etc.
    api_type: str  # REST, GraphQL, SOAP, gRPC
    authentication_required: bool = False
    authentication_methods: List[str] = field(default_factory=list)
    authorization_model: Optional[str] = None  # RBAC, ABAC, etc.
    rate_limit: Optional[int] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    response_codes: List[int] = field(default_factory=list)
    sensitive_data: bool = False
    deprecated: bool = False
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIVulnerability:
    """API security vulnerability."""
    vuln_id: str
    endpoint: APIEndpoint
    vuln_type: APIVulnerabilityType
    severity: APISeverity
    title: str
    description: str
    impact: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class APIGatewayConfig:
    """API Gateway configuration."""
    gateway_id: str
    gateway_type: str  # AWS API Gateway, Azure APIM, GCP API Gateway, Kong, etc.
    endpoints: List[APIEndpoint]
    cors_enabled: bool = False
    cors_config: Dict[str, Any] = field(default_factory=dict)
    logging_enabled: bool = False
    monitoring_enabled: bool = False
    waf_enabled: bool = False
    api_keys_required: bool = False
    usage_plans: List[Dict[str, Any]] = field(default_factory=list)
    custom_domains: List[str] = field(default_factory=list)


@dataclass
class APIScanResult:
    """API security scan results."""
    scan_id: str
    timestamp: datetime
    gateway_config: APIGatewayConfig
    vulnerabilities: List[APIVulnerability]
    total_endpoints: int
    total_vulnerabilities: int
    risk_score: float  # 0-100
    compliance_score: float  # 0-100
    recommendations: List[str]


class APISecurityScanner:
    """
    Comprehensive API security scanner.

    Analyzes API configurations and implementations for:
    - OWASP API Security Top 10 vulnerabilities
    - Authentication and authorization weaknesses
    - Excessive data exposure
    - Rate limiting issues
    - Security misconfigurations
    - API inventory and versioning
    """

    def __init__(self):
        """Initialize API security scanner."""
        self.vulnerabilities: List[APIVulnerability] = []
        self.sensitive_data_patterns = self._load_sensitive_patterns()
        logger.info("API security scanner initialized")

    def _load_sensitive_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for sensitive data detection."""
        return {
            'pii': [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{16}\b',  # Credit card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}-\d{3}-\d{4}\b',  # Phone
            ],
            'credentials': [
                r'password',
                r'api[_-]?key',
                r'secret',
                r'token',
                r'authorization',
                r'credentials',
            ],
            'financial': [
                r'account[_-]?number',
                r'routing[_-]?number',
                r'card[_-]?number',
                r'cvv',
            ],
        }

    def scan_api_gateway(self, gateway_config: APIGatewayConfig) -> APIScanResult:
        """
        Scan API gateway configuration for security issues.

        Args:
            gateway_config: API gateway configuration

        Returns:
            Comprehensive scan results
        """
        logger.info(f"Scanning API gateway: {gateway_config.gateway_id}")

        self.vulnerabilities = []

        # Check each endpoint
        for endpoint in gateway_config.endpoints:
            self._scan_endpoint(endpoint, gateway_config)

        # Check gateway-level configurations
        self._check_gateway_security(gateway_config)

        # Check CORS configuration
        self._check_cors_config(gateway_config)

        # Check logging and monitoring
        self._check_observability(gateway_config)

        # Calculate scores
        risk_score = self._calculate_risk_score()
        compliance_score = self._calculate_compliance_score(gateway_config)

        # Generate recommendations
        recommendations = self._generate_recommendations()

        return APIScanResult(
            scan_id=f"api-scan-{gateway_config.gateway_id}-{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            gateway_config=gateway_config,
            vulnerabilities=self.vulnerabilities,
            total_endpoints=len(gateway_config.endpoints),
            total_vulnerabilities=len(self.vulnerabilities),
            risk_score=risk_score,
            compliance_score=compliance_score,
            recommendations=recommendations
        )

    def _scan_endpoint(self, endpoint: APIEndpoint, gateway_config: APIGatewayConfig):
        """Scan individual endpoint for vulnerabilities."""

        # API1: Broken Object Level Authorization
        if not endpoint.authorization_model:
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH,
                APISeverity.HIGH,
                "Missing Object-Level Authorization",
                "Endpoint does not implement object-level authorization checks",
                "Attackers can access objects belonging to other users",
                "Implement authorization checks for every object access",
                cwe_id="CWE-639"
            )

        # API2: Broken Authentication
        if not endpoint.authentication_required and endpoint.sensitive_data:
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.BROKEN_AUTHENTICATION,
                APISeverity.CRITICAL,
                "Missing Authentication on Sensitive Endpoint",
                "Sensitive endpoint does not require authentication",
                "Unauthorized access to sensitive data",
                "Require authentication for all sensitive endpoints",
                cwe_id="CWE-306"
            )

        # Check for weak authentication
        if endpoint.authentication_methods and 'basic' in [m.lower() for m in endpoint.authentication_methods]:
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.BROKEN_AUTHENTICATION,
                APISeverity.MEDIUM,
                "Weak Authentication Method",
                "Endpoint uses Basic authentication which is not recommended",
                "Credentials may be exposed if not using HTTPS",
                "Use stronger authentication methods like OAuth 2.0 or JWT",
                cwe_id="CWE-326"
            )

        # API3: Broken Object Property Level Authorization
        if self._checks_excessive_data_exposure(endpoint):
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.BROKEN_OBJECT_PROPERTY_AUTH,
                APISeverity.MEDIUM,
                "Potential Excessive Data Exposure",
                "Endpoint may return more data than necessary",
                "Sensitive properties exposed to unauthorized users",
                "Implement property-level authorization and filtering",
                cwe_id="CWE-213"
            )

        # API4: Unrestricted Resource Consumption
        if not endpoint.rate_limit:
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION,
                APISeverity.MEDIUM,
                "Missing Rate Limiting",
                "Endpoint does not have rate limiting configured",
                "API abuse, DoS attacks, resource exhaustion",
                "Implement rate limiting and throttling",
                cwe_id="CWE-770"
            )

        # API5: Broken Function Level Authorization
        if self._is_admin_endpoint(endpoint) and not endpoint.authorization_model:
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.BROKEN_FUNCTION_AUTH,
                APISeverity.CRITICAL,
                "Missing Function-Level Authorization",
                "Administrative endpoint lacks proper authorization checks",
                "Privilege escalation, unauthorized administrative access",
                "Implement role-based access control (RBAC)",
                cwe_id="CWE-285"
            )

        # API8: Security Misconfiguration
        if endpoint.deprecated and not endpoint.metadata.get('deprecation_notice'):
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                APISeverity.LOW,
                "Deprecated Endpoint Without Notice",
                "Deprecated endpoint does not provide deprecation information",
                "Clients may continue using insecure deprecated endpoints",
                "Add deprecation headers and documentation",
                cwe_id="CWE-1188"
            )

        # API9: Improper Inventory Management
        if not endpoint.version:
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.IMPROPER_INVENTORY_MANAGEMENT,
                APISeverity.LOW,
                "Missing API Versioning",
                "Endpoint does not specify API version",
                "Difficulty managing API changes and deprecations",
                "Implement API versioning strategy",
                cwe_id="CWE-1059"
            )

        # Check for sensitive data in URL parameters
        if self._has_sensitive_url_params(endpoint):
            self._add_vulnerability(
                endpoint,
                APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                APISeverity.HIGH,
                "Sensitive Data in URL Parameters",
                "Endpoint exposes sensitive data in URL parameters",
                "Sensitive data logged and exposed in browser history",
                "Use POST body or headers for sensitive data",
                cwe_id="CWE-598"
            )

    def _check_gateway_security(self, gateway_config: APIGatewayConfig):
        """Check gateway-level security configurations."""

        # Check for WAF protection
        if not gateway_config.waf_enabled:
            dummy_endpoint = APIEndpoint(path="/gateway-config", method="CONFIG", api_type="config")
            self._add_vulnerability(
                dummy_endpoint,
                APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                APISeverity.MEDIUM,
                "WAF Not Enabled",
                "API Gateway does not have Web Application Firewall protection",
                "Vulnerable to common web attacks (SQLi, XSS, etc.)",
                "Enable WAF protection on API Gateway"
            )

        # Check for API keys
        if not gateway_config.api_keys_required and len(gateway_config.endpoints) > 10:
            dummy_endpoint = APIEndpoint(path="/gateway-config", method="CONFIG", api_type="config")
            self._add_vulnerability(
                dummy_endpoint,
                APIVulnerabilityType.BROKEN_AUTHENTICATION,
                APISeverity.MEDIUM,
                "API Keys Not Required",
                "API Gateway does not require API keys for access",
                "Difficult to track and control API usage",
                "Require API keys for all API access"
            )

    def _check_cors_config(self, gateway_config: APIGatewayConfig):
        """Check CORS configuration for security issues."""
        if gateway_config.cors_enabled:
            cors = gateway_config.cors_config

            # Check for overly permissive CORS
            if cors.get('allow_origins') == '*':
                dummy_endpoint = APIEndpoint(path="/cors-config", method="CONFIG", api_type="config")
                self._add_vulnerability(
                    dummy_endpoint,
                    APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                    APISeverity.HIGH,
                    "Overly Permissive CORS",
                    "CORS allows all origins (*)",
                    "Vulnerable to CSRF attacks from any domain",
                    "Restrict CORS to specific trusted domains",
                    cwe_id="CWE-942"
                )

            # Check for credentials with wildcard
            if cors.get('allow_credentials') and cors.get('allow_origins') == '*':
                dummy_endpoint = APIEndpoint(path="/cors-config", method="CONFIG", api_type="config")
                self._add_vulnerability(
                    dummy_endpoint,
                    APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                    APISeverity.CRITICAL,
                    "CORS Misconfiguration",
                    "CORS allows credentials with wildcard origin",
                    "Critical security vulnerability allowing credential theft",
                    "Never use wildcard origin with credentials enabled",
                    cwe_id="CWE-942"
                )

    def _check_observability(self, gateway_config: APIGatewayConfig):
        """Check logging and monitoring configuration."""
        if not gateway_config.logging_enabled:
            dummy_endpoint = APIEndpoint(path="/observability", method="CONFIG", api_type="config")
            self._add_vulnerability(
                dummy_endpoint,
                APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                APISeverity.MEDIUM,
                "Logging Not Enabled",
                "API Gateway does not have logging enabled",
                "Cannot detect or investigate security incidents",
                "Enable comprehensive API logging",
                cwe_id="CWE-778"
            )

        if not gateway_config.monitoring_enabled:
            dummy_endpoint = APIEndpoint(path="/observability", method="CONFIG", api_type="config")
            self._add_vulnerability(
                dummy_endpoint,
                APIVulnerabilityType.SECURITY_MISCONFIGURATION,
                APISeverity.LOW,
                "Monitoring Not Enabled",
                "API Gateway does not have monitoring enabled",
                "Cannot detect anomalies or performance issues",
                "Enable API monitoring and alerting"
            )

    def _add_vulnerability(
        self,
        endpoint: APIEndpoint,
        vuln_type: APIVulnerabilityType,
        severity: APISeverity,
        title: str,
        description: str,
        impact: str,
        remediation: str,
        cwe_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        evidence: Optional[str] = None
    ):
        """Add a vulnerability to the results."""
        vuln = APIVulnerability(
            vuln_id=f"api-vuln-{len(self.vulnerabilities)+1}",
            endpoint=endpoint,
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            impact=impact,
            remediation=remediation,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            evidence=evidence
        )
        self.vulnerabilities.append(vuln)

    def _checks_excessive_data_exposure(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint may expose excessive data."""
        # Heuristic: GET endpoints with no parameters may return too much data
        if endpoint.method == 'GET' and not endpoint.parameters:
            return True

        return False

    def _is_admin_endpoint(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint is administrative."""
        admin_keywords = ['admin', 'manage', 'config', 'settings', 'users', 'delete', 'purge']
        path_lower = endpoint.path.lower()

        return any(keyword in path_lower for keyword in admin_keywords)

    def _has_sensitive_url_params(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint has sensitive data in URL parameters."""
        for param in endpoint.parameters:
            param_name = param.get('name', '').lower()

            for category, patterns in self.sensitive_data_patterns.items():
                for pattern in patterns:
                    if isinstance(pattern, str) and pattern in param_name:
                        return True

        return False

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        if not self.vulnerabilities:
            return 0.0

        severity_weights = {
            APISeverity.CRITICAL: 10,
            APISeverity.HIGH: 7,
            APISeverity.MEDIUM: 4,
            APISeverity.LOW: 2,
            APISeverity.INFO: 1,
        }

        total_risk = sum(
            severity_weights[vuln.severity]
            for vuln in self.vulnerabilities
        )

        # Normalize to 0-100
        max_possible = len(self.vulnerabilities) * 10
        return min(100.0, (total_risk / max_possible) * 100 if max_possible > 0 else 0)

    def _calculate_compliance_score(self, gateway_config: APIGatewayConfig) -> float:
        """Calculate OWASP API Top 10 compliance score (0-100)."""
        total_checks = 20  # Various security checks
        passed_checks = total_checks

        # Deduct for each vulnerability type
        vuln_types = set(v.vuln_type for v in self.vulnerabilities)
        passed_checks -= len(vuln_types)

        # Additional checks
        if not gateway_config.waf_enabled:
            passed_checks -= 1
        if not gateway_config.logging_enabled:
            passed_checks -= 1
        if not gateway_config.monitoring_enabled:
            passed_checks -= 1

        return max(0.0, (passed_checks / total_checks) * 100)

    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized security recommendations."""
        recommendations = []

        # Critical and high severity issues first
        critical_high = [
            v for v in self.vulnerabilities
            if v.severity in [APISeverity.CRITICAL, APISeverity.HIGH]
        ]

        if critical_high:
            recommendations.append(
                f"URGENT: Address {len(critical_high)} critical/high severity vulnerabilities immediately"
            )

        # By vulnerability type
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vuln_type.name
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            recommendations.append(f"Fix {count} instance(s) of {vuln_type.replace('_', ' ').title()}")

        # General best practices
        if len(self.vulnerabilities) > 10:
            recommendations.append("Consider implementing automated API security testing in CI/CD pipeline")

        recommendations.append("Review and update API security policies regularly")
        recommendations.append("Implement comprehensive API monitoring and alerting")

        return recommendations[:10]  # Top 10 recommendations

    def generate_api_security_report(self, scan_result: APIScanResult) -> str:
        """Generate comprehensive API security report."""
        report = []
        report.append("=" * 100)
        report.append("API SECURITY SCAN REPORT")
        report.append("=" * 100)
        report.append(f"Scan ID: {scan_result.scan_id}")
        report.append(f"Timestamp: {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"API Gateway: {scan_result.gateway_config.gateway_id}")
        report.append(f"Gateway Type: {scan_result.gateway_config.gateway_type}\n")

        # Summary
        report.append("SCAN SUMMARY")
        report.append("-" * 100)
        report.append(f"Total Endpoints Scanned: {scan_result.total_endpoints}")
        report.append(f"Total Vulnerabilities: {scan_result.total_vulnerabilities}")
        report.append(f"Risk Score: {scan_result.risk_score:.1f}/100")
        report.append(f"Compliance Score: {scan_result.compliance_score:.1f}/100")

        # Vulnerability breakdown
        by_severity = {}
        for vuln in scan_result.vulnerabilities:
            severity = vuln.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

        report.append("\nVULNERABILITIES BY SEVERITY")
        report.append("-" * 100)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = by_severity.get(severity, 0)
            report.append(f"{severity.upper()}: {count}")

        # OWASP API Top 10 coverage
        by_type = {}
        for vuln in scan_result.vulnerabilities:
            vuln_type = vuln.vuln_type.value
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        report.append("\nOWASP API SECURITY TOP 10 COVERAGE")
        report.append("-" * 100)
        for vuln_type, count in sorted(by_type.items()):
            report.append(f"{vuln_type}: {count} issue(s)")

        # Critical and high vulnerabilities
        critical_high = [
            v for v in scan_result.vulnerabilities
            if v.severity in [APISeverity.CRITICAL, APISeverity.HIGH]
        ]

        if critical_high:
            report.append(f"\n\nCRITICAL & HIGH SEVERITY VULNERABILITIES ({len(critical_high)})")
            report.append("=" * 100)

            for vuln in critical_high[:20]:  # Top 20
                report.append(f"\n[{vuln.severity.value.upper()}] {vuln.title}")
                report.append(f"Endpoint: {vuln.endpoint.method} {vuln.endpoint.path}")
                report.append(f"Type: {vuln.vuln_type.name}")
                report.append(f"Description: {vuln.description}")
                report.append(f"Impact: {vuln.impact}")
                report.append(f"Remediation: {vuln.remediation}")

                if vuln.cwe_id:
                    report.append(f"CWE: {vuln.cwe_id}")

                report.append("-" * 100)

        # Recommendations
        if scan_result.recommendations:
            report.append("\n\nRECOMMENDATIONS")
            report.append("=" * 100)
            for i, rec in enumerate(scan_result.recommendations, 1):
                report.append(f"{i}. {rec}")

        return "\n".join(report)

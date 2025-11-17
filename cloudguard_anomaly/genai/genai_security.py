"""
GenAI Security Monitoring for CloudGuard-Anomaly v3.

Monitor and secure GenAI/LLM usage:
- LLM API usage tracking
- Prompt injection detection
- Data leakage prevention
- Model access controls
- Training data security
- API key exposure
- Cost optimization
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class GenAIRisk(Enum):
    """GenAI security risk level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GenAISecurityFinding:
    """GenAI security finding."""
    finding_id: str
    service: str  # OpenAI, Anthropic, Bedrock, etc.
    risk_level: GenAIRisk
    title: str
    description: str
    remediation: str
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GenAIUsageMetrics:
    """GenAI usage metrics."""
    service: str
    api_calls: int
    tokens_consumed: int
    estimated_cost: float
    unique_users: int
    time_period: str


class GenAISecurityMonitor:
    """
    GenAI/LLM security monitoring.

    Monitors:
    - API key exposure
    - Prompt injection attempts
    - Excessive API usage
    - Unauthorized model access
    - Training data exposure
    - Cost anomalies
    """

    def __init__(self):
        """Initialize GenAI security monitor."""
        self.findings: List[GenAISecurityFinding] = []
        self.usage_metrics: List[GenAIUsageMetrics] = []
        self.prompt_injection_patterns = self._load_injection_patterns()
        logger.info("GenAI security monitor initialized")

    def _load_injection_patterns(self) -> List[str]:
        """Load prompt injection patterns."""
        return [
            r"ignore previous instructions",
            r"disregard above",
            r"forget all",
            r"system:.*admin",
            r"<\|endoftext\|>",
            r"###\s*(?:Human|Assistant):",
        ]

    def scan_api_keys(self, resources: List[Dict[str, Any]]) -> List[GenAISecurityFinding]:
        """Scan for exposed GenAI API keys."""
        findings = []

        api_key_patterns = {
            'openai': r'sk-[A-Za-z0-9]{32,}',
            'anthropic': r'sk-ant-[A-Za-z0-9]{32,}',
            'google': r'AIza[0-9A-Za-z_-]{35}',
        }

        for resource in resources:
            content = str(resource.get('content', ''))

            for service, pattern in api_key_patterns.items():
                import re
                if re.search(pattern, content):
                    findings.append(GenAISecurityFinding(
                        finding_id=f"genai-key-{service}-{resource.get('id')}",
                        service=service,
                        risk_level=GenAIRisk.CRITICAL,
                        title=f"Exposed {service.title()} API Key",
                        description=f"API key for {service} found in {resource.get('location')}",
                        remediation="Revoke exposed key immediately and use secrets management"
                    ))

        self.findings.extend(findings)
        return findings

    def analyze_prompt_injection(self, prompts: List[str]) -> List[GenAISecurityFinding]:
        """Analyze prompts for injection attempts."""
        findings = []

        for i, prompt in enumerate(prompts):
            prompt_lower = prompt.lower()

            for pattern in self.prompt_injection_patterns:
                import re
                if re.search(pattern, prompt_lower, re.IGNORECASE):
                    findings.append(GenAISecurityFinding(
                        finding_id=f"genai-injection-{i}",
                        service="generic",
                        risk_level=GenAIRisk.HIGH,
                        title="Potential Prompt Injection Detected",
                        description=f"Suspicious pattern detected in prompt: {pattern}",
                        remediation="Implement prompt sanitization and validation"
                    ))
                    break

        self.findings.extend(findings)
        return findings

    def monitor_usage_anomalies(
        self,
        current_usage: GenAIUsageMetrics,
        baseline_usage: GenAIUsageMetrics
    ) -> List[GenAISecurityFinding]:
        """Monitor for usage anomalies."""
        findings = []

        # Check for cost spike
        if current_usage.estimated_cost > baseline_usage.estimated_cost * 3:
            findings.append(GenAISecurityFinding(
                finding_id=f"genai-cost-spike-{current_usage.service}",
                service=current_usage.service,
                risk_level=GenAIRisk.MEDIUM,
                title="GenAI Cost Spike Detected",
                description=f"Cost increased by {((current_usage.estimated_cost / baseline_usage.estimated_cost) - 1) * 100:.0f}%",
                remediation="Review API usage and implement rate limiting"
            ))

        # Check for excessive token usage
        if current_usage.tokens_consumed > baseline_usage.tokens_consumed * 5:
            findings.append(GenAISecurityFinding(
                finding_id=f"genai-token-spike-{current_usage.service}",
                service=current_usage.service,
                risk_level=GenAIRisk.MEDIUM,
                title="Excessive Token Consumption",
                description="Token usage significantly higher than baseline",
                remediation="Investigate potential API abuse or optimization opportunities"
            ))

        self.findings.extend(findings)
        return findings

    def generate_genai_report(self) -> str:
        """Generate GenAI security report."""
        report = []
        report.append("=" * 80)
        report.append("GENAI SECURITY MONITORING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Findings: {len(self.findings)}\n")

        # By risk level
        by_risk = {}
        for finding in self.findings:
            risk = finding.risk_level.value
            by_risk[risk] = by_risk.get(risk, 0) + 1

        report.append("FINDINGS BY RISK LEVEL")
        report.append("-" * 80)
        for risk in ['critical', 'high', 'medium', 'low']:
            count = by_risk.get(risk, 0)
            report.append(f"{risk.upper()}: {count}")

        # Critical findings
        critical = [f for f in self.findings if f.risk_level == GenAIRisk.CRITICAL]

        if critical:
            report.append(f"\n\nCRITICAL FINDINGS ({len(critical)})")
            report.append("=" * 80)

            for finding in critical:
                report.append(f"\n[{finding.risk_level.value.upper()}] {finding.title}")
                report.append(f"Service: {finding.service}")
                report.append(f"Description: {finding.description}")
                report.append(f"Remediation: {finding.remediation}")
                report.append("-" * 80)

        return "\n".join(report)

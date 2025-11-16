"""
Notification system for CloudGuard-Anomaly.

Supports webhooks, Slack, Microsoft Teams, and email notifications.
"""

import logging
from typing import Optional, Dict, Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from cloudguard_anomaly.core.models import ScanResult, Finding, Severity

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Generic webhook notifier."""

    def __init__(self, webhook_url: str, timeout: int = 10):
        """
        Initialize webhook notifier.

        Args:
            webhook_url: URL to send webhooks to
            timeout: Request timeout in seconds
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests required. Install with: pip install requests")

        self.webhook_url = webhook_url
        self.timeout = timeout

    def notify_scan_complete(self, scan_result: ScanResult) -> bool:
        """
        Notify when scan completes.

        Args:
            scan_result: Completed scan result

        Returns:
            True if notification sent successfully
        """
        try:
            payload = {
                "event": "scan_complete",
                "environment": scan_result.environment.name,
                "provider": scan_result.environment.provider.value,
                "timestamp": scan_result.timestamp.isoformat(),
                "summary": {
                    "risk_score": scan_result.summary.get("risk_score", 0),
                    "total_findings": len(scan_result.findings),
                    "total_anomalies": len(scan_result.anomalies),
                    "severity_counts": scan_result.summary.get("severity_counts", {}),
                },
            }

            response = requests.post(
                self.webhook_url, json=payload, timeout=self.timeout
            )
            response.raise_for_status()

            logger.info("Scan complete notification sent successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")
            return False

    def notify_critical_finding(self, finding: Finding) -> bool:
        """Notify immediately for critical findings."""
        try:
            payload = {
                "event": "critical_finding",
                "severity": finding.severity.value,
                "title": finding.title,
                "resource": {
                    "id": finding.resource.id,
                    "name": finding.resource.name,
                    "type": finding.resource.type.value,
                },
                "description": finding.description,
                "remediation": finding.remediation,
                "timestamp": finding.timestamp.isoformat(),
            }

            response = requests.post(
                self.webhook_url, json=payload, timeout=self.timeout
            )
            response.raise_for_status()

            logger.info(f"Critical finding notification sent for {finding.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send critical finding notification: {e}")
            return False


class SlackNotifier:
    """Slack-specific notifier with rich formatting."""

    def __init__(self, webhook_url: str):
        """Initialize Slack notifier."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests required. Install with: pip install requests")

        self.webhook_url = webhook_url

    def send_scan_summary(self, scan_result: ScanResult) -> bool:
        """Send formatted scan summary to Slack."""
        try:
            critical = len(scan_result.get_critical_findings())
            high = len(scan_result.get_high_findings())
            risk_score = scan_result.summary.get("risk_score", 0)

            # Determine color based on severity
            if critical > 0:
                color = "danger"
                status = "🚨 CRITICAL ISSUES FOUND"
            elif high > 0:
                color = "warning"
                status = "⚠️ HIGH SEVERITY ISSUES"
            elif risk_score > 50:
                color = "warning"
                status = "⚡ ELEVATED RISK"
            else:
                color = "good"
                status = "✅ SCAN COMPLETE"

            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"CloudGuard Security Scan: {scan_result.environment.name}",
                        "text": status,
                        "fields": [
                            {
                                "title": "Risk Score",
                                "value": f"{risk_score}/100",
                                "short": True,
                            },
                            {
                                "title": "Total Findings",
                                "value": str(len(scan_result.findings)),
                                "short": True,
                            },
                            {
                                "title": "Critical",
                                "value": str(critical),
                                "short": True,
                            },
                            {
                                "title": "High",
                                "value": str(high),
                                "short": True,
                            },
                            {
                                "title": "Provider",
                                "value": scan_result.environment.provider.value.upper(),
                                "short": True,
                            },
                            {
                                "title": "Resources",
                                "value": str(len(scan_result.environment.resources)),
                                "short": True,
                            },
                        ],
                        "footer": "CloudGuard-Anomaly",
                        "ts": int(scan_result.timestamp.timestamp()),
                    }
                ]
            }

            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()

            logger.info("Slack notification sent successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

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
    """Slack-specific notifier with rich Block Kit formatting."""

    def __init__(self, webhook_url: str, use_blocks: bool = True):
        """
        Initialize Slack notifier.
        
        Args:
            webhook_url: Slack webhook URL
            use_blocks: Use modern Block Kit (recommended) vs legacy attachments
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests required. Install with: pip install requests")

        self.webhook_url = webhook_url
        self.use_blocks = use_blocks

    def send_scan_summary(self, scan_result: ScanResult) -> bool:
        """Send formatted scan summary to Slack using Block Kit."""
        try:
            if self.use_blocks:
                payload = self._build_blocks_payload(scan_result)
            else:
                payload = self._build_legacy_payload(scan_result)

            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()

            logger.info("Slack notification sent successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def _build_blocks_payload(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build modern Slack Block Kit payload with rich formatting."""
        critical = len(scan_result.get_critical_findings())
        high = len(scan_result.get_high_findings())
        medium = len([f for f in scan_result.findings if f.severity == Severity.MEDIUM])
        low = len([f for f in scan_result.findings if f.severity == Severity.LOW])
        risk_score = scan_result.summary.get("risk_score", 0)
        
        # Determine status emoji and text
        if critical > 0:
            status = f"🚨 *CRITICAL SECURITY ISSUES DETECTED*"
            color = "#d32f2f"
        elif high > 0:
            status = f"⚠️ *HIGH SEVERITY ISSUES FOUND*"
            color = "#f57c00"
        elif risk_score > 50:
            status = f"⚡ *ELEVATED RISK LEVEL*"
            color = "#fbc02d"
        else:
            status = f"✅ *Security Scan Complete*"
            color = "#388e3c"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"CloudGuard Security Scan Results",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": status
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Environment:*\n{scan_result.environment.name}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Provider:*\n{scan_result.environment.provider.value.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{risk_score}/100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Resources:*\n{len(scan_result.environment.resources)}"
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Findings by Severity*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*🔴 Critical:*\n{critical}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*🟠 High:*\n{high}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*🟡 Medium:*\n{medium}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*🟢 Low:*\n{low}"
                    }
                ]
            }
        ]
        
        # Add top critical findings if any
        if critical > 0:
            critical_findings = scan_result.get_critical_findings()[:3]
            
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🚨 Top Critical Findings:*"
                }
            })
            
            for finding in critical_findings:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• *{finding.title}*\n_{finding.resource.name}_ - {finding.description[:100]}..."
                    }
                })
        
        # Add context/footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"CloudGuard-Anomaly • {scan_result.timestamp.strftime('%Y-%m-%d %H:%M UTC')}"
                }
            ]
        })
        
        return {"blocks": blocks}
    
    def _build_legacy_payload(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build legacy attachment payload (for backwards compatibility)."""
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
        
        return payload
    
    def send_critical_alert(self, finding: Finding, report_url: Optional[str] = None) -> bool:
        """Send immediate alert for critical finding with action button."""
        try:
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 CRITICAL SECURITY ALERT",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{finding.title}*"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Resource:*\n{finding.resource.name}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Type:*\n{finding.resource.type.value}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{finding.severity.value.upper()}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Provider:*\n{finding.resource.provider.value.upper()}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Description:*\n{finding.description}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Remediation:*\n{finding.remediation}"
                    }
                }
            ]
            
            # Add action button if report URL provided
            if report_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "View Full Report",
                                "emoji": True
                            },
                            "url": report_url,
                            "style": "danger"
                        }
                    ]
                })
            
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Finding ID: {finding.id} • {finding.timestamp.strftime('%Y-%m-%d %H:%M UTC')}"
                    }
                ]
            })
            
            payload = {"blocks": blocks}
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info(f"Slack critical alert sent for {finding.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack critical alert: {e}")
            return False

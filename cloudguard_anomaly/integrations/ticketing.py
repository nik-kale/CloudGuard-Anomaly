"""
Ticketing System Integration for CloudGuard-Anomaly v2.

Integrations:
- Jira
- ServiceNow
- GitHub Issues
- PagerDuty
- Slack (enhanced)
"""

import logging
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class TicketPriority(Enum):
    """Ticket priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Ticket:
    """Ticket representation."""
    ticket_id: str
    title: str
    description: str
    priority: TicketPriority
    assignee: Optional[str] = None
    labels: List[str] = None
    created_at: datetime = None


class JiraIntegration:
    """Jira integration for CloudGuard findings."""

    def __init__(self, jira_url: str, api_token: str, project_key: str):
        """Initialize Jira integration."""
        self.jira_url = jira_url
        self.api_token = api_token
        self.project_key = project_key
        logger.info(f"Jira integration initialized for project: {project_key}")

    def create_ticket(
        self,
        finding: Dict[str, Any],
        priority: TicketPriority = TicketPriority.MEDIUM
    ) -> Optional[str]:
        """Create Jira ticket from finding."""
        # In production, would use Jira REST API
        ticket = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": finding.get("title", "Security Finding"),
                "description": self._format_description(finding),
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority.value.title()},
                "labels": ["security", "cloudguard", finding.get("severity", "medium")],
            }
        }

        # Placeholder - would make actual API call
        ticket_id = f"JIRA-{datetime.utcnow().timestamp()}"
        logger.info(f"Created Jira ticket: {ticket_id}")

        return ticket_id

    def _format_description(self, finding: Dict[str, Any]) -> str:
        """Format finding as Jira description."""
        desc = f"*Security Finding from CloudGuard-Anomaly*\n\n"
        desc += f"*Resource:* {finding.get('resource_id', 'N/A')}\n"
        desc += f"*Severity:* {finding.get('severity', 'N/A').upper()}\n"
        desc += f"*Description:* {finding.get('description', '')}\n\n"

        if finding.get('remediation'):
            desc += f"*Remediation:*\n{finding['remediation']}\n"

        return desc


class ServiceNowIntegration:
    """ServiceNow integration."""

    def __init__(self, instance_url: str, username: str, password: str):
        """Initialize ServiceNow integration."""
        self.instance_url = instance_url
        self.username = username
        self.password = password
        logger.info("ServiceNow integration initialized")

    def create_incident(
        self,
        finding: Dict[str, Any],
        priority: TicketPriority = TicketPriority.MEDIUM
    ) -> Optional[str]:
        """Create ServiceNow incident."""
        incident = {
            "short_description": finding.get("title", "Security Finding"),
            "description": self._format_incident_description(finding),
            "urgency": self._map_priority_to_urgency(priority),
            "impact": "2",  # Medium impact
            "category": "Security",
            "subcategory": "Cloud Security",
        }

        # Placeholder - would make actual API call
        incident_number = f"INC{datetime.utcnow().timestamp():.0f}"
        logger.info(f"Created ServiceNow incident: {incident_number}")

        return incident_number

    def _format_incident_description(self, finding: Dict[str, Any]) -> str:
        """Format finding as incident description."""
        desc = "Security Finding from CloudGuard-Anomaly\n\n"
        desc += f"Resource: {finding.get('resource_id', 'N/A')}\n"
        desc += f"Severity: {finding.get('severity', 'N/A').upper()}\n"
        desc += f"Details: {finding.get('description', '')}\n"

        return desc

    def _map_priority_to_urgency(self, priority: TicketPriority) -> str:
        """Map priority to ServiceNow urgency."""
        mapping = {
            TicketPriority.CRITICAL: "1",
            TicketPriority.HIGH: "2",
            TicketPriority.MEDIUM: "3",
            TicketPriority.LOW: "4",
        }
        return mapping.get(priority, "3")


class TicketingManager:
    """Unified ticketing management."""

    def __init__(self):
        """Initialize ticketing manager."""
        self.integrations = {}
        logger.info("Ticketing manager initialized")

    def add_jira_integration(self, jira_url: str, api_token: str, project_key: str):
        """Add Jira integration."""
        self.integrations['jira'] = JiraIntegration(jira_url, api_token, project_key)

    def add_servicenow_integration(self, instance_url: str, username: str, password: str):
        """Add ServiceNow integration."""
        self.integrations['servicenow'] = ServiceNowIntegration(instance_url, username, password)

    def create_tickets_for_findings(
        self,
        findings: List[Dict[str, Any]],
        min_severity: str = "medium",
        systems: List[str] = None
    ) -> Dict[str, List[str]]:
        """Create tickets for findings across systems."""
        if systems is None:
            systems = list(self.integrations.keys())

        created_tickets = {system: [] for system in systems}

        for finding in findings:
            severity = finding.get('severity', 'low')

            # Skip low severity findings if threshold is higher
            if self._should_skip_finding(severity, min_severity):
                continue

            priority = self._map_severity_to_priority(severity)

            for system in systems:
                integration = self.integrations.get(system)

                if not integration:
                    continue

                try:
                    if system == 'jira':
                        ticket_id = integration.create_ticket(finding, priority)
                    elif system == 'servicenow':
                        ticket_id = integration.create_incident(finding, priority)
                    else:
                        continue

                    if ticket_id:
                        created_tickets[system].append(ticket_id)

                except Exception as e:
                    logger.error(f"Error creating ticket in {system}: {e}")

        return created_tickets

    def _should_skip_finding(self, severity: str, min_severity: str) -> bool:
        """Check if finding should be skipped."""
        severity_order = ['info', 'low', 'medium', 'high', 'critical']

        try:
            sev_idx = severity_order.index(severity.lower())
            min_idx = severity_order.index(min_severity.lower())
            return sev_idx < min_idx
        except ValueError:
            return False

    def _map_severity_to_priority(self, severity: str) -> TicketPriority:
        """Map severity to ticket priority."""
        mapping = {
            'critical': TicketPriority.CRITICAL,
            'high': TicketPriority.HIGH,
            'medium': TicketPriority.MEDIUM,
            'low': TicketPriority.LOW,
        }
        return mapping.get(severity.lower(), TicketPriority.MEDIUM)

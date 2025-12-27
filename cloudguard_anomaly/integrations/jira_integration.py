"""
Jira integration for CloudGuard-Anomaly.

Automatically creates and manages Jira tickets for security findings.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    from jira import JIRA
    from jira.exceptions import JIRAError
    JIRA_AVAILABLE = True
except ImportError:
    JIRA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class JiraTicket:
    """Represents a created Jira ticket."""
    key: str
    url: str
    finding_id: str
    created_at: datetime


class JiraIntegration:
    """
    Jira integration for creating tickets from security findings.
    
    Features:
    - Automatic ticket creation from findings
    - Severity to priority mapping
    - Custom field support
    - Bulk ticket creation
    - Duplicate detection
    - Ticket updates and transitions
    """
    
    def __init__(
        self,
        server: str,
        username: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        verify_ssl: bool = True
    ):
        """
        Initialize Jira integration.
        
        Args:
            server: Jira server URL (e.g., https://company.atlassian.net)
            username: Jira username/email
            api_token: Jira API token
            project_key: Jira project key (e.g., SEC)
            issue_type: Issue type for tickets (default: Bug)
            verify_ssl: Verify SSL certificates
        """
        if not JIRA_AVAILABLE:
            raise ImportError(
                "jira package required. Install with: pip install jira"
            )
        
        self.server = server
        self.project_key = project_key
        self.issue_type = issue_type
        
        # Connect to Jira
        try:
            self.jira = JIRA(
                server=server,
                basic_auth=(username, api_token),
                options={'verify': verify_ssl}
            )
            logger.info(f"Connected to Jira: {server}")
        except JIRAError as e:
            logger.error(f"Failed to connect to Jira: {e}")
            raise
        
        # Severity to priority mapping
        self.priority_mapping = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Lowest'
        }
    
    def create_ticket_from_finding(
        self,
        finding: Dict[str, Any],
        labels: Optional[List[str]] = None,
        components: Optional[List[str]] = None,
        assignee: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None
    ) -> JiraTicket:
        """
        Create a Jira ticket from a security finding.
        
        Args:
            finding: Security finding dictionary
            labels: Additional labels for the ticket
            components: Jira components to assign
            assignee: Username to assign ticket to
            custom_fields: Custom field values
            
        Returns:
            Created JiraTicket object
        """
        # Extract finding details
        finding_id = finding.get('id', 'unknown')
        severity = finding.get('severity', 'medium').lower()
        title = finding.get('title', 'Security Finding')
        description = finding.get('description', '')
        remediation = finding.get('remediation', 'No remediation provided')
        resource_id = finding.get('resource_id', 'N/A')
        policy_id = finding.get('policy_id', 'N/A')
        
        # Build ticket summary
        summary = f"[{severity.upper()}] {title}"
        
        # Build detailed description
        jira_description = self._format_description(
            finding_id=finding_id,
            severity=severity,
            description=description,
            resource_id=resource_id,
            policy_id=policy_id,
            remediation=remediation,
            finding=finding
        )
        
        # Map severity to Jira priority
        priority = self.priority_mapping.get(severity, 'Medium')
        
        # Prepare issue fields
        issue_fields = {
            'project': {'key': self.project_key},
            'summary': summary[:255],  # Jira limit
            'description': jira_description,
            'issuetype': {'name': self.issue_type},
            'priority': {'name': priority},
        }
        
        # Add labels
        ticket_labels = labels or []
        ticket_labels.extend([
            'cloudguard-anomaly',
            'security',
            severity,
            finding.get('finding_type', 'security')
        ])
        issue_fields['labels'] = ticket_labels
        
        # Add components
        if components:
            issue_fields['components'] = [{'name': c} for c in components]
        
        # Add assignee
        if assignee:
            issue_fields['assignee'] = {'name': assignee}
        
        # Add custom fields
        if custom_fields:
            issue_fields.update(custom_fields)
        
        try:
            # Create issue
            issue = self.jira.create_issue(fields=issue_fields)
            
            logger.info(f"Created Jira ticket {issue.key} for finding {finding_id}")
            
            return JiraTicket(
                key=issue.key,
                url=f"{self.server}/browse/{issue.key}",
                finding_id=finding_id,
                created_at=datetime.utcnow()
            )
            
        except JIRAError as e:
            logger.error(f"Failed to create Jira ticket: {e}")
            raise
    
    def create_tickets_bulk(
        self,
        findings: List[Dict[str, Any]],
        min_severity: str = 'low',
        labels: Optional[List[str]] = None,
        dry_run: bool = False
    ) -> List[JiraTicket]:
        """
        Create Jira tickets for multiple findings.
        
        Args:
            findings: List of security findings
            min_severity: Minimum severity to create tickets for
            labels: Additional labels for all tickets
            dry_run: If True, don't actually create tickets
            
        Returns:
            List of created JiraTicket objects
        """
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        min_level = severity_order.get(min_severity.lower(), 3)
        
        created_tickets = []
        
        # Filter findings by severity
        filtered_findings = [
            f for f in findings
            if severity_order.get(f.get('severity', 'low').lower(), 4) <= min_level
        ]
        
        logger.info(
            f"Creating Jira tickets for {len(filtered_findings)}/{len(findings)} findings "
            f"(min severity: {min_severity})"
        )
        
        for finding in filtered_findings:
            try:
                if dry_run:
                    logger.info(
                        f"[DRY RUN] Would create ticket for: {finding.get('title')} "
                        f"({finding.get('severity')})"
                    )
                    continue
                
                # Check for existing ticket
                existing = self.find_existing_ticket(finding.get('id'))
                if existing:
                    logger.info(
                        f"Ticket already exists for finding {finding.get('id')}: {existing}"
                    )
                    continue
                
                ticket = self.create_ticket_from_finding(finding, labels=labels)
                created_tickets.append(ticket)
                
            except Exception as e:
                logger.error(f"Failed to create ticket for finding {finding.get('id')}: {e}")
        
        logger.info(f"Created {len(created_tickets)} Jira tickets")
        
        return created_tickets
    
    def find_existing_ticket(self, finding_id: str) -> Optional[str]:
        """
        Search for existing Jira ticket for a finding.
        
        Args:
            finding_id: Finding ID to search for
            
        Returns:
            Ticket key if found, None otherwise
        """
        try:
            # Search for tickets with the finding ID in description or comments
            jql = f'project = {self.project_key} AND description ~ "{finding_id}"'
            issues = self.jira.search_issues(jql, maxResults=1)
            
            if issues:
                return issues[0].key
            
            return None
            
        except JIRAError as e:
            logger.error(f"Error searching for existing ticket: {e}")
            return None
    
    def update_ticket(
        self,
        ticket_key: str,
        comment: Optional[str] = None,
        status: Optional[str] = None,
        fields: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update an existing Jira ticket.
        
        Args:
            ticket_key: Jira ticket key (e.g., SEC-123)
            comment: Comment to add
            status: New status to transition to
            fields: Fields to update
            
        Returns:
            True if successful
        """
        try:
            issue = self.jira.issue(ticket_key)
            
            # Add comment
            if comment:
                self.jira.add_comment(issue, comment)
                logger.info(f"Added comment to {ticket_key}")
            
            # Update fields
            if fields:
                issue.update(fields=fields)
                logger.info(f"Updated fields on {ticket_key}")
            
            # Transition status
            if status:
                transitions = self.jira.transitions(issue)
                transition_id = None
                
                for t in transitions:
                    if t['name'].lower() == status.lower():
                        transition_id = t['id']
                        break
                
                if transition_id:
                    self.jira.transition_issue(issue, transition_id)
                    logger.info(f"Transitioned {ticket_key} to {status}")
                else:
                    logger.warning(f"Status '{status}' not available for {ticket_key}")
            
            return True
            
        except JIRAError as e:
            logger.error(f"Failed to update ticket {ticket_key}: {e}")
            return False
    
    def close_resolved_findings(
        self,
        resolved_findings: List[str],
        resolution: str = "Fixed"
    ) -> int:
        """
        Close Jira tickets for findings that have been resolved.
        
        Args:
            resolved_findings: List of finding IDs that are now resolved
            resolution: Resolution to set (e.g., Fixed, Won't Fix)
            
        Returns:
            Number of tickets closed
        """
        closed_count = 0
        
        for finding_id in resolved_findings:
            ticket_key = self.find_existing_ticket(finding_id)
            
            if ticket_key:
                comment = f"Security finding {finding_id} has been resolved."
                
                success = self.update_ticket(
                    ticket_key=ticket_key,
                    comment=comment,
                    status="Done",
                    fields={'resolution': {'name': resolution}}
                )
                
                if success:
                    closed_count += 1
        
        logger.info(f"Closed {closed_count} Jira tickets for resolved findings")
        
        return closed_count
    
    def _format_description(
        self,
        finding_id: str,
        severity: str,
        description: str,
        resource_id: str,
        policy_id: str,
        remediation: str,
        finding: Dict[str, Any]
    ) -> str:
        """Format Jira ticket description."""
        lines = [
            f"*Security Finding Details*",
            "",
            f"*Finding ID:* {finding_id}",
            f"*Severity:* {severity.upper()}",
            f"*Resource:* {resource_id}",
            f"*Policy:* {policy_id}",
            "",
            "*Description:*",
            description,
            "",
            "*Remediation Steps:*",
            remediation,
            "",
        ]
        
        # Add additional context
        if finding.get('compliance_frameworks'):
            frameworks = ', '.join(finding['compliance_frameworks'])
            lines.extend([
                "*Compliance Impact:*",
                f"This finding affects: {frameworks}",
                ""
            ])
        
        # Add metadata
        lines.extend([
            "---",
            f"_Generated by CloudGuard-Anomaly on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
        ])
        
        return "\n".join(lines)
    
    def get_project_info(self) -> Dict[str, Any]:
        """Get information about the configured Jira project."""
        try:
            project = self.jira.project(self.project_key)
            
            return {
                'key': project.key,
                'name': project.name,
                'lead': project.lead.displayName if hasattr(project, 'lead') else None,
                'issue_types': [it.name for it in self.jira.issue_types_for_project(project.key)],
            }
        except JIRAError as e:
            logger.error(f"Failed to get project info: {e}")
            return {}
    
    def test_connection(self) -> bool:
        """Test Jira connection."""
        try:
            self.jira.myself()
            logger.info("Jira connection test successful")
            return True
        except JIRAError as e:
            logger.error(f"Jira connection test failed: {e}")
            return False


def generate_jira_config_example() -> Dict[str, Any]:
    """Generate example Jira configuration."""
    return {
        'jira': {
            'enabled': True,
            'server': 'https://yourcompany.atlassian.net',
            'username': 'user@example.com',
            'api_token': 'your-api-token-here',
            'project_key': 'SEC',
            'issue_type': 'Bug',
            'auto_create_tickets': True,
            'min_severity': 'high',
            'labels': ['cloudguard', 'security-scan'],
            'components': ['Security'],
            'default_assignee': None
        }
    }


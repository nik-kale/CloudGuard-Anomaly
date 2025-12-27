"""
ServiceNow integration for CloudGuard-Anomaly.

Automatically creates and manages ServiceNow incidents from security findings.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ServiceNowIncident:
    """Represents a created ServiceNow incident."""
    sys_id: str
    number: str
    url: str
    finding_id: str
    created_at: datetime


class ServiceNowIntegration:
    """
    ServiceNow integration for incident management.
    
    Features:
    - Auto-create incidents from findings
    - Severity to impact/urgency mapping
    - Incident updates and resolution
    - Assignment group routing
    - Work notes and comments
    """
    
    def __init__(
        self,
        instance: str,
        username: str,
        password: str,
        assignment_group: Optional[str] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize ServiceNow integration.
        
        Args:
            instance: ServiceNow instance name (e.g., 'dev12345')
            username: ServiceNow username
            password: ServiceNow password or API key
            assignment_group: Default assignment group
            verify_ssl: Verify SSL certificates
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests required. Install with: pip install requests")
        
        self.base_url = f"https://{instance}.service-now.com/api/now"
        self.auth = (username, password)
        self.assignment_group = assignment_group
        self.verify_ssl = verify_ssl
        
        # Severity mapping
        self.impact_mapping = {
            'critical': '1',  # High
            'high': '2',      # Medium
            'medium': '3',    # Low
            'low': '3'        # Low
        }
        
        self.urgency_mapping = {
            'critical': '1',  # High
            'high': '2',      # Medium
            'medium': '3',    # Low
            'low': '3'        # Low
        }
        
        logger.info(f"ServiceNow integration initialized: {instance}")
    
    def create_incident(
        self,
        finding: Dict[str, Any],
        category: str = "Security",
        assignment_group: Optional[str] = None
    ) -> ServiceNowIncident:
        """
        Create ServiceNow incident from security finding.
        
        Args:
            finding: Security finding dictionary
            category: Incident category
            assignment_group: Override default assignment group
            
        Returns:
            Created ServiceNowIncident object
        """
        severity = finding.get('severity', 'medium').lower()
        
        # Build incident payload
        payload = {
            'short_description': f"[CloudGuard] {finding.get('title', 'Security Finding')}",
            'description': self._format_description(finding),
            'impact': self.impact_mapping.get(severity, '3'),
            'urgency': self.urgency_mapping.get(severity, '3'),
            'category': category,
            'subcategory': 'Security Vulnerability',
            'u_source': 'CloudGuard-Anomaly',
            'work_notes': f"Finding ID: {finding.get('id')}\\nResource: {finding.get('resource_id')}"
        }
        
        # Add assignment group
        if assignment_group or self.assignment_group:
            payload['assignment_group'] = assignment_group or self.assignment_group
        
        try:
            response = requests.post(
                f"{self.base_url}/table/incident",
                auth=self.auth,
                headers={'Content-Type': 'application/json'},
                json=payload,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            result = response.json().get('result', {})
            
            incident = ServiceNowIncident(
                sys_id=result.get('sys_id'),
                number=result.get('number'),
                url=f"{self.base_url.replace('/api/now', '')}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}",
                finding_id=finding.get('id'),
                created_at=datetime.utcnow()
            )
            
            logger.info(f"Created ServiceNow incident {incident.number} for finding {finding.get('id')}")
            return incident
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create ServiceNow incident: {e}")
            raise
    
    def create_incidents_bulk(
        self,
        findings: List[Dict[str, Any]],
        min_severity: str = 'high'
    ) -> List[ServiceNowIncident]:
        """
        Create multiple ServiceNow incidents from findings.
        
        Args:
            findings: List of security findings
            min_severity: Minimum severity to create incidents for
            
        Returns:
            List of created ServiceNowIncident objects
        """
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        min_level = severity_order.get(min_severity.lower(), 1)
        
        filtered_findings = [
            f for f in findings
            if severity_order.get(f.get('severity', 'low').lower(), 3) <= min_level
        ]
        
        incidents = []
        for finding in filtered_findings:
            try:
                incident = self.create_incident(finding)
                incidents.append(incident)
            except Exception as e:
                logger.error(f"Failed to create incident for {finding.get('id')}: {e}")
        
        logger.info(f"Created {len(incidents)} ServiceNow incidents")
        return incidents
    
    def update_incident(
        self,
        sys_id: str,
        state: Optional[str] = None,
        work_notes: Optional[str] = None,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """
        Update an existing ServiceNow incident.
        
        Args:
            sys_id: Incident sys_id
            state: New state (1=New, 2=In Progress, 6=Resolved, 7=Closed)
            work_notes: Work notes to add
            resolution_notes: Resolution notes
            
        Returns:
            True if successful
        """
        payload = {}
        
        if state:
            payload['state'] = state
        if work_notes:
            payload['work_notes'] = work_notes
        if resolution_notes:
            payload['close_notes'] = resolution_notes
        
        try:
            response = requests.patch(
                f"{self.base_url}/table/incident/{sys_id}",
                auth=self.auth,
                headers={'Content-Type': 'application/json'},
                json=payload,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            logger.info(f"Updated ServiceNow incident {sys_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update incident {sys_id}: {e}")
            return False
    
    def resolve_incident(
        self,
        sys_id: str,
        resolution_notes: str,
        resolution_code: str = "Solved (Permanently)"
    ) -> bool:
        """
        Resolve a ServiceNow incident.
        
        Args:
            sys_id: Incident sys_id
            resolution_notes: Resolution description
            resolution_code: Resolution code
            
        Returns:
            True if successful
        """
        payload = {
            'state': '6',  # Resolved
            'close_code': resolution_code,
            'close_notes': resolution_notes
        }
        
        try:
            response = requests.patch(
                f"{self.base_url}/table/incident/{sys_id}",
                auth=self.auth,
                headers={'Content-Type': 'application/json'},
                json=payload,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            logger.info(f"Resolved ServiceNow incident {sys_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to resolve incident {sys_id}: {e}")
            return False
    
    def search_incident(self, finding_id: str) -> Optional[str]:
        """
        Search for incident by finding ID.
        
        Args:
            finding_id: CloudGuard finding ID
            
        Returns:
            Incident sys_id if found
        """
        try:
            response = requests.get(
                f"{self.base_url}/table/incident",
                auth=self.auth,
                params={
                    'sysparm_query': f'work_notesLIKE{finding_id}',
                    'sysparm_limit': 1
                },
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            results = response.json().get('result', [])
            if results:
                return results[0].get('sys_id')
            
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to search incidents: {e}")
            return None
    
    def _format_description(self, finding: Dict[str, Any]) -> str:
        """Format incident description from finding."""
        lines = [
            "=== CloudGuard Security Finding ===",
            "",
            f"Finding ID: {finding.get('id')}",
            f"Severity: {finding.get('severity', 'N/A').upper()}",
            f"Resource: {finding.get('resource_id', 'N/A')}",
            f"Policy: {finding.get('policy_id', 'N/A')}",
            "",
            "Description:",
            finding.get('description', 'No description provided'),
            "",
            "Remediation:",
            finding.get('remediation', 'No remediation provided'),
            "",
            f"Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        ]
        
        return "\\n".join(lines)
    
    def test_connection(self) -> bool:
        """Test ServiceNow connection."""
        try:
            response = requests.get(
                f"{self.base_url}/table/incident",
                auth=self.auth,
                params={'sysparm_limit': 1},
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            logger.info("ServiceNow connection test successful")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"ServiceNow connection test failed: {e}")
            return False


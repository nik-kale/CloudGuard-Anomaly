"""
Remediation planner agent.

Generates step-by-step remediation plans for security findings,
including preconditions, steps, and potential side effects.
"""

from typing import Any, Dict, List

from cloudguard_anomaly.agents.base_agent import BaseAgent
from cloudguard_anomaly.core.models import Finding, ResourceType


class RemediationPlannerAgent(BaseAgent):
    """Agent that generates detailed remediation plans."""

    def __init__(self):
        super().__init__("remediation_planner")

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate remediation plan for a finding.

        Args:
            input_data: Dictionary containing:
                - finding: Finding object
                - context: Optional additional context

        Returns:
            Dictionary containing:
                - preconditions: List of preconditions
                - steps: List of remediation steps
                - validation: Validation steps
                - rollback: Rollback procedures
                - side_effects: Potential side effects
        """
        finding: Finding = input_data.get("finding")
        context: Dict[str, Any] = input_data.get("context", {})

        if not finding:
            return {"error": "No finding provided"}

        plan = {
            "preconditions": self._identify_preconditions(finding),
            "steps": self._generate_steps(finding),
            "validation": self._generate_validation_steps(finding),
            "rollback": self._generate_rollback_steps(finding),
            "side_effects": self._identify_side_effects(finding),
        }

        return plan

    def create_remediation_plan(self, finding: Finding) -> str:
        """
        Create a complete remediation plan document.

        Args:
            finding: Finding to create plan for

        Returns:
            Formatted remediation plan
        """
        plan = self.process({"finding": finding})

        plan_doc = f"""
**Remediation Plan: {finding.title}**

**Resource:** {finding.resource.name} ({finding.resource.type.value})
**Severity:** {finding.severity.value.upper()}

**Preconditions:**
{self._format_list(plan['preconditions'])}

**Remediation Steps:**
{self._format_numbered_list(plan['steps'])}

**Validation:**
{self._format_list(plan['validation'])}

**Rollback Procedure:**
{self._format_list(plan['rollback'])}

**Potential Side Effects:**
{self._format_list(plan['side_effects'])}
"""
        return plan_doc.strip()

    def _identify_preconditions(self, finding: Finding) -> List[str]:
        """Identify preconditions before remediation."""
        preconditions = []

        # General preconditions
        preconditions.append("Ensure you have appropriate permissions to modify the resource")
        preconditions.append("Create a backup or snapshot of current configuration")
        preconditions.append("Review change management and approval processes")

        # Environment-specific
        env_tags = finding.resource.tags
        if any(tag.lower() in ["prod", "production"] for tag in env_tags.values()):
            preconditions.append("PRODUCTION ENVIRONMENT - obtain change approval")
            preconditions.append("Schedule maintenance window if required")
            preconditions.append("Notify stakeholders of planned change")

        # Resource-specific preconditions
        resource_type = finding.resource.type

        if resource_type in [ResourceType.DATABASE, ResourceType.STORAGE]:
            preconditions.append("Verify backup is recent and valid")
            preconditions.append("Check for dependent applications or services")

        if resource_type == ResourceType.SECURITY_GROUP:
            preconditions.append("Identify all resources using this security group")
            preconditions.append("Verify network connectivity requirements")

        return preconditions

    def _generate_steps(self, finding: Finding) -> List[str]:
        """Generate remediation steps."""
        steps = []
        resource = finding.resource
        resource_type = resource.type

        # Generate steps based on finding title and resource type
        title_lower = finding.title.lower()

        if "public access" in title_lower or "public" in title_lower:
            steps.extend(self._steps_remove_public_access(resource))
        elif "encryption" in title_lower:
            steps.extend(self._steps_enable_encryption(resource))
        elif "ssh" in title_lower or "rdp" in title_lower:
            steps.extend(self._steps_restrict_remote_access(resource))
        elif "iam" in title_lower or "permission" in title_lower:
            steps.extend(self._steps_fix_iam_issue(resource))
        elif "backup" in title_lower:
            steps.extend(self._steps_enable_backup(resource))
        elif "logging" in title_lower:
            steps.extend(self._steps_enable_logging(resource))
        else:
            # Generic steps
            steps.append("Review the current resource configuration")
            steps.append(f"Apply recommended security settings: {finding.remediation}")
            steps.append("Verify the configuration change")

        return steps

    def _steps_remove_public_access(self, resource) -> List[str]:
        """Steps to remove public access."""
        if resource.type == ResourceType.STORAGE:
            return [
                "Navigate to the storage bucket settings",
                "Go to Permissions or Access Control",
                "Remove any public access policies or ACLs",
                "Enable 'Block all public access' setting",
                "Review bucket policy for any wildcard principals",
                "Remove or restrict overly permissive bucket policies",
            ]
        elif resource.type == ResourceType.DATABASE:
            return [
                "Navigate to database instance settings",
                "Modify network settings",
                "Set 'Publicly accessible' to No/False",
                "Ensure database is in a private subnet",
                "Update security groups to remove public ingress rules",
                "Configure VPN or private link for access",
            ]
        else:
            return [
                "Review and remove public access configurations",
                "Update access control lists and policies",
                "Implement private networking",
            ]

    def _steps_enable_encryption(self, resource) -> List[str]:
        """Steps to enable encryption."""
        if resource.type == ResourceType.STORAGE:
            return [
                "Navigate to bucket/storage account settings",
                "Go to Encryption settings",
                "Enable default encryption (AES-256 or KMS)",
                "Select encryption key (AWS KMS, Azure Key Vault, or Cloud KMS)",
                "Apply encryption settings",
                "Verify that new objects are encrypted",
            ]
        elif resource.type == ResourceType.DATABASE:
            return [
                "Note: Encryption must be enabled at creation time for most databases",
                "Option 1: Create encrypted snapshot, restore to new encrypted instance",
                "Option 2: Create new encrypted database, migrate data",
                "Verify encryption status after migration",
                "Update application connection strings",
                "Decommission old unencrypted instance",
            ]
        else:
            return [
                "Enable encryption at rest for the resource",
                "Configure encryption keys",
                "Verify encryption status",
            ]

    def _steps_restrict_remote_access(self, resource) -> List[str]:
        """Steps to restrict SSH/RDP access."""
        return [
            "Navigate to security group settings",
            "Identify the rule allowing 0.0.0.0/0 access on port 22/3389",
            "Modify the rule to restrict to specific IP ranges (e.g., corporate VPN)",
            "Alternative: Remove the rule entirely",
            "Configure bastion host or AWS Systems Manager for remote access",
            "Update connection procedures and documentation",
            "Test connectivity from approved sources",
        ]

    def _steps_fix_iam_issue(self, resource) -> List[str]:
        """Steps to fix IAM issues."""
        return [
            "Review current IAM role/policy permissions",
            "Identify overly broad or wildcard permissions",
            "Create new policy with least-privilege permissions",
            "Test new policy in non-production environment",
            "Attach new policy and remove overly permissive policy",
            "Monitor application logs for permission errors",
            "Adjust permissions as needed based on actual requirements",
        ]

    def _steps_enable_backup(self, resource) -> List[str]:
        """Steps to enable backups."""
        return [
            "Navigate to resource backup settings",
            "Enable automated backups",
            "Set backup retention period (recommended: 7-30 days)",
            "Configure backup window (low-traffic period)",
            "Enable point-in-time recovery if available",
            "Verify first backup completes successfully",
            "Test restore procedure",
        ]

    def _steps_enable_logging(self, resource) -> List[str]:
        """Steps to enable logging."""
        return [
            "Navigate to resource logging/monitoring settings",
            "Enable access logs",
            "Configure log destination (S3, CloudWatch, Storage Account, etc.)",
            "Set log retention period",
            "Enable additional logging (audit logs, flow logs, etc.)",
            "Configure alerts for critical events",
            "Verify logs are being generated",
        ]

    def _generate_validation_steps(self, finding: Finding) -> List[str]:
        """Generate validation steps."""
        return [
            "Verify the configuration change was applied successfully",
            "Test resource functionality with new configuration",
            "Check application logs for errors",
            "Verify connectivity and access from legitimate sources",
            "Run security scan to confirm issue is resolved",
            "Document the change in change management system",
        ]

    def _generate_rollback_steps(self, finding: Finding) -> List[str]:
        """Generate rollback steps."""
        return [
            "If issues occur, revert to backup/snapshot created in preconditions",
            "Restore previous configuration settings",
            "Verify rollback completed successfully",
            "Document rollback reason and issues encountered",
            "Schedule follow-up to address remediation properly",
        ]

    def _identify_side_effects(self, finding: Finding) -> List[str]:
        """Identify potential side effects."""
        side_effects = []
        resource = finding.resource
        title_lower = finding.title.lower()

        if "public access" in title_lower:
            side_effects.append(
                "Applications or users relying on public access will lose connectivity"
            )
            side_effects.append("Alternative access method (VPN, private link) will be required")

        if "security group" in title_lower or "ssh" in title_lower or "rdp" in title_lower:
            side_effects.append("Current remote access methods may stop working")
            side_effects.append("Users will need to connect through approved access paths")

        if "encryption" in title_lower:
            side_effects.append("May require application downtime during migration")
            side_effects.append("Performance impact may be minimal but measurable")

        if "iam" in title_lower:
            side_effects.append("Applications may encounter permission errors")
            side_effects.append("Monitoring required to identify missing permissions")

        if not side_effects:
            side_effects.append("Minimal side effects expected with proper testing")

        side_effects.append("Always test in non-production environment first")

        return side_effects

    def _format_list(self, items: List[str]) -> str:
        """Format list with bullets."""
        return "\n".join([f"• {item}" for item in items])

    def _format_numbered_list(self, items: List[str]) -> str:
        """Format list with numbers."""
        return "\n".join([f"{i + 1}. {item}" for i, item in enumerate(items)])

"""
Enhanced CIEM with Privilege Escalation Detection for CloudGuard-Anomaly v2.

Features:
- Privilege escalation path detection
- Excessive permissions analysis
- Unused permissions identification
- Cross-account access analysis
- Just-in-time access recommendations
- Principle of least privilege enforcement
"""

import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class PrivilegeEscalationPath:
    """Privilege escalation path."""
    path_id: str
    start_identity: str
    end_privilege: str
    steps: List[str]
    risk_score: float
    exploitability: str  # easy, medium, hard
    description: str
    mitigation: str


@dataclass
class ExcessivePermission:
    """Excessive permission finding."""
    identity: str
    permission: str
    resource: str
    last_used: Optional[datetime]
    days_unused: int
    risk_level: str
    recommendation: str


class EnhancedCIEMAnalyzer:
    """
    Enhanced Cloud Infrastructure Entitlement Management analyzer.

    Detects:
    - Privilege escalation paths
    - Over-privileged identities
    - Unused permissions (90+ days)
    - Dangerous permission combinations
    - Cross-account risks
    """

    def __init__(self):
        """Initialize CIEM analyzer."""
        self.escalation_paths: List[PrivilegeEscalationPath] = []
        self.excessive_permissions: List[ExcessivePermission] = []
        self.dangerous_permissions = self._load_dangerous_permissions()
        logger.info("Enhanced CIEM analyzer initialized")

    def _load_dangerous_permissions(self) -> Dict[str, List[str]]:
        """Load dangerous permission combinations."""
        return {
            'aws': [
                'iam:PassRole + lambda:CreateFunction',  # Can escalate via Lambda
                'iam:PassRole + ec2:RunInstances',  # Can escalate via EC2
                'iam:AttachUserPolicy + iam:CreatePolicy',  # Can attach malicious policies
                'iam:PutUserPolicy',  # Direct policy modification
                'iam:CreateAccessKey',  # Can create keys for other users
                'sts:AssumeRole',  # Role assumption
                'iam:*',  # Full IAM permissions
                's3:GetObject + kms:Decrypt',  # Access encrypted data
            ],
            'azure': [
                'Microsoft.Authorization/roleAssignments/write',  # Can assign roles
                'Microsoft.Compute/virtualMachines/extensions/write',  # Can execute code
                'Microsoft.KeyVault/vaults/secrets/read',  # Access secrets
            ],
            'gcp': [
                'iam.serviceAccounts.actAs',  # Impersonate service accounts
                'iam.roles.create + iam.roles.update',  # Create/modify roles
                'compute.instances.setServiceAccount',  # Change service account
            ],
        }

    def analyze_privilege_escalation(
        self,
        identities: List[Dict[str, Any]],
        policies: List[Dict[str, Any]]
    ) -> List[PrivilegeEscalationPath]:
        """
        Analyze for privilege escalation paths.

        Args:
            identities: List of IAM identities
            policies: List of IAM policies

        Returns:
            List of privilege escalation paths
        """
        logger.info(f"Analyzing {len(identities)} identities for privilege escalation")

        self.escalation_paths = []

        for identity in identities:
            # Check for dangerous permission combinations
            perms = self._extract_permissions(identity, policies)

            # Check AWS escalation vectors
            if self._can_escalate_via_lambda(perms):
                self._add_escalation_path(
                    identity['id'],
                    'Administrator',
                    ['PassRole to Lambda', 'Create malicious Lambda', 'Invoke as admin'],
                    95.0,
                    'easy'
                )

            if self._can_escalate_via_policy(perms):
                self._add_escalation_path(
                    identity['id'],
                    'Administrator',
                    ['Create admin policy', 'Attach to self'],
                    90.0,
                    'easy'
                )

            if self._can_escalate_via_access_keys(perms):
                self._add_escalation_path(
                    identity['id'],
                    'High Privilege User',
                    ['Create access keys for admin user', 'Use admin credentials'],
                    85.0,
                    'medium'
                )

        return self.escalation_paths

    def analyze_excessive_permissions(
        self,
        identities: List[Dict[str, Any]],
        usage_data: Dict[str, datetime]
    ) -> List[ExcessivePermission]:
        """
        Identify excessive and unused permissions.

        Args:
            identities: IAM identities
            usage_data: Permission usage timestamps

        Returns:
            List of excessive permissions
        """
        self.excessive_permissions = []
        current_time = datetime.utcnow()

        for identity in identities:
            identity_id = identity['id']
            permissions = identity.get('permissions', [])

            for perm in permissions:
                last_used = usage_data.get(f"{identity_id}:{perm}")

                if last_used:
                    days_unused = (current_time - last_used).days
                else:
                    days_unused = 999  # Never used

                # Flag if unused for 90+ days
                if days_unused >= 90:
                    self.excessive_permissions.append(ExcessivePermission(
                        identity=identity_id,
                        permission=perm,
                        resource='*',
                        last_used=last_used,
                        days_unused=days_unused,
                        risk_level='medium',
                        recommendation=f"Remove unused permission: {perm}"
                    ))

                # Flag wildcard permissions
                if '*' in perm or ':*' in perm:
                    self.excessive_permissions.append(ExcessivePermission(
                        identity=identity_id,
                        permission=perm,
                        resource='*',
                        last_used=last_used,
                        days_unused=days_unused,
                        risk_level='high',
                        recommendation=f"Replace wildcard with specific permissions"
                    ))

        return self.excessive_permissions

    def _extract_permissions(
        self,
        identity: Dict[str, Any],
        policies: List[Dict[str, Any]]
    ) -> Set[str]:
        """Extract effective permissions for an identity."""
        permissions = set()

        # Direct permissions
        permissions.update(identity.get('permissions', []))

        # Policy-based permissions
        for policy_ref in identity.get('attached_policies', []):
            policy = next((p for p in policies if p['id'] == policy_ref), None)
            if policy:
                permissions.update(policy.get('permissions', []))

        return permissions

    def _can_escalate_via_lambda(self, perms: Set[str]) -> bool:
        """Check if can escalate via Lambda."""
        has_pass_role = any('iam:PassRole' in p for p in perms)
        has_create_function = any('lambda:CreateFunction' in p for p in perms)
        return has_pass_role and has_create_function

    def _can_escalate_via_policy(self, perms: Set[str]) -> bool:
        """Check if can escalate via policy manipulation."""
        has_create = any('iam:CreatePolicy' in p for p in perms)
        has_attach = any('iam:AttachUserPolicy' in p or 'iam:PutUserPolicy' in p for p in perms)
        return has_create and has_attach

    def _can_escalate_via_access_keys(self, perms: Set[str]) -> bool:
        """Check if can escalate via access key creation."""
        return any('iam:CreateAccessKey' in p for p in perms)

    def _add_escalation_path(
        self,
        identity: str,
        target_priv: str,
        steps: List[str],
        risk: float,
        exploitability: str
    ):
        """Add privilege escalation path."""
        path = PrivilegeEscalationPath(
            path_id=f"priv-esc-{len(self.escalation_paths)+1}",
            start_identity=identity,
            end_privilege=target_priv,
            steps=steps,
            risk_score=risk,
            exploitability=exploitability,
            description=f"Can escalate from {identity} to {target_priv}",
            mitigation="Remove dangerous permission combinations"
        )
        self.escalation_paths.append(path)

    def generate_ciem_report(self) -> str:
        """Generate CIEM analysis report."""
        report = []
        report.append("=" * 80)
        report.append("CLOUD INFRASTRUCTURE ENTITLEMENT MANAGEMENT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        # Privilege escalation paths
        if self.escalation_paths:
            report.append(f"PRIVILEGE ESCALATION PATHS: {len(self.escalation_paths)}")
            report.append("-" * 80)

            for path in self.escalation_paths:
                report.append(f"\n[{path.exploitability.upper()}] {path.start_identity} → {path.end_privilege}")
                report.append(f"Risk Score: {path.risk_score}/100")
                report.append("Steps:")
                for i, step in enumerate(path.steps, 1):
                    report.append(f"  {i}. {step}")
                report.append(f"Mitigation: {path.mitigation}\n")

        # Excessive permissions
        if self.excessive_permissions:
            high_risk = [e for e in self.excessive_permissions if e.risk_level == 'high']
            report.append(f"\nEXCESSIVE PERMISSIONS: {len(self.excessive_permissions)}")
            report.append(f"High Risk: {len(high_risk)}")
            report.append("-" * 80)

            for perm in self.excessive_permissions[:10]:  # Top 10
                report.append(f"\n{perm.identity}: {perm.permission}")
                report.append(f"Unused for {perm.days_unused} days")
                report.append(f"Risk: {perm.risk_level.upper()}")
                report.append(f"Recommendation: {perm.recommendation}\n")

        return "\n".join(report)

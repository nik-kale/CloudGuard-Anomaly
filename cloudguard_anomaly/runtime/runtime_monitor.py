"""
Runtime Security Monitoring for CloudGuard-Anomaly v2.

Provides real-time security monitoring capabilities:
- Agentless runtime monitoring via cloud APIs
- Agent-based monitoring for detailed telemetry
- Process and network activity tracking
- Behavioral anomaly detection
- Real-time threat detection
- Container runtime security
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class MonitoringMode(Enum):
    """Runtime monitoring mode."""
    AGENTLESS = "agentless"  # API-based monitoring
    AGENT_BASED = "agent_based"  # Requires agent deployment
    HYBRID = "hybrid"  # Both modes


class ThreatLevel(Enum):
    """Runtime threat level."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RuntimeEvent:
    """Runtime security event."""
    event_id: str
    timestamp: datetime
    event_type: str  # process, network, file, authentication, etc.
    resource_id: str
    description: str
    threat_level: ThreatLevel
    details: Dict[str, Any] = field(default_factory=dict)
    mitre_tactics: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    is_anomaly: bool = False


@dataclass
class ProcessEvent:
    """Process execution event."""
    pid: int
    ppid: int
    command: str
    user: str
    executable_path: str
    arguments: List[str]
    timestamp: datetime
    hash_sha256: Optional[str] = None
    is_suspicious: bool = False
    risk_indicators: List[str] = field(default_factory=list)


@dataclass
class NetworkEvent:
    """Network connection event."""
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    timestamp: datetime
    is_suspicious: bool = False
    threat_intel_match: Optional[str] = None


@dataclass
class FileEvent:
    """File system event."""
    file_path: str
    operation: str  # create, modify, delete, execute
    user: str
    timestamp: datetime
    file_hash: Optional[str] = None
    is_sensitive: bool = False
    permissions_changed: bool = False


@dataclass
class RuntimeMonitoringConfig:
    """Configuration for runtime monitoring."""
    mode: MonitoringMode = MonitoringMode.AGENTLESS
    polling_interval: int = 60  # seconds
    enable_process_monitoring: bool = True
    enable_network_monitoring: bool = True
    enable_file_monitoring: bool = True
    enable_behavioral_analysis: bool = True
    alert_threshold: ThreatLevel = ThreatLevel.MEDIUM
    retain_events_days: int = 30


class RuntimeSecurityMonitor:
    """
    Runtime security monitoring system.

    Monitors cloud workloads for suspicious runtime behavior including:
    - Unexpected process execution
    - Anomalous network connections
    - Unauthorized file access
    - Privilege escalation attempts
    - Crypto mining indicators
    - Data exfiltration patterns
    """

    def __init__(self, config: Optional[RuntimeMonitoringConfig] = None):
        """Initialize runtime monitor."""
        self.config = config or RuntimeMonitoringConfig()
        self.events: List[RuntimeEvent] = []
        self.baseline_behaviors: Dict[str, Any] = {}
        self.threat_indicators = self._load_threat_indicators()
        logger.info(f"Runtime security monitor initialized in {self.config.mode.value} mode")

    def _load_threat_indicators(self) -> Dict[str, List[str]]:
        """Load threat indicators for detection."""
        return {
            'crypto_mining_processes': [
                'xmrig', 'minerd', 'cpuminer', 'ethminer', 'cgminer',
                'bfgminer', 'nicehash', 'phoenixminer'
            ],
            'reverse_shell_patterns': [
                'nc -e', 'ncat -e', 'bash -i', 'sh -i', '/dev/tcp',
                'python -c', 'perl -e', 'ruby -rsocket'
            ],
            'credential_access': [
                'mimikatz', 'lazagne', 'secretsdump', 'hashdump',
                '/etc/shadow', '/etc/passwd', '.aws/credentials', '.ssh/id_rsa'
            ],
            'privilege_escalation': [
                'sudo su', 'sudo -i', 'chmod +s', 'setuid', 'pkexec',
                'dirty_sock', 'dirty_pipe'
            ],
            'suspicious_network_ports': [
                '4444',  # Metasploit default
                '5555',  # Common backdoor
                '6666', '6667',  # IRC
                '31337',  # Common backdoor
                '1337',  # Leet speak port
            ],
            'data_exfiltration_commands': [
                'curl', 'wget', 'scp', 'rsync', 'nc', 'ncat',
                'base64', 'gzip', 'tar'
            ],
        }

    async def start_monitoring(self, resource_ids: List[str]):
        """
        Start runtime monitoring for specified resources.

        Args:
            resource_ids: List of resource IDs to monitor
        """
        logger.info(f"Starting runtime monitoring for {len(resource_ids)} resources")

        if self.config.mode == MonitoringMode.AGENTLESS:
            await self._start_agentless_monitoring(resource_ids)
        elif self.config.mode == MonitoringMode.AGENT_BASED:
            await self._start_agent_based_monitoring(resource_ids)
        else:  # HYBRID
            await asyncio.gather(
                self._start_agentless_monitoring(resource_ids),
                self._start_agent_based_monitoring(resource_ids)
            )

    async def _start_agentless_monitoring(self, resource_ids: List[str]):
        """Start agentless monitoring via cloud APIs."""
        logger.info("Starting agentless monitoring")

        while True:
            for resource_id in resource_ids:
                try:
                    # Monitor via cloud provider APIs
                    events = await self._fetch_cloud_events(resource_id)

                    for event in events:
                        analyzed_event = self._analyze_event(event)
                        if analyzed_event:
                            self.events.append(analyzed_event)

                            if analyzed_event.threat_level.value in ['high', 'critical']:
                                logger.warning(
                                    f"High-severity runtime event detected: {analyzed_event.description}"
                                )

                except Exception as e:
                    logger.error(f"Error monitoring resource {resource_id}: {e}")

            await asyncio.sleep(self.config.polling_interval)

    async def _start_agent_based_monitoring(self, resource_ids: List[str]):
        """Start agent-based monitoring with deployed agents."""
        logger.info("Starting agent-based monitoring")

        # In production, this would connect to agents running on workloads
        # For now, this is a placeholder for the architecture

        while True:
            for resource_id in resource_ids:
                try:
                    # Collect telemetry from agents
                    process_events = await self._collect_process_events(resource_id)
                    network_events = await self._collect_network_events(resource_id)
                    file_events = await self._collect_file_events(resource_id)

                    # Analyze for threats
                    self._analyze_process_events(resource_id, process_events)
                    self._analyze_network_events(resource_id, network_events)
                    self._analyze_file_events(resource_id, file_events)

                except Exception as e:
                    logger.error(f"Error in agent-based monitoring for {resource_id}: {e}")

            await asyncio.sleep(self.config.polling_interval)

    async def _fetch_cloud_events(self, resource_id: str) -> List[Dict[str, Any]]:
        """Fetch events from cloud provider APIs."""
        # Placeholder - would integrate with CloudWatch, Azure Monitor, GCP Operations
        # For demonstration purposes
        return []

    async def _collect_process_events(self, resource_id: str) -> List[ProcessEvent]:
        """Collect process execution events from agent."""
        # Placeholder for agent communication
        return []

    async def _collect_network_events(self, resource_id: str) -> List[NetworkEvent]:
        """Collect network events from agent."""
        # Placeholder for agent communication
        return []

    async def _collect_file_events(self, resource_id: str) -> List[FileEvent]:
        """Collect file system events from agent."""
        # Placeholder for agent communication
        return []

    def _analyze_event(self, event: Dict[str, Any]) -> Optional[RuntimeEvent]:
        """Analyze a raw event for threats."""
        # Example analysis logic
        event_type = event.get('type', 'unknown')
        description = event.get('description', '')

        threat_level = ThreatLevel.INFO
        is_anomaly = False
        mitre_tactics = []

        # Check for known threat patterns
        if self._contains_threat_indicators(description):
            threat_level = ThreatLevel.HIGH
            mitre_tactics = self._map_to_mitre_tactics(description)

        # Check against behavioral baseline
        if self._is_behavioral_anomaly(event):
            is_anomaly = True
            if threat_level == ThreatLevel.INFO:
                threat_level = ThreatLevel.MEDIUM

        if threat_level.value in ['medium', 'high', 'critical']:
            return RuntimeEvent(
                event_id=self._generate_event_id(event),
                timestamp=datetime.utcnow(),
                event_type=event_type,
                resource_id=event.get('resource_id', 'unknown'),
                description=description,
                threat_level=threat_level,
                details=event,
                mitre_tactics=mitre_tactics,
                is_anomaly=is_anomaly
            )

        return None

    def _analyze_process_events(self, resource_id: str, events: List[ProcessEvent]):
        """Analyze process execution events for threats."""
        for proc_event in events:
            risk_indicators = []

            # Check for crypto mining
            if self._is_crypto_mining_process(proc_event.command):
                risk_indicators.append("Crypto mining detected")
                proc_event.is_suspicious = True

            # Check for reverse shells
            if self._is_reverse_shell(proc_event.command):
                risk_indicators.append("Reverse shell pattern detected")
                proc_event.is_suspicious = True

            # Check for privilege escalation
            if self._is_privilege_escalation(proc_event.command):
                risk_indicators.append("Privilege escalation attempt")
                proc_event.is_suspicious = True

            if proc_event.is_suspicious:
                proc_event.risk_indicators = risk_indicators

                runtime_event = RuntimeEvent(
                    event_id=f"proc-{proc_event.pid}-{proc_event.timestamp.timestamp()}",
                    timestamp=proc_event.timestamp,
                    event_type="process",
                    resource_id=resource_id,
                    description=f"Suspicious process: {proc_event.command}",
                    threat_level=ThreatLevel.HIGH,
                    details=vars(proc_event),
                    mitre_tactics=["T1059"],  # Command and Scripting Interpreter
                    remediation="Investigate and terminate if malicious"
                )
                self.events.append(runtime_event)

    def _analyze_network_events(self, resource_id: str, events: List[NetworkEvent]):
        """Analyze network events for threats."""
        for net_event in events:
            # Check for connections to suspicious ports
            if str(net_event.dest_port) in self.threat_indicators['suspicious_network_ports']:
                net_event.is_suspicious = True

            # Check for unusual data transfer volumes
            if net_event.bytes_sent > 100_000_000:  # 100 MB
                net_event.is_suspicious = True

            # Check against threat intelligence
            # (In production, would check against real threat feeds)

            if net_event.is_suspicious:
                runtime_event = RuntimeEvent(
                    event_id=f"net-{net_event.source_ip}-{net_event.timestamp.timestamp()}",
                    timestamp=net_event.timestamp,
                    event_type="network",
                    resource_id=resource_id,
                    description=f"Suspicious network activity to {net_event.dest_ip}:{net_event.dest_port}",
                    threat_level=ThreatLevel.MEDIUM,
                    details=vars(net_event),
                    mitre_tactics=["T1071"],  # Application Layer Protocol
                    remediation="Block suspicious connections and investigate"
                )
                self.events.append(runtime_event)

    def _analyze_file_events(self, resource_id: str, events: List[FileEvent]):
        """Analyze file system events for threats."""
        for file_event in events:
            is_suspicious = False

            # Check for access to sensitive files
            sensitive_paths = self.threat_indicators['credential_access']
            if any(path in file_event.file_path for path in sensitive_paths):
                file_event.is_sensitive = True
                is_suspicious = True

            # Check for permission changes on sensitive files
            if file_event.permissions_changed and file_event.file_path.startswith('/bin'):
                is_suspicious = True

            if is_suspicious:
                runtime_event = RuntimeEvent(
                    event_id=f"file-{hashlib.md5(file_event.file_path.encode()).hexdigest()[:8]}-{file_event.timestamp.timestamp()}",
                    timestamp=file_event.timestamp,
                    event_type="file",
                    resource_id=resource_id,
                    description=f"Suspicious file access: {file_event.file_path}",
                    threat_level=ThreatLevel.HIGH if file_event.is_sensitive else ThreatLevel.MEDIUM,
                    details=vars(file_event),
                    mitre_tactics=["T1005", "T1552"],  # Data from Local System, Unsecured Credentials
                    remediation="Review file access and restrict if unauthorized"
                )
                self.events.append(runtime_event)

    def _contains_threat_indicators(self, text: str) -> bool:
        """Check if text contains known threat indicators."""
        text_lower = text.lower()

        for category, indicators in self.threat_indicators.items():
            for indicator in indicators:
                if indicator.lower() in text_lower:
                    return True

        return False

    def _map_to_mitre_tactics(self, text: str) -> List[str]:
        """Map text to MITRE ATT&CK tactics."""
        tactics = []
        text_lower = text.lower()

        if any(ind in text_lower for ind in self.threat_indicators['crypto_mining_processes']):
            tactics.append("T1496")  # Resource Hijacking

        if any(ind in text_lower for ind in self.threat_indicators['reverse_shell_patterns']):
            tactics.append("T1059")  # Command and Scripting Interpreter

        if any(ind in text_lower for ind in self.threat_indicators['credential_access']):
            tactics.append("T1552")  # Unsecured Credentials

        if any(ind in text_lower for ind in self.threat_indicators['privilege_escalation']):
            tactics.append("T1068")  # Exploitation for Privilege Escalation

        return tactics

    def _is_behavioral_anomaly(self, event: Dict[str, Any]) -> bool:
        """Check if event deviates from baseline behavior."""
        # Placeholder for behavioral analysis
        # In production, would compare against learned baselines
        return False

    def _is_crypto_mining_process(self, command: str) -> bool:
        """Detect crypto mining processes."""
        command_lower = command.lower()
        return any(
            miner in command_lower
            for miner in self.threat_indicators['crypto_mining_processes']
        )

    def _is_reverse_shell(self, command: str) -> bool:
        """Detect reverse shell patterns."""
        return any(
            pattern in command
            for pattern in self.threat_indicators['reverse_shell_patterns']
        )

    def _is_privilege_escalation(self, command: str) -> bool:
        """Detect privilege escalation attempts."""
        command_lower = command.lower()
        return any(
            pattern in command_lower
            for pattern in self.threat_indicators['privilege_escalation']
        )

    def _generate_event_id(self, event: Dict[str, Any]) -> str:
        """Generate unique event ID."""
        event_str = f"{event.get('type')}-{event.get('resource_id')}-{datetime.utcnow().timestamp()}"
        return hashlib.sha256(event_str.encode()).hexdigest()[:16]

    def get_events_by_severity(
        self,
        min_severity: ThreatLevel = ThreatLevel.MEDIUM
    ) -> List[RuntimeEvent]:
        """Get events filtered by minimum severity."""
        severity_order = {
            ThreatLevel.INFO: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }

        min_level = severity_order[min_severity]

        return [
            event for event in self.events
            if severity_order[event.threat_level] >= min_level
        ]

    def get_events_by_resource(self, resource_id: str) -> List[RuntimeEvent]:
        """Get all events for a specific resource."""
        return [
            event for event in self.events
            if event.resource_id == resource_id
        ]

    def get_anomalies(self) -> List[RuntimeEvent]:
        """Get all behavioral anomalies."""
        return [event for event in self.events if event.is_anomaly]

    def generate_runtime_report(self) -> str:
        """Generate runtime security report."""
        report = []
        report.append("=" * 80)
        report.append("RUNTIME SECURITY MONITORING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Monitoring Mode: {self.config.mode.value}")
        report.append(f"Total Events: {len(self.events)}\n")

        # Summary by severity
        by_severity = {}
        for event in self.events:
            severity = event.threat_level.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

        report.append("EVENTS BY SEVERITY")
        report.append("-" * 80)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = by_severity.get(severity, 0)
            report.append(f"{severity.upper()}: {count}")

        # Summary by type
        by_type = {}
        for event in self.events:
            event_type = event.event_type
            by_type[event_type] = by_type.get(event_type, 0) + 1

        report.append("\nEVENTS BY TYPE")
        report.append("-" * 80)
        for event_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            report.append(f"{event_type}: {count}")

        # Critical and High severity events
        critical_events = [e for e in self.events if e.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]

        if critical_events:
            report.append(f"\n\nCRITICAL & HIGH SEVERITY EVENTS ({len(critical_events)})")
            report.append("=" * 80)

            for event in critical_events[:20]:  # Top 20
                report.append(f"\n[{event.threat_level.value.upper()}] {event.event_type.upper()}")
                report.append(f"Resource: {event.resource_id}")
                report.append(f"Time: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                report.append(f"Description: {event.description}")

                if event.mitre_tactics:
                    report.append(f"MITRE ATT&CK: {', '.join(event.mitre_tactics)}")

                if event.remediation:
                    report.append(f"Remediation: {event.remediation}")

                report.append("-" * 80)

        return "\n".join(report)

    def clear_old_events(self, days: int = 30):
        """Clear events older than specified days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        self.events = [
            event for event in self.events
            if event.timestamp > cutoff
        ]
        logger.info(f"Cleared events older than {days} days")

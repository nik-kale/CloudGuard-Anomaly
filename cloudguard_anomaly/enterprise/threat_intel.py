"""
Threat Intelligence Integration for CloudGuard-Anomaly.

Integrates with threat intelligence feeds to enrich security findings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from enum import Enum
import hashlib

from cloudguard_anomaly.core.models import Resource, Finding, Severity


class ThreatLevel(Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(Enum):
    """Types of threats."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    CRYPTO_MINING = "crypto_mining"
    RANSOMWARE = "ransomware"
    APT = "apt"  # Advanced Persistent Threat
    KNOWN_ATTACKER = "known_attacker"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"


@dataclass
class ThreatIndicator:
    """Threat indicator from intelligence feeds."""

    id: str
    type: ThreatType
    value: str  # IP, domain, hash, etc.
    level: ThreatLevel
    source: str
    description: str = ""
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.5  # 0.0 to 1.0
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatMatch:
    """Match between resource and threat indicator."""

    resource_id: str
    indicator: ThreatIndicator
    matched_on: str  # What field matched (IP, domain, etc.)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    false_positive: bool = False


class ThreatIntelligence:
    """Threat intelligence integration."""

    def __init__(self):
        """Initialize threat intelligence system."""
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.matches: List[ThreatMatch] = []

        # Load built-in threat indicators (simplified demo)
        self._load_builtin_indicators()

    def _load_builtin_indicators(self):
        """Load built-in threat indicators."""
        # Example malicious IPs (these are example IPs, not real threats)
        malicious_ips = [
            ("198.51.100.1", "Known botnet C2 server"),
            ("203.0.113.1", "Brute force attack source"),
            ("192.0.2.1", "Cryptocurrency mining malware"),
        ]

        for ip, description in malicious_ips:
            indicator = ThreatIndicator(
                id=self._generate_id(f"ip-{ip}"),
                type=ThreatType.KNOWN_ATTACKER,
                value=ip,
                level=ThreatLevel.HIGH,
                source="builtin",
                description=description,
                confidence=0.9,
                tags=["malicious-ip", "blocklist"],
            )
            self.indicators[indicator.id] = indicator

        # Example malicious domains
        malicious_domains = [
            ("evil-phishing.example", "Phishing campaign"),
            ("malware-download.example", "Malware distribution"),
        ]

        for domain, description in malicious_domains:
            indicator = ThreatIndicator(
                id=self._generate_id(f"domain-{domain}"),
                type=ThreatType.PHISHING,
                value=domain,
                level=ThreatLevel.HIGH,
                source="builtin",
                description=description,
                confidence=0.85,
                tags=["malicious-domain", "phishing"],
            )
            self.indicators[indicator.id] = indicator

        # Known vulnerable ports
        vulnerable_configs = [
            ("port:23", "Telnet - Unencrypted remote access", ThreatType.VULNERABILITY_EXPLOIT),
            ("port:21", "FTP - Unencrypted file transfer", ThreatType.VULNERABILITY_EXPLOIT),
            ("port:3389", "RDP - Common brute force target", ThreatType.BRUTE_FORCE),
            ("port:22", "SSH - Brute force target if exposed", ThreatType.BRUTE_FORCE),
        ]

        for config, description, threat_type in vulnerable_configs:
            indicator = ThreatIndicator(
                id=self._generate_id(config),
                type=threat_type,
                value=config,
                level=ThreatLevel.MEDIUM,
                source="builtin",
                description=description,
                confidence=0.7,
                tags=["vulnerable-config"],
            )
            self.indicators[indicator.id] = indicator

    def _generate_id(self, value: str) -> str:
        """Generate unique ID for indicator."""
        return hashlib.md5(value.encode()).hexdigest()[:16]

    def add_indicator(self, indicator: ThreatIndicator):
        """Add threat indicator to database."""
        self.indicators[indicator.id] = indicator

    def check_ip(self, ip_address: str) -> List[ThreatIndicator]:
        """Check if IP address is in threat database."""
        matches = []
        for indicator in self.indicators.values():
            if indicator.value == ip_address:
                matches.append(indicator)
        return matches

    def check_domain(self, domain: str) -> List[ThreatIndicator]:
        """Check if domain is in threat database."""
        matches = []
        for indicator in self.indicators.values():
            if indicator.value == domain or domain.endswith(indicator.value):
                matches.append(indicator)
        return matches

    def check_port(self, port: int) -> List[ThreatIndicator]:
        """Check if port has known vulnerabilities."""
        port_str = f"port:{port}"
        matches = []
        for indicator in self.indicators.values():
            if indicator.value == port_str:
                matches.append(indicator)
        return matches

    def enrich_resource(self, resource: Resource) -> List[ThreatMatch]:
        """
        Enrich resource with threat intelligence.

        Args:
            resource: Resource to check

        Returns:
            List of threat matches
        """
        matches = []

        # Check public IPs
        if "public_ip" in resource.properties:
            ip = resource.properties["public_ip"]
            threats = self.check_ip(ip)
            for threat in threats:
                match = ThreatMatch(
                    resource_id=resource.id,
                    indicator=threat,
                    matched_on=f"public_ip:{ip}",
                )
                matches.append(match)
                self.matches.append(match)

        # Check allowed IPs in security groups
        if "allowed_ips" in resource.properties:
            for ip in resource.properties["allowed_ips"]:
                threats = self.check_ip(ip)
                for threat in threats:
                    match = ThreatMatch(
                        resource_id=resource.id,
                        indicator=threat,
                        matched_on=f"allowed_ip:{ip}",
                    )
                    matches.append(match)
                    self.matches.append(match)

        # Check open ports
        if "ingress_rules" in resource.properties:
            for rule in resource.properties["ingress_rules"]:
                port = rule.get("port", rule.get("from_port"))
                if port:
                    threats = self.check_port(port)
                    for threat in threats:
                        match = ThreatMatch(
                            resource_id=resource.id,
                            indicator=threat,
                            matched_on=f"port:{port}",
                        )
                        matches.append(match)
                        self.matches.append(match)

        # Check domains in configuration
        if "domain" in resource.properties:
            domain = resource.properties["domain"]
            threats = self.check_domain(domain)
            for threat in threats:
                match = ThreatMatch(
                    resource_id=resource.id,
                    indicator=threat,
                    matched_on=f"domain:{domain}",
                )
                matches.append(match)
                self.matches.append(match)

        return matches

    def enrich_finding(self, finding: Finding, resource: Resource) -> Dict[str, Any]:
        """
        Enrich security finding with threat intelligence.

        Args:
            finding: Finding to enrich
            resource: Related resource

        Returns:
            Enrichment data
        """
        enrichment = {
            "threat_matches": [],
            "threat_level": None,
            "threat_score": 0.0,
            "recommendations": [],
        }

        # Check resource for threats
        matches = self.enrich_resource(resource)

        if matches:
            enrichment["threat_matches"] = [
                {
                    "type": match.indicator.type.value,
                    "value": match.indicator.value,
                    "level": match.indicator.level.value,
                    "description": match.indicator.description,
                    "confidence": match.indicator.confidence,
                    "matched_on": match.matched_on,
                }
                for match in matches
            ]

            # Calculate threat score
            max_confidence = max(m.indicator.confidence for m in matches)
            threat_levels = {
                ThreatLevel.CRITICAL: 1.0,
                ThreatLevel.HIGH: 0.75,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.LOW: 0.25,
                ThreatLevel.INFO: 0.1,
            }
            max_level_score = max(
                threat_levels.get(m.indicator.level, 0.0) for m in matches
            )
            enrichment["threat_score"] = max_confidence * max_level_score

            # Determine overall threat level
            critical_threats = [
                m for m in matches if m.indicator.level == ThreatLevel.CRITICAL
            ]
            high_threats = [
                m for m in matches if m.indicator.level == ThreatLevel.HIGH
            ]

            if critical_threats:
                enrichment["threat_level"] = ThreatLevel.CRITICAL.value
            elif high_threats:
                enrichment["threat_level"] = ThreatLevel.HIGH.value
            else:
                enrichment["threat_level"] = ThreatLevel.MEDIUM.value

            # Add recommendations
            enrichment["recommendations"] = self._generate_recommendations(matches)

        return enrichment

    def _generate_recommendations(self, matches: List[ThreatMatch]) -> List[str]:
        """Generate remediation recommendations based on threat matches."""
        recommendations = []

        for match in matches:
            indicator = match.indicator

            if indicator.type in [ThreatType.KNOWN_ATTACKER, ThreatType.BOTNET]:
                recommendations.append(
                    f"Block IP address {indicator.value} immediately"
                )
                recommendations.append(
                    "Review logs for any successful connections from this source"
                )

            elif indicator.type == ThreatType.PHISHING:
                recommendations.append(f"Block domain {indicator.value} at DNS/firewall")
                recommendations.append(
                    "Educate users about phishing from this domain"
                )

            elif indicator.type == ThreatType.VULNERABILITY_EXPLOIT:
                if "port:" in indicator.value:
                    port = indicator.value.split(":")[1]
                    recommendations.append(
                        f"Restrict access to port {port} or disable service"
                    )
                    recommendations.append(
                        f"Enable additional authentication for port {port} services"
                    )

            elif indicator.type == ThreatType.BRUTE_FORCE:
                recommendations.append("Implement rate limiting and account lockout")
                recommendations.append("Enable multi-factor authentication")
                recommendations.append("Use IP allowlisting where possible")

        return list(set(recommendations))  # Remove duplicates

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of threat intelligence database."""
        type_counts = {}
        level_counts = {}

        for indicator in self.indicators.values():
            type_counts[indicator.type.value] = (
                type_counts.get(indicator.type.value, 0) + 1
            )
            level_counts[indicator.level.value] = (
                level_counts.get(indicator.level.value, 0) + 1
            )

        return {
            "total_indicators": len(self.indicators),
            "type_breakdown": type_counts,
            "level_breakdown": level_counts,
            "total_matches": len(self.matches),
            "last_updated": datetime.utcnow().isoformat(),
        }

    def update_from_feed(self, feed_url: str, feed_type: str = "json"):
        """
        Update threat indicators from external feed.

        In production, integrate with:
        - AlienVault OTX
        - Abuse.ch
        - Threat Intelligence Platform (TIP)
        - MISP
        - Commercial feeds (Recorded Future, etc.)

        Args:
            feed_url: URL of threat feed
            feed_type: Format of feed (json, csv, stix)
        """
        # Placeholder for feed integration
        # In production, fetch and parse external threat feeds
        pass

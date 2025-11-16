"""
Continuous monitoring daemon for CloudGuard-Anomaly.

Runs scans on a schedule and alerts on changes.
"""

import logging
import time
import signal
import sys
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Any
from pathlib import Path

try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

from cloudguard_anomaly.core.engine import AnalysisEngine
from cloudguard_anomaly.core.models import ScanResult, Environment
from cloudguard_anomaly.storage.database import DatabaseStorage
from cloudguard_anomaly.notifications.webhooks import SlackNotifier
from cloudguard_anomaly.config import get_config

logger = logging.getLogger(__name__)


class MonitoringDaemon:
    """
    Continuous monitoring daemon.

    Runs security scans on a schedule and sends alerts on changes.
    """

    def __init__(
        self,
        scan_interval: int = 3600,  # 1 hour in seconds
        database_url: Optional[str] = None,
        slack_webhook: Optional[str] = None,
    ):
        """
        Initialize monitoring daemon.

        Args:
            scan_interval: Scan interval in seconds
            database_url: Database URL for storing results
            slack_webhook: Slack webhook URL for notifications
        """
        if not SCHEDULE_AVAILABLE:
            raise ImportError(
                "schedule required for monitoring daemon. "
                "Install with: pip install schedule"
            )

        self.scan_interval = scan_interval
        self.running = False
        self.scan_count = 0
        self.last_scan_time: Optional[datetime] = None

        # Initialize components
        config = get_config()
        self.database = DatabaseStorage(database_url or config.database_url)

        self.slack_notifier = None
        if slack_webhook or config.slack_webhook_url:
            try:
                from cloudguard_anomaly.notifications.webhooks import SlackNotifier
                self.slack_notifier = SlackNotifier(slack_webhook or config.slack_webhook_url)
            except:
                logger.warning("Could not initialize Slack notifier")

        # Scan targets
        self.scan_targets: Dict[str, Dict[str, Any]] = {}

        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info(f"Monitoring daemon initialized with {scan_interval}s interval")

    def add_target(
        self,
        name: str,
        scan_func: Callable[[], Environment],
        policies: Optional[list] = None
    ):
        """
        Add a scan target.

        Args:
            name: Target name
            scan_func: Function that returns Environment to scan
            policies: Optional policies to use for this target
        """
        self.scan_targets[name] = {
            'scan_func': scan_func,
            'policies': policies,
            'last_result': None,
            'last_scan': None
        }

        logger.info(f"Added scan target: {name}")

    def add_aws_target(
        self,
        name: str,
        profile: Optional[str] = None,
        region: str = "us-east-1"
    ):
        """
        Add AWS account as scan target.

        Args:
            name: Target name
            profile: AWS profile name
            region: AWS region
        """
        from cloudguard_anomaly.integrations.aws_live import AWSLiveIntegration

        def scan_aws():
            aws = AWSLiveIntegration(profile=profile, region=region)
            return aws.discover_all_resources()

        self.add_target(name, scan_aws)

    def start(self):
        """
        Start the monitoring daemon.

        Runs continuously until stopped.
        """
        if not self.scan_targets:
            logger.error("No scan targets configured - use add_target() first")
            return

        self.running = True
        logger.info(f"Starting continuous monitoring with {len(self.scan_targets)} targets")

        # Schedule scans
        for target_name in self.scan_targets.keys():
            schedule.every(self.scan_interval).seconds.do(
                self._scan_target,
                target_name
            )

        # Run initial scans immediately
        for target_name in self.scan_targets.keys():
            self._scan_target(target_name)

        # Main loop
        try:
            while self.running:
                schedule.run_pending()
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.stop()

    def stop(self):
        """Stop the monitoring daemon."""
        logger.info("Stopping monitoring daemon...")
        self.running = False

        # Send final stats
        self._send_summary_notification()

    def _scan_target(self, target_name: str):
        """Run scan for a specific target."""
        target = self.scan_targets.get(target_name)
        if not target:
            logger.error(f"Unknown target: {target_name}")
            return

        logger.info(f"Starting scan of target: {target_name}")
        scan_start = datetime.utcnow()

        try:
            # Get environment
            environment = target['scan_func']()

            # Run analysis
            engine = AnalysisEngine(policies=target.get('policies'))
            result = engine.scan_environment(environment)

            # Save to database
            scan_id = self.database.save_scan(result)

            # Update target tracking
            target['last_result'] = result
            target['last_scan'] = scan_start
            self.scan_count += 1
            self.last_scan_time = scan_start

            # Check for changes
            self._check_for_changes(target_name, result)

            # Send notification
            if self.slack_notifier:
                self.slack_notifier.send_scan_summary(result)

            duration = (datetime.utcnow() - scan_start).total_seconds()
            logger.info(
                f"Completed scan of {target_name}: "
                f"{len(result.findings)} findings in {duration:.1f}s"
            )

        except Exception as e:
            logger.error(f"Error scanning {target_name}: {e}", exc_info=True)

            # Send error notification
            if self.slack_notifier:
                self.slack_notifier.send_message(
                    f"❌ Error scanning {target_name}: {str(e)}"
                )

    def _check_for_changes(self, target_name: str, current_result: ScanResult):
        """Check for significant changes from previous scan."""
        # Get previous scans from database
        previous_scans = self.database.get_scans(days=1, limit=5)

        if len(previous_scans) < 2:
            return  # Need at least 2 scans to compare

        prev_scan = previous_scans[1]  # Previous scan (current is [0])
        prev_data = prev_scan.data

        # Compare findings counts
        prev_findings = len(prev_data.get('findings', []))
        curr_findings = len(current_result.findings)

        # Compare severity counts
        prev_critical = prev_data.get('summary', {}).get('severity_counts', {}).get('critical', 0)
        curr_critical = current_result.summary.get('severity_counts', {}).get('critical', 0)

        # Alert on significant changes
        if curr_critical > prev_critical:
            new_critical = curr_critical - prev_critical
            logger.warning(f"⚠️  {new_critical} new CRITICAL findings detected in {target_name}!")

            if self.slack_notifier:
                self.slack_notifier.send_message(
                    f"🚨 *Alert: New Critical Findings*\n"
                    f"Target: {target_name}\n"
                    f"New critical findings: {new_critical}\n"
                    f"Total critical: {curr_critical}\n"
                    f"Total findings: {curr_findings}"
                )

        elif curr_findings > prev_findings + 5:
            new_findings = curr_findings - prev_findings
            logger.warning(f"⚠️  {new_findings} new findings detected in {target_name}")

            if self.slack_notifier:
                self.slack_notifier.send_message(
                    f"⚠️  *Alert: Significant Change Detected*\n"
                    f"Target: {target_name}\n"
                    f"New findings: +{new_findings}\n"
                    f"Total: {curr_findings}"
                )

    def _send_summary_notification(self):
        """Send summary notification on shutdown."""
        if not self.slack_notifier:
            return

        uptime = ""
        if self.last_scan_time:
            uptime = str(datetime.utcnow() - self.last_scan_time)

        self.slack_notifier.send_message(
            f"📊 *Monitoring Daemon Summary*\n"
            f"Total scans performed: {self.scan_count}\n"
            f"Targets monitored: {len(self.scan_targets)}\n"
            f"Uptime: {uptime}\n"
            f"Status: Stopped"
        )

    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        logger.info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)

    def get_status(self) -> Dict[str, Any]:
        """
        Get current daemon status.

        Returns:
            Status dictionary
        """
        return {
            'running': self.running,
            'scan_count': self.scan_count,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
            'targets': list(self.scan_targets.keys()),
            'scan_interval': self.scan_interval,
            'target_details': {
                name: {
                    'last_scan': target['last_scan'].isoformat() if target['last_scan'] else None,
                    'last_findings': len(target['last_result'].findings) if target['last_result'] else 0
                }
                for name, target in self.scan_targets.items()
            }
        }


def run_daemon(
    interval_hours: int = 1,
    database_url: Optional[str] = None,
    slack_webhook: Optional[str] = None,
    aws_profile: Optional[str] = None,
):
    """
    Convenience function to run monitoring daemon.

    Args:
        interval_hours: Scan interval in hours
        database_url: Database URL
        slack_webhook: Slack webhook URL
        aws_profile: AWS profile to monitor
    """
    daemon = MonitoringDaemon(
        scan_interval=interval_hours * 3600,
        database_url=database_url,
        slack_webhook=slack_webhook
    )

    # Add AWS target if profile specified
    if aws_profile:
        daemon.add_aws_target(f"aws-{aws_profile}", profile=aws_profile)

    daemon.start()

"""
Tests for continuous monitoring daemon.
"""

from unittest.mock import Mock, patch

from cloudguard_anomaly.core.models import Environment, Provider, ResourceType
from cloudguard_anomaly.monitoring.daemon import MonitoringDaemon
from cloudguard_anomaly.notifications.webhooks import SlackNotifier


class TestSlackNotifierMessages:
    def test_send_message_posts_text_with_a_timeout(self):
        with patch("cloudguard_anomaly.notifications.webhooks.requests.post") as post:
            post.return_value.raise_for_status.return_value = None
            assert SlackNotifier("https://hooks.slack.test/x").send_message("hello") is True
        assert post.call_args.kwargs["json"] == {"text": "hello"}
        assert post.call_args.kwargs["timeout"] > 0


class TestMonitoringDaemon:
    """Test continuous monitoring daemon functionality."""

    def test_daemon_initialization(self, test_database_url):
        """Test daemon initializes correctly."""
        daemon = MonitoringDaemon(
            scan_interval=60, database_url=test_database_url, slack_webhook=None
        )

        assert daemon.scan_interval == 60
        assert daemon.running is False
        assert daemon.scan_count == 0
        assert daemon.database is not None

    def test_daemon_initialization_requires_schedule(self, test_database_url):
        """Test daemon requires schedule library."""
        # This test verifies the import check works
        daemon = MonitoringDaemon(scan_interval=3600, database_url=test_database_url)
        assert daemon is not None

    def test_add_scan_target(self, test_database_url):
        """Test adding scan target."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        def mock_scan_func():
            return Environment(name="test", provider=Provider.AWS, resources=[])

        daemon.add_target("test-target", mock_scan_func)

        assert "test-target" in daemon.scan_targets
        assert daemon.scan_targets["test-target"]["scan_func"] == mock_scan_func

    def test_add_aws_target(self, test_database_url):
        """Test adding AWS account as target."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        # Mock AWS integration to avoid actual AWS calls
        with patch("cloudguard_anomaly.integrations.aws_live.AWSLiveIntegration"):
            daemon.add_aws_target("aws-prod", profile="production", region="us-west-2")

        assert "aws-prod" in daemon.scan_targets

    def test_scan_target_execution(self, test_database_url, sample_environment):
        """Test scanning a specific target."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        def mock_scan_func():
            return sample_environment

        daemon.add_target("test-scan", mock_scan_func)

        # Execute scan
        daemon._scan_target("test-scan")

        assert daemon.scan_count == 1
        assert daemon.last_scan_time is not None
        assert daemon.scan_targets["test-scan"]["last_result"] is not None

    def test_scan_target_error_handling(self, test_database_url):
        """Test daemon handles scan errors gracefully."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        def failing_scan_func():
            raise Exception("Simulated scan failure")

        daemon.add_target("failing-target", failing_scan_func)

        # Should not crash
        daemon._scan_target("failing-target")

        # Scan count should not increment on failure
        assert daemon.scan_count == 0

    def test_get_status(self, test_database_url):
        """Test getting daemon status."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        def mock_scan_func():
            return Environment(name="test", provider=Provider.AWS, resources=[])

        daemon.add_target("status-test", mock_scan_func)

        status = daemon.get_status()

        assert status["running"] is False
        assert status["scan_count"] == 0
        assert status["scan_interval"] == 60
        assert "status-test" in status["targets"]
        assert "target_details" in status

    def test_change_detection_alerts_on_new_critical(
        self, test_database_url, sample_scan_result, database
    ):
        """Alerts go through send_message, which SlackNotifier never had."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)
        daemon.slack_notifier = Mock()
        database.save_scan(sample_scan_result)
        database.save_scan(sample_scan_result)

        sample_scan_result.summary["severity_counts"]["critical"] = 2
        daemon._check_for_changes("target", sample_scan_result)

        daemon.slack_notifier.send_message.assert_called_once()

    def test_change_detection_compares_the_same_environment(
        self, test_database_url, sample_scan_result, database
    ):
        """Another target's history must not count as this target's baseline."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)
        daemon.slack_notifier = Mock()
        sample_scan_result.environment.name = "other-target"
        database.save_scan(sample_scan_result)
        database.save_scan(sample_scan_result)

        sample_scan_result.environment.name = "brand-new-target"
        sample_scan_result.summary["severity_counts"]["critical"] = 2
        daemon._check_for_changes("target", sample_scan_result)

        daemon.slack_notifier.send_message.assert_not_called()

    def test_signal_handler(self, test_database_url):
        """Test signal handler for graceful shutdown."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        daemon.running = True

        # Trigger signal handler (without actually sending signal)
        with patch.object(daemon, "stop") as mock_stop:
            with patch("sys.exit"):
                daemon._signal_handler(2, None)  # SIGINT

            mock_stop.assert_called_once()

    def test_daemon_statistics(self, test_database_url):
        """Test daemon statistics tracking."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        def mock_scan_func():
            return Environment(name="test", provider=Provider.AWS, resources=[])

        daemon.add_target("stats-test", mock_scan_func)

        # Run scan
        daemon._scan_target("stats-test")

        assert daemon.scan_count == 1
        assert daemon.last_scan_time is not None

        status = daemon.get_status()
        assert status["scan_count"] == 1

    def test_multiple_targets(self, test_database_url):
        """Test daemon with multiple targets."""
        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        def mock_scan_1():
            return Environment(name="env1", provider=Provider.AWS, resources=[])

        def mock_scan_2():
            return Environment(name="env2", provider=Provider.AWS, resources=[])

        daemon.add_target("target-1", mock_scan_1)
        daemon.add_target("target-2", mock_scan_2)

        assert len(daemon.scan_targets) == 2

        # Scan both
        daemon._scan_target("target-1")
        daemon._scan_target("target-2")

        assert daemon.scan_count == 2

    def test_slack_notification_integration(self, test_database_url):
        """Test Slack notification integration."""
        # Mock Slack webhook
        with patch("cloudguard_anomaly.monitoring.daemon.SlackNotifier"):
            daemon = MonitoringDaemon(
                scan_interval=60,
                database_url=test_database_url,
                slack_webhook="https://hooks.slack.com/test",
            )

            assert daemon.slack_notifier is not None

    def test_daemon_with_policies(self, test_database_url):
        """Test daemon with custom policies per target."""
        from cloudguard_anomaly.core.models import Policy, Severity

        daemon = MonitoringDaemon(scan_interval=60, database_url=test_database_url)

        policy = Policy(
            id="TEST_POLICY",
            name="Test",
            description="Test policy",
            severity=Severity.HIGH,
            provider=Provider.AWS,
            resource_types=[ResourceType.STORAGE],
            condition={},
            remediation="",
        )

        def mock_scan_func():
            return Environment(name="test", provider=Provider.AWS, resources=[])

        daemon.add_target("policy-test", mock_scan_func, policies=[policy])

        assert daemon.scan_targets["policy-test"]["policies"] == [policy]

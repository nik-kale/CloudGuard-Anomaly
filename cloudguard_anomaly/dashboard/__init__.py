"""Web dashboard for CloudGuard-Anomaly."""

from cloudguard_anomaly.dashboard.app import broadcast_scan_update, run_dashboard

__all__ = ["run_dashboard", "broadcast_scan_update"]

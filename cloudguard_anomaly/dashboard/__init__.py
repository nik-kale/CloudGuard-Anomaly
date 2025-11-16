"""Web dashboard for CloudGuard-Anomaly."""

from cloudguard_anomaly.dashboard.app import run_dashboard, broadcast_scan_update

__all__ = ["run_dashboard", "broadcast_scan_update"]

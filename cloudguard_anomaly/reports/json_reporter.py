"""
JSON reporter for CloudGuard-Anomaly.
"""

import json
import logging
from pathlib import Path
from typing import Any

from cloudguard_anomaly.core.models import ScanResult
from cloudguard_anomaly.reports.common import report_data

logger = logging.getLogger(__name__)


class JSONReporter:
    """JSON report generator."""

    def __init__(self, pretty: bool = True):
        """Initialize JSON reporter with optional pretty printing."""
        self.pretty = pretty

    def save_report(
        self, scan_result: ScanResult | dict[str, Any], output_path: str | Path
    ) -> None:
        """Save scan results as JSON."""
        logger.info(f"Generating JSON report: {output_path}")

        data = report_data(scan_result)
        with open(output_path, "w") as f:
            if self.pretty:
                json.dump(data, f, indent=2, default=str)
            else:
                json.dump(data, f, default=str)

        logger.info(f"JSON report saved: {output_path}")

"""
JSON reporter for CloudGuard-Anomaly.
"""

import json
import logging
from typing import Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class JSONReporter:
    """JSON report generator."""

    def __init__(self, pretty: bool = True):
        """Initialize JSON reporter with optional pretty printing."""
        self.pretty = pretty

    def save_report(self, scan_result: Dict[str, Any], output_path: str) -> None:
        """Save scan results as JSON."""
        logger.info(f"Generating JSON report: {output_path}")

        with open(output_path, 'w') as f:
            if self.pretty:
                json.dump(scan_result, f, indent=2, default=str)
            else:
                json.dump(scan_result, f, default=str)

        logger.info(f"JSON report saved: {output_path}")


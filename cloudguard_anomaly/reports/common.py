"""Helpers shared by the report generators."""

import re
from typing import Any

from cloudguard_anomaly.core.models import ScanResult


def report_data(scan_result: ScanResult | dict[str, Any]) -> dict[str, Any]:
    """Return scan results as a plain dictionary, whichever form the caller holds."""
    if isinstance(scan_result, ScanResult):
        return scan_result.to_dict()
    return scan_result


def safe_report_name(name: str) -> str:
    """
    Build a filename component from an environment name.

    Names come from scanned configuration, so path separators and dot segments are
    removed to keep reports inside the requested output directory.
    """
    cleaned = re.sub(r"[^a-z0-9.-]+", "_", name.lower()).strip("._")
    return cleaned or "environment"

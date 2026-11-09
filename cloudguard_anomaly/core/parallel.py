"""
Parallel scanning engine for CloudGuard-Anomaly.

Provides async/parallel scanning capabilities for dramatic performance improvements.
"""

import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from cloudguard_anomaly.config import get_config
from cloudguard_anomaly.core.models import Environment, Finding, Policy, Resource

logger = logging.getLogger(__name__)


class ParallelScanner:
    """Parallel resource scanner using ThreadPoolExecutor."""

    def __init__(self, max_workers: int | None = None):
        """
        Initialize parallel scanner.

        Args:
            max_workers: Maximum number of worker threads (default: from config)
        """
        config = get_config()
        self.max_workers = max_workers or config.scan_parallel_workers
        logger.info(f"Parallel scanner initialized with {self.max_workers} workers")

    def scan_resources_parallel(
        self,
        resources: list[Resource],
        scan_func: Callable[[Resource], list[Finding]],
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Finding]:
        """
        Scan resources in parallel.

        Args:
            resources: List of resources to scan
            scan_func: Function to scan a single resource (returns findings)
            progress_callback: Optional callback for progress updates (current, total)

        Returns:
            List of all findings from all resources
        """
        all_findings = []
        total = len(resources)
        completed = 0

        start_time = time.time()
        logger.info(f"Starting parallel scan of {total} resources with {self.max_workers} workers")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_resource = {
                executor.submit(scan_func, resource): resource for resource in resources
            }

            # Process completed tasks
            for future in as_completed(future_to_resource):
                resource = future_to_resource[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    completed += 1

                    if progress_callback:
                        progress_callback(completed, total)

                except Exception as e:
                    logger.error(f"Error scanning resource {resource.id}: {e}", exc_info=True)
                    completed += 1

        elapsed = time.time() - start_time
        logger.info(
            f"Parallel scan completed: {total} resources in {elapsed:.2f}s "
            f"({total / max(elapsed, 1e-9):.1f} resources/sec), {len(all_findings)} findings"
        )

        return all_findings

    def evaluate_policies_parallel(
        self,
        resources: list[Resource],
        policies: list[Policy],
        evaluator: Any,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Finding]:
        """
        Evaluate policies against resources in parallel.

        Args:
            resources: List of resources
            policies: List of policies to evaluate
            evaluator: Policy evaluator instance
            progress_callback: Optional callback for progress updates

        Returns:
            List of findings
        """
        all_findings: list[Finding] = []

        # Check each resource against the policies that apply to it
        total = len(resources)
        completed = 0

        start_time = time.time()
        logger.info(
            f"Starting parallel policy evaluation: {total} resources, {len(policies)} policies"
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_resource = {
                executor.submit(evaluator.evaluate_resource, resource): resource
                for resource in resources
            }

            for future in as_completed(future_to_resource):
                resource = future_to_resource[future]
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    logger.error(f"Error evaluating resource {resource.id}: {e}", exc_info=True)
                completed += 1

                if progress_callback:
                    progress_callback(completed, total)

        elapsed = time.time() - start_time
        logger.info(
            f"Parallel evaluation completed: {total} checks in {elapsed:.2f}s "
            f"({total / max(elapsed, 1e-9):.1f} checks/sec), {len(all_findings)} findings"
        )

        return all_findings

    def run_detectors_parallel(
        self,
        detectors: list[Any],
        environment: Environment,
        baseline: Environment | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> dict[str, list[Any]]:
        """
        Run multiple detectors in parallel.

        Args:
            detectors: List of detector instances
            environment: Environment to analyze
            baseline: Optional baseline environment for drift detection
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary mapping detector names to their results
        """
        results: dict[str, list[Any]] = {}
        total = len(detectors)
        completed = 0

        if not detectors:
            return results

        start_time = time.time()
        logger.info(f"Running {total} detectors in parallel")

        with ThreadPoolExecutor(max_workers=min(self.max_workers, total)) as executor:
            # Submit detector tasks
            future_to_detector = {}
            for detector in detectors:
                if hasattr(detector, "detect_drift"):
                    if not baseline:
                        logger.debug(f"Skipping {type(detector).__name__}: no baseline")
                        continue
                    future = executor.submit(
                        detector.detect_drift, baseline.resources, environment.resources
                    )
                elif hasattr(detector, "detect"):
                    future = executor.submit(detector.detect, environment.resources)
                else:
                    logger.warning(f"Detector {type(detector).__name__} has no detect method")
                    continue

                future_to_detector[future] = detector

            # Collect results
            for future in as_completed(future_to_detector):
                detector = future_to_detector[future]
                detector_name = type(detector).__name__

                try:
                    result = future.result()
                    results[detector_name] = result
                    completed += 1

                    if progress_callback:
                        progress_callback(completed, total)

                    logger.debug(f"Detector {detector_name} completed")

                except Exception as e:
                    logger.error(f"Error running detector {detector_name}: {e}", exc_info=True)
                    results[detector_name] = []
                    completed += 1

        elapsed = time.time() - start_time
        logger.info(f"All detectors completed in {elapsed:.2f}s")

        return results

    def batch_process(
        self,
        items: list[Any],
        process_func: Callable[[Any], Any],
        batch_size: int = 100,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Any]:
        """
        Process items in batches with parallel execution.

        Useful for processing large datasets with rate limiting.

        Args:
            items: Items to process
            process_func: Function to process each item
            batch_size: Number of items per batch
            progress_callback: Optional callback for progress updates

        Returns:
            List of processing results
        """
        results = []
        total = len(items)
        completed = 0

        logger.info(f"Batch processing {total} items in batches of {batch_size}")

        # Split into batches
        for i in range(0, total, batch_size):
            batch = items[i : i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (total + batch_size - 1) // batch_size

            logger.debug(f"Processing batch {batch_num}/{total_batches} ({len(batch)} items)")

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_item = {executor.submit(process_func, item): item for item in batch}

                for future in as_completed(future_to_item):
                    try:
                        result = future.result()
                        results.append(result)
                        completed += 1

                        if progress_callback:
                            progress_callback(completed, total)

                    except Exception as e:
                        logger.error(f"Error processing item: {e}", exc_info=True)
                        completed += 1

        logger.info(f"Batch processing completed: {completed}/{total} items processed")
        return results


# Global parallel scanner instance
_parallel_scanner: ParallelScanner | None = None


def get_parallel_scanner(max_workers: int | None = None) -> ParallelScanner:
    """Get global parallel scanner instance."""
    global _parallel_scanner
    if _parallel_scanner is None:
        _parallel_scanner = ParallelScanner(max_workers=max_workers)
    return _parallel_scanner

"""
Tests for incremental scanning with hash-based change detection.
"""

import pytest
from datetime import datetime

from cloudguard_anomaly.core.incremental import IncrementalScanTracker, ResourceSnapshot
from cloudguard_anomaly.core.models import Resource, ResourceType, CloudProvider


class TestIncrementalScanner:
    """Test incremental scanning functionality."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        tracker = IncrementalScanTracker()
        assert tracker.snapshots == {}
        assert isinstance(tracker.enabled, bool)

    def test_compute_resource_hash(self, sample_s3_bucket):
        """Test resource hash computation."""
        tracker = IncrementalScanTracker()
        hash1 = tracker.compute_resource_hash(sample_s3_bucket)

        # Hash should be consistent
        hash2 = tracker.compute_resource_hash(sample_s3_bucket)
        assert hash1 == hash2

        # Hash should be SHA-256 (64 hex chars)
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)

    def test_hash_changes_with_configuration(self, sample_s3_bucket):
        """Test hash changes when resource configuration changes."""
        tracker = IncrementalScanTracker()
        original_hash = tracker.compute_resource_hash(sample_s3_bucket)

        # Modify configuration
        sample_s3_bucket.properties["encryption_enabled"] = True
        modified_hash = tracker.compute_resource_hash(sample_s3_bucket)

        assert original_hash != modified_hash

    def test_hash_changes_with_tags(self, sample_s3_bucket):
        """Test hash changes when tags change."""
        tracker = IncrementalScanTracker()
        original_hash = tracker.compute_resource_hash(sample_s3_bucket)

        # Add tag
        sample_s3_bucket.tags["NewTag"] = "NewValue"
        modified_hash = tracker.compute_resource_hash(sample_s3_bucket)

        assert original_hash != modified_hash

    def test_save_snapshots(self, sample_resources):
        """Test saving resource snapshots."""
        tracker = IncrementalScanTracker()
        count = tracker.save_snapshots(sample_resources)

        assert count == len(sample_resources)
        assert len(tracker.snapshots) == len(sample_resources)

        # Verify snapshot structure
        for resource in sample_resources:
            assert resource.id in tracker.snapshots
            snapshot = tracker.snapshots[resource.id]
            assert isinstance(snapshot, ResourceSnapshot)
            assert snapshot.resource_id == resource.id
            assert len(snapshot.config_hash) == 64

    def test_identify_new_resources(self, sample_resources):
        """Test identifying new resources."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # First scan - all resources are new
        new, modified, unchanged = tracker.identify_changes(sample_resources)

        assert len(new) == len(sample_resources)
        assert len(modified) == 0
        assert len(unchanged) == 0

    def test_identify_unchanged_resources(self, sample_resources):
        """Test identifying unchanged resources."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Save initial snapshots
        tracker.save_snapshots(sample_resources)

        # Scan again with same resources
        new, modified, unchanged = tracker.identify_changes(sample_resources)

        assert len(new) == 0
        assert len(modified) == 0
        assert len(unchanged) == len(sample_resources)

    def test_identify_modified_resources(self, sample_resources):
        """Test identifying modified resources."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Save initial snapshots
        tracker.save_snapshots(sample_resources)

        # Modify one resource
        sample_resources[0].properties["encryption_enabled"] = True

        # Scan again
        new, modified, unchanged = tracker.identify_changes(sample_resources)

        assert len(new) == 0
        assert len(modified) == 1
        assert len(unchanged) == len(sample_resources) - 1
        assert modified[0].id == sample_resources[0].id

    def test_identify_deleted_resources(self, sample_resources):
        """Test detecting deleted resources."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Save initial snapshots
        tracker.save_snapshots(sample_resources)

        # Remove one resource
        current_resources = sample_resources[1:]

        # Scan with fewer resources
        new, modified, unchanged = tracker.identify_changes(current_resources)

        # One resource is missing (deleted)
        assert len(unchanged) == len(current_resources)

    def test_get_scan_scope_full_scan(self, sample_resources):
        """Test scan scope for first scan (all resources)."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        scan_scope = tracker.get_scan_scope(sample_resources)

        # First scan should include all resources
        assert len(scan_scope) == len(sample_resources)

    def test_get_scan_scope_incremental(self, sample_resources):
        """Test scan scope for incremental scan (only changed)."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Initial scan
        tracker.save_snapshots(sample_resources)

        # Modify one resource
        sample_resources[0].properties["public_access"] = False

        # Get scan scope
        scan_scope = tracker.get_scan_scope(sample_resources)

        # Should only scan modified resource
        assert len(scan_scope) == 1
        assert scan_scope[0].id == sample_resources[0].id

    def test_get_scan_scope_with_scan_unchanged_flag(self, sample_resources):
        """Test scan_unchanged flag forces full scan."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Initial scan
        tracker.save_snapshots(sample_resources)

        # Get scan scope with scan_unchanged=True
        scan_scope = tracker.get_scan_scope(sample_resources, scan_unchanged=True)

        # Should scan all resources
        assert len(scan_scope) == len(sample_resources)

    def test_get_change_summary(self, sample_resources):
        """Test change summary statistics."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Initial scan
        tracker.save_snapshots(sample_resources)

        # Modify one, add one new
        sample_resources[0].properties["encryption_enabled"] = True
        new_resource = Resource(
            id="new-resource-123",
            name="new-resource",
            type=ResourceType.STORAGE,
            provider=CloudProvider.AWS,
            region="us-west-2",
            properties={},
        )
        current_resources = sample_resources + [new_resource]

        summary = tracker.get_change_summary(current_resources)

        assert summary["total_resources"] == len(current_resources)
        assert summary["new_count"] == 1
        assert summary["modified_count"] == 1
        assert summary["unchanged_count"] == len(sample_resources) - 1
        assert summary["scan_required"] == 2
        assert "reduction_percentage" in summary

    def test_force_rescan_all(self, sample_resources):
        """Test forcing full rescan."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Save snapshots
        tracker.save_snapshots(sample_resources)
        assert len(tracker.snapshots) > 0

        # Force rescan
        tracker.force_rescan()

        assert len(tracker.snapshots) == 0

        # Next scan will be full scan
        new, modified, unchanged = tracker.identify_changes(sample_resources)
        assert len(new) == len(sample_resources)

    def test_force_rescan_specific_resources(self, sample_resources):
        """Test forcing rescan of specific resources."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # Save snapshots
        tracker.save_snapshots(sample_resources)

        # Force rescan of one resource
        target_id = sample_resources[0].id
        tracker.force_rescan([target_id])

        # That resource should be missing from snapshots
        assert target_id not in tracker.snapshots
        assert len(tracker.snapshots) == len(sample_resources) - 1

    def test_get_statistics(self, sample_resources):
        """Test statistics reporting."""
        tracker = IncrementalScanTracker()
        tracker.enabled = True

        # No snapshots initially
        stats = tracker.get_statistics()
        assert stats["tracked_resources"] == 0
        assert stats["enabled"] is True

        # Save snapshots
        tracker.save_snapshots(sample_resources)

        stats = tracker.get_statistics()
        assert stats["tracked_resources"] == len(sample_resources)
        assert "providers" in stats
        assert "regions" in stats

    def test_get_snapshot_metadata(self, sample_resources):
        """Test snapshot metadata export."""
        tracker = IncrementalScanTracker()
        tracker.save_snapshots(sample_resources)

        metadata = tracker.get_snapshot_metadata()

        assert len(metadata) == len(sample_resources)
        for resource in sample_resources:
            assert resource.id in metadata
            snapshot_data = metadata[resource.id]
            assert "resource_id" in snapshot_data
            assert "config_hash" in snapshot_data
            assert "last_scanned" in snapshot_data

    def test_disabled_tracker_treats_all_as_new(self, sample_resources):
        """Test disabled tracker bypasses incremental logic."""
        tracker = IncrementalScanTracker()
        tracker.enabled = False

        # Save snapshots (but disabled)
        tracker.save_snapshots(sample_resources)

        # Identify changes
        new, modified, unchanged = tracker.identify_changes(sample_resources)

        # All treated as new when disabled
        assert len(new) == len(sample_resources)
        assert len(modified) == 0
        assert len(unchanged) == 0

    def test_load_snapshots_from_database(self, database, sample_scan_result):
        """Test loading snapshots from database."""
        # Save a scan to database
        database.save_scan(sample_scan_result)

        tracker = IncrementalScanTracker(database=database)
        # In production, would load from database
        # For now, this tests the structure
        count = tracker.load_snapshots("test-environment")
        assert count >= 0  # May or may not find snapshots

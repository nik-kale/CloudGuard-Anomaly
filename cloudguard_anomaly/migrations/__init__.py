"""
Database migration utilities for CloudGuard-Anomaly.

Provides programmatic access to Alembic migrations.
"""

import logging
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config as AlembicConfig

logger = logging.getLogger(__name__)


class MigrationManager:
    """
    Manages database migrations using Alembic.

    Provides high-level interface for running, creating, and managing
    database schema migrations.
    """

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize migration manager.

        Args:
            database_url: Database URL (uses config default if not provided)
        """
        from cloudguard_anomaly.config import get_config

        config = get_config()
        self.database_url = database_url or config.database_url

        # Locate alembic.ini
        project_root = Path(__file__).parents[2]
        alembic_ini_path = project_root / "alembic.ini"

        if not alembic_ini_path.exists():
            raise FileNotFoundError(
                f"alembic.ini not found at {alembic_ini_path}. "
                "Run from project root or set CLOUDGUARD_ROOT env var."
            )

        self.alembic_cfg = AlembicConfig(str(alembic_ini_path))
        self.alembic_cfg.set_main_option("sqlalchemy.url", self.database_url)

        logger.info(f"Migration manager initialized for: {self.database_url}")

    def upgrade(self, revision: str = "head"):
        """
        Upgrade database to a later version.

        Args:
            revision: Target revision (default: 'head' for latest)
        """
        logger.info(f"Upgrading database to revision: {revision}")
        command.upgrade(self.alembic_cfg, revision)
        logger.info("Database upgrade completed")

    def downgrade(self, revision: str):
        """
        Downgrade database to a previous version.

        Args:
            revision: Target revision
        """
        logger.warning(f"Downgrading database to revision: {revision}")
        command.downgrade(self.alembic_cfg, revision)
        logger.info("Database downgrade completed")

    def current(self) -> str:
        """
        Show current database revision.

        Returns:
            Current revision ID
        """
        logger.info("Checking current database revision")
        command.current(self.alembic_cfg)
        return "Current revision displayed in logs"

    def history(self):
        """Show migration history."""
        logger.info("Retrieving migration history")
        command.history(self.alembic_cfg)

    def stamp(self, revision: str):
        """
        Mark database as being at a specific revision without running migrations.

        Args:
            revision: Target revision to stamp
        """
        logger.info(f"Stamping database with revision: {revision}")
        command.stamp(self.alembic_cfg, revision)

    def create_migration(
        self, message: str, autogenerate: bool = True
    ) -> str:
        """
        Create a new migration script.

        Args:
            message: Migration description
            autogenerate: Auto-detect schema changes

        Returns:
            Path to created migration script
        """
        logger.info(f"Creating migration: {message}")

        if autogenerate:
            command.revision(
                self.alembic_cfg,
                message=message,
                autogenerate=True,
            )
        else:
            command.revision(
                self.alembic_cfg,
                message=message,
            )

        logger.info("Migration script created")
        return f"Migration created: {message}"

    def check_pending_migrations(self) -> bool:
        """
        Check if there are pending migrations.

        Returns:
            True if migrations are pending, False otherwise
        """
        from alembic.script import ScriptDirectory
        from alembic.runtime.migration import MigrationContext
        from sqlalchemy import create_engine

        # Get current database revision
        engine = create_engine(self.database_url)
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current_rev = context.get_current_revision()

        # Get head revision
        script = ScriptDirectory.from_config(self.alembic_cfg)
        head_rev = script.get_current_head()

        if current_rev != head_rev:
            logger.warning(
                f"Pending migrations detected. Current: {current_rev}, Head: {head_rev}"
            )
            return True

        logger.info("Database is up to date")
        return False


def upgrade_database(database_url: Optional[str] = None, revision: str = "head"):
    """
    Convenience function to upgrade database.

    Args:
        database_url: Database URL
        revision: Target revision
    """
    manager = MigrationManager(database_url)
    manager.upgrade(revision)


def check_migrations(database_url: Optional[str] = None) -> bool:
    """
    Check if migrations are pending.

    Args:
        database_url: Database URL

    Returns:
        True if migrations needed
    """
    manager = MigrationManager(database_url)
    return manager.check_pending_migrations()


def create_migration(message: str, database_url: Optional[str] = None):
    """
    Create a new migration.

    Args:
        message: Migration description
        database_url: Database URL
    """
    manager = MigrationManager(database_url)
    manager.create_migration(message, autogenerate=True)

# CloudGuard-Anomaly Database Migrations

This directory contains Alembic database migrations for CloudGuard-Anomaly.

## Overview

Database migrations allow you to:
- Evolve your database schema over time
- Track schema changes in version control
- Apply/rollback changes safely
- Maintain schema consistency across environments

## Quick Start

### Check Current Status

```bash
# From project root
alembic current
```

### Apply Migrations

```bash
# Upgrade to latest version
alembic upgrade head

# Upgrade to specific revision
alembic upgrade <revision_id>
```

### Rollback Migrations

```bash
# Downgrade by 1 revision
alembic downgrade -1

# Downgrade to specific revision
alembic downgrade <revision_id>
```

### Create New Migration

```bash
# Auto-generate migration from model changes
alembic revision --autogenerate -m "Add user table"

# Create empty migration template
alembic revision -m "Add custom index"
```

### View Migration History

```bash
# Show all migrations
alembic history

# Show current revision
alembic current
```

## Programmatic Usage

CloudGuard provides Python API for migrations:

```python
from cloudguard_anomaly.migrations import MigrationManager, upgrade_database

# Upgrade database
upgrade_database()

# Check for pending migrations
from cloudguard_anomaly.migrations import check_migrations
if check_migrations():
    print("Migrations pending!")

# Using manager directly
manager = MigrationManager()
manager.upgrade("head")
manager.current()
manager.history()
```

## Migration Workflow

### Creating a New Migration

1. **Modify SQLAlchemy models** in `cloudguard_anomaly/storage/database.py`
2. **Generate migration**:
   ```bash
   alembic revision --autogenerate -m "Description of changes"
   ```
3. **Review generated script** in `alembic/versions/`
4. **Test migration**:
   ```bash
   alembic upgrade head
   ```
5. **Verify schema changes** in database
6. **Commit migration script** to version control

### Best Practices

1. **Always review auto-generated migrations** - Alembic may miss some changes
2. **Test migrations on copy of production data** before applying to production
3. **Write reversible migrations** - Always implement downgrade()
4. **Use descriptive migration messages** - Makes history easier to understand
5. **Never edit existing migrations** - Create new one to fix issues
6. **Backup before migrating production** - Safety first!

## Migration File Structure

```
alembic/
├── env.py                    # Alembic environment configuration
├── script.py.mako            # Migration template
├── README.md                 # This file
└── versions/                 # Migration scripts
    ├── 20241116_000001_initial_schema.py
    └── <timestamp>_<revision>_<description>.py
```

## Configuration

Database URL is automatically loaded from CloudGuard configuration:
- Environment variable: `DATABASE_URL`
- Config file: `config.py`
- Default: `sqlite:///cloudguard.db`

Override in alembic.ini if needed (not recommended):
```ini
sqlalchemy.url = postgresql://user:pass@localhost/cloudguard
```

## Common Tasks

### Migrate Fresh Database

```bash
# Apply all migrations
alembic upgrade head
```

### Rollback Last Migration

```bash
alembic downgrade -1
```

### Reset Database (Danger!)

```bash
# Downgrade to base
alembic downgrade base

# Re-upgrade to latest
alembic upgrade head
```

### Check What Would Be Applied

```bash
# Show SQL without executing
alembic upgrade head --sql
```

## Troubleshooting

### "Can't locate revision identified by..."

Database is at revision that doesn't exist in migrations. Possible solutions:
1. Check out correct branch with that migration
2. Stamp database with known revision: `alembic stamp head`

### "Multiple head revisions are present"

Migration branching detected. Solutions:
1. Merge heads: `alembic merge heads -m "Merge migrations"`
2. Check migration history: `alembic history`

### "Target database is not up to date"

Run migrations: `alembic upgrade head`

### Auto-generate detects no changes

1. Ensure models are imported in `env.py`
2. Check that `Base.metadata` includes all tables
3. Verify database URL is correct

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run database migrations
  run: |
    alembic upgrade head
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

### Pre-deployment Hook

```bash
#!/bin/bash
# Check for pending migrations
if alembic current | grep -q "head"; then
    echo "Database is up to date"
else
    echo "Running migrations..."
    alembic upgrade head
fi
```

## Additional Resources

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- CloudGuard Migration API: `cloudguard_anomaly/migrations/__init__.py`

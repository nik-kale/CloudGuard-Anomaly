#!/bin/bash
# CloudGuard-Anomaly Docker Entrypoint Script

set -e

echo "🛡️  CloudGuard-Anomaly Starting..."

# Wait for database to be ready
if [ -n "$DATABASE_URL" ]; then
    echo "⏳ Waiting for database..."

    # Extract host and port from DATABASE_URL
    DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
    DB_PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')

    if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
        timeout 60 bash -c "until pg_isready -h $DB_HOST -p $DB_PORT; do sleep 2; done"
        echo "✅ Database is ready!"
    fi
fi

# Run database migrations
if [ "$SKIP_MIGRATIONS" != "true" ]; then
    echo "🔄 Running database migrations..."
    alembic upgrade head || echo "⚠️  Migrations failed or not configured"
fi

# Create default admin user if needed
if [ "$CREATE_ADMIN" = "true" ]; then
    echo "👤 Creating default admin user..."
    python -c "
from cloudguard_anomaly.auth import get_auth_manager
try:
    auth = get_auth_manager()
    auth.create_admin_user(
        username='${ADMIN_USERNAME:-admin}',
        email='${ADMIN_EMAIL:-admin@cloudguard.local}',
        password='${ADMIN_PASSWORD:-changeme123}'
    )
    print('✅ Admin user created')
except ValueError as e:
    print(f'ℹ️  Admin user already exists or error: {e}')
" || echo "⚠️  Could not create admin user"
fi

# Execute the command
case "$1" in
    dashboard)
        echo "🚀 Starting CloudGuard Dashboard..."
        exec python -m cloudguard_anomaly.dashboard.app
        ;;

    daemon)
        echo "🔁 Starting CloudGuard Monitoring Daemon..."
        exec python -c "
from cloudguard_anomaly.monitoring.daemon import MonitoringDaemon
from cloudguard_anomaly.config import get_config

config = get_config()
daemon = MonitoringDaemon(
    scan_interval=config.monitoring_interval,
    slack_webhook=config.slack_webhook_url
)

# Add AWS account as target if credentials available
if config.aws_access_key_id:
    daemon.add_aws_target(
        name='aws-primary',
        region=config.aws_region
    )

print('Starting continuous monitoring...')
daemon.start()
"
        ;;

    scan)
        echo "🔍 Running one-time scan..."
        exec python -m cloudguard_anomaly.cli.main scan "$@"
        ;;

    cli)
        shift
        exec python -m cloudguard_anomaly.cli.main "$@"
        ;;

    shell)
        echo "🐚 Starting interactive shell..."
        exec /bin/bash
        ;;

    *)
        # Execute whatever command was passed
        exec "$@"
        ;;
esac

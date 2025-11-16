"""Initial database schema for CloudGuard-Anomaly

Revision ID: 20241116_000001
Revises:
Create Date: 2024-11-16 00:00:01.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20241116_000001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial database schema."""

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('environment_name', sa.String(), nullable=False),
        sa.Column('provider', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=True),
        sa.Column('anomalies_count', sa.Integer(), nullable=True),
        sa.Column('critical_count', sa.Integer(), nullable=True),
        sa.Column('high_count', sa.Integer(), nullable=True),
        sa.Column('medium_count', sa.Integer(), nullable=True),
        sa.Column('low_count', sa.Integer(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_env_timestamp', 'scans', ['environment_name', 'timestamp'])
    op.create_index('idx_risk_score', 'scans', ['risk_score'])
    op.create_index(op.f('ix_scans_environment_name'), 'scans', ['environment_name'])
    op.create_index(op.f('ix_scans_provider'), 'scans', ['provider'])
    op.create_index(op.f('ix_scans_timestamp'), 'scans', ['timestamp'])

    # Create findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('environment_name', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('type', sa.String(), nullable=True),
        sa.Column('resource_id', sa.String(), nullable=True),
        sa.Column('resource_type', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('resolved', sa.Boolean(), default=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_resource', 'findings', ['resource_id', 'resource_type'])
    op.create_index('idx_severity_type', 'findings', ['severity', 'type'])
    op.create_index(op.f('ix_findings_environment_name'), 'findings', ['environment_name'])
    op.create_index(op.f('ix_findings_resource_id'), 'findings', ['resource_id'])
    op.create_index(op.f('ix_findings_resource_type'), 'findings', ['resource_type'])
    op.create_index(op.f('ix_findings_scan_id'), 'findings', ['scan_id'])
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'])
    op.create_index(op.f('ix_findings_timestamp'), 'findings', ['timestamp'])
    op.create_index(op.f('ix_findings_type'), 'findings', ['type'])

    # Create anomalies table
    op.create_table(
        'anomalies',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('environment_name', sa.String(), nullable=True),
        sa.Column('type', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('resource_id', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_anomalies_environment_name'), 'anomalies', ['environment_name'])
    op.create_index(op.f('ix_anomalies_resource_id'), 'anomalies', ['resource_id'])
    op.create_index(op.f('ix_anomalies_scan_id'), 'anomalies', ['scan_id'])
    op.create_index(op.f('ix_anomalies_severity'), 'anomalies', ['severity'])
    op.create_index(op.f('ix_anomalies_timestamp'), 'anomalies', ['timestamp'])
    op.create_index(op.f('ix_anomalies_type'), 'anomalies', ['type'])

    # Create compliance table
    op.create_table(
        'compliance',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('environment_name', sa.String(), nullable=True),
        sa.Column('framework', sa.String(), nullable=True),
        sa.Column('compliance_score', sa.Float(), nullable=True),
        sa.Column('passed_controls', sa.Integer(), nullable=True),
        sa.Column('failed_controls', sa.Integer(), nullable=True),
        sa.Column('total_controls', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_compliance_environment_name'), 'compliance', ['environment_name'])
    op.create_index(op.f('ix_compliance_framework'), 'compliance', ['framework'])
    op.create_index(op.f('ix_compliance_scan_id'), 'compliance', ['scan_id'])
    op.create_index(op.f('ix_compliance_timestamp'), 'compliance', ['timestamp'])


def downgrade() -> None:
    """Drop all tables."""

    op.drop_index(op.f('ix_compliance_timestamp'), table_name='compliance')
    op.drop_index(op.f('ix_compliance_scan_id'), table_name='compliance')
    op.drop_index(op.f('ix_compliance_framework'), table_name='compliance')
    op.drop_index(op.f('ix_compliance_environment_name'), table_name='compliance')
    op.drop_table('compliance')

    op.drop_index(op.f('ix_anomalies_type'), table_name='anomalies')
    op.drop_index(op.f('ix_anomalies_timestamp'), table_name='anomalies')
    op.drop_index(op.f('ix_anomalies_severity'), table_name='anomalies')
    op.drop_index(op.f('ix_anomalies_scan_id'), table_name='anomalies')
    op.drop_index(op.f('ix_anomalies_resource_id'), table_name='anomalies')
    op.drop_index(op.f('ix_anomalies_environment_name'), table_name='anomalies')
    op.drop_table('anomalies')

    op.drop_index(op.f('ix_findings_type'), table_name='findings')
    op.drop_index(op.f('ix_findings_timestamp'), table_name='findings')
    op.drop_index(op.f('ix_findings_severity'), table_name='findings')
    op.drop_index(op.f('ix_findings_scan_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_resource_type'), table_name='findings')
    op.drop_index(op.f('ix_findings_resource_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_environment_name'), table_name='findings')
    op.drop_index('idx_severity_type', table_name='findings')
    op.drop_index('idx_resource', table_name='findings')
    op.drop_table('findings')

    op.drop_index(op.f('ix_scans_timestamp'), table_name='scans')
    op.drop_index(op.f('ix_scans_provider'), table_name='scans')
    op.drop_index(op.f('ix_scans_environment_name'), table_name='scans')
    op.drop_index('idx_risk_score', table_name='scans')
    op.drop_index('idx_env_timestamp', table_name='scans')
    op.drop_table('scans')

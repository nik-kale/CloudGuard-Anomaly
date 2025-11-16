"""Add audit logs table

Revision ID: 20251116_add_audit_logs
Revises: 20251116_add_policies
Create Date: 2025-11-16

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20251116_add_audit_logs'
down_revision = '20251116_add_policies'
branch_labels = None
depends_on = None


def upgrade():
    """Create audit_logs table."""
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('resource_type', sa.String(), nullable=True),
        sa.Column('resource_id', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for query performance
    op.create_index('idx_user_timestamp', 'audit_logs', ['user_id', 'timestamp'])
    op.create_index('idx_action_status', 'audit_logs', ['action', 'status'])
    op.create_index('idx_resource', 'audit_logs', ['resource_type', 'resource_id'])
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'])
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'])
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'])
    op.create_index(op.f('ix_audit_logs_resource_type'), 'audit_logs', ['resource_type'])
    op.create_index(op.f('ix_audit_logs_resource_id'), 'audit_logs', ['resource_id'])
    op.create_index(op.f('ix_audit_logs_status'), 'audit_logs', ['status'])


def downgrade():
    """Drop audit_logs table."""
    op.drop_index(op.f('ix_audit_logs_status'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_resource_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_resource_type'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_user_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_timestamp'), table_name='audit_logs')
    op.drop_index('idx_resource', table_name='audit_logs')
    op.drop_index('idx_action_status', table_name='audit_logs')
    op.drop_index('idx_user_timestamp', table_name='audit_logs')
    op.drop_table('audit_logs')

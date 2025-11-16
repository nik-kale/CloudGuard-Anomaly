"""Add policies table

Revision ID: 20251116_add_policies
Revises: 
Create Date: 2025-11-16

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20251116_add_policies'
down_revision = None  # Update this if there's a previous migration
branch_labels = None
depends_on = None


def upgrade():
    """Create policies table."""
    op.create_table(
        'policies',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('provider', sa.String(), nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('idx_provider_enabled', 'policies', ['provider', 'enabled'])
    op.create_index('idx_severity', 'policies', ['severity'])
    op.create_index(op.f('ix_policies_name'), 'policies', ['name'])


def downgrade():
    """Drop policies table."""
    op.drop_index(op.f('ix_policies_name'), table_name='policies')
    op.drop_index('idx_severity', table_name='policies')
    op.drop_index('idx_provider_enabled', table_name='policies')
    op.drop_table('policies')

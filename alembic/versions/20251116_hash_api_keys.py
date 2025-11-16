"""Hash API keys for security

Revision ID: 20251116_hash_api_keys
Revises: 20251116_add_audit_logs
Create Date: 2025-11-16

This migration adds api_key_hash and api_key_prefix columns and removes
the plaintext api_key column for enhanced security.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20251116_hash_api_keys'
down_revision = '20251116_add_audit_logs'
branch_labels = None
depends_on = None


def upgrade():
    """
    Add api_key_hash and api_key_prefix columns.
    
    Note: Existing API keys will be invalidated. Users must regenerate.
    """
    # Add new columns
    op.add_column('users', sa.Column('api_key_hash', sa.String(), nullable=True))
    op.add_column('users', sa.Column('api_key_prefix', sa.String(), nullable=True))
    
    # Create unique index on api_key_hash
    op.create_index('ix_users_api_key_hash', 'users', ['api_key_hash'], unique=True)
    
    # Drop old api_key column (this will invalidate existing keys)
    # Users must regenerate their API keys after this migration
    op.drop_index('ix_users_api_key', table_name='users')
    op.drop_column('users', 'api_key')


def downgrade():
    """
    Revert to plaintext API keys (not recommended for production).
    """
    # Add back api_key column
    op.add_column('users', sa.Column('api_key', sa.String(), nullable=True))
    op.create_index('ix_users_api_key', 'users', ['api_key'], unique=True)
    
    # Drop hash columns
    op.drop_index('ix_users_api_key_hash', table_name='users')
    op.drop_column('users', 'api_key_prefix')
    op.drop_column('users', 'api_key_hash')

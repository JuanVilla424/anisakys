"""Add api_keys table for multi-tenant authentication with scopes.

Revision ID: 002
Revises: 001
Create Date: 2026-03-23
"""

from typing import Sequence, Union
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            key_hash VARCHAR(64) NOT NULL UNIQUE,
            key_prefix VARCHAR(12) NOT NULL,
            name VARCHAR(100) NOT NULL,
            scopes TEXT NOT NULL DEFAULT 'read',
            allowed_ips TEXT,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            last_used_at TIMESTAMP,
            revoked_at TIMESTAMP,
            description TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(active)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS api_keys")

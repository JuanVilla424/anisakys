"""Add whois_data to scans table

Revision ID: 002
Revises: 001_initial_schema
Create Date: 2026-01-03 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_add_whois_data'
down_revision = '001_initial_schema'
branch_labels = None
depends_on = None


def upgrade():
    """Add whois_data JSONB column to scans table."""
    op.add_column('scans', sa.Column('whois_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade():
    """Remove whois_data column from scans table."""
    op.drop_column('scans', 'whois_data')

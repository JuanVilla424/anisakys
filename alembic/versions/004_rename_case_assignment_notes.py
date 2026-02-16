"""Rename case_assignments.notes to assignment_notes

Revision ID: 004_rename_assignment_notes
Revises: 003_sprint4
Create Date: 2026-01-03

Fix: The case_assignments table had a 'notes' column that conflicted with
the 'notes' relationship (list of Note objects). Renamed the column to
'assignment_notes' to avoid the conflict.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '004_rename_assignment_notes'
down_revision = '003_sprint4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Rename notes column to assignment_notes in case_assignments table."""
    op.alter_column(
        'case_assignments',
        'notes',
        new_column_name='assignment_notes'
    )


def downgrade() -> None:
    """Rename assignment_notes back to notes."""
    op.alter_column(
        'case_assignments',
        'assignment_notes',
        new_column_name='notes'
    )

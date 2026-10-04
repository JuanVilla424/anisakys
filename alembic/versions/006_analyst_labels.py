"""Analyst labels: ground truth for evaluation and a gate on reporting.

Revision ID: 006
Revises: 005
Create Date: 2026-10-04

``labels`` keeps every analyst decision about a site, append-only:

* ``confirm`` — the site is phishing; nothing is sent;
* ``dismiss`` — the site is benign; it is kept out of the reporting loop;
* ``report``  — the site is phishing and an abuse report must go out (the API
  requires the ``report_send`` scope for it).

The latest verdict is denormalised on ``phishing_sites`` (``label_verdict``,
``labeled_at``) so the reporting claim queries and the console filters stay
index-friendly. ``detector_snapshot`` records what the deployed detector said
about the site when it was labelled (threat level, confidence, kit, decision
flags): the evaluation harness measures that prediction instead of a later
re-scan that may already know the answer.

``approval_requested_at``/``approval_requested_by`` mark a ``POST /report``
submission from a key without ``report_send`` (new or already tracked site):
the analyst approval queue lists those sites until a label decides them.

The SQL lives in module-level tuples so tests can build the same schema without
running Alembic. Every statement is idempotent.
"""

from typing import Sequence, Tuple, Union

from alembic import op

# revision identifiers
revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LABELS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS labels (
    id BIGSERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES phishing_sites(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    registrable_domain TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('phishing', 'benign')),
    action TEXT NOT NULL CHECK (action IN ('confirm', 'dismiss', 'report')),
    brand TEXT,
    kit TEXT,
    note TEXT,
    labeled_by TEXT,
    detector_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

PHISHING_SITES_LABEL_COLUMNS_SQL: Tuple[str, ...] = (
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS label_verdict TEXT "
    "CHECK (label_verdict IN ('phishing', 'benign'))",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS labeled_at TIMESTAMPTZ",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS approval_requested_at TIMESTAMPTZ",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS approval_requested_by TEXT",
)

INDEX_SQL: Tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_labels_site_created ON labels (site_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_labels_url ON labels (url)",
    "CREATE INDEX IF NOT EXISTS idx_labels_verdict_created ON labels (verdict, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_phishing_sites_label_verdict "
    "ON phishing_sites (label_verdict)",
    "CREATE INDEX IF NOT EXISTS idx_phishing_sites_approval_requested "
    "ON phishing_sites (approval_requested_at) WHERE approval_requested_at IS NOT NULL",
)

UPGRADE_STATEMENTS: Tuple[str, ...] = (
    LABELS_TABLE_SQL,
    *PHISHING_SITES_LABEL_COLUMNS_SQL,
    *INDEX_SQL,
)

DOWNGRADE_STATEMENTS: Tuple[str, ...] = (
    "DROP INDEX IF EXISTS idx_phishing_sites_approval_requested",
    "DROP INDEX IF EXISTS idx_phishing_sites_label_verdict",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS approval_requested_by",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS approval_requested_at",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS labeled_at",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS label_verdict",
    "DROP TABLE IF EXISTS labels",
)


def upgrade() -> None:
    """Create ``labels`` and the denormalised verdict columns."""
    for statement in UPGRADE_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    """Drop everything this revision added."""
    for statement in DOWNGRADE_STATEMENTS:
        op.execute(statement)

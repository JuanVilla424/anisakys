"""Reporting outbox, shared SMTP rate ledger and report-claim columns.

Revision ID: 004
Revises: 003
Create Date: 2026-10-03

Adds what the phase 0 reporting pipeline needs to run safely from several
processes at once:

* ``abuse_report_outbox`` — one row per outbound message (or analyst task)
  with an explicit ``pending → sending → sent | failed`` lifecycle, so a
  send is claimed with ``FOR UPDATE SKIP LOCKED`` and recorded in its own
  short transaction. ``UNIQUE (report_id, recipient, followup_seq)`` makes
  enqueueing idempotent.
* ``smtp_send_ledger`` — one row per SMTP transaction; counting the last
  hour gives a rate limit shared by every process.
* ``phishing_sites`` claim columns — a lease (``report_lease_until``) and
  its owner, plus bounded retry bookkeeping for the site-level loop.
* ``abuse_reports`` — follow-up counters and the evidence snapshot used by
  follow-ups. Repairing the legacy columns of that table (the tracker's old
  runtime fallback kept only six) and its ``report_id`` uniqueness is left
  to revision 003, which consolidates every pre-existing table.

The SQL lives in module-level tuples so tests can build the same schema
without running Alembic (``UPGRADE_STATEMENTS``/``DOWNGRADE_STATEMENTS``).
Every statement is idempotent. New timestamp columns are ``TIMESTAMPTZ``.
"""

from typing import Sequence, Tuple, Union

from alembic import op

# revision identifiers
revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


OUTBOX_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS abuse_report_outbox (
    id BIGSERIAL PRIMARY KEY,
    report_id TEXT NOT NULL,
    site_url TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'email'
        CHECK (channel IN ('email', 'web_form', 'manual_review')),
    audience TEXT NOT NULL DEFAULT 'primary'
        CHECK (audience IN ('primary', 'cc')),
    followup_seq INTEGER NOT NULL DEFAULT 0 CHECK (followup_seq >= 0),
    recipient TEXT NOT NULL,
    cc TEXT NOT NULL DEFAULT '',
    form_url TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'pending_manual')),
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    last_error TEXT,
    message_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ,
    locked_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ,
    CONSTRAINT uq_abuse_report_outbox_report_recipient
        UNIQUE (report_id, recipient, followup_seq)
)
"""

SMTP_LEDGER_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS smtp_send_ledger (
    id BIGSERIAL PRIMARY KEY,
    bucket TEXT NOT NULL DEFAULT 'smtp',
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

ABUSE_REPORTS_NEW_COLUMNS_SQL: Tuple[str, ...] = (
    "ALTER TABLE abuse_reports ADD COLUMN IF NOT EXISTS follow_up_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE abuse_reports ADD COLUMN IF NOT EXISTS last_follow_up_at TIMESTAMPTZ",
    "ALTER TABLE abuse_reports ADD COLUMN IF NOT EXISTS evidence JSONB",
)

PHISHING_SITES_CLAIM_COLUMNS_SQL: Tuple[str, ...] = (
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS report_lease_until TIMESTAMPTZ",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS report_claimed_by TEXT",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS report_attempts INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS report_last_error TEXT",
)

INDEX_SQL: Tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_abuse_report_outbox_dispatch "
    "ON abuse_report_outbox (status, next_attempt_at)",
    "CREATE INDEX IF NOT EXISTS idx_abuse_report_outbox_report "
    "ON abuse_report_outbox (report_id)",
    "CREATE INDEX IF NOT EXISTS idx_abuse_report_outbox_site ON abuse_report_outbox (site_url)",
    "CREATE INDEX IF NOT EXISTS idx_smtp_send_ledger_bucket_time "
    "ON smtp_send_ledger (bucket, acquired_at)",
    "CREATE INDEX IF NOT EXISTS idx_phishing_sites_report_queue "
    "ON phishing_sites (abuse_report_sent, site_status)",
)

UPGRADE_STATEMENTS: Tuple[str, ...] = (
    OUTBOX_TABLE_SQL,
    SMTP_LEDGER_TABLE_SQL,
    *ABUSE_REPORTS_NEW_COLUMNS_SQL,
    *PHISHING_SITES_CLAIM_COLUMNS_SQL,
    *INDEX_SQL,
)

DOWNGRADE_STATEMENTS: Tuple[str, ...] = (
    "DROP INDEX IF EXISTS idx_phishing_sites_report_queue",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS report_last_error",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS report_attempts",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS report_claimed_by",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS report_lease_until",
    "ALTER TABLE abuse_reports DROP COLUMN IF EXISTS evidence",
    "ALTER TABLE abuse_reports DROP COLUMN IF EXISTS last_follow_up_at",
    "ALTER TABLE abuse_reports DROP COLUMN IF EXISTS follow_up_count",
    "DROP TABLE IF EXISTS smtp_send_ledger",
    "DROP TABLE IF EXISTS abuse_report_outbox",
)


def upgrade() -> None:
    """Create the outbox and ledger tables and the claim/follow-up columns."""
    for statement in UPGRADE_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    """Drop everything this revision added."""
    for statement in DOWNGRADE_STATEMENTS:
        op.execute(statement)

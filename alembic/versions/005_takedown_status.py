"""Track takedown probes: consecutive-failure counters and status history.

Revision ID: 005
Revises: 004
Create Date: 2026-10-03

The takedown monitor only confirms a site as ``down`` after N consecutive
failing probe cycles and keeps every status transition (including
resurrections) in ``site_status_events``. All statements are idempotent
(``IF NOT EXISTS`` / ``IF EXISTS``). The SQL is exposed as module constants so
tests can build the schema without running Alembic.
"""

from typing import Sequence, Tuple, Union

from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

UPGRADE_STATEMENTS: Tuple[str, ...] = (
    # Consecutive cycles whose probe failed (nxdomain, connection error,
    # HTTP 404/410); reset by any other outcome.
    "ALTER TABLE phishing_sites "
    "ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0",
    # Consecutive cycles that saw a parking/registrar placeholder page.
    "ALTER TABLE phishing_sites "
    "ADD COLUMN IF NOT EXISTS consecutive_parked INTEGER NOT NULL DEFAULT 0",
    # Classification of the latest probe (up, nxdomain, connection_error,
    # http_error, waf_challenge, parked, ssrf_blocked) and when it ran.
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS last_probe_class TEXT",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS last_probe_at TIMESTAMP",
    # Last RDAP/IP enrichment, so it runs only on IP change or once a day.
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS ip_checked_at TIMESTAMP",
    """
    CREATE TABLE IF NOT EXISTS site_status_events (
        id BIGSERIAL PRIMARY KEY,
        site_id INTEGER NOT NULL REFERENCES phishing_sites(id) ON DELETE CASCADE,
        site_url TEXT NOT NULL,
        old_status TEXT,
        new_status TEXT NOT NULL,
        probe_class TEXT,
        status_code INTEGER,
        detail TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_site_status_events_site "
    "ON site_status_events(site_id, created_at)",
)

DOWNGRADE_STATEMENTS: Tuple[str, ...] = (
    "DROP TABLE IF EXISTS site_status_events",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS ip_checked_at",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS last_probe_at",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS last_probe_class",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS consecutive_parked",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS consecutive_failures",
)


def upgrade() -> None:
    """Add probe counters to phishing_sites and create site_status_events."""
    for statement in UPGRADE_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    """Drop site_status_events and the probe columns."""
    for statement in DOWNGRADE_STATEMENTS:
        op.execute(statement)

"""Detection core v2: brand catalogue, captures, LLM judge audit, fusion output.

Revision ID: 007
Revises: 006
Create Date: 2026-10-04

* ``brands``, ``brand_domains``, ``brand_assets`` — the brand catalogue managed from the
  console (aliases, official domains, lure vocabulary, takedown preferences, reference
  favicons/logos with their perceptual hashes). The detector matches hosts and pages
  against it; a brand's official domains are never flagged as impersonating it.
* ``captures`` — one real-browser capture per URL and client profile (redirect chain, TLS,
  server IP/ASN, extracted features, HTML/screenshot/favicon hashes, artefacts on disk).
* ``llm_judgements`` — audit log of the optional multimodal judge (input hash, model,
  prompt version, verdict, tokens, cost); the daily budget is summed from it.
* ``phishing_sites`` gains the calibrated fusion output (probability, coverage), the
  detector version that produced it and the latest capture.

The SQL lives in module-level tuples so tests can build the same schema without running
Alembic. Every statement is idempotent.
"""

from typing import Sequence, Tuple, Union

from alembic import op

# revision identifiers
revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BRANDS_SQL = """
CREATE TABLE IF NOT EXISTS brands (
    id BIGSERIAL PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name TEXT NOT NULL,
    category TEXT,
    country TEXT,
    priority SMALLINT NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
    aliases JSONB NOT NULL DEFAULT '[]'::jsonb,
    lure_keywords JSONB NOT NULL DEFAULT '{}'::jsonb,
    takedown_preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

BRAND_DOMAINS_SQL = """
CREATE TABLE IF NOT EXISTS brand_domains (
    id BIGSERIAL PRIMARY KEY,
    brand_id BIGINT NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    domain TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'official' CHECK (kind IN ('official', 'login', 'app')),
    login_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

BRAND_ASSETS_SQL = """
CREATE TABLE IF NOT EXISTS brand_assets (
    id BIGSERIAL PRIMARY KEY,
    brand_id BIGINT NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('favicon', 'logo')),
    source_url TEXT,
    sha256 TEXT NOT NULL,
    mmh3 INTEGER,
    phash TEXT NOT NULL,
    dhash TEXT NOT NULL,
    width INTEGER,
    height INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (brand_id, sha256)
)
"""

CAPTURES_SQL = """
CREATE TABLE IF NOT EXISTS captures (
    id BIGSERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES phishing_sites(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ok', 'error', 'blocked', 'timeout')),
    error TEXT,
    final_url TEXT,
    http_status INTEGER,
    server_ip TEXT,
    asn INTEGER,
    asn_org TEXT,
    tls JSONB NOT NULL DEFAULT '{}'::jsonb,
    redirect_chain JSONB NOT NULL DEFAULT '[]'::jsonb,
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    html_sha256 TEXT,
    html_tlsh TEXT,
    screenshot_phash TEXT,
    favicon_mmh3 INTEGER,
    favicon_phash TEXT,
    artifacts_path TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

LLM_JUDGEMENTS_SQL = """
CREATE TABLE IF NOT EXISTS llm_judgements (
    id BIGSERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES phishing_sites(id) ON DELETE SET NULL,
    capture_id BIGINT REFERENCES captures(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ok', 'refused', 'invalid', 'error', 'budget')),
    verdict JSONB NOT NULL DEFAULT '{}'::jsonb,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd NUMERIC(12, 6),
    latency_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

PHISHING_SITES_FUSION_COLUMNS_SQL: Tuple[str, ...] = (
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS last_capture_id BIGINT "
    "REFERENCES captures(id) ON DELETE SET NULL",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS fusion_probability REAL",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS fusion_coverage REAL",
    "ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS detector_version TEXT",
)

INDEX_SQL: Tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_brand_domains_brand ON brand_domains (brand_id)",
    "CREATE INDEX IF NOT EXISTS idx_brand_assets_brand ON brand_assets (brand_id)",
    "CREATE INDEX IF NOT EXISTS idx_brand_assets_mmh3 ON brand_assets (mmh3)",
    "CREATE INDEX IF NOT EXISTS idx_captures_site_captured ON captures (site_id, captured_at)",
    "CREATE INDEX IF NOT EXISTS idx_captures_url_captured ON captures (url, captured_at)",
    "CREATE INDEX IF NOT EXISTS idx_llm_judgements_created ON llm_judgements (created_at)",
    "CREATE INDEX IF NOT EXISTS idx_llm_judgements_input ON llm_judgements (input_sha256)",
)

UPGRADE_STATEMENTS: Tuple[str, ...] = (
    BRANDS_SQL,
    BRAND_DOMAINS_SQL,
    BRAND_ASSETS_SQL,
    CAPTURES_SQL,
    LLM_JUDGEMENTS_SQL,
    *PHISHING_SITES_FUSION_COLUMNS_SQL,
    *INDEX_SQL,
)

DOWNGRADE_STATEMENTS: Tuple[str, ...] = (
    "DROP INDEX IF EXISTS idx_llm_judgements_input",
    "DROP INDEX IF EXISTS idx_llm_judgements_created",
    "DROP INDEX IF EXISTS idx_captures_url_captured",
    "DROP INDEX IF EXISTS idx_captures_site_captured",
    "DROP INDEX IF EXISTS idx_brand_assets_mmh3",
    "DROP INDEX IF EXISTS idx_brand_assets_brand",
    "DROP INDEX IF EXISTS idx_brand_domains_brand",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS detector_version",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS fusion_coverage",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS fusion_probability",
    "ALTER TABLE phishing_sites DROP COLUMN IF EXISTS last_capture_id",
    "DROP TABLE IF EXISTS llm_judgements",
    "DROP TABLE IF EXISTS captures",
    "DROP TABLE IF EXISTS brand_assets",
    "DROP TABLE IF EXISTS brand_domains",
    "DROP TABLE IF EXISTS brands",
)


def upgrade() -> None:
    """Create the detection-core tables and the fusion columns."""
    for statement in UPGRADE_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    """Drop everything this revision added."""
    for statement in DOWNGRADE_STATEMENTS:
        op.execute(statement)

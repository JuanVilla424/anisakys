"""Alembic environment configuration for Anisakys.

DATABASE_URL is loaded from the .env file or environment variable.
No ORM models are used — migrations are written in raw SQL via op.execute().
"""

import os
from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

# ---------------------------------------------------------------------------
# Load DATABASE_URL
# ---------------------------------------------------------------------------

database_url = os.environ.get("DATABASE_URL")

if not database_url:
    # Fall back to reading .env in the project root directly
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_file = os.path.join(project_root, ".env")
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("DATABASE_URL=") and not line.startswith("#"):
                    database_url = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

if not database_url:
    raise RuntimeError(
        "DATABASE_URL is not set. "
        "Add it to your .env file or export it as an environment variable."
    )

config.set_main_option("sqlalchemy.url", database_url)

# No ORM models — all migrations use raw SQL via op.execute()
target_metadata = None


# ---------------------------------------------------------------------------
# Migration runner (online mode only)
# ---------------------------------------------------------------------------


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()

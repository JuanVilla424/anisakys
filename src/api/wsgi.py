"""WSGI entrypoint serving the Anisakys REST API in production.

Run it with gunicorn (``entrypoint-backend.sh`` does)::

    gunicorn --bind 0.0.0.0:8091 --worker-class gthread --threads 4 'src.api.wsgi:create_app()'
    gunicorn --bind 0.0.0.0:8091 src.api.wsgi:app   # same app, created on first access

This module is the *API process role*: it only serves HTTP. Unlike
``anisakys.py --start-api`` (the local development server), it never starts
background jobs and never sends e-mail, because every gunicorn worker imports
it and each would run its own copy of every job:

* no abuse-reporting loop, takedown monitor, GSB rescan, CT/feed jobs or
  image/ads/e-mail schedulers are started;
* the API gets no ``report_manager``, so ``POST /api/v1/report`` only persists
  the submission and the reporting process role sends the report;
* it gets no ``scheduler``/``email_scheduler``, so on-demand thread searches
  answer 503 while the created thread rows are processed by the scheduler role.

Schema changes are not applied here either: ``alembic upgrade head`` runs
before the server starts, and :func:`create_app` refuses to serve a database
that is behind the code.
"""

from typing import Any, Optional

from flask import Flask

# Import order matters: loading src.detection first resolves the
# src.intelligence <-> src.detection import cycle (src.main and the test
# suite import them in the same order).
import src.detection.analyzer  # noqa: F401
from src.api.phishing_api import PhishingAPI
from src.config import settings, secret_value
from src.database import DatabaseManager, ensure_schema_is_current
from src.logger import logger
from src.reporting.email_detector import EnhancedAbuseEmailDetector

_app: Optional[Flask] = None


def create_app(api_key: Optional[str] = None) -> Flask:
    """Build the Flask application for the API process role.

    Args:
        api_key: Master API key; defaults to ``settings.ANISAKYS_API_KEY``. When
            neither is set only database-issued API keys are accepted.

    Returns:
        The configured Flask application (WSGI callable).

    Raises:
        RuntimeError: If the database schema is not at the latest Alembic
            revision.
    """
    master_key = api_key or secret_value(settings.ANISAKYS_API_KEY)
    if not master_key:
        logger.warning("⚠️  ANISAKYS_API_KEY is not set: only database API keys are accepted")

    db_manager = DatabaseManager()
    ensure_schema_is_current(db_manager.engine)
    api = PhishingAPI(
        db_manager,
        EnhancedAbuseEmailDetector(db_manager),
        api_key=master_key,
        report_manager=None,
        scheduler=None,
        email_scheduler=None,
    )
    logger.info("🚀 Anisakys API (WSGI) ready; background jobs run in the scheduler role")
    return api.app


def __getattr__(name: str) -> Any:
    """Create the module-level ``app`` lazily, on first access.

    Importing this module (e.g. in tests) therefore has no side effects, while
    ``gunicorn src.api.wsgi:app`` still finds the application.

    Args:
        name: Attribute being looked up on the module.

    Returns:
        The WSGI application when ``name == "app"``.

    Raises:
        AttributeError: For any other unknown attribute.
    """
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""
logger.py
~~~~~~~~~

Application logger.

Every module logs through :data:`logger` (the ``app`` logger). It has no
handlers of its own and propagates to the root logger, which
:func:`src.observability.structured_logger.configure_logging` sets up once per
process: level from ``LOG_LEVEL`` (default INFO), console output and a JSON
rotating file owned by this process only, with secrets redacted.

Importing this module applies that configuration from the environment so
that early log lines are not lost; ``src.main.main`` re-applies it with the
loaded settings and command-line overrides (a no-op when nothing changed).
"""

import logging

from src.observability.structured_logger import configure_logging

configure_logging()

logger = logging.getLogger("app")

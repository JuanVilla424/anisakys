"""
API module for Anisakys Phishing Detection Engine.

Provides REST API for external phishing reports.
"""

from src.api.phishing_api import PhishingAPI, upgrade_phishing_db
from src.utils.timeouts import OperationTimeoutError, timeout

# Backwards-compatible alias: the API used to define its own TimeoutError.
TimeoutError = OperationTimeoutError  # noqa: A001

__all__ = [
    "PhishingAPI",
    "OperationTimeoutError",
    "TimeoutError",
    "timeout",
    "upgrade_phishing_db",
]

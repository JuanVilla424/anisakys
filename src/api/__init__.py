"""
API module for Anisakys Phishing Detection Engine.

Provides REST API for external phishing reports.
"""

from src.api.phishing_api import PhishingAPI, TimeoutError, timeout, upgrade_phishing_db

__all__ = [
    "PhishingAPI",
    "TimeoutError",
    "timeout",
    "upgrade_phishing_db",
]

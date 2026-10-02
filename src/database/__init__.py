"""
Database module for Anisakys Phishing Detection Engine.

Provides database management and connection handling.
"""

from src.database.manager import DatabaseManager, db_engine, DATABASE_URL

__all__ = [
    "DatabaseManager",
    "db_engine",
    "DATABASE_URL",
]

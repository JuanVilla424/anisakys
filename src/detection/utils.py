"""
Phishing Utils for Anisakys Phishing Detection Engine.

Utility functions for URL processing and phishing detection.
"""

import datetime
import re
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from sqlalchemy import create_engine, text

from src.config import settings
from src.database import DATABASE_URL, db_engine
from src.dns.network_utils import safe_get_with_redirects, SSRFRedirectError
from src.logger import logger

# Default User-Agent for HTTP requests
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


class PhishingUtils:
    """Utility functions for phishing detection and processing."""

    @staticmethod
    def store_scan_result(
        url: str, response_code: int, found_keywords: List[str], db_file: str = DATABASE_URL
    ) -> None:
        """Store scan result in database."""
        engine = create_engine(db_file, pool_pre_ping=True, echo=False)
        with engine.begin() as conn:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            keywords_str = ", ".join(found_keywords) if found_keywords else ""

            result = conn.execute(
                text("SELECT id, first_seen, count FROM scan_results WHERE url=:url"), {"url": url}
            ).fetchone()

            if result:
                new_count = result[2] + 1
                conn.execute(
                    text(
                        """
                        UPDATE scan_results
                        SET last_seen=:timestamp, response_code=:response_code,
                            found_keywords=:keywords_str, count=:new_count
                        WHERE url=:url
                    """
                    ),
                    {
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "keywords_str": keywords_str,
                        "new_count": new_count,
                        "url": url,
                    },
                )
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO scan_results
                        (url, first_seen, last_seen, response_code, found_keywords, count)
                        VALUES (:url, :timestamp, :timestamp, :response_code, :keywords_str, 1)
                    """
                    ),
                    {
                        "url": url,
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "keywords_str": keywords_str,
                    },
                )
            logger.info(f"💾 Stored scan result for {url}")
        engine.dispose()

    @staticmethod
    def update_scan_result_response_code(url: str, response_code: int) -> None:
        """Update response code for existing scan result."""
        with db_engine.begin() as conn:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = conn.execute(
                text("SELECT id, count FROM scan_results WHERE url=:url"), {"url": url}
            ).fetchone()

            if result:
                new_count = result[1] + 1
                conn.execute(
                    text(
                        """
                        UPDATE scan_results
                        SET last_seen=:timestamp, response_code=:response_code, count=:new_count
                        WHERE url=:url
                    """
                    ),
                    {
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "new_count": new_count,
                        "url": url,
                    },
                )
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO scan_results
                        (url, first_seen, last_seen, response_code, found_keywords, count)
                        VALUES (:url, :timestamp, :timestamp, :response_code, '', 1)
                    """
                    ),
                    {"url": url, "timestamp": timestamp, "response_code": response_code},
                )
            logger.info(f"💾 Updated scan result response code for {url}")

    @staticmethod
    def log_positive_result(url: str, found_keywords: List[str]) -> None:
        """Log a positive phishing detection result."""
        log_file = "positive_report.txt"
        entry = (
            f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {url}: {', '.join(found_keywords)}\n"
        )

        try:
            with open(log_file, "r+") as f:
                if url in f.read():
                    logger.debug(f"⏭️ Duplicate entry skipped: {url}")
                    return
                f.write(entry)
        except FileNotFoundError:
            with open(log_file, "w") as f:
                f.write(entry)

        logger.info(f"🎯 Logged phishing match: {url}")

    @staticmethod
    def determine_site_status(
        url: str,
        resolved_ip: Optional[str],
        current_status: str,
        current_takedown: Optional[str],
        timestamp: str,
        timeout: int,
    ) -> Tuple[str, Optional[str]]:
        """Determine the site's status ("up" or "down") and takedown date."""
        if not resolved_ip:
            new_status = "down"
            new_takedown = current_takedown if current_status == "down" else timestamp
        else:
            try:
                response = safe_get_with_redirects(
                    url,
                    timeout=timeout,
                    headers={
                        "User-Agent": DEFAULT_USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate, br",
                        "DNT": "1",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                    },
                )
                if response.status_code == 200:
                    if "suspended" in response.text.lower():
                        new_status = "down"
                        new_takedown = current_takedown if current_status == "down" else timestamp
                    else:
                        new_status = "up"
                        new_takedown = None
                else:
                    new_status = "down"
                    new_takedown = current_takedown if current_status == "down" else timestamp
            except SSRFRedirectError as e:
                logger.warning(f"🛑 SSRF: {e.blocked_url} is non-public; marking site down")
                new_status = "down"
                new_takedown = current_takedown if current_status == "down" else timestamp
            except Exception as e:
                logger.error(f"❌ GET request failed for {url}: {e}")
                new_status = "down"
                new_takedown = current_takedown if current_status == "down" else timestamp

        return new_status, new_takedown


# EPIC-006: generate_queries_file moved to src/generators/query_generator.py

"""
Phishing Utils for Anisakys Phishing Detection Engine.

Utility functions for URL processing and phishing detection.
"""

import datetime
from typing import List, Optional, Tuple

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from src.database import DATABASE_URL, db_engine
from src.detection.liveness import probe_site
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
                    text("""
                        UPDATE scan_results
                        SET last_seen=:timestamp, response_code=:response_code,
                            found_keywords=:keywords_str, count=:new_count
                        WHERE url=:url
                    """),
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
                    text("""
                        INSERT INTO scan_results
                        (url, first_seen, last_seen, response_code, found_keywords, count)
                        VALUES (:url, :timestamp, :timestamp, :response_code, :keywords_str, 1)
                    """),
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
                    text("""
                        UPDATE scan_results
                        SET last_seen=:timestamp, response_code=:response_code, count=:new_count
                        WHERE url=:url
                    """),
                    {
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "new_count": new_count,
                        "url": url,
                    },
                )
            else:
                conn.execute(
                    text("""
                        INSERT INTO scan_results
                        (url, first_seen, last_seen, response_code, found_keywords, count)
                        VALUES (:url, :timestamp, :timestamp, :response_code, '', 1)
                    """),
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
    def _stored_site_status(url: str) -> Tuple[Optional[str], Optional[str]]:
        """Read the persisted status and takedown date of a site.

        Args:
            url: Site URL as stored in ``phishing_sites``.

        Returns:
            ``(site_status, takedown_date)``; ``(None, None)`` if unknown or
            the database is unavailable.
        """
        try:
            with db_engine.connect() as conn:
                row = conn.execute(
                    text("SELECT site_status, takedown_date FROM phishing_sites WHERE url = :url"),
                    {"url": url},
                ).first()
        except SQLAlchemyError as e:
            logger.warning(f"⚠️ Could not read stored status for {url}: {type(e).__name__}")
            return None, None
        if row is None:
            return None, None
        return row[0], (str(row[1]) if row[1] is not None else None)

    @staticmethod
    def determine_site_status(
        url: str,
        resolved_ip: Optional[str],
        current_status: Optional[str],
        current_takedown: Optional[str],
        timestamp: str,
        timeout: int,
    ) -> Tuple[str, Optional[str]]:
        """Probe a site once and report whether it is (still) up.

        Compatibility wrapper for callers that probe outside the takedown
        monitor. One observation can show that a site is alive, but it can
        never confirm a takedown: that needs ``TAKEDOWN_CONSECUTIVE_FAILURES``
        failing cycles, which only :class:`src.monitoring.takedown.TakedownMonitor`
        tracks. A failing, challenged, parked or blocked probe therefore keeps
        the known status (the caller's, else the stored one, else ``"up"``).

        Args:
            url: Site URL.
            resolved_ip: Ignored; the probe resolves the host itself (callers
                used to pass ``None`` whenever an RDAP lookup failed).
            current_status: Status known to the caller, if any.
            current_takedown: Takedown date known to the caller, if any.
            timestamp: Unused; kept for signature compatibility.
            timeout: Per-request timeout in seconds.

        Returns:
            ``("up", None)`` when the probe saw the site alive, otherwise the
            unchanged ``(status, takedown_date)``.
        """
        probe = probe_site(url, timeout)
        if probe.result.is_alive:
            return "up", None

        status, takedown = current_status, current_takedown
        if status is None:
            status, takedown = PhishingUtils._stored_site_status(url)
        status = status or "up"
        logger.info(
            f"🔎 Single probe of {url} saw {probe.result.classification.value} "
            f"({probe.result.detail or probe.result.status_code}); keeping status '{status}' "
            "(takedowns are confirmed by the takedown monitor)"
        )
        return status, (takedown if status == "down" else None)


# EPIC-006: generate_queries_file moved to src/generators/query_generator.py

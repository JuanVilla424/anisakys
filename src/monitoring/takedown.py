"""
Takedown Monitor for Anisakys Phishing Detection Engine.

Monitors phishing sites for takedown status and updates database.
"""

from __future__ import annotations

import datetime
import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional

import requests
from sqlalchemy import text

from src.config import settings
from src.database import DatabaseManager
from src.detection import PhishingUtils
from src.dns.network_utils import get_ip_info
from src.logger import logger
from src.shutdown import shutdown_requested


class TakedownMonitor:
    """Enhanced takedown monitor with better status detection."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        timeout: int,
        check_interval: int = 3600,
        monitoring_event: threading.Event = None,
    ):
        self.db_manager = db_manager
        self.timeout = timeout
        self.check_interval = check_interval
        self.monitoring_event = monitoring_event

    def run(self):
        """Main monitoring loop."""
        first_cycle_done = False

        while not shutdown_requested:
            try:
                with self.db_manager.engine.begin() as conn:
                    sites = conn.execute(
                        text("SELECT url, site_status, takedown_date FROM phishing_sites")
                    ).fetchall()

                    for url, current_status, current_takedown in sites:
                        try:
                            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            resolved_ip, asn_provider = get_ip_info(domain)

                            # Use the refactored function to determine site status
                            new_status, new_takedown = PhishingUtils.determine_site_status(
                                url,
                                resolved_ip,
                                current_status,
                                current_takedown,
                                timestamp,
                                self.timeout,
                            )

                            # Update database if status changed
                            if new_status != current_status or new_takedown != current_takedown:
                                conn.execute(
                                    text(
                                        """
                                        UPDATE phishing_sites
                                        SET site_status=:new_status, takedown_date=:new_takedown, last_seen=:timestamp
                                        WHERE url=:url
                                    """
                                    ),
                                    {
                                        "new_status": new_status,
                                        "new_takedown": new_takedown,
                                        "timestamp": timestamp,
                                        "url": url,
                                    },
                                )
                                logger.info(
                                    f"🔄 Updated {url}: site_status='{new_status}', takedown_date='{new_takedown}'"
                                )

                        except Exception as e:
                            logger.error(f"❌ Error checking status for {url}: {e}")
                            continue

                # Signal completion of first cycle
                if not first_cycle_done:
                    first_cycle_done = True
                    if self.monitoring_event and not self.monitoring_event.is_set():
                        logger.info(
                            "✅ Takedown monitor initial cycle complete, setting monitoring event."
                        )
                        self.monitoring_event.set()

            except Exception as e:
                logger.error(f"❌ Error in monitoring loop: {e}")

            time.sleep(self.check_interval)


def save_offset(offset: int):
    """Save current offset to file."""
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))
    logger.debug(f"💾 Offset saved as: {offset}")


def get_offset() -> int:
    """Get the current offset from a file."""
    try:
        with open(OFFSET_FILE, "r") as f:
            offset_str = f.read().strip()
            offset = int(float(offset_str))
            logger.debug(f"📖 Retrieved offset: {offset}")
            return offset
    except Exception as ex:
        logger.error(f"❌ Error getting offset from {OFFSET_FILE}: {ex}")
        return 0

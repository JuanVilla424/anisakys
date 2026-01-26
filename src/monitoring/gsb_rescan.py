"""
Google Safe Browsing Re-scan Job

Periodically re-verifies existing phishing sites against Google Safe Browsing API.
This catches cases where:
1. A site wasn't in GSB initially but was later reported
2. GSB classification changed (e.g., from safe to MALWARE)

Author: BMAD Dev Team
Date: 2026-01-25
"""

import logging
import time
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.database.manager import DatabaseManager
from src.intelligence.google_safe_browsing import GoogleSafeBrowsingIntegration
from src.observability.structured_logger import log_with_context, set_correlation_id

logger = logging.getLogger(__name__)


class GSBRescanJob:
    """
    Background job for re-scanning sites against Google Safe Browsing.

    Features:
    - Batch processing to respect API rate limits
    - Configurable re-scan interval
    - Alert generation on status changes
    - Thread-safe operation
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        rescan_interval_hours: int = 12,
        batch_size: int = 50,
        max_age_hours: int = 24,
    ):
        """
        Initialize GSB Re-scan Job.

        Args:
            db_manager: Database manager instance
            rescan_interval_hours: How often to run the job (default: 12 hours)
            batch_size: Number of URLs to check per batch (default: 50)
            max_age_hours: Re-scan sites not checked in this many hours (default: 24)
        """
        self.db_manager = db_manager or DatabaseManager()
        self.gsb = GoogleSafeBrowsingIntegration()
        self.rescan_interval_hours = rescan_interval_hours
        self.batch_size = batch_size
        self.max_age_hours = max_age_hours

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Statistics
        self.stats = {
            "total_rescans": 0,
            "threats_detected": 0,
            "status_changes": 0,
            "last_run": None,
            "last_run_duration_seconds": 0,
            "errors": 0,
        }

    def start(self):
        """Start the background re-scan job."""
        if self._running:
            logger.warning("GSB rescan job is already running")
            return

        if not self.gsb.is_available():
            logger.error("GSB API key not configured, cannot start rescan job")
            return

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(
            f"🔄 GSB rescan job started (interval: {self.rescan_interval_hours}h, "
            f"batch: {self.batch_size}, max_age: {self.max_age_hours}h)"
        )

    def stop(self):
        """Stop the background re-scan job."""
        if not self._running:
            return

        self._stop_event.set()
        self._running = False

        if self._thread:
            self._thread.join(timeout=10)

        logger.info("🛑 GSB rescan job stopped")

    def _run_loop(self):
        """Main loop for the background job."""
        while not self._stop_event.is_set():
            try:
                self._run_rescan()
            except Exception as e:
                self.stats["errors"] += 1
                logger.error(f"❌ GSB rescan job error: {e}")

            # Wait for next interval or stop signal
            self._stop_event.wait(timeout=self.rescan_interval_hours * 3600)

    def _run_rescan(self) -> Dict[str, Any]:
        """
        Run a single re-scan cycle.

        Returns:
            Dict with rescan results and statistics
        """
        correlation_id = set_correlation_id()
        start_time = time.time()

        log_with_context(
            logger,
            logging.INFO,
            "Starting GSB rescan cycle",
            correlation_id=correlation_id,
            max_age_hours=self.max_age_hours,
            batch_size=self.batch_size,
            event_type="gsb_rescan_start",
        )

        results = {
            "correlation_id": correlation_id,
            "started_at": datetime.now().isoformat(),
            "sites_checked": 0,
            "threats_found": 0,
            "status_changes": [],
            "errors": [],
        }

        try:
            # Get sites needing re-scan
            sites = self.db_manager.get_sites_for_gsb_rescan(
                max_age_hours=self.max_age_hours, limit=self.batch_size
            )

            if not sites:
                logger.info("📭 No sites need GSB re-scanning")
                results["message"] = "No sites to rescan"
                return results

            logger.info(f"🔍 Re-scanning {len(sites)} sites against GSB")

            # Process sites in batches for rate limiting
            for site in sites:
                url = site["url"]
                previous_safe = site.get("gsb_safe", 1) == 1

                try:
                    # Check URL against GSB
                    gsb_result = self.gsb.check_url(url)
                    results["sites_checked"] += 1

                    if gsb_result.get("checked"):
                        # Update database with result
                        update_result = self.db_manager.update_gsb_result(
                            url=url, gsb_result=gsb_result, previous_safe=previous_safe
                        )

                        if not gsb_result.get("safe", True):
                            results["threats_found"] += 1
                            self.stats["threats_detected"] += 1

                        if update_result.get("status_changed"):
                            results["status_changes"].append(
                                {
                                    "url": url,
                                    "threat_type": update_result.get("threat_type"),
                                    "alert": update_result.get("alert"),
                                }
                            )
                            self.stats["status_changes"] += 1

                            # Log the status change prominently
                            log_with_context(
                                logger,
                                logging.WARNING,
                                f"🚨 GSB STATUS CHANGE: {url}",
                                url=url,
                                threat_type=update_result.get("threat_type"),
                                previous_status="safe",
                                new_status="threat",
                                event_type="gsb_status_change",
                            )
                    else:
                        # GSB check failed (API error, rate limit, etc.)
                        error_msg = gsb_result.get("error", "Unknown error")
                        results["errors"].append({"url": url, "error": error_msg})

                    # Small delay between requests to avoid rate limiting
                    time.sleep(0.1)

                except Exception as e:
                    results["errors"].append({"url": url, "error": str(e)})
                    logger.error(f"❌ Error re-scanning {url}: {e}")

            # Update statistics
            self.stats["total_rescans"] += results["sites_checked"]
            self.stats["last_run"] = datetime.now().isoformat()
            self.stats["last_run_duration_seconds"] = time.time() - start_time

            results["completed_at"] = datetime.now().isoformat()
            results["duration_seconds"] = time.time() - start_time

            log_with_context(
                logger,
                logging.INFO,
                "GSB rescan cycle completed",
                sites_checked=results["sites_checked"],
                threats_found=results["threats_found"],
                status_changes=len(results["status_changes"]),
                errors=len(results["errors"]),
                duration_seconds=results["duration_seconds"],
                event_type="gsb_rescan_complete",
            )

            return results

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"❌ GSB rescan cycle failed: {e}")
            results["error"] = str(e)
            return results

    def run_once(self) -> Dict[str, Any]:
        """
        Run a single re-scan cycle (for manual invocation).

        Returns:
            Dict with rescan results
        """
        return self._run_rescan()

    def get_stats(self) -> Dict[str, Any]:
        """Get current job statistics."""
        return {
            **self.stats,
            "is_running": self._running,
            "gsb_available": self.gsb.is_available(),
            "config": {
                "rescan_interval_hours": self.rescan_interval_hours,
                "batch_size": self.batch_size,
                "max_age_hours": self.max_age_hours,
            },
        }


# Singleton instance for easy access
gsb_rescan_job: Optional[GSBRescanJob] = None


def get_gsb_rescan_job(
    db_manager: Optional[DatabaseManager] = None,
    rescan_interval_hours: int = 12,
    batch_size: int = 50,
    max_age_hours: int = 24,
) -> GSBRescanJob:
    """
    Get or create the GSB rescan job instance.

    Args:
        db_manager: Database manager instance
        rescan_interval_hours: How often to run the job
        batch_size: Number of URLs per batch
        max_age_hours: Maximum age before re-scan

    Returns:
        GSBRescanJob instance
    """
    global gsb_rescan_job
    if gsb_rescan_job is None:
        gsb_rescan_job = GSBRescanJob(
            db_manager=db_manager,
            rescan_interval_hours=rescan_interval_hours,
            batch_size=batch_size,
            max_age_hours=max_age_hours,
        )
    return gsb_rescan_job


def start_gsb_rescan_job(
    rescan_interval_hours: int = 12,
    batch_size: int = 50,
    max_age_hours: int = 24,
) -> GSBRescanJob:
    """
    Start the GSB rescan background job.

    Args:
        rescan_interval_hours: How often to run (default: 12 hours)
        batch_size: URLs per batch (default: 50)
        max_age_hours: Re-scan sites older than this (default: 24 hours)

    Returns:
        Started GSBRescanJob instance
    """
    job = get_gsb_rescan_job(
        rescan_interval_hours=rescan_interval_hours,
        batch_size=batch_size,
        max_age_hours=max_age_hours,
    )
    job.start()
    return job


def stop_gsb_rescan_job():
    """Stop the GSB rescan background job."""
    global gsb_rescan_job
    if gsb_rescan_job:
        gsb_rescan_job.stop()

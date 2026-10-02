"""Background scheduler for periodic image tracking and ads searches."""

import json
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy import text

from src.database.manager import db_engine
from src.intelligence.image_search import ImageSearchClient
from src.intelligence.ads_search import AdsSearchClient
from src.logger import logger

STALE_EXECUTION_MINUTES = 40


class ImageTrackingScheduler:
    def __init__(self, serpapi_key: str, s3_bucket: str, aws_region: str):
        self._running = False
        self._thread = None
        self.client = ImageSearchClient(serpapi_key, s3_bucket, aws_region) if s3_bucket else None
        self.ads_client = AdsSearchClient(serpapi_key) if serpapi_key else None
        self.check_interval = 3600  # check every hour

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Image tracking scheduler started")

    def stop(self):
        self._running = False
        logger.info("Image tracking scheduler stopped")

    def _run(self):
        while self._running:
            try:
                self._process_due_threads()
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
            time.sleep(self.check_interval)

    def _cleanup_stale_executions(self, conn):
        """Mark executions stuck in 'running' for 40+ minutes as failed."""
        result = conn.execute(
            text(
                "UPDATE thread_executions SET status='failed', "
                "error_message='Stale execution (40+ min)', "
                "completed_at=NOW() "
                "WHERE status='running' "
                "AND started_at < NOW() - make_interval(mins => :minutes)"
            ),
            {"minutes": STALE_EXECUTION_MINUTES},
        )
        if result.rowcount > 0:
            logger.warning(f"Cleaned up {result.rowcount} stale execution(s)")

    def _process_due_threads(self):
        with db_engine.begin() as conn:
            self._cleanup_stale_executions(conn)

            # --- image_tracking threads ---
            if self.client:
                rows = conn.execute(
                    text(
                        """
                        SELECT id, image_s3_key FROM analysis_threads
                        WHERE thread_type = 'image_tracking'
                          AND status = 'active'
                          AND search_interval_hours IS NOT NULL
                          AND (
                              last_searched_at IS NULL
                              OR last_searched_at < NOW() - (search_interval_hours || ' hours')::INTERVAL
                          )
                        """
                    )
                ).fetchall()

                for row in rows:
                    if not row.image_s3_key:
                        continue
                    self._run_image_tracking(conn, row.id, row.image_s3_key)

            # --- google_ads threads ---
            if self.ads_client:
                ads_rows = conn.execute(
                    text(
                        """
                        SELECT id, details FROM analysis_threads
                        WHERE thread_type = 'google_ads'
                          AND status = 'active'
                          AND search_interval_hours IS NOT NULL
                          AND (
                              last_searched_at IS NULL
                              OR last_searched_at < NOW() - (search_interval_hours || ' hours')::INTERVAL
                          )
                        """
                    )
                ).fetchall()

                for row in ads_rows:
                    self._run_google_ads(conn, row.id, row.details)

    def _run_image_tracking(self, conn, thread_id: int, s3_key: str):
        execution_id = None
        try:
            exec_result = conn.execute(
                text(
                    "INSERT INTO thread_executions (thread_id, execution_type, status) "
                    "VALUES (:tid, 'scheduled_search', 'running') RETURNING id"
                ),
                {"tid": thread_id},
            )
            execution_id = exec_result.scalar()

            results = self.client.search_by_s3_key(s3_key)
            new_count = 0

            for r in results:
                existing = conn.execute(
                    text(
                        "SELECT id FROM thread_results WHERE thread_id = :tid AND found_url = :url"
                    ),
                    {"tid": thread_id, "url": r["url"]},
                ).fetchone()

                if existing:
                    conn.execute(
                        text(
                            "UPDATE thread_results SET last_detected_at = NOW(), execution_id = :eid "
                            "WHERE id = :id"
                        ),
                        {"id": existing.id, "eid": execution_id},
                    )
                else:
                    conn.execute(
                        text(
                            "INSERT INTO thread_results "
                            "(thread_id, result_type, found_url, title, thumbnail_url, source, execution_id) "
                            "VALUES (:tid, 'image_match', :url, :title, :thumb, :source, :eid)"
                        ),
                        {
                            "tid": thread_id,
                            "url": r["url"],
                            "title": r.get("title"),
                            "thumb": r.get("thumbnail"),
                            "source": r.get("source"),
                            "eid": execution_id,
                        },
                    )
                    new_count += 1

            total = conn.execute(
                text("SELECT COUNT(*) FROM thread_results WHERE thread_id = :tid"),
                {"tid": thread_id},
            ).scalar()

            conn.execute(
                text(
                    "UPDATE analysis_threads SET last_searched_at = NOW(), results_count = :count "
                    "WHERE id = :id"
                ),
                {"count": total, "id": thread_id},
            )
            conn.execute(
                text(
                    "UPDATE thread_executions SET status = 'completed', completed_at = NOW(), "
                    "results_count = :count WHERE id = :eid"
                ),
                {"count": new_count, "eid": execution_id},
            )
            logger.info(
                f"Thread {thread_id}: {new_count} new results, {total} total (execution {execution_id})"
            )
        except Exception as e:
            if execution_id is not None:
                try:
                    conn.execute(
                        text(
                            "UPDATE thread_executions SET status = 'failed', completed_at = NOW(), "
                            "error_message = :err WHERE id = :eid"
                        ),
                        {"err": str(e), "eid": execution_id},
                    )
                except Exception:
                    pass
            logger.error(f"Failed to search thread {thread_id}: {e}")

    def _run_google_ads(self, conn, thread_id: int, details):
        execution_id = None
        try:
            if isinstance(details, str):
                details = json.loads(details)
            elif details is None:
                details = {}

            keyword = details.get("keyword", "")
            location = details.get("location", "")
            language = details.get("language", "en")
            country_code = details.get("country_code", "us")

            if not keyword or not location:
                raise ValueError("google_ads thread missing keyword or location in details")

            exec_result = conn.execute(
                text(
                    "INSERT INTO thread_executions (thread_id, execution_type, status) "
                    "VALUES (:tid, 'scheduled_search', 'running') RETURNING id"
                ),
                {"tid": thread_id},
            )
            execution_id = exec_result.scalar()

            results = self.ads_client.search_ads(
                keyword=keyword,
                location=location,
                language=language,
                country_code=country_code,
            )
            new_count = 0

            for r in results:
                existing = conn.execute(
                    text(
                        "SELECT id FROM thread_results WHERE thread_id = :tid AND found_url = :url"
                    ),
                    {"tid": thread_id, "url": r["url"]},
                ).fetchone()

                if existing:
                    conn.execute(
                        text(
                            "UPDATE thread_results SET last_detected_at = NOW(), execution_id = :eid "
                            "WHERE id = :id"
                        ),
                        {"id": existing.id, "eid": execution_id},
                    )
                else:
                    conn.execute(
                        text(
                            "INSERT INTO thread_results "
                            "(thread_id, result_type, found_url, title, source, execution_id, extra_data) "
                            "VALUES (:tid, 'google_ad', :url, :title, :source, :eid, :extra)"
                        ),
                        {
                            "tid": thread_id,
                            "url": r["url"],
                            "title": r.get("title"),
                            "source": r.get("displayed_link"),
                            "eid": execution_id,
                            "extra": json.dumps(
                                {
                                    "description": r.get("description"),
                                    "position": r.get("position"),
                                    "ad_type": r.get("ad_type"),
                                    "sitelinks": r.get("sitelinks"),
                                }
                            ),
                        },
                    )
                    new_count += 1

            total = conn.execute(
                text("SELECT COUNT(*) FROM thread_results WHERE thread_id = :tid"),
                {"tid": thread_id},
            ).scalar()

            conn.execute(
                text(
                    "UPDATE analysis_threads SET last_searched_at = NOW(), results_count = :count "
                    "WHERE id = :id"
                ),
                {"count": total, "id": thread_id},
            )
            conn.execute(
                text(
                    "UPDATE thread_executions SET status = 'completed', completed_at = NOW(), "
                    "results_count = :count WHERE id = :eid"
                ),
                {"count": new_count, "eid": execution_id},
            )
            logger.info(
                f"google_ads thread {thread_id}: {new_count} new results, {total} total "
                f"(execution {execution_id})"
            )
        except Exception as e:
            if execution_id is not None:
                try:
                    conn.execute(
                        text(
                            "UPDATE thread_executions SET status = 'failed', completed_at = NOW(), "
                            "error_message = :err WHERE id = :eid"
                        ),
                        {"err": str(e), "eid": execution_id},
                    )
                except Exception:
                    pass
            logger.error(f"Failed to process google_ads thread {thread_id}: {e}")

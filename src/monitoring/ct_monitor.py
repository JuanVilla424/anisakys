"""
Certificate Transparency (CT) log monitoring background job.

Consumes the public certstream firehose (wss://certstream.calidog.io/ by
default) over a websocket, scores every newly-observed domain against the
brands anisakys protects, and records high-confidence candidates as
thread_results for human review via the existing Threads UI -- catching
lookalike domains as soon as their operator requests a TLS certificate,
typically before the phishing kit is even deployed.

Mirrors GSBRescanJob's shape (src/monitoring/gsb_rescan.py): a singleton
global background job with .start()/.stop()/module-level helpers, NOT the
per-thread-row due-check loop used by ImageTrackingScheduler/
EmailMonitorScheduler (there's exactly one global firehose, not N
independently-scheduled things). Differs from GSBRescanJob in that its
_run_loop is an event-driven websocket consumer with reconnect-backoff, not
a periodic-timer poll -- and it writes to thread_results/thread_executions
(GSBRescanJob writes directly to phishing_sites and never touches the
threads tables at all).

Per house convention (confirmed by reading main.py/shutdown.py): background
jobs here are "start conditionally, provide .stop() for tests/manual
control, never wired into the signal handler" -- daemon threads simply die
with the process. This job follows that convention; it does not invent new
graceful-shutdown machinery.
"""

import json
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import websocket
from sqlalchemy import text

from src.config import settings
from src.database.manager import DatabaseManager
from src.detection.ct_scorer import (
    DEFAULT_MIN_SCORE,
    build_permutation_set,
    quick_prefilter,
    score_ct_candidate,
)
from src.detection.url_analyzer import url_analyzer

logger = logging.getLogger(__name__)

DEFAULT_STREAM_URL = "wss://certstream.calidog.io/"
# In-process dedup window -- certstream repeats a cert's SANs across
# multiple log entries; don't re-record the same domain within this window.
DEDUP_WINDOW_SECONDS = 3600
# Prune the in-process dedup cache once it grows past this many entries.
DEDUP_CACHE_PRUNE_THRESHOLD = 5000


class CTMonitorJob:
    """Background job consuming the CT log firehose and recording
    high-confidence brand-impersonation candidates as thread_results."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        brand_seeds: Optional[Dict[str, List[str]]] = None,
        extra_keywords: Optional[List[str]] = None,
        stream_url: Optional[str] = None,
        min_score: Optional[int] = None,
        reconnect_backoff_seconds: int = 5,
        reconnect_backoff_max_seconds: int = 300,
    ):
        self.db_manager = db_manager or DatabaseManager()
        self.known_brands = (
            brand_seeds if brand_seeds is not None else dict(url_analyzer.KNOWN_BRANDS)
        )
        if extra_keywords is not None:
            self.extra_keywords = extra_keywords
        else:
            raw_keywords = getattr(settings, "KEYWORDS", "") or ""
            self.extra_keywords = [k.strip().lower() for k in raw_keywords.split(",") if k.strip()]
        self.stream_url = stream_url or DEFAULT_STREAM_URL
        self.min_score = min_score if min_score is not None else DEFAULT_MIN_SCORE
        self.reconnect_backoff_seconds = reconnect_backoff_seconds
        self.reconnect_backoff_max_seconds = reconnect_backoff_max_seconds

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._ws: Optional["websocket.WebSocketApp"] = None
        self._thread_id: Optional[int] = None
        self._execution_id: Optional[int] = None
        self._permutation_map: Dict[str, str] = {}
        self._brand_substrings: List[str] = []
        self._seen_recently: Dict[str, float] = {}

        self.stats = {
            "domains_seen": 0,
            "candidates_recorded": 0,
            "connections": 0,
            "errors": 0,
            "last_message_at": None,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the background CT-monitoring job. Idempotent."""
        if self._running:
            logger.warning("CT monitor job is already running")
            return

        self._thread_id = self._bootstrap_thread_row()
        if self._thread_id is None:
            logger.error("❌ CT monitor: could not bootstrap thread row, not starting")
            return

        self._brand_substrings = sorted(set(self.known_brands.keys()) | set(self.extra_keywords))
        logger.info(
            f"🔭 Building CT permutation set for {len(self._brand_substrings)} brand seeds..."
        )
        self._permutation_map = build_permutation_set(self.known_brands, self.extra_keywords)

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(
            f"🔭 CT monitor job started (stream: {self.stream_url}, min_score: {self.min_score})"
        )

    def stop(self):
        """Stop the background CT-monitoring job."""
        if not self._running:
            return
        self._stop_event.set()
        self._running = False
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("🛑 CT monitor job stopped")

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            "is_running": self._running,
            "thread_id": self._thread_id,
            "permutation_count": len(self._permutation_map),
        }

    # ------------------------------------------------------------------
    # Thread-row bootstrap (idempotent -- mirrors the API create-route)
    # ------------------------------------------------------------------

    def _bootstrap_thread_row(self) -> Optional[int]:
        try:
            with self.db_manager.engine.begin() as conn:
                existing = conn.execute(
                    text("SELECT id FROM analysis_threads WHERE thread_type = 'ct_monitor' LIMIT 1")
                ).fetchone()
                if existing:
                    return existing[0]
                row = conn.execute(
                    text(
                        "INSERT INTO analysis_threads (thread_type, label, status) "
                        "VALUES ('ct_monitor', 'Certificate Transparency Monitor', 'active') "
                        "RETURNING id"
                    )
                ).fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"❌ CT monitor: failed to bootstrap thread row: {e}")
            return None

    # ------------------------------------------------------------------
    # Reconnect-with-backoff outer loop
    # ------------------------------------------------------------------

    def _run_loop(self):
        backoff = self.reconnect_backoff_seconds
        while not self._stop_event.is_set():
            connected_at = time.time()
            try:
                self._consume_stream()
            except Exception as e:
                self.stats["errors"] += 1
                logger.error(f"❌ CT monitor stream error: {e}")

            if self._stop_event.is_set():
                break

            # Reset backoff after a connection that stayed up a while;
            # otherwise back off further, capped at the configured max.
            if time.time() - connected_at > backoff:
                backoff = self.reconnect_backoff_seconds
            else:
                backoff = min(backoff * 2, self.reconnect_backoff_max_seconds)

            logger.warning(f"🔌 CT monitor disconnected; reconnecting in {backoff}s")
            self._stop_event.wait(timeout=backoff)

    def _consume_stream(self):
        """Open one websocket connection and block until it closes."""
        execution_id = self._start_execution()
        self._execution_id = execution_id
        self.stats["connections"] += 1

        def _on_open(ws):
            logger.info(f"🔭 CT monitor connected to {self.stream_url}")

        def _on_message(ws, message):
            self._on_message(message)

        def _on_error(ws, error):
            logger.error(f"❌ CT monitor websocket error: {error}")

        def _on_close(ws, close_status_code, close_msg):
            logger.warning(f"🔌 CT monitor connection closed: {close_status_code} {close_msg}")

        self._ws = websocket.WebSocketApp(
            self.stream_url,
            on_open=_on_open,
            on_message=_on_message,
            on_error=_on_error,
            on_close=_on_close,
        )
        try:
            self._ws.run_forever(ping_interval=30, ping_timeout=10)
            self._complete_execution(execution_id, status="completed")
        except Exception as e:
            self._complete_execution(execution_id, status="failed", error_message=str(e))
            raise
        finally:
            self._ws = None

    # ------------------------------------------------------------------
    # Message handling -- filter/score OUTSIDE any DB transaction (pure
    # CPU), only open a transaction for domains that actually passed the
    # threshold (typically zero or very few per message).
    # ------------------------------------------------------------------

    def _on_message(self, raw_message: str):
        self.stats["last_message_at"] = datetime.now().isoformat()
        try:
            payload = json.loads(raw_message)
        except (ValueError, TypeError) as e:
            logger.debug(f"CT monitor: unparseable message: {e}")
            return

        if payload.get("message_type") != "certificate_update":
            return

        all_domains = payload.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
        if not all_domains:
            return

        candidates = []
        now = time.time()
        for raw_domain in all_domains:
            domain = raw_domain.lstrip("*.") if raw_domain else ""
            if not domain:
                continue
            self.stats["domains_seen"] += 1

            if not quick_prefilter(domain, self._brand_substrings, self._permutation_map):
                continue

            last_seen = self._seen_recently.get(domain)
            if last_seen and (now - last_seen) < DEDUP_WINDOW_SECONDS:
                continue

            result = score_ct_candidate(domain, self._permutation_map)
            if result["score"] < self.min_score:
                continue

            self._seen_recently[domain] = now
            candidates.append(result)

        if not candidates:
            return

        self._prune_seen_recently(now)
        try:
            with self.db_manager.engine.begin() as conn:
                for result in candidates:
                    self._record_candidate(conn, result)
        except Exception as e:
            logger.error(f"❌ CT monitor: error recording candidates: {e}")

    def _record_candidate(self, conn, result: Dict):
        domain = result["domain"]
        existing = conn.execute(
            text(
                "SELECT 1 FROM thread_results WHERE thread_id = :tid "
                "AND found_url = :domain AND status != 'discarded'"
            ),
            {"tid": self._thread_id, "domain": domain},
        ).fetchone()
        if existing:
            return

        conn.execute(
            text(
                "INSERT INTO thread_results "
                "(thread_id, result_type, found_url, confidence, source, "
                "status, execution_id, extra_data) "
                "VALUES (:tid, 'ct_candidate', :domain, :confidence, 'certstream', "
                "'new', :execution_id, :extra_data::jsonb)"
            ),
            {
                "tid": self._thread_id,
                "domain": domain,
                # thread_results.confidence has no established convention today
                # (none of the 3 existing thread types ever populate it), but
                # the frontend's generic renderer does `${confidence}%` with no
                # scaling -- confirmed via ThreadsView.vue -- so this must be
                # the raw 0-100 score, not a 0.0-1.0 fraction.
                "confidence": float(result["score"]),
                "execution_id": self._execution_id,
                "extra_data": json.dumps(
                    {
                        "score": result["score"],
                        "matched_brand": result["matched_brand"],
                        "permutation_hit": result["permutation_hit"],
                        "confusable_hit": result["confusable_hit"],
                        "risk_factors": result["risk_factors"],
                    }
                ),
            },
        )
        conn.execute(
            text(
                "UPDATE analysis_threads SET last_searched_at = NOW(), "
                "results_count = results_count + 1 WHERE id = :tid"
            ),
            {"tid": self._thread_id},
        )
        self.stats["candidates_recorded"] += 1
        logger.warning(
            f"🚨 CT candidate: {domain} (score={result['score']}, brand={result['matched_brand']})"
        )

    def _prune_seen_recently(self, now: float):
        if len(self._seen_recently) > DEDUP_CACHE_PRUNE_THRESHOLD:
            cutoff = now - DEDUP_WINDOW_SECONDS
            self._seen_recently = {d: t for d, t in self._seen_recently.items() if t > cutoff}

    # ------------------------------------------------------------------
    # thread_executions bookkeeping -- one row per connection lifetime
    # (departs from the other 3 thread types' "one execution per discrete
    # search cycle" semantics -- a continuous stream has no discrete
    # cycles; each reconnect naturally starts a new execution row, which
    # doubles as connection-uptime history in the existing executions UI).
    # ------------------------------------------------------------------

    def _start_execution(self) -> Optional[int]:
        try:
            with self.db_manager.engine.begin() as conn:
                row = conn.execute(
                    text(
                        "INSERT INTO thread_executions (thread_id, execution_type, status) "
                        "VALUES (:tid, 'ct_stream_connection', 'running') RETURNING id"
                    ),
                    {"tid": self._thread_id},
                ).fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"❌ CT monitor: failed to start execution row: {e}")
            return None

    def _complete_execution(
        self, execution_id: Optional[int], status: str, error_message: Optional[str] = None
    ):
        if execution_id is None:
            return
        try:
            with self.db_manager.engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE thread_executions SET status = :status, completed_at = NOW(), "
                        "error_message = :error_message WHERE id = :id"
                    ),
                    {"status": status, "error_message": error_message, "id": execution_id},
                )
        except Exception as e:
            logger.error(f"❌ CT monitor: failed to complete execution row: {e}")


# ---------------------------------------------------------------------------
# Module-level singleton, mirroring gsb_rescan_job / get_/start_/stop_gsb_rescan_job
# ---------------------------------------------------------------------------

ct_monitor_job: Optional[CTMonitorJob] = None


def get_ct_monitor_job(**kwargs) -> CTMonitorJob:
    global ct_monitor_job
    if ct_monitor_job is None:
        ct_monitor_job = CTMonitorJob(**kwargs)
    return ct_monitor_job


def start_ct_monitor_job(**kwargs) -> CTMonitorJob:
    job = get_ct_monitor_job(**kwargs)
    job.start()
    return job


def stop_ct_monitor_job():
    global ct_monitor_job
    if ct_monitor_job:
        ct_monitor_job.stop()

"""
External feed intelligence background job.

Runs two independent cycles against public threat-intel sources:

- Corroboration (OpenPhish + URLhaus): both are flat URL lists with no
  search-by-keyword capability -- cross-referenced against phishing_sites
  already tracked by anisakys. A match is an independent, external signal
  that a site anisakys already flagged is ALSO known to these sources; it
  does not discover anything new, so it never touches phishing_sites, only
  records the corroboration as a thread_result for review.
- Discovery (urlscan.io): the only one of the three with real keyword
  search on its free tier (the paid-only "brand" classification field is
  NOT used, see src/intelligence/urlscan.py) -- queried per protected brand,
  mirroring CTMonitorJob's candidate-recording into thread_results for
  human review, no auto-insert into phishing_sites.

Two analysis_threads rows (thread_type='feed_corroboration' and
'feed_discovery') under one job process -- kept separate because they're
semantically distinct to an analyst (existing-site corroboration vs.
brand-new candidate), mirroring CTMonitorJob's bootstrap pattern
(src/monitoring/ct_monitor.py). The outer loop is a periodic timer
(GSBRescanJob's shape, src/monitoring/gsb_rescan.py), not an event-driven
stream consumer like CT monitoring's websocket.
"""

import json
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy import text

from src.config import settings
from src.database.manager import DatabaseManager
from src.detection.url_analyzer import url_analyzer
from src.intelligence.openphish import OpenPhishIntegration
from src.intelligence.urlhaus import URLhausIntegration
from src.intelligence.urlscan import URLscanIntegration, build_brand_query

logger = logging.getLogger(__name__)

DEFAULT_CORROBORATION_INTERVAL_SECONDS = 1800
DEFAULT_DISCOVERY_INTERVAL_SECONDS = 1800
# In-process dedup window -- a domain/URL re-appearing across cycles within
# this window isn't re-recorded (mirrors CTMonitorJob's DEDUP_WINDOW_SECONDS).
DEDUP_WINDOW_SECONDS = 3600
DEDUP_CACHE_PRUNE_THRESHOLD = 5000


def _extract_domain(url: str) -> str:
    """Best-effort domain extraction; adds a scheme if missing so urlparse
    puts the host in .netloc instead of .path."""
    if "://" not in url:
        url = f"http://{url}"
    return urlparse(url).netloc.lower().split(":")[0]


class FeedIntelJob:
    """Background job running the corroboration and discovery cycles
    described above."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        brand_seeds: Optional[Dict[str, List[str]]] = None,
        extra_keywords: Optional[List[str]] = None,
        corroboration_interval_seconds: int = DEFAULT_CORROBORATION_INTERVAL_SECONDS,
        discovery_interval_seconds: int = DEFAULT_DISCOVERY_INTERVAL_SECONDS,
        openphish: Optional[OpenPhishIntegration] = None,
        urlhaus: Optional[URLhausIntegration] = None,
        urlscan: Optional[URLscanIntegration] = None,
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
        self.corroboration_interval_seconds = corroboration_interval_seconds
        self.discovery_interval_seconds = discovery_interval_seconds

        self.openphish = openphish or OpenPhishIntegration()
        self.urlhaus = urlhaus or URLhausIntegration()
        self.urlscan = urlscan or URLscanIntegration()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._corroboration_thread_id: Optional[int] = None
        self._discovery_thread_id: Optional[int] = None
        self._brand_substrings: List[str] = []
        self._seen_recently: Dict[str, float] = {}

        self.stats = {
            "corroboration_cycles": 0,
            "discovery_cycles": 0,
            "corroborations_recorded": 0,
            "candidates_recorded": 0,
            "errors": 0,
            "last_cycle_at": None,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the background feed-intel job. Idempotent."""
        if self._running:
            logger.warning("Feed intel job is already running")
            return

        self._corroboration_thread_id = self._bootstrap_thread_row(
            "feed_corroboration", "Feed Corroboration (OpenPhish/URLhaus)"
        )
        self._discovery_thread_id = self._bootstrap_thread_row(
            "feed_discovery", "Feed Discovery (urlscan.io)"
        )
        if self._corroboration_thread_id is None or self._discovery_thread_id is None:
            logger.error("❌ Feed intel: could not bootstrap thread rows, not starting")
            return

        self._brand_substrings = sorted(set(self.known_brands.keys()) | set(self.extra_keywords))

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(
            "🌐 Feed intel job started (OpenPhish + URLhaus corroboration, urlscan.io discovery)"
        )

    def stop(self):
        """Stop the background feed-intel job."""
        if not self._running:
            return
        self._stop_event.set()
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("🛑 Feed intel job stopped")

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            "is_running": self._running,
            "corroboration_thread_id": self._corroboration_thread_id,
            "discovery_thread_id": self._discovery_thread_id,
        }

    # ------------------------------------------------------------------
    # Thread-row bootstrap (idempotent -- mirrors CTMonitorJob's)
    # ------------------------------------------------------------------

    def _bootstrap_thread_row(self, thread_type: str, label: str) -> Optional[int]:
        try:
            with self.db_manager.engine.begin() as conn:
                existing = conn.execute(
                    text("SELECT id FROM analysis_threads WHERE thread_type = :tt LIMIT 1"),
                    {"tt": thread_type},
                ).fetchone()
                if existing:
                    return existing[0]
                row = conn.execute(
                    text(
                        "INSERT INTO analysis_threads (thread_type, label, status) "
                        "VALUES (:tt, :label, 'active') RETURNING id"
                    ),
                    {"tt": thread_type, "label": label},
                ).fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"❌ Feed intel: failed to bootstrap {thread_type} thread row: {e}")
            return None

    # ------------------------------------------------------------------
    # Periodic-timer outer loop -- two independently-tracked intervals in
    # one loop (GSBRescanJob's timer shape, not CT monitoring's event-driven
    # stream consumer).
    # ------------------------------------------------------------------

    def _run_loop(self):
        next_corroboration = 0.0
        next_discovery = 0.0
        while not self._stop_event.is_set():
            now = time.time()
            if now >= next_corroboration:
                try:
                    self._run_corroboration_cycle()
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"❌ Feed intel corroboration cycle error: {e}")
                next_corroboration = time.time() + self.corroboration_interval_seconds

            if now >= next_discovery:
                try:
                    self._run_discovery_cycle()
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"❌ Feed intel discovery cycle error: {e}")
                next_discovery = time.time() + self.discovery_interval_seconds

            self.stats["last_cycle_at"] = datetime.now().isoformat()
            self._stop_event.wait(timeout=60)

    # ------------------------------------------------------------------
    # Corroboration cycle: OpenPhish + URLhaus URL lists cross-referenced
    # against phishing_sites already tracked by anisakys.
    # ------------------------------------------------------------------

    def _run_corroboration_cycle(self):
        self.stats["corroboration_cycles"] += 1
        tracked_domains = self._load_tracked_domains()
        if not tracked_domains:
            return

        self._process_corroboration_entries(
            "openphish", self.openphish.fetch_feed(), tracked_domains
        )
        self._process_corroboration_entries("urlhaus", self.urlhaus.fetch_recent(), tracked_domains)

    def _load_tracked_domains(self) -> Dict[str, str]:
        """domain -> full tracked URL, loaded once per cycle rather than
        querying per feed entry."""
        try:
            with self.db_manager.engine.begin() as conn:
                rows = conn.execute(text("SELECT url FROM phishing_sites")).fetchall()
        except Exception as e:
            logger.error(f"❌ Feed intel: failed to load tracked domains: {e}")
            return {}
        domains = {}
        for (url,) in rows:
            if url:
                domains[_extract_domain(url)] = url
        return domains

    def _process_corroboration_entries(self, source_name, entries, tracked_domains):
        now = time.time()
        matches = []
        for entry in entries:
            url = entry if isinstance(entry, str) else entry.get("url", "")
            if not url:
                continue
            domain = _extract_domain(url)
            matched_url = tracked_domains.get(domain)
            if not matched_url:
                continue

            dedup_key = f"corrob:{source_name}:{domain}"
            last_seen = self._seen_recently.get(dedup_key)
            if last_seen and (now - last_seen) < DEDUP_WINDOW_SECONDS:
                continue
            self._seen_recently[dedup_key] = now
            matches.append(
                {
                    "domain": domain,
                    "matched_url": matched_url,
                    "source": source_name,
                    "entry": entry,
                }
            )

        if not matches:
            return
        self._prune_seen_recently(now)
        try:
            with self.db_manager.engine.begin() as conn:
                for match in matches:
                    self._record_corroboration(conn, match)
        except Exception as e:
            logger.error(f"❌ Feed intel: error recording corroborations: {e}")

    def _record_corroboration(self, conn, match: Dict):
        existing = conn.execute(
            text(
                "SELECT 1 FROM thread_results WHERE thread_id = :tid "
                "AND found_url = :url AND status != 'discarded'"
            ),
            {"tid": self._corroboration_thread_id, "url": match["matched_url"]},
        ).fetchone()
        if existing:
            return

        conn.execute(
            text(
                "INSERT INTO thread_results "
                "(thread_id, result_type, found_url, source, status, extra_data) "
                "VALUES (:tid, 'feed_corroboration', :url, :source, 'new', :extra_data::jsonb)"
            ),
            {
                "tid": self._corroboration_thread_id,
                "url": match["matched_url"],
                "source": match["source"],
                "extra_data": json.dumps({"domain": match["domain"], "feed_entry": match["entry"]}),
            },
        )
        conn.execute(
            text(
                "UPDATE analysis_threads SET last_searched_at = NOW(), "
                "results_count = results_count + 1 WHERE id = :tid"
            ),
            {"tid": self._corroboration_thread_id},
        )
        self.stats["corroborations_recorded"] += 1
        logger.info(f"✅ Feed corroboration: {match['matched_url']} confirmed by {match['source']}")

    # ------------------------------------------------------------------
    # Discovery cycle: urlscan.io keyword search per protected brand,
    # mirrors CTMonitorJob's candidate-recording into thread_results.
    # ------------------------------------------------------------------

    def _run_discovery_cycle(self):
        self.stats["discovery_cycles"] += 1
        now = time.time()
        candidates = []
        for brand in self._brand_substrings:
            for result in self.urlscan.search(build_brand_query(brand)):
                page = result.get("page", {})
                url = page.get("url", "")
                if not url:
                    continue
                dedup_key = f"disc:urlscan:{url}"
                last_seen = self._seen_recently.get(dedup_key)
                if last_seen and (now - last_seen) < DEDUP_WINDOW_SECONDS:
                    continue
                self._seen_recently[dedup_key] = now
                candidates.append({"url": url, "brand": brand, "page": page, "result": result})

        if not candidates:
            return
        self._prune_seen_recently(now)
        try:
            with self.db_manager.engine.begin() as conn:
                for candidate in candidates:
                    self._record_discovery(conn, candidate)
        except Exception as e:
            logger.error(f"❌ Feed intel: error recording discoveries: {e}")

    def _record_discovery(self, conn, candidate: Dict):
        existing = conn.execute(
            text(
                "SELECT 1 FROM thread_results WHERE thread_id = :tid "
                "AND found_url = :url AND status != 'discarded'"
            ),
            {"tid": self._discovery_thread_id, "url": candidate["url"]},
        ).fetchone()
        if existing:
            return

        conn.execute(
            text(
                "INSERT INTO thread_results "
                "(thread_id, result_type, found_url, source, status, extra_data) "
                "VALUES (:tid, 'feed_discovery', :url, 'urlscan', 'new', :extra_data::jsonb)"
            ),
            {
                "tid": self._discovery_thread_id,
                "url": candidate["url"],
                "extra_data": json.dumps(
                    {
                        "matched_brand": candidate["brand"],
                        "domain": candidate["page"].get("domain"),
                        "title": candidate["page"].get("title"),
                        "urlscan_uuid": candidate["result"].get("task", {}).get("uuid"),
                    }
                ),
            },
        )
        conn.execute(
            text(
                "UPDATE analysis_threads SET last_searched_at = NOW(), "
                "results_count = results_count + 1 WHERE id = :tid"
            ),
            {"tid": self._discovery_thread_id},
        )
        self.stats["candidates_recorded"] += 1
        logger.warning(
            f"🚨 Feed discovery candidate: {candidate['url']} (brand={candidate['brand']})"
        )

    def _prune_seen_recently(self, now: float):
        if len(self._seen_recently) > DEDUP_CACHE_PRUNE_THRESHOLD:
            cutoff = now - DEDUP_WINDOW_SECONDS
            self._seen_recently = {k: t for k, t in self._seen_recently.items() if t > cutoff}


# ---------------------------------------------------------------------------
# Module-level singleton, mirroring ct_monitor_job / get_/start_/stop_ct_monitor_job
# ---------------------------------------------------------------------------

feed_intel_job: Optional[FeedIntelJob] = None


def get_feed_intel_job(**kwargs) -> FeedIntelJob:
    global feed_intel_job
    if feed_intel_job is None:
        feed_intel_job = FeedIntelJob(**kwargs)
    return feed_intel_job


def start_feed_intel_job(**kwargs) -> FeedIntelJob:
    job = get_feed_intel_job(**kwargs)
    job.start()
    return job


def stop_feed_intel_job():
    global feed_intel_job
    if feed_intel_job:
        feed_intel_job.stop()

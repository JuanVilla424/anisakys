"""
Tests for src/monitoring/feed_intel.py

Covers: FeedIntelJob -- init, thread-row bootstrap (x2), corroboration cycle
(domain matching against phishing_sites, dedup), discovery cycle (urlscan.io
brand search, dedup), start/stop lifecycle, module-level singleton helpers.
The 3 intelligence clients (OpenPhish/URLhaus/urlscan.io) are mocked here --
this file tests FeedIntelJob's orchestration, not their HTTP clients
(covered by their own tests/intelligence/test_*.py files).
"""

import unittest
from unittest.mock import MagicMock, patch

import src.monitoring.feed_intel as feed_intel_module
from src.monitoring.feed_intel import (
    FeedIntelJob,
    get_feed_intel_job,
    stop_feed_intel_job,
)


class TestFeedIntelJobInit(unittest.TestCase):
    def test_creates_with_default_config(self):
        mock_db = MagicMock()
        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        self.assertEqual(
            job.corroboration_interval_seconds,
            feed_intel_module.DEFAULT_CORROBORATION_INTERVAL_SECONDS,
        )
        self.assertFalse(job._running)

    def test_accepts_custom_config(self):
        mock_db = MagicMock()
        job = FeedIntelJob(
            db_manager=mock_db,
            brand_seeds={},
            extra_keywords=["nequi"],
            corroboration_interval_seconds=60,
            discovery_interval_seconds=90,
        )
        self.assertEqual(job.corroboration_interval_seconds, 60)
        self.assertEqual(job.discovery_interval_seconds, 90)
        self.assertEqual(job.extra_keywords, ["nequi"])


class TestBootstrapThreadRow(unittest.TestCase):
    def test_returns_existing_row_id_without_inserting(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (99,)
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        thread_id = job._bootstrap_thread_row("feed_corroboration", "Feed Corroboration")

        self.assertEqual(thread_id, 99)
        self.assertEqual(conn.execute.call_count, 1)

    def test_inserts_new_row_when_none_exists(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.side_effect = [None, (100,)]
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        thread_id = job._bootstrap_thread_row("feed_discovery", "Feed Discovery")

        self.assertEqual(thread_id, 100)
        self.assertEqual(conn.execute.call_count, 2)

    def test_db_error_returns_none(self):
        mock_db = MagicMock()
        mock_db.engine.begin.side_effect = RuntimeError("db down")

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        self.assertIsNone(job._bootstrap_thread_row("feed_corroboration", "x"))


class TestCorroborationCycle(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_openphish = MagicMock()
        self.mock_urlhaus = MagicMock()
        self.job = FeedIntelJob(
            db_manager=self.mock_db,
            brand_seeds={},
            extra_keywords=[],
            openphish=self.mock_openphish,
            urlhaus=self.mock_urlhaus,
            urlscan=MagicMock(),
        )
        self.job._corroboration_thread_id = 1
        self.job._discovery_thread_id = 2

    def test_no_tracked_domains_skips_fetch_entirely(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = []
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn

        self.job._run_corroboration_cycle()

        self.mock_openphish.fetch_feed.assert_not_called()
        self.mock_urlhaus.fetch_recent.assert_not_called()

    def test_matching_domain_is_recorded_as_corroboration(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [("https://tracked-evil.example.com/",)]
        conn.execute.return_value.fetchone.return_value = None  # no existing thread_result
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn
        self.mock_openphish.fetch_feed.return_value = {"https://tracked-evil.example.com/login"}
        self.mock_urlhaus.fetch_recent.return_value = []

        self.job._run_corroboration_cycle()

        self.assertEqual(self.job.stats["corroborations_recorded"], 1)

    def test_non_matching_domain_is_not_recorded(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [("https://tracked-evil.example.com/",)]
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn
        self.mock_openphish.fetch_feed.return_value = {"https://totally-unrelated.example.net/"}
        self.mock_urlhaus.fetch_recent.return_value = []

        self.job._run_corroboration_cycle()

        self.assertEqual(self.job.stats["corroborations_recorded"], 0)

    def test_urlhaus_dict_entries_are_handled(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [("https://tracked-evil.example.com/",)]
        conn.execute.return_value.fetchone.return_value = None
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn
        self.mock_openphish.fetch_feed.return_value = set()
        self.mock_urlhaus.fetch_recent.return_value = [
            {"id": "1", "url": "https://tracked-evil.example.com/", "threat": "malware"}
        ]

        self.job._run_corroboration_cycle()

        self.assertEqual(self.job.stats["corroborations_recorded"], 1)

    def test_same_domain_not_rerecorded_within_dedup_window(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [("https://tracked-evil.example.com/",)]
        conn.execute.return_value.fetchone.return_value = None
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn
        self.mock_openphish.fetch_feed.return_value = {"https://tracked-evil.example.com/"}
        self.mock_urlhaus.fetch_recent.return_value = []

        self.job._run_corroboration_cycle()
        self.job._run_corroboration_cycle()

        self.assertEqual(self.job.stats["corroborations_recorded"], 1)


class TestDiscoveryCycle(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_urlscan = MagicMock()
        self.job = FeedIntelJob(
            db_manager=self.mock_db,
            brand_seeds={},
            extra_keywords=["nequi"],
            openphish=MagicMock(),
            urlhaus=MagicMock(),
            urlscan=self.mock_urlscan,
        )
        self.job._discovery_thread_id = 2
        self.job._corroboration_thread_id = 1
        self.job._brand_substrings = ["nequi"]

    def test_search_result_is_recorded_as_candidate(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn
        self.mock_urlscan.search.return_value = [
            {
                "page": {
                    "url": "https://nequi-verify.example.com/",
                    "domain": "nequi-verify.example.com",
                },
                "task": {"uuid": "abc-123"},
            }
        ]

        self.job._run_discovery_cycle()

        self.mock_urlscan.search.assert_called_once()
        self.assertEqual(self.job.stats["candidates_recorded"], 1)

    def test_empty_search_results_record_nothing(self):
        self.mock_urlscan.search.return_value = []
        self.job._run_discovery_cycle()
        self.assertEqual(self.job.stats["candidates_recorded"], 0)
        self.mock_db.engine.begin.assert_not_called()

    def test_same_url_not_rerecorded_within_dedup_window(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn
        self.mock_urlscan.search.return_value = [
            {"page": {"url": "https://nequi-verify.example.com/"}, "task": {"uuid": "abc-123"}}
        ]

        self.job._run_discovery_cycle()
        self.job._run_discovery_cycle()

        self.assertEqual(self.job.stats["candidates_recorded"], 1)


class TestLifecycle(unittest.TestCase):
    """_run_loop is patched out in every test that calls start() -- otherwise
    the real background thread races the test's own assertions (its very
    first iteration fires a real cycle immediately, since next_corroboration/
    next_discovery start at 0.0), mirroring test_ct_monitor.py's identical
    patch.object(job, "_run_loop") pattern for the same reason."""

    def test_start_bootstraps_both_threads_and_spawns_thread(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.side_effect = [(1,), (2,)]
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        with patch.object(job, "_run_loop"):
            job.start()
            try:
                self.assertTrue(job._running)
                self.assertEqual(job._corroboration_thread_id, 1)
                self.assertEqual(job._discovery_thread_id, 2)
                self.assertIsNotNone(job._thread)
            finally:
                job.stop()

    def test_start_is_idempotent(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.side_effect = [(1,), (2,)]
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        with patch.object(job, "_run_loop"):
            job.start()
            try:
                job.start()
                self.assertEqual(mock_db.engine.begin.call_count, 2)  # 2 bootstraps only, not 4
            finally:
                job.stop()

    def test_start_bails_out_when_bootstrap_fails(self):
        mock_db = MagicMock()
        mock_db.engine.begin.side_effect = RuntimeError("db down")

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        job.start()

        self.assertFalse(job._running)

    def test_stop_sets_stop_event(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.side_effect = [(1,), (2,)]
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = FeedIntelJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        with patch.object(job, "_run_loop"):
            job.start()
        job.stop()

        self.assertFalse(job._running)
        self.assertTrue(job._stop_event.is_set())


class TestSingletonHelpers(unittest.TestCase):
    def tearDown(self):
        feed_intel_module.feed_intel_job = None

    def test_get_creates_singleton_once(self):
        feed_intel_module.feed_intel_job = None
        job1 = get_feed_intel_job(db_manager=MagicMock(), brand_seeds={}, extra_keywords=[])
        job2 = get_feed_intel_job()
        self.assertIs(job1, job2)

    def test_stop_singleton_when_none_does_not_raise(self):
        feed_intel_module.feed_intel_job = None
        stop_feed_intel_job()


if __name__ == "__main__":
    unittest.main()

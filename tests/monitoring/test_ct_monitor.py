"""
Tests for src/monitoring/ct_monitor.py

Covers: CTMonitorJob -- init, thread-row bootstrap, message parsing/dispatch,
candidate recording + dedup, start/stop lifecycle, module-level singleton
helpers. The websocket transport itself is never actually opened in any
test -- _on_message is called directly with synthetic JSON strings, mirroring
how certstream would invoke it, without a live connection.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

import src.monitoring.ct_monitor as ct_monitor_module
from src.monitoring.ct_monitor import (
    CTMonitorJob,
    get_ct_monitor_job,
    stop_ct_monitor_job,
)


def _cert_update(domains):
    return json.dumps(
        {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": domains}}}
    )


def _heartbeat():
    return json.dumps({"message_type": "heartbeat"})


class TestCTMonitorJobInit(unittest.TestCase):
    def test_creates_with_default_config(self):
        mock_db = MagicMock()
        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        self.assertEqual(job.stream_url, ct_monitor_module.DEFAULT_STREAM_URL)
        self.assertEqual(job.min_score, ct_monitor_module.DEFAULT_MIN_SCORE)
        self.assertFalse(job._running)

    def test_accepts_custom_config(self):
        mock_db = MagicMock()
        job = CTMonitorJob(
            db_manager=mock_db,
            brand_seeds={},
            extra_keywords=["nequi"],
            stream_url="wss://example.test/",
            min_score=80,
            reconnect_backoff_seconds=1,
            reconnect_backoff_max_seconds=10,
        )
        self.assertEqual(job.stream_url, "wss://example.test/")
        self.assertEqual(job.min_score, 80)
        self.assertEqual(job.extra_keywords, ["nequi"])


class TestOnMessageDispatch(unittest.TestCase):
    """quick_prefilter/score_ct_candidate are mocked here -- this file tests
    CTMonitorJob's orchestration, not the scorer (covered by its own
    dedicated tests/detection/test_ct_scorer.py)."""

    def setUp(self):
        self.mock_db = MagicMock()
        self.job = CTMonitorJob(db_manager=self.mock_db, brand_seeds={}, extra_keywords=["nequi"])
        self.job._thread_id = 42
        self.job._execution_id = 7
        self.job._brand_substrings = ["nequi"]

    def test_heartbeat_message_is_ignored(self):
        self.job._on_message(_heartbeat())
        self.assertEqual(self.job.stats["domains_seen"], 0)
        self.mock_db.engine.begin.assert_not_called()

    def test_unparseable_message_does_not_raise(self):
        self.job._on_message("not valid json{{{")
        self.assertEqual(self.job.stats["domains_seen"], 0)

    def test_message_with_no_domains_is_ignored(self):
        self.job._on_message(_cert_update([]))
        self.mock_db.engine.begin.assert_not_called()

    @patch("src.monitoring.ct_monitor.quick_prefilter", return_value=False)
    def test_domain_failing_prefilter_is_not_scored_or_recorded(self, mock_prefilter):
        with patch("src.monitoring.ct_monitor.score_ct_candidate") as mock_score:
            self.job._on_message(_cert_update(["totally-unrelated.com"]))
        mock_score.assert_not_called()
        self.mock_db.engine.begin.assert_not_called()
        self.assertEqual(self.job.stats["domains_seen"], 1)

    @patch("src.monitoring.ct_monitor.quick_prefilter", return_value=True)
    @patch("src.monitoring.ct_monitor.score_ct_candidate")
    def test_domain_below_min_score_is_not_recorded(self, mock_score, mock_prefilter):
        mock_score.return_value = {
            "domain": "nequi-lookalike.tk",
            "score": self.job.min_score - 1,
            "matched_brand": "nequi",
            "permutation_hit": None,
            "confusable_hit": False,
            "risk_factors": [],
        }
        self.job._on_message(_cert_update(["nequi-lookalike.tk"]))
        self.mock_db.engine.begin.assert_not_called()

    @patch("src.monitoring.ct_monitor.quick_prefilter", return_value=True)
    @patch("src.monitoring.ct_monitor.score_ct_candidate")
    def test_domain_at_or_above_min_score_gets_recorded(self, mock_score, mock_prefilter):
        mock_score.return_value = {
            "domain": "nequi-lookalike.tk",
            "score": self.job.min_score,
            "matched_brand": "nequi",
            "permutation_hit": "nequi",
            "confusable_hit": False,
            "risk_factors": ["Matches precomputed permutation of 'nequi'"],
        }
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None  # no existing row
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn

        self.job._on_message(_cert_update(["nequi-lookalike.tk"]))

        insert_call = conn.execute.call_args_list[1]  # [0] is the existing-row SELECT
        params = insert_call.args[1]
        self.assertEqual(params["domain"], "nequi-lookalike.tk")
        self.assertEqual(params["tid"], 42)
        # Raw 0-100 score, not a 0.0-1.0 fraction -- the frontend's generic
        # renderer does `${confidence}%` with no scaling (ThreadsView.vue).
        self.assertAlmostEqual(params["confidence"], float(self.job.min_score))
        self.assertEqual(self.job.stats["candidates_recorded"], 1)

    @patch("src.monitoring.ct_monitor.quick_prefilter", return_value=True)
    @patch("src.monitoring.ct_monitor.score_ct_candidate")
    def test_existing_non_discarded_result_is_not_reinserted(self, mock_score, mock_prefilter):
        mock_score.return_value = {
            "domain": "nequi-lookalike.tk",
            "score": self.job.min_score,
            "matched_brand": "nequi",
            "permutation_hit": "nequi",
            "confusable_hit": False,
            "risk_factors": [],
        }
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (1,)  # existing row found
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn

        self.job._on_message(_cert_update(["nequi-lookalike.tk"]))

        self.assertEqual(conn.execute.call_count, 1)  # only the SELECT, no INSERT/UPDATE
        self.assertEqual(self.job.stats["candidates_recorded"], 0)

    @patch("src.monitoring.ct_monitor.quick_prefilter", return_value=True)
    @patch("src.monitoring.ct_monitor.score_ct_candidate")
    def test_same_domain_not_rescored_within_dedup_window(self, mock_score, mock_prefilter):
        mock_score.return_value = {
            "domain": "nequi-lookalike.tk",
            "score": self.job.min_score,
            "matched_brand": "nequi",
            "permutation_hit": "nequi",
            "confusable_hit": False,
            "risk_factors": [],
        }
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None
        self.mock_db.engine.begin.return_value.__enter__.return_value = conn

        self.job._on_message(_cert_update(["nequi-lookalike.tk"]))
        self.job._on_message(_cert_update(["nequi-lookalike.tk"]))

        self.assertEqual(mock_score.call_count, 1)  # 2nd call short-circuited by dedup cache

    def test_wildcard_prefix_is_stripped_before_processing(self):
        with (
            patch(
                "src.monitoring.ct_monitor.quick_prefilter", return_value=False
            ) as mock_prefilter,
        ):
            self.job._on_message(_cert_update(["*.nequi-lookalike.tk"]))
        called_domain = mock_prefilter.call_args.args[0]
        self.assertEqual(called_domain, "nequi-lookalike.tk")


class TestBootstrapThreadRow(unittest.TestCase):
    def test_returns_existing_row_id_without_inserting(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (99,)
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        thread_id = job._bootstrap_thread_row()

        self.assertEqual(thread_id, 99)
        self.assertEqual(conn.execute.call_count, 1)  # only the SELECT, no INSERT

    def test_inserts_new_row_when_none_exists(self):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.side_effect = [None, (100,)]
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        thread_id = job._bootstrap_thread_row()

        self.assertEqual(thread_id, 100)
        self.assertEqual(conn.execute.call_count, 2)  # SELECT then INSERT

    def test_db_error_returns_none(self):
        mock_db = MagicMock()
        mock_db.engine.begin.side_effect = RuntimeError("db down")

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        self.assertIsNone(job._bootstrap_thread_row())


class TestLifecycle(unittest.TestCase):
    @patch("src.monitoring.ct_monitor.build_permutation_set", return_value={})
    def test_start_bootstraps_and_spawns_thread(self, mock_build):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (1,)
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        with patch.object(job, "_run_loop"):
            job.start()
            try:
                self.assertTrue(job._running)
                self.assertEqual(job._thread_id, 1)
                self.assertIsNotNone(job._thread)
            finally:
                job.stop()

    @patch("src.monitoring.ct_monitor.build_permutation_set", return_value={})
    def test_start_is_idempotent(self, mock_build):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (1,)
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        with patch.object(job, "_run_loop"):
            job.start()
            try:
                job.start()  # second call should just warn and return
                self.assertEqual(mock_db.engine.begin.call_count, 1)  # bootstrap only ran once
            finally:
                job.stop()

    def test_start_bails_out_when_bootstrap_fails(self):
        mock_db = MagicMock()
        mock_db.engine.begin.side_effect = RuntimeError("db down")

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        job.start()

        self.assertFalse(job._running)
        self.assertIsNone(job._thread)

    @patch("src.monitoring.ct_monitor.build_permutation_set", return_value={})
    def test_stop_sets_stop_event_and_closes_websocket(self, mock_build):
        mock_db = MagicMock()
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (1,)
        mock_db.engine.begin.return_value.__enter__.return_value = conn

        job = CTMonitorJob(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        with patch.object(job, "_run_loop"):
            job.start()
        fake_ws = MagicMock()
        job._ws = fake_ws

        job.stop()

        self.assertTrue(job._stop_event.is_set())
        self.assertFalse(job._running)
        fake_ws.close.assert_called_once()


class TestReconnectLoop(unittest.TestCase):
    def test_reconnects_after_failure_and_is_stoppable(self):
        mock_db = MagicMock()
        job = CTMonitorJob(
            db_manager=mock_db,
            brand_seeds={},
            extra_keywords=[],
            reconnect_backoff_seconds=1,
            reconnect_backoff_max_seconds=5,
        )
        call_count = {"n": 0}

        def fake_consume_stream():
            call_count["n"] += 1
            if call_count["n"] >= 2:
                job._stop_event.set()
            raise RuntimeError("disconnected")

        job._consume_stream = fake_consume_stream
        job._stop_event.wait = lambda timeout=None: None  # don't actually block in the test

        job._run_loop()

        self.assertEqual(call_count["n"], 2)


class TestSingletonHelpers(unittest.TestCase):
    def setUp(self):
        ct_monitor_module.ct_monitor_job = None

    def tearDown(self):
        stop_ct_monitor_job()
        ct_monitor_module.ct_monitor_job = None

    def test_get_creates_singleton_once(self):
        mock_db = MagicMock()
        job1 = get_ct_monitor_job(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        job2 = get_ct_monitor_job(db_manager=mock_db, brand_seeds={}, extra_keywords=[])
        self.assertIs(job1, job2)


if __name__ == "__main__":
    unittest.main()

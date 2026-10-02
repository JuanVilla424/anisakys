"""
Tests for src/monitoring/gsb_rescan.py

Covers: GSBRescanJob — init, run_once cycle, start/stop lifecycle,
        module-level singleton helper functions.
"""

import pytest
from unittest.mock import MagicMock, patch

import src.monitoring.gsb_rescan as gsb_rescan_module
from src.monitoring.gsb_rescan import GSBRescanJob, get_gsb_rescan_job, stop_gsb_rescan_job


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_singleton(monkeypatch):
    """Reset the module-level singleton before each test to prevent cross-test leakage."""
    monkeypatch.setattr(gsb_rescan_module, "gsb_rescan_job", None)


@pytest.fixture
def mock_db():
    """Mock DatabaseManager with default empty returns."""
    db = MagicMock()
    db.get_sites_for_gsb_rescan.return_value = []
    db.update_gsb_result.return_value = {"status_changed": False}
    return db


@pytest.fixture
def job(mock_db):
    """GSBRescanJob with GSB integration mocked to avoid API key requirement."""
    with patch("src.monitoring.gsb_rescan.GoogleSafeBrowsingIntegration") as mock_gsb_class:
        mock_gsb_class.return_value.is_available.return_value = True
        mock_gsb_class.return_value.check_url.return_value = {"checked": True, "safe": True}
        j = GSBRescanJob(
            db_manager=mock_db,
            rescan_interval_hours=12,
            batch_size=50,
            max_age_hours=24,
        )
    return j


# ---------------------------------------------------------------------------
# TestGSBRescanJobInit
# ---------------------------------------------------------------------------


class TestGSBRescanJobInit:
    def test_creates_with_default_config(self, mock_db):
        """Should use default interval=12h, batch_size=50, max_age=24h."""
        with patch("src.monitoring.gsb_rescan.GoogleSafeBrowsingIntegration"):
            j = GSBRescanJob(db_manager=mock_db)

        assert j.rescan_interval_hours == 12
        assert j.batch_size == 50
        assert j.max_age_hours == 24

    def test_accepts_custom_config(self, mock_db):
        """Should store custom interval, batch_size, and max_age_hours."""
        with patch("src.monitoring.gsb_rescan.GoogleSafeBrowsingIntegration"):
            j = GSBRescanJob(
                db_manager=mock_db,
                rescan_interval_hours=6,
                batch_size=100,
                max_age_hours=48,
            )

        assert j.rescan_interval_hours == 6
        assert j.batch_size == 100
        assert j.max_age_hours == 48

    def test_starts_not_running(self, job):
        """Should initialize with _running=False."""
        assert job._running is False

    def test_initial_stats_are_zero(self, job):
        """Should start with all counters at zero and last_run=None."""
        stats = job.get_stats()
        assert stats["total_rescans"] == 0
        assert stats["threats_detected"] == 0
        assert stats["status_changes"] == 0
        assert stats["errors"] == 0
        assert stats["last_run"] is None


# ---------------------------------------------------------------------------
# TestGSBRescanJobRunOnce
# ---------------------------------------------------------------------------


class TestGSBRescanJobRunOnce:
    def test_handles_empty_batch(self, job, mock_db):
        """Should return sites_checked=0 and not call GSB when no sites to scan."""
        mock_db.get_sites_for_gsb_rescan.return_value = []

        result = job.run_once()

        assert result["sites_checked"] == 0
        assert not job.gsb.check_url.called

    def test_rescans_all_sites_returned_by_db(self, job, mock_db):
        """Should call gsb.check_url once per site from DB."""
        mock_db.get_sites_for_gsb_rescan.return_value = [
            {"url": "https://phish1.com", "gsb_safe": 1},
            {"url": "https://phish2.com", "gsb_safe": 1},
        ]
        job.gsb.check_url.return_value = {"checked": True, "safe": True}

        result = job.run_once()

        assert job.gsb.check_url.call_count == 2
        assert result["sites_checked"] == 2

    def test_counts_threats_when_gsb_detects_unsafe_url(self, job, mock_db):
        """Should increment threats_found when GSB flags a URL as unsafe."""
        mock_db.get_sites_for_gsb_rescan.return_value = [
            {"url": "https://malware.com", "gsb_safe": 1},
        ]
        job.gsb.check_url.return_value = {"checked": True, "safe": False}
        mock_db.update_gsb_result.return_value = {
            "status_changed": True,
            "threat_type": "MALWARE",
            "alert": "Threat detected",
        }

        result = job.run_once()

        assert result["threats_found"] == 1

    def test_records_status_change_details(self, job, mock_db):
        """Should append status change dict when DB update reports a change."""
        mock_db.get_sites_for_gsb_rescan.return_value = [
            {"url": "https://newmalware.com", "gsb_safe": 1},
        ]
        job.gsb.check_url.return_value = {"checked": True, "safe": False}
        mock_db.update_gsb_result.return_value = {
            "status_changed": True,
            "threat_type": "MALWARE",
            "alert": "Status changed",
        }

        result = job.run_once()

        assert len(result["status_changes"]) == 1
        assert result["status_changes"][0]["url"] == "https://newmalware.com"
        assert result["status_changes"][0]["threat_type"] == "MALWARE"

    def test_records_error_and_continues_on_gsb_exception(self, job, mock_db):
        """Should log the error and continue processing when GSB raises."""
        mock_db.get_sites_for_gsb_rescan.return_value = [
            {"url": "https://error-site.com", "gsb_safe": 1},
            {"url": "https://ok-site.com", "gsb_safe": 1},
        ]
        job.gsb.check_url.side_effect = [
            Exception("API timeout"),
            {"checked": True, "safe": True},
        ]

        result = job.run_once()

        assert len(result["errors"]) == 1
        assert result["errors"][0]["url"] == "https://error-site.com"
        # Second site should still be processed
        assert result["sites_checked"] == 1

    def test_updates_total_rescans_stat_after_run(self, job, mock_db):
        """Should increment total_rescans by the number of sites checked."""
        mock_db.get_sites_for_gsb_rescan.return_value = [
            {"url": "https://site1.com", "gsb_safe": 1},
            {"url": "https://site2.com", "gsb_safe": 1},
        ]
        job.gsb.check_url.return_value = {"checked": True, "safe": True}

        job.run_once()

        assert job.stats["total_rescans"] == 2
        assert job.stats["last_run"] is not None


# ---------------------------------------------------------------------------
# TestGSBRescanJobLifecycle
# ---------------------------------------------------------------------------


class TestGSBRescanJobLifecycle:
    def test_start_launches_daemon_thread_when_gsb_available(self, job):
        """Should mark _running=True and start a daemon thread."""
        job.gsb.is_available.return_value = True

        with patch("src.monitoring.gsb_rescan.threading.Thread") as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            job.start()

        assert job._running is True
        mock_thread.start.assert_called_once()

    def test_start_skips_when_gsb_unavailable(self, job):
        """Should not set _running=True when GSB API key is not configured."""
        job.gsb.is_available.return_value = False
        job.start()
        assert job._running is False

    def test_start_is_idempotent_when_already_running(self, job):
        """Calling start() twice should not create a second thread."""
        job._running = True  # Simulate already started
        with patch("src.monitoring.gsb_rescan.threading.Thread") as mock_thread_class:
            job.start()
        mock_thread_class.assert_not_called()

    def test_stop_clears_running_flag_and_signals_event(self, job):
        """Should set _running=False and trigger the stop event."""
        job._running = True
        job.stop()
        assert job._running is False
        assert job._stop_event.is_set()

    def test_stop_is_safe_when_not_running(self, job):
        """Calling stop() when not running should not raise."""
        assert job._running is False
        job.stop()  # Should not raise

    def test_get_stats_returns_all_expected_keys(self, job):
        """get_stats() should include counters, is_running, gsb_available, and config."""
        stats = job.get_stats()
        for key in (
            "total_rescans",
            "threats_detected",
            "status_changes",
            "errors",
            "last_run",
            "is_running",
            "gsb_available",
            "config",
        ):
            assert key in stats, f"Missing key: {key}"

    def test_get_stats_config_reflects_constructor_args(self, job):
        """Config sub-dict should match the values passed to the constructor."""
        stats = job.get_stats()
        assert stats["config"]["rescan_interval_hours"] == 12
        assert stats["config"]["batch_size"] == 50
        assert stats["config"]["max_age_hours"] == 24


# ---------------------------------------------------------------------------
# TestModuleFunctions
# ---------------------------------------------------------------------------


class TestModuleFunctions:
    def test_get_gsb_rescan_job_creates_singleton_on_first_call(self, mock_db):
        """First call should create the job; subsequent calls return the same instance."""
        with patch("src.monitoring.gsb_rescan.GoogleSafeBrowsingIntegration"):
            job1 = get_gsb_rescan_job(db_manager=mock_db)
            job2 = get_gsb_rescan_job(db_manager=mock_db)

        assert job1 is job2

    def test_get_gsb_rescan_job_returns_existing_singleton(self, mock_db, monkeypatch):
        """Should return the existing instance without re-creating it."""
        existing = MagicMock()
        monkeypatch.setattr(gsb_rescan_module, "gsb_rescan_job", existing)

        result = get_gsb_rescan_job(db_manager=mock_db)

        assert result is existing

    def test_stop_gsb_rescan_job_is_safe_when_no_job_exists(self):
        """Should not raise when module-level job is None."""
        # Singleton is already None from autouse fixture
        stop_gsb_rescan_job()  # Must not raise

    def test_stop_gsb_rescan_job_calls_stop_on_existing_job(self, monkeypatch):
        """Should delegate to job.stop() when a job exists."""
        mock_job = MagicMock()
        monkeypatch.setattr(gsb_rescan_module, "gsb_rescan_job", mock_job)

        stop_gsb_rescan_job()

        mock_job.stop.assert_called_once()

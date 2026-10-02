"""
Tests for src/monitoring/takedown.py

Covers: TakedownMonitor — init, run loop control, DB status updates,
        per-site exception handling; save_offset / get_offset file I/O.

Known bug: OFFSET_FILE is referenced in save_offset/get_offset but never
defined/imported in the module. Tests inject it via monkeypatch(raising=False).
"""

import threading
import pytest
from unittest.mock import MagicMock, patch

import src.monitoring.takedown as takedown_module
from src.monitoring.takedown import TakedownMonitor, save_offset, get_offset


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db():
    """Mock DatabaseManager with engine context-manager support."""
    db = MagicMock()
    mock_conn = MagicMock()
    mock_conn.execute.return_value.fetchall.return_value = []
    db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)
    db.engine.begin.return_value.__exit__ = MagicMock(return_value=False)
    return db


@pytest.fixture
def monitor(mock_db):
    """TakedownMonitor with default config."""
    return TakedownMonitor(db_manager=mock_db, timeout=10, check_interval=3600)


@pytest.fixture
def offset_file(monkeypatch, tmp_path):
    """Inject OFFSET_FILE into the module using a writable temp path."""
    path = str(tmp_path / "offset.txt")
    monkeypatch.setattr(takedown_module, "OFFSET_FILE", path, raising=False)
    return path


# ---------------------------------------------------------------------------
# TestTakedownMonitorInit
# ---------------------------------------------------------------------------


class TestTakedownMonitorInit:
    def test_stores_db_manager_and_timeout(self, mock_db):
        """Should store db_manager and timeout as instance attributes."""
        mon = TakedownMonitor(db_manager=mock_db, timeout=30)
        assert mon.db_manager is mock_db
        assert mon.timeout == 30

    def test_default_check_interval_is_3600(self, mock_db):
        """check_interval should default to 3600 seconds when not specified."""
        mon = TakedownMonitor(db_manager=mock_db, timeout=10)
        assert mon.check_interval == 3600

    def test_accepts_custom_check_interval(self, mock_db):
        """Should store a custom check_interval."""
        mon = TakedownMonitor(db_manager=mock_db, timeout=10, check_interval=1800)
        assert mon.check_interval == 1800

    def test_stores_optional_monitoring_event(self, mock_db):
        """Should store the monitoring_event when provided."""
        event = threading.Event()
        mon = TakedownMonitor(db_manager=mock_db, timeout=10, monitoring_event=event)
        assert mon.monitoring_event is event

    def test_monitoring_event_defaults_to_none(self, mock_db):
        """monitoring_event should be None when not provided."""
        mon = TakedownMonitor(db_manager=mock_db, timeout=10)
        assert mon.monitoring_event is None


# ---------------------------------------------------------------------------
# TestSaveAndGetOffset
# ---------------------------------------------------------------------------


class TestSaveAndGetOffset:
    def test_save_offset_writes_integer_to_file(self, offset_file):
        """Should write the integer offset as a string to the configured file."""
        save_offset(42)
        with open(offset_file) as f:
            assert f.read() == "42"

    def test_get_offset_reads_and_returns_integer(self, offset_file):
        """Should read the file and return its content as an integer."""
        with open(offset_file, "w") as f:
            f.write("100")
        result = get_offset()
        assert result == 100

    def test_get_offset_returns_zero_when_file_missing(self, monkeypatch):
        """Should return 0 when the offset file does not exist."""
        monkeypatch.setattr(
            takedown_module, "OFFSET_FILE", "/nonexistent/path/offset.txt", raising=False
        )
        result = get_offset()
        assert result == 0

    def test_save_then_get_roundtrip(self, offset_file):
        """Saving and then reading back should return the same integer."""
        save_offset(777)
        assert get_offset() == 777

    def test_get_offset_handles_float_string(self, offset_file):
        """Should correctly parse float-formatted integers like '42.0'."""
        with open(offset_file, "w") as f:
            f.write("42.0")
        result = get_offset()
        assert result == 42


# ---------------------------------------------------------------------------
# TestTakedownMonitorRun
# ---------------------------------------------------------------------------


class TestTakedownMonitorRun:
    def test_exits_immediately_when_shutdown_requested(self, monitor, mock_db, monkeypatch):
        """Should return without touching DB when shutdown_requested is True at entry."""
        monkeypatch.setattr(takedown_module, "shutdown_requested", True)

        monitor.run()

        assert not mock_db.engine.begin.called

    def test_queries_phishing_sites_table(self, monitor, mock_db, monkeypatch):
        """Should execute a SELECT on phishing_sites during each loop iteration."""
        monkeypatch.setattr(takedown_module, "shutdown_requested", False)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)

        with patch("src.monitoring.takedown.time.sleep", side_effect=StopIteration):
            try:
                monitor.run()
            except StopIteration:
                pass

        assert mock_db.engine.begin.called

    def test_updates_db_when_status_changes(self, monitor, mock_db, monkeypatch):
        """Should execute UPDATE when PhishingUtils returns a different status."""
        monkeypatch.setattr(takedown_module, "shutdown_requested", False)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [
            ("https://phish.com", "active", None)
        ]
        mock_db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)

        with (
            patch("src.monitoring.takedown.get_ip_info", return_value=("1.2.3.4", "TestASN")),
            patch(
                "src.monitoring.takedown.PhishingUtils.determine_site_status",
                return_value=("down", "2026-01-01 00:00:00"),
            ),
            patch("src.monitoring.takedown.time.sleep", side_effect=StopIteration),
        ):
            try:
                monitor.run()
            except StopIteration:
                pass

        # execute should have been called at least twice (SELECT + UPDATE)
        assert mock_conn.execute.call_count >= 2

    def test_skips_update_when_status_unchanged(self, monitor, mock_db, monkeypatch):
        """Should not call UPDATE when the new status matches the current status."""
        monkeypatch.setattr(takedown_module, "shutdown_requested", False)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [
            ("https://phish.com", "active", None)
        ]
        mock_db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)

        with (
            patch("src.monitoring.takedown.get_ip_info", return_value=("1.2.3.4", "TestASN")),
            patch(
                "src.monitoring.takedown.PhishingUtils.determine_site_status",
                return_value=("active", None),  # same status
            ),
            patch("src.monitoring.takedown.time.sleep", side_effect=StopIteration),
        ):
            try:
                monitor.run()
            except StopIteration:
                pass

        # Only the SELECT should have been called (no UPDATE)
        assert mock_conn.execute.call_count == 1

    def test_continues_after_per_site_exception(self, monitor, mock_db, monkeypatch):
        """Should process the second site even when the first site raises an exception."""
        monkeypatch.setattr(takedown_module, "shutdown_requested", False)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [
            ("https://phish1.com", "active", None),
            ("https://phish2.com", "active", None),
        ]
        mock_db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)

        call_count = [0]

        def flaky_get_ip(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("DNS resolution failed")
            return ("5.6.7.8", "OtherASN")

        with (
            patch("src.monitoring.takedown.get_ip_info", side_effect=flaky_get_ip),
            patch(
                "src.monitoring.takedown.PhishingUtils.determine_site_status",
                return_value=("active", None),
            ),
            patch("src.monitoring.takedown.time.sleep", side_effect=StopIteration),
        ):
            try:
                monitor.run()
            except StopIteration:
                pass

        # Both sites attempted: get_ip_info called twice
        assert call_count[0] == 2

    def test_sets_monitoring_event_after_first_cycle(self, mock_db, monkeypatch):
        """Should set monitoring_event after the first loop cycle completes."""
        monkeypatch.setattr(takedown_module, "shutdown_requested", False)

        event = threading.Event()
        mon = TakedownMonitor(db_manager=mock_db, timeout=10, monitoring_event=event)

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)

        with patch("src.monitoring.takedown.time.sleep", side_effect=StopIteration):
            try:
                mon.run()
            except StopIteration:
                pass

        assert event.is_set()

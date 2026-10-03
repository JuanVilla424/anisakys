"""Tests for src/shutdown.py - event-based graceful shutdown coordination."""

import signal
import threading
import time
from unittest.mock import patch

import pytest

import src.shutdown as shutdown


@pytest.fixture(autouse=True)
def _reset_shutdown_state():
    """Every test starts and ends with no pending shutdown request."""
    shutdown.reset_shutdown()
    yield
    shutdown.reset_shutdown()


class TestShutdownState:
    """Shutdown flag semantics."""

    def test_initial_state_is_false(self):
        assert shutdown.is_shutdown_requested() is False

    def test_request_shutdown_sets_flag(self):
        shutdown.request_shutdown()
        assert shutdown.is_shutdown_requested() is True

    def test_flag_is_visible_through_late_lookups(self):
        """Regression: importers used to copy the boolean at import time and
        never saw the change. The function must reflect the live state."""
        from src.shutdown import is_shutdown_requested

        assert is_shutdown_requested() is False
        shutdown.request_shutdown()
        assert is_shutdown_requested() is True

    def test_wait_for_shutdown_returns_early_when_requested(self):
        threading.Timer(0.05, shutdown.request_shutdown).start()
        started = time.monotonic()
        assert shutdown.wait_for_shutdown(5) is True
        assert time.monotonic() - started < 2

    def test_wait_for_shutdown_times_out_without_request(self):
        assert shutdown.wait_for_shutdown(0.01) is False


class TestRegisteredThreads:
    """Graceful join of worker threads."""

    def test_join_waits_for_loop_that_polls_the_event(self):
        finished = threading.Event()

        def worker():
            while not shutdown.wait_for_shutdown(0.01):
                pass
            finished.set()

        thread = shutdown.register_thread(threading.Thread(target=worker, daemon=True))
        thread.start()
        shutdown.request_shutdown()
        stragglers = shutdown.join_registered_threads(timeout_per_thread=2)
        assert finished.is_set()
        assert thread.name not in stragglers


class TestSignalHandler:
    """Signal handling: graceful first, forced second."""

    @patch("src.shutdown.logger")
    def test_first_signal_requests_shutdown_without_exiting(self, _logger):
        with patch("src.shutdown.os._exit") as fake_exit:
            shutdown.signal_handler(signal.SIGTERM, None)
        assert shutdown.is_shutdown_requested() is True
        fake_exit.assert_not_called()

    @patch("src.shutdown.logger")
    def test_second_signal_forces_exit(self, _logger):
        with patch("src.shutdown.os._exit") as fake_exit:
            shutdown.signal_handler(signal.SIGINT, None)
            shutdown.signal_handler(signal.SIGINT, None)
        fake_exit.assert_called_once_with(130)

    @patch("src.shutdown.logger")
    def test_interrupt_main_raises_keyboard_interrupt(self, _logger, monkeypatch):
        monkeypatch.setattr(shutdown, "_interrupt_main", True)
        with pytest.raises(KeyboardInterrupt):
            shutdown.signal_handler(signal.SIGTERM, None)
        assert shutdown.is_shutdown_requested() is True

    def test_install_registers_sigint_and_sigterm(self):
        with patch("src.shutdown.signal.signal") as fake_signal:
            shutdown.install_signal_handlers()
        registered = {call.args[0] for call in fake_signal.call_args_list}
        assert registered == {signal.SIGINT, signal.SIGTERM}

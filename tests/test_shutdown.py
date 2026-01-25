"""
Tests for src/shutdown.py - Graceful shutdown state management
"""

import signal
from unittest.mock import patch, MagicMock

import pytest

from src.shutdown import (
    shutdown_requested,
    request_shutdown,
    is_shutdown_requested,
    signal_handler,
)


class TestShutdownState:
    """Tests for shutdown state management."""

    def setup_method(self):
        """Reset shutdown state before each test."""
        import src.shutdown

        src.shutdown.shutdown_requested = False

    def test_initial_state_is_false(self):
        """Shutdown should not be requested initially."""
        import src.shutdown

        src.shutdown.shutdown_requested = False
        assert is_shutdown_requested() is False

    def test_request_shutdown_sets_flag(self):
        """request_shutdown should set the flag to True."""
        import src.shutdown

        src.shutdown.shutdown_requested = False
        request_shutdown()
        assert src.shutdown.shutdown_requested is True

    def test_is_shutdown_requested_returns_state(self):
        """is_shutdown_requested should return current state."""
        import src.shutdown

        src.shutdown.shutdown_requested = False
        assert is_shutdown_requested() is False
        src.shutdown.shutdown_requested = True
        assert is_shutdown_requested() is True


class TestSignalHandler:
    """Tests for signal handler function."""

    def setup_method(self):
        """Reset shutdown state before each test."""
        import src.shutdown

        src.shutdown.shutdown_requested = False

    @patch("src.shutdown.logger")
    @patch("threading.Timer")
    def test_signal_handler_requests_shutdown(self, mock_timer, mock_logger):
        """Signal handler should request shutdown."""
        import src.shutdown

        mock_timer_instance = MagicMock()
        mock_timer.return_value = mock_timer_instance

        signal_handler(signal.SIGINT, None)

        assert src.shutdown.shutdown_requested is True

    @patch("src.shutdown.logger")
    @patch("threading.Timer")
    def test_signal_handler_starts_force_exit_timer(self, mock_timer, mock_logger):
        """Signal handler should start a timer for force exit."""
        mock_timer_instance = MagicMock()
        mock_timer.return_value = mock_timer_instance

        signal_handler(signal.SIGINT, None)

        mock_timer.assert_called_once()
        mock_timer_instance.start.assert_called_once()

    @patch("src.shutdown.logger")
    @patch("threading.Timer")
    def test_signal_handler_logs_message(self, mock_timer, mock_logger):
        """Signal handler should log shutdown message."""
        mock_timer_instance = MagicMock()
        mock_timer.return_value = mock_timer_instance

        signal_handler(signal.SIGTERM, None)

        assert mock_logger.info.called

"""
Unit tests for structured logging module.

Tests cover:
- JSON formatting
- Correlation ID management
- Context field inclusion
- Exception formatting
- Source location for errors
- Non-serializable object handling
- Edge cases
"""

import json
import logging
import sys
from datetime import datetime
from io import StringIO

import pytest

from src.observability.structured_logger import (
    StructuredFormatter,
    set_correlation_id,
    get_correlation_id,
    setup_structured_logging,
    log_with_context,
    log_detection,
    log_api_call,
    log_error,
)


class TestStructuredFormatter:
    """Tests for StructuredFormatter class."""

    def test_basic_json_formatting(self):
        """Test that basic log produces valid JSON with required fields."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should be valid JSON
        log_data = json.loads(output)

        # Verify required fields
        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test.logger"
        assert log_data["message"] == "Test message"
        assert "timestamp" in log_data
        assert "correlation_id" in log_data

        # Verify timestamp format (ISO8601 UTC)
        timestamp = log_data["timestamp"]
        assert timestamp.endswith("Z")
        # Should be parseable as ISO8601
        datetime.fromisoformat(timestamp.rstrip("Z"))

    def test_all_log_levels(self):
        """Test formatting for all log levels."""
        formatter = StructuredFormatter()
        levels = [
            (logging.DEBUG, "DEBUG"),
            (logging.INFO, "INFO"),
            (logging.WARNING, "WARNING"),
            (logging.ERROR, "ERROR"),
            (logging.CRITICAL, "CRITICAL"),
        ]

        for level_int, level_name in levels:
            record = logging.LogRecord(
                name="test.logger",
                level=level_int,
                pathname="test.py",
                lineno=10,
                msg=f"{level_name} message",
                args=(),
                exc_info=None,
            )

            output = formatter.format(record)
            log_data = json.loads(output)

            assert log_data["level"] == level_name
            assert log_data["message"] == f"{level_name} message"

    def test_context_field_inclusion(self):
        """Test that context field is included when provided."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Detection event",
            args=(),
            exc_info=None,
        )
        record.context = {
            "url": "https://test.com",
            "confidence": 90,
            "keywords": ["login", "bank"],
        }

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "context" in log_data
        assert log_data["context"]["url"] == "https://test.com"
        assert log_data["context"]["confidence"] == 90
        assert log_data["context"]["keywords"] == ["login", "bank"]

    def test_exception_formatting(self):
        """Test that exceptions are properly formatted."""
        formatter = StructuredFormatter()

        # Create an exception
        try:
            1 / 0
        except ZeroDivisionError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "exception" in log_data
        assert "ZeroDivisionError" in log_data["exception"]
        assert "Traceback" in log_data["exception"]

    def test_source_location_for_errors(self):
        """Test that source location is included for ERROR and above."""
        formatter = StructuredFormatter()

        # ERROR level should include source
        error_record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="/path/to/test.py",
            lineno=42,
            msg="Error message",
            args=(),
            exc_info=None,
            func="test_function",
        )

        output = formatter.format(error_record)
        log_data = json.loads(output)

        assert "source" in log_data
        assert log_data["source"]["file"] == "/path/to/test.py"
        assert log_data["source"]["line"] == 42
        assert log_data["source"]["function"] == "test_function"

        # INFO level should NOT include source
        info_record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/path/to/test.py",
            lineno=42,
            msg="Info message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(info_record)
        log_data = json.loads(output)

        assert "source" not in log_data

    def test_non_serializable_object_handling(self):
        """Test that non-serializable objects are converted to strings."""
        formatter = StructuredFormatter()

        # Create a non-serializable object
        class NonSerializable:
            def __str__(self):
                return "NonSerializable instance"

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test with non-serializable",
            args=(),
            exc_info=None,
        )
        record.context = {
            "normal_value": 42,
            "non_serializable": NonSerializable(),
        }

        # Should not raise exception
        output = formatter.format(record)
        log_data = json.loads(output)

        assert "context" in log_data
        assert log_data["context"]["normal_value"] == 42
        assert "NonSerializable" in str(log_data["context"]["non_serializable"])

    def test_empty_context(self):
        """Test handling of empty context."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Message",
            args=(),
            exc_info=None,
        )
        record.context = {}

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "context" in log_data
        assert log_data["context"] == {}

    def test_none_correlation_id(self):
        """Test that correlation_id can be None."""
        # Import ContextVar to properly reset it
        from src.observability.structured_logger import correlation_id_var

        # Properly reset the context variable to None
        correlation_id_var.set(None)

        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        log_data = json.loads(output)

        assert "correlation_id" in log_data
        assert log_data["correlation_id"] is None


class TestCorrelationID:
    """Tests for correlation ID management."""

    def test_set_and_get_correlation_id(self):
        """Test setting and getting correlation ID."""
        corr_id = set_correlation_id("test-123")

        assert corr_id == "test-123"
        assert get_correlation_id() == "test-123"

    def test_auto_generate_correlation_id(self):
        """Test that correlation ID is auto-generated when None."""
        corr_id = set_correlation_id()

        assert corr_id is not None
        assert len(corr_id) > 0
        assert get_correlation_id() == corr_id

        # Should be a valid UUID format
        import uuid

        uuid.UUID(corr_id)  # Should not raise

    def test_correlation_id_in_logs(self):
        """Test that correlation ID appears in formatted logs."""
        set_correlation_id("test-correlation-123")

        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        log_data = json.loads(output)

        assert log_data["correlation_id"] == "test-correlation-123"

    def test_correlation_id_persists_across_logs(self):
        """Test that correlation ID persists across multiple log calls."""
        set_correlation_id("persistent-123")

        formatter = StructuredFormatter()

        # First log
        record1 = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="First",
            args=(),
            exc_info=None,
        )
        log1 = json.loads(formatter.format(record1))

        # Second log
        record2 = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=11,
            msg="Second",
            args=(),
            exc_info=None,
        )
        log2 = json.loads(formatter.format(record2))

        assert log1["correlation_id"] == "persistent-123"
        assert log2["correlation_id"] == "persistent-123"


class TestSetupStructuredLogging:
    """Tests for setup_structured_logging function."""

    def test_setup_basic_configuration(self, tmp_path):
        """Test basic logging setup."""
        log_file = tmp_path / "test.log"

        logger = setup_structured_logging(log_level="DEBUG", log_file=str(log_file))

        assert logger is not None
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 2  # Console + File

    def test_log_file_creation(self, tmp_path):
        """Test that log file is created."""
        log_file = tmp_path / "logs" / "test.log"

        setup_structured_logging(log_file=str(log_file))

        # Log something
        logging.info("Test message")

        # File should exist
        assert log_file.exists()


class TestConvenienceFunctions:
    """Tests for convenience logging functions."""

    def test_log_with_context(self):
        """Test log_with_context function."""
        logger = logging.getLogger("test")
        logger.handlers.clear()

        # Capture output
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_with_context(logger, logging.INFO, "Test message", url="https://test.com", score=95)

        output = stream.getvalue()
        log_data = json.loads(output)

        assert log_data["message"] == "Test message"
        assert log_data["context"]["url"] == "https://test.com"
        assert log_data["context"]["score"] == 95

    def test_log_detection(self):
        """Test log_detection convenience function."""
        logger = logging.getLogger("test")
        logger.handlers.clear()

        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_detection(
            logger,
            url="https://phishing.com",
            confidence=95,
            keywords=["login", "bank"],
            extra_field="extra_value",
        )

        output = stream.getvalue()
        log_data = json.loads(output)

        assert log_data["message"] == "Phishing site detected"
        assert log_data["context"]["url"] == "https://phishing.com"
        assert log_data["context"]["confidence"] == 95
        assert log_data["context"]["keywords"] == ["login", "bank"]
        assert log_data["context"]["event_type"] == "detection"
        assert log_data["context"]["extra_field"] == "extra_value"

    def test_log_api_call(self):
        """Test log_api_call convenience function."""
        logger = logging.getLogger("test")
        logger.handlers.clear()

        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_api_call(
            logger,
            api_name="VirusTotal",
            url="https://virustotal.com",
            status_code=200,
            response_time_ms=150,
        )

        output = stream.getvalue()
        log_data = json.loads(output)

        assert "VirusTotal" in log_data["message"]
        assert log_data["context"]["api"] == "VirusTotal"
        assert log_data["context"]["status_code"] == 200
        assert log_data["context"]["response_time_ms"] == 150
        assert log_data["context"]["event_type"] == "api_call"

    def test_log_error(self):
        """Test log_error convenience function."""
        logger = logging.getLogger("test")
        logger.handlers.clear()

        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        try:
            1 / 0
        except ZeroDivisionError as e:
            log_error(logger, e, {"url": "https://test.com", "step": "analysis"})

        output = stream.getvalue()
        log_data = json.loads(output)

        assert "Error occurred" in log_data["message"]
        assert log_data["context"]["error_type"] == "ZeroDivisionError"
        assert log_data["context"]["url"] == "https://test.com"
        assert log_data["context"]["step"] == "analysis"

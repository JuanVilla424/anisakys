"""
Structured logging infrastructure for Anisakys.

This module provides JSON-formatted structured logging with correlation IDs
for request tracing, making logs easily parseable and queryable.

Usage Example:
    >>> import logging
    >>> from src.observability.structured_logger import (
    ...     setup_structured_logging,
    ...     set_correlation_id,
    ...     log_with_context
    ... )
    >>>
    >>> # Setup (once at application startup)
    >>> logger = setup_structured_logging(log_level="INFO")
    >>>
    >>> # In each request/scan cycle
    >>> correlation_id = set_correlation_id()
    >>> logger.info("Starting scan", extra={"context": {"url": "https://example.com"}})
    >>>
    >>> # Output (JSON):
    >>> # {"timestamp":"2025-11-21T10:30:45.123Z","level":"INFO",...}
"""

import logging
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from logging.handlers import RotatingFileHandler
from contextvars import ContextVar


# Global context variable for correlation ID (thread-safe)
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Formats log records as JSON with the following schema:
    {
        "timestamp": "2025-11-21T10:30:45.123Z",  # ISO8601 UTC
        "level": "INFO",                           # Log level
        "logger": "anisakys.detection",            # Logger name
        "message": "Phishing site detected",       # Log message
        "correlation_id": "abc-123-def",           # Request correlation ID
        "context": {...},                          # Optional: custom context
        "exception": "Traceback...",               # Optional: for exceptions
        "source": {                                # Optional: for ERROR+
            "file": "main.py",
            "line": 123,
            "function": "scan_site"
        }
    }

    Thread-safe: Yes (stateless formatter)
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as JSON.

        Args:
            record: The logging.LogRecord to format

        Returns:
            JSON string representation of the log record
        """
        # Build base log data with required fields
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id_var.get(),
        }

        # Add exception information if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add custom context if provided via extra={'context': {...}}
        if hasattr(record, "context"):
            log_data["context"] = record.context

        # Add source location for ERROR level and above
        if record.levelno >= logging.ERROR:
            log_data["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Serialize to JSON with fallback for non-serializable objects
        try:
            return json.dumps(log_data, default=str)
        except Exception as e:
            # Fallback if JSON serialization fails completely
            return json.dumps(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "level": "ERROR",
                    "message": f"Log formatting error: {str(e)}",
                    "original_message": str(record.getMessage()),
                }
            )


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """
    Set correlation ID for the current execution context.

    Correlation IDs allow tracing a request/operation through multiple
    log statements and components.

    Args:
        correlation_id: Optional correlation ID. If None, generates a new UUID.

    Returns:
        The correlation ID that was set

    Example:
        >>> corr_id = set_correlation_id()  # Auto-generates UUID
        >>> print(corr_id)
        'abc-123-def-456'
        >>>
        >>> set_correlation_id("custom-id")  # Use custom ID
        'custom-id'
    """
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    correlation_id_var.set(correlation_id)
    return correlation_id


def get_correlation_id() -> Optional[str]:
    """
    Get the current correlation ID.

    Returns:
        Current correlation ID, or None if not set

    Example:
        >>> set_correlation_id("test-123")
        >>> get_correlation_id()
        'test-123'
    """
    return correlation_id_var.get()


def setup_structured_logging(
    log_level: str = "INFO",
    log_file: str = "logs/anisakys.log",
    max_bytes: int = 50 * 1024 * 1024,  # 50MB
    backup_count: int = 30,  # Keep 30 days of logs
) -> logging.Logger:
    """
    Set up structured logging for the application.

    Configures the root logger with:
    - JSON-formatted console output
    - Rotating file handler (50MB max, 30 backups by default)
    - Configurable log level

    Args:
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
        max_bytes: Maximum file size before rotation
        backup_count: Number of backup files to keep

    Returns:
        Configured root logger

    Example:
        >>> logger = setup_structured_logging(log_level="DEBUG")
        >>> logger.info("Application started")
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Console handler with JSON formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(console_handler)

    # File handler with rotation
    try:
        # Create logs directory if it doesn't exist
        import os

        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(file_handler)
    except Exception as e:
        # If file handler fails, continue with console only
        root_logger.error(f"Failed to create file handler: {e}")

    return root_logger


def log_with_context(logger: logging.Logger, level: int, message: str, **context: Any) -> None:
    """
    Log a message with additional context fields.

    Convenience function for adding context to log messages.

    Args:
        logger: Logger instance to use
        level: Log level (e.g., logging.INFO, logging.ERROR)
        message: Log message
        **context: Arbitrary keyword arguments to include as context

    Example:
        >>> logger = logging.getLogger("anisakys")
        >>> log_with_context(
        ...     logger,
        ...     logging.INFO,
        ...     "Detected phishing site",
        ...     url="https://phishing.com",
        ...     confidence=95,
        ...     keywords=["login", "bank"]
        ... )
        >>>
        >>> # Output:
        >>> # {"timestamp":"...","level":"INFO","message":"Detected phishing site",
        >>> #  "context":{"url":"https://phishing.com","confidence":95,"keywords":["login","bank"]}}
    """
    extra = {"context": context}
    logger.log(level, message, extra=extra)


# Convenience functions for common log events


def log_detection(
    logger: logging.Logger, url: str, confidence: int, keywords: list, **extra_context: Any
) -> None:
    """
    Log a phishing detection event with standard fields.

    Args:
        logger: Logger instance
        url: URL that was detected
        confidence: Confidence score (0-100)
        keywords: List of keywords detected
        **extra_context: Additional context fields
    """
    context = {
        "url": url,
        "confidence": confidence,
        "keywords": keywords,
        "event_type": "detection",
        **extra_context,
    }
    log_with_context(logger, logging.INFO, "Phishing site detected", **context)


def log_api_call(
    logger: logging.Logger,
    api_name: str,
    url: str,
    status_code: int,
    response_time_ms: int,
    **extra_context: Any,
) -> None:
    """
    Log an external API call with standard fields.

    Args:
        logger: Logger instance
        api_name: Name of the API (e.g., "VirusTotal", "URLVoid")
        url: URL that was queried
        status_code: HTTP status code
        response_time_ms: Response time in milliseconds
        **extra_context: Additional context fields
    """
    context = {
        "api": api_name,
        "url": url,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "event_type": "api_call",
        **extra_context,
    }
    log_with_context(logger, logging.DEBUG, f"{api_name} API call completed", **context)


def log_error(logger: logging.Logger, error: Exception, context: Dict[str, Any]) -> None:
    """
    Log an error with context.

    Args:
        logger: Logger instance
        error: Exception that occurred
        context: Context dictionary with additional information
    """
    context_with_error = {"error_type": type(error).__name__, **context}
    log_with_context(logger, logging.ERROR, f"Error occurred: {str(error)}", **context_with_error)

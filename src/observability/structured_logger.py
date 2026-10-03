"""
Structured logging infrastructure for Anisakys.

One logging configuration per process, applied to the root logger:

* a console handler (human-readable text by default, JSON on request);
* a single ``RotatingFileHandler`` writing JSON lines with the correlation id
  to a file that belongs to this process only
  (``<LOG_DIR>/anisakys-<role>-<pid>.log``), so rotation never races with
  another process writing the same file;
* a filter on both handlers that redacts secrets (``Authorization`` headers,
  ``api_key=``, ``key=``, ``token=``, ``password`` and URL credentials).

The level comes from ``LOG_LEVEL`` (default ``INFO``). Configuration is
idempotent: calling :func:`configure_logging` again with the same parameters
in the same process does nothing, and only handlers installed by this module
are ever replaced (handlers added by others, e.g. pytest, are left alone).

Usage Example:
    >>> import logging
    >>> from src.observability.structured_logger import (
    ...     configure_logging,
    ...     set_correlation_id,
    ...     log_with_context,
    ... )
    >>>
    >>> configure_logging(level="INFO", process_name="api")  # once, at startup
    >>> correlation_id = set_correlation_id()
    >>> logging.getLogger("app").info("Starting scan")
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional

# Global context variable for correlation ID (thread-safe)
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)

DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_DIR = "logs"
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5
DEFAULT_CONSOLE_FORMAT = "text"
TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s [%(correlation_id)s] %(message)s"
REDACTED = "[REDACTED]"

# Libraries that are chatty at INFO and drown application logs.
NOISY_LOGGERS = (
    "urllib3",
    "botocore",
    "boto3",
    "s3transfer",
    "selenium",
    "websocket",
    # Importing alembic for the startup schema check logs every plugin it registers.
    "alembic.runtime.plugins",
)

# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

# A sensitive name is an optional dotted/underscored/dashed prefix followed by
# one of these words, e.g. key, api_key, X-API-Key, access_token, SMTP_PASS.
_SENSITIVE_WORDS = (
    r"api[_\-]?key|apikey|key|token|secret|password|passwd|pwd|pass|passphrase"
    r"|credentials?|auth|authorization|cookie|signature"
)
_SENSITIVE_NAME = rf"(?:[A-Za-z0-9]+[_.\-])*(?:{_SENSITIVE_WORDS})"
_SENSITIVE_NAME_RE = re.compile(rf"^{_SENSITIVE_NAME}$", re.IGNORECASE)

_KEY_VALUE_RE = re.compile(
    rf"""
    (?P<name>\b{_SENSITIVE_NAME})\b
    (?P<sep>["']?\s*[:=]\s*)
    (?P<quote>["']?)
    (?!\[REDACTED\])
    (?P<value>(?:Bearer|Basic|Token|Digest)\s+[^\s"',;&}}\]]+|[^\s"',;&}}\]]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_BEARER_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]{8,}=*", re.IGNORECASE)
_URL_CREDENTIALS_RE = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.\-]*://[^:/\s@]+:)(?P<password>[^@/\s]+)@", re.IGNORECASE
)


def redact_secrets(text: str) -> str:
    """Mask credentials that may appear in a log line.

    Args:
        text: Text to sanitise.

    Returns:
        The text with secret values replaced by ``[REDACTED]``.
    """
    if not text:
        return text
    text = _URL_CREDENTIALS_RE.sub(rf"\g<prefix>{REDACTED}@", text)
    text = _KEY_VALUE_RE.sub(rf"\g<name>\g<sep>\g<quote>{REDACTED}", text)
    return _BEARER_RE.sub(rf"\1 {REDACTED}", text)


def redact_value(value: Any) -> Any:
    """Recursively redact secrets in structured log context.

    Mapping entries whose key looks sensitive (``api_key``, ``password``...)
    are replaced wholesale; strings are passed through :func:`redact_secrets`.

    Args:
        value: Context value (dict, list, tuple, str or scalar).

    Returns:
        A redacted copy; the input is not modified.
    """
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if isinstance(key, str) and _SENSITIVE_NAME_RE.match(key) and value[key]
                else redact_value(value[key])
            )
            for key in value
        }
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(item) for item in value)
    if isinstance(value, str):
        return redact_secrets(value)
    return value


class SecretRedactionFilter(logging.Filter):
    """Redact secrets from a record before any of our handlers format it.

    The rendered message, the formatted exception and the ``context`` extra
    are rewritten in place, so every handler that sees the record afterwards
    (console, file, test capture) gets the sanitised version.
    """

    _exception_formatter = logging.Formatter()

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitise the record.

        Args:
            record: Record being emitted.

        Returns:
            Always True: the record is kept, only its content changes.
        """
        if not getattr(record, "_anisakys_redacted", False):
            try:
                message = record.getMessage()
            except (TypeError, ValueError):
                # Let the formatter surface the broken format string as usual.
                return True
            record.msg = redact_secrets(message)
            record.args = None
            if record.exc_info and not record.exc_text:
                record.exc_text = self._exception_formatter.formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = redact_secrets(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_secrets(record.stack_info)
            if hasattr(record, "context"):
                setattr(record, "context", redact_value(getattr(record, "context")))
            setattr(record, "_anisakys_redacted", True)
        return True


class CorrelationIdFilter(logging.Filter):
    """Expose the current correlation id and process role on every record."""

    def __init__(self, process_name: str) -> None:
        """Create the filter.

        Args:
            process_name: Role of this process (``api``, ``threads``...).
        """
        super().__init__()
        self.process_name = process_name

    def filter(self, record: logging.LogRecord) -> bool:
        """Attach ``correlation_id`` and ``process_role`` attributes.

        Args:
            record: Record being emitted.

        Returns:
            Always True.
        """
        setattr(record, "correlation_id", correlation_id_var.get() or "-")
        setattr(record, "process_role", self.process_name)
        return True


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
        "process": "api",                          # Optional: process role
        "pid": 1234,                               # Process id
        "context": {...},                          # Optional: custom context
        "exception": "Traceback...",               # Optional: for exceptions
        "source": {                                # Optional: for ERROR+
            "file": "main.py",
            "line": 123,
            "function": "scan_site"
        }
    }

    Secrets are redacted even when the formatter is used without
    :class:`SecretRedactionFilter`.

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
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
            "correlation_id": correlation_id_var.get(),
            "pid": record.process,
        }
        role = getattr(record, "process_role", None)
        if role:
            log_data["process"] = role

        if record.exc_text:
            log_data["exception"] = redact_secrets(record.exc_text)
        elif record.exc_info:
            log_data["exception"] = redact_secrets(self.formatException(record.exc_info))

        if hasattr(record, "context"):
            log_data["context"] = redact_value(getattr(record, "context"))

        if record.levelno >= logging.ERROR:
            log_data["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        try:
            return json.dumps(log_data, default=str)
        except (TypeError, ValueError) as e:
            return json.dumps(
                {
                    "timestamp": log_data["timestamp"],
                    "level": "ERROR",
                    "message": f"Log formatting error: {e}",
                    "original_message": log_data["message"],
                }
            )


class RedactingTextFormatter(logging.Formatter):
    """Plain-text formatter that never prints a secret."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the record and redact the result.

        Args:
            record: Record to format.

        Returns:
            The formatted, redacted line.
        """
        if not hasattr(record, "correlation_id"):
            setattr(record, "correlation_id", correlation_id_var.get() or "-")
        return redact_secrets(super().format(record))


# ---------------------------------------------------------------------------
# Process-wide configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoggingConfig:
    """Resolved logging configuration of the current process."""

    level: int
    process_name: str
    log_file: Optional[str]
    max_bytes: int
    backup_count: int
    console_format: str
    pid: int


_config_lock = threading.RLock()
_current: Optional[LoggingConfig] = None


def _setting(name: str) -> Any:
    """Read a setting from the environment, then from loaded app settings.

    ``src.config`` is consulted only if something already imported it: this
    module must stay importable without a ``.env`` file (CLI tools, the
    sandboxed screenshot worker).

    Args:
        name: Setting name, e.g. ``LOG_LEVEL``.

    Returns:
        The value, or None when unset.
    """
    if name in os.environ:
        return os.environ[name]
    config_module = sys.modules.get("src.config")
    settings = getattr(config_module, "settings", None) if config_module else None
    return getattr(settings, name, None) if settings is not None else None


def parse_level(level: Any) -> int:
    """Convert a level name or number to a logging level.

    Args:
        level: ``"debug"``, ``"INFO"``, ``"10"``, ``logging.WARNING``...

    Returns:
        The numeric level.

    Raises:
        ValueError: If the value is not a known level.
    """
    if isinstance(level, int):
        return level
    text = str(level).strip()
    if text.isdigit():
        return int(text)
    value = logging.getLevelName(text.upper())
    if not isinstance(value, int):
        raise ValueError(
            f"Invalid log level {level!r}; use DEBUG, INFO, WARNING, ERROR or CRITICAL"
        )
    return value


def default_process_name(argv: Optional[List[str]] = None) -> str:
    """Infer the role of this process from its command line.

    Args:
        argv: Command line (defaults to ``sys.argv``).

    Returns:
        ``api``, ``threads``, ``screenshot-worker``, ``engine`` or the
        executable's name (``alembic``, ``pytest``...).
    """
    argv = list(sys.argv if argv is None else argv)
    args = set(argv[1:])
    if "--start-api" in args:
        return "api"
    if "--threads-only" in args:
        return "threads"
    if "--start-screenshot-worker" in args:
        return "screenshot-worker"
    executable = Path(argv[0]).stem if argv and argv[0] else ""
    if executable in ("", "-c", "anisakys", "main", "__main__"):
        return "engine"
    if executable == "gunicorn":
        return "api"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", executable)


def _resolve(
    level: Any,
    process_name: Optional[str],
    log_dir: Optional[str],
    log_file: Optional[str],
    max_bytes: Optional[int],
    backup_count: Optional[int],
    console_format: Optional[str],
) -> LoggingConfig:
    """Merge explicit arguments, environment and settings into one config."""
    resolved_level = parse_level(level or _setting("LOG_LEVEL") or DEFAULT_LOG_LEVEL)
    role = process_name or _setting("LOG_PROCESS_NAME") or default_process_name()
    pid = os.getpid()

    if log_file is None:
        directory = log_dir if log_dir is not None else _setting("LOG_DIR")
        if directory is None:
            # Tests must not litter the repository; opt in with LOG_DIR.
            directory = "" if "pytest" in sys.modules else DEFAULT_LOG_DIR
        log_file = str(Path(directory) / f"anisakys-{role}-{pid}.log") if directory else None

    fmt = (console_format or _setting("LOG_CONSOLE_FORMAT") or DEFAULT_CONSOLE_FORMAT).lower()
    if fmt not in ("text", "json"):
        raise ValueError(f"Invalid LOG_CONSOLE_FORMAT {fmt!r}; use 'text' or 'json'")

    if max_bytes is None:
        max_bytes = int(_setting("LOG_MAX_BYTES") or DEFAULT_MAX_BYTES)
    if backup_count is None:
        configured = _setting("LOG_BACKUP_COUNT")
        backup_count = DEFAULT_BACKUP_COUNT if configured in (None, "") else int(configured)

    return LoggingConfig(
        level=resolved_level,
        process_name=role,
        log_file=log_file,
        max_bytes=max_bytes,
        backup_count=backup_count,
        console_format=fmt,
        pid=pid,
    )


def _managed_handlers(root: logging.Logger) -> List[logging.Handler]:
    """Return the handlers this module installed on ``root``."""
    return [h for h in root.handlers if getattr(h, "_anisakys_managed", False)]


def _build_handlers(config: LoggingConfig) -> List[logging.Handler]:
    """Create the console and file handlers for ``config``."""
    filters: List[logging.Filter] = [
        CorrelationIdFilter(config.process_name),
        SecretRedactionFilter(),
    ]

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(
        StructuredFormatter()
        if config.console_format == "json"
        else RedactingTextFormatter(TEXT_FORMAT)
    )
    handlers: List[logging.Handler] = [console]

    if config.log_file:
        Path(config.log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            config.log_file,
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(StructuredFormatter())
        handlers.append(file_handler)

    for handler in handlers:
        for log_filter in filters:
            handler.addFilter(log_filter)
        setattr(handler, "_anisakys_managed", True)
    return handlers


def configure_logging(
    level: Any = None,
    *,
    process_name: Optional[str] = None,
    log_dir: Optional[str] = None,
    log_file: Optional[str] = None,
    max_bytes: Optional[int] = None,
    backup_count: Optional[int] = None,
    console_format: Optional[str] = None,
) -> logging.Logger:
    """Configure process-wide logging once (idempotent).

    Every argument falls back to the matching setting (``LOG_LEVEL``,
    ``LOG_PROCESS_NAME``, ``LOG_DIR``, ``LOG_MAX_BYTES``, ``LOG_BACKUP_COUNT``,
    ``LOG_CONSOLE_FORMAT``), read from the environment or the loaded app
    settings, then to the defaults. ``LOG_DIR`` set to an empty string
    disables the log file (console only).

    Args:
        level: Minimum level for the root logger (name or number).
        process_name: Role used in the file name and records (``api``...).
        log_dir: Directory for ``anisakys-<role>-<pid>.log``.
        log_file: Explicit file path; overrides ``log_dir``.
        max_bytes: Rotation size of the file.
        backup_count: Rotated files to keep.
        console_format: ``"text"`` or ``"json"``.

    Returns:
        The configured root logger.

    Raises:
        ValueError: If the level or console format is invalid.
        OSError: If the log file cannot be opened (logging must not fail
            silently at startup).
    """
    global _current
    config = _resolve(
        level, process_name, log_dir, log_file, max_bytes, backup_count, console_format
    )
    root = logging.getLogger()
    with _config_lock:
        if config == _current and _managed_handlers(root):
            return root

        handlers = _build_handlers(config)
        for old in _managed_handlers(root):
            root.removeHandler(old)
            old.close()
        for handler in handlers:
            root.addHandler(handler)
        root.setLevel(config.level)
        for name in NOISY_LOGGERS:
            logging.getLogger(name).setLevel(max(config.level, logging.WARNING))
        _current = config
    return root


def setup_structured_logging(
    log_level: Any = None,
    log_file: Optional[str] = None,
    max_bytes: Optional[int] = None,
    backup_count: Optional[int] = None,
    **kwargs: Any,
) -> logging.Logger:
    """Backwards-compatible entry point; see :func:`configure_logging`.

    Args:
        log_level: Minimum log level.
        log_file: Explicit log file path (default: per-process file in LOG_DIR).
        max_bytes: Maximum file size before rotation.
        backup_count: Number of rotated files to keep.
        **kwargs: Extra keyword arguments for :func:`configure_logging`.

    Returns:
        The configured root logger.
    """
    return configure_logging(
        log_level,
        log_file=log_file,
        max_bytes=max_bytes,
        backup_count=backup_count,
        **kwargs,
    )


def current_logging_config() -> Optional[LoggingConfig]:
    """Return the active configuration, or None if logging is not configured."""
    return _current


def reset_logging() -> None:
    """Remove the handlers installed by :func:`configure_logging` (tests)."""
    global _current
    root = logging.getLogger()
    with _config_lock:
        for handler in _managed_handlers(root):
            root.removeHandler(handler)
            handler.close()
        _current = None


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
        'test-123'
        >>> get_correlation_id()
        'test-123'
    """
    return correlation_id_var.get()


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

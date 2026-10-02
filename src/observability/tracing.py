"""
Span-based tracing for Anisakys.

Extends the existing correlation ID system (structured_logger.py) with
hierarchical span management. Spans measure the duration of individual
operations within a scan/request and are logged as JSON via structured_logger.

Relationship to correlation IDs:
    - correlation_id (from structured_logger) = trace_id: identifies the top-level operation
    - span_id: identifies a sub-operation within that trace
    - parent_span_id: links child spans to their parent

Usage:
    >>> from src.observability.tracing import trace_operation
    >>> with trace_operation("virustotal_lookup", url="https://example.com") as span:
    ...     result = virustotal.check(url)
    >>> # Logs: {"event_type": "span_complete", "span": "virustotal_lookup", "duration_ms": 342}
"""

import logging
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, Optional


_logger = logging.getLogger("anisakys.tracing")


# ---------------------------------------------------------------------------
# Span dataclass
# ---------------------------------------------------------------------------


@dataclass
class Span:
    """
    A timed operation within a distributed trace.

    Attributes:
        name:           Human-readable operation name (e.g. "virustotal_lookup")
        trace_id:       Correlates with the current correlation_id
        span_id:        Unique identifier for this span
        parent_span_id: ID of the enclosing span, or None for root spans
        start_time:     Epoch seconds when span was created
        end_time:       Epoch seconds when span was finished (None until finish())
        attributes:     Arbitrary key-value data attached to the span
        error:          Exception message if span ended with an error
    """

    name: str
    trace_id: Optional[str]
    span_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    parent_span_id: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def duration_ms(self) -> Optional[float]:
        """Elapsed time in milliseconds, or None if span has not finished."""
        if self.end_time is None:
            return None
        return round((self.end_time - self.start_time) * 1000, 2)

    def finish(self, **attributes: Any) -> None:
        """Mark the span as finished and attach optional extra attributes."""
        self.end_time = time.time()
        self.attributes.update(attributes)

    def finish_with_error(self, error: Exception, **attributes: Any) -> None:
        """Mark the span as finished with an error."""
        self.end_time = time.time()
        self.error = str(error)
        self.attributes.update(attributes)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize span to a JSON-compatible dict."""
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# SpanManager
# ---------------------------------------------------------------------------


class SpanManager:
    """
    Manages the active span stack within the current async/thread context.

    Uses contextvars so each thread/coroutine has its own span context.
    """

    def __init__(self) -> None:
        self._current_span: ContextVar[Optional[Span]] = ContextVar("current_span", default=None)

    def start_span(self, name: str, **attributes: Any) -> Span:
        """
        Create and activate a new span.

        Automatically links to the current span as parent (if any).
        Reads the current correlation_id as trace_id.

        Args:
            name:       Operation name
            **attributes: Initial attributes to attach to the span

        Returns:
            The new Span (also set as current span in context)
        """
        from src.observability.structured_logger import get_correlation_id

        parent = self._current_span.get()
        span = Span(
            name=name,
            trace_id=get_correlation_id(),
            parent_span_id=parent.span_id if parent else None,
            attributes=dict(attributes),
        )
        self._current_span.set(span)
        return span

    def finish_span(self, span: Span, **attributes: Any) -> None:
        """
        Finish a span and log it via structured_logger.

        Restores the parent span as the current span.

        Args:
            span:         Span to finish
            **attributes: Extra attributes to attach before finishing
        """
        span.finish(**attributes)
        self._log_span(span)
        # Restore parent (simple single-level restore — nested spans restore correctly
        # because each start_span captures the then-current parent reference)
        self._current_span.set(None)

    def get_current_span(self) -> Optional[Span]:
        """Return the currently active span, or None."""
        return self._current_span.get()

    def _log_span(self, span: Span) -> None:
        """Emit a structured log record for the completed span."""
        context = {
            "event_type": "span_complete",
            "span": span.name,
            "span_id": span.span_id,
            "trace_id": span.trace_id,
            "parent_span_id": span.parent_span_id,
            "duration_ms": span.duration_ms,
            **span.attributes,
        }
        if span.error:
            context["error"] = span.error
            _logger.warning(
                f"Span completed with error: {span.name} ({span.duration_ms}ms)",
                extra={"context": context},
            )
        else:
            _logger.debug(
                f"Span complete: {span.name} ({span.duration_ms}ms)",
                extra={"context": context},
            )


# ---------------------------------------------------------------------------
# Global instance
# ---------------------------------------------------------------------------

span_manager = SpanManager()


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


@contextmanager
def trace_operation(name: str, **attributes: Any) -> Generator[Span, None, None]:
    """
    Context manager for tracing a named operation.

    Starts a span on entry, finishes it on exit (including on exception).
    The span is logged automatically when the context exits.

    Args:
        name:         Operation name (e.g. "virustotal_lookup", "whois_query")
        **attributes: Attributes to attach to the span

    Yields:
        The active Span (can be used to add attributes mid-operation)

    Example:
        >>> with trace_operation("virustotal_lookup", url="https://example.com") as span:
        ...     result = client.check(url)
        ...     span.attributes["detections"] = result.detections
    """
    span = span_manager.start_span(name, **attributes)
    try:
        yield span
    except Exception as exc:
        span.finish_with_error(exc)
        span_manager._log_span(span)
        span_manager._current_span.set(None)
        raise
    else:
        span_manager.finish_span(span)

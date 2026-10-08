"""
Circuit Breaker Pattern Implementation
EPIC-004: API Circuit Breakers

Prevents cascading failures when external APIs are down or slow.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Failure threshold exceeded, requests fail fast
- HALF_OPEN: Testing if service recovered; exactly one trial call at a time

Failures are exceptions raised by the wrapped callable *and* HTTP responses
that signal an unhealthy upstream (429 and 5xx) when the callable returns a
``requests.Response`` (or a tuple whose first element is one). Such responses
are still returned to the caller, so existing status-code handling keeps
working, but they count towards opening the circuit.

Retries never re-send non-idempotent requests (POST/PUT/PATCH) unless the
caller explicitly marks the call idempotent, and backoff waits are interrupted
by a shutdown request.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, Optional

import requests

from src.observability.metrics import (
    METRIC_API_CALLS_TOTAL,
    METRIC_API_LATENCY_SECONDS,
    METRIC_CIRCUIT_BREAKER_STATE,
    increment_counter,
    observe_histogram,
    set_gauge,
)
from src.observability.structured_logger import log_with_context
from src.shutdown import wait_for_shutdown
from src.utils.redaction import redact_secrets

# HTTP methods whose repetition may duplicate a side effect upstream.
NON_IDEMPOTENT_METHODS = frozenset({"POST", "PUT", "PATCH"})


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker.

    Attributes:
        failure_threshold: Consecutive failures (in CLOSED) before opening.
        recovery_timeout: Seconds to stay OPEN before admitting a trial call.
        success_threshold: Successful trial calls in HALF_OPEN before closing.
        timeout: Per-request timeout in seconds. The breaker cannot interrupt
            an arbitrary callable, so integrations must pass this value as the
            ``timeout`` of the HTTP call they wrap.
        max_retries: Total attempts per call (1 disables retries).
        retry_backoff_base: Base seconds for exponential backoff.
        retry_backoff_max: Upper bound for a single backoff wait.
    """

    failure_threshold: int = 5
    recovery_timeout: int = 60
    success_threshold: int = 2
    timeout: float = 10.0

    # Retry configuration
    max_retries: int = 3
    retry_backoff_base: float = 1.0
    retry_backoff_max: float = 30.0


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: Optional[datetime] = None
    last_call_ms: Optional[float] = None
    state_changes: Dict[str, int] = field(
        default_factory=lambda: {"CLOSED": 0, "OPEN": 0, "HALF_OPEN": 0}
    )


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and rejects request."""

    pass


class UnhealthyResponseError(requests.HTTPError):
    """Marker for a 429/5xx response that was recorded as a breaker failure."""


def _extract_response(result: Any) -> Optional[requests.Response]:
    """Return the ``requests.Response`` carried by a call result, if any.

    Args:
        result: Whatever the wrapped callable returned.

    Returns:
        The response when ``result`` is one, or is a tuple starting with one
        (the ``(response, elapsed_ms)`` shape used by the integrations).
    """
    if isinstance(result, requests.Response):
        return result
    if isinstance(result, tuple) and result and isinstance(result[0], requests.Response):
        return result[0]
    return None


def _is_unhealthy_status(status_code: int) -> bool:
    """Tell whether an HTTP status means the upstream is unhealthy.

    Args:
        status_code: HTTP status code.

    Returns:
        ``True`` for 429 (rate limited) and every 5xx.
    """
    return status_code == 429 or status_code >= 500


def _request_method(obj: Any) -> Optional[str]:
    """Best-effort HTTP method of the request behind a response/exception.

    ``requests`` attaches the prepared request to the exceptions raised by its
    transport adapter (connection errors, timeouts, TLS errors) and to every
    response, so the method is known for all HTTP failures.

    Args:
        obj: A ``requests.Response`` or a ``requests.RequestException``.

    Returns:
        Upper-case method name, or ``None`` when it cannot be determined.
    """
    request = getattr(obj, "request", None)
    method = getattr(request, "method", None)
    return method.upper() if isinstance(method, str) else None


class CircuitBreaker:
    """
    Thread-safe circuit breaker for API calls.

    Usage:
        cb = CircuitBreaker("MyAPI", config)
        response = cb.call(session.get, url, timeout=cb.config.timeout)

        @cb
        def my_api_call():
            return requests.get("https://api.example.com", timeout=10)
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """Create a breaker.

        Args:
            name: Name used in logs and metrics (usually the API name).
            config: Thresholds/retry settings; defaults to ``CircuitBreakerConfig()``.
            logger: Logger to use; defaults to this module's logger.
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.logger = logger or logging.getLogger(__name__)

        self._lock = threading.RLock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_trial_in_flight = False
        self._stats = CircuitBreakerStats()

        log_with_context(
            self.logger,
            logging.INFO,
            f"Circuit breaker initialized: {name}",
            circuit_breaker=name,
            failure_threshold=self.config.failure_threshold,
            recovery_timeout=self.config.recovery_timeout,
            event_type="circuit_breaker_init",
        )

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def stats(self) -> CircuitBreakerStats:
        """Get circuit breaker statistics."""
        return self._stats

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state. Caller must hold ``self._lock``.

        Args:
            new_state: Target state.
        """
        if new_state == self._state:
            return

        old_state = self._state
        self._state = new_state
        self._stats.last_state_change = datetime.now()
        self._stats.state_changes[new_state.value.upper()] += 1

        log_with_context(
            self.logger,
            logging.WARNING if new_state == CircuitState.OPEN else logging.INFO,
            f"Circuit breaker state transition: {old_state.value} → {new_state.value}",
            circuit_breaker=self.name,
            old_state=old_state.value,
            new_state=new_state.value,
            failure_count=self._failure_count,
            success_count=self._success_count,
            event_type="circuit_breaker_state_change",
        )

        _state_val = {"closed": 0.0, "half_open": 0.5, "open": 1.0}
        set_gauge(METRIC_CIRCUIT_BREAKER_STATE, _state_val[new_state.value], api_name=self.name)

        # Reset counters on state change
        if new_state == CircuitState.HALF_OPEN:
            self._success_count = 0
            self._failure_count = 0

    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset (transition to HALF_OPEN)."""
        if self._state != CircuitState.OPEN:
            return False

        if self._last_failure_time is None:
            return True

        elapsed = time.time() - self._last_failure_time
        return elapsed >= self.config.recovery_timeout

    def _record_success(self) -> None:
        """Record a successful request. Caller must hold ``self._lock``."""
        self._stats.total_requests += 1
        self._stats.successful_requests += 1

        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.success_threshold:
                self._transition_to(CircuitState.CLOSED)
                self._failure_count = 0
        elif self._state == CircuitState.CLOSED:
            # Reset failure count on success
            self._failure_count = 0

    def _record_failure(self, error: Exception) -> None:
        """Record a failed request. Caller must hold ``self._lock``.

        Args:
            error: The exception (or synthetic HTTP error) that failed the call.
        """
        self._stats.total_requests += 1
        self._stats.failed_requests += 1
        self._stats.last_failure_time = datetime.now()
        self._last_failure_time = time.time()
        self._failure_count += 1

        # Exception text from requests embeds the request URL, which may carry
        # a credential in its query string: never log it unredacted.
        log_with_context(
            self.logger,
            logging.ERROR,
            f"Error occurred: {redact_secrets(error)}",
            error_type=type(error).__name__,
            circuit_breaker=self.name,
            state=self._state.value,
            failure_count=self._failure_count,
            failure_threshold=self.config.failure_threshold,
            event_type="circuit_breaker_failure",
        )

        if self._state == CircuitState.HALF_OPEN:
            # Any failure in half-open immediately opens circuit
            self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.config.failure_threshold:
                self._transition_to(CircuitState.OPEN)

    def _admit(self) -> bool:
        """Decide whether a call may proceed.

        Returns:
            ``True`` when the admitted call is the single HALF_OPEN trial.

        Raises:
            CircuitBreakerOpenError: When the circuit is OPEN, or HALF_OPEN with
                its trial call already in flight.
        """
        with self._lock:
            if self._should_attempt_reset():
                self._transition_to(CircuitState.HALF_OPEN)

            if self._state == CircuitState.OPEN:
                self._stats.rejected_requests += 1
                log_with_context(
                    self.logger,
                    logging.WARNING,
                    f"Circuit breaker OPEN: rejecting request to {self.name}",
                    circuit_breaker=self.name,
                    failure_count=self._failure_count,
                    seconds_until_retry=int(
                        self.config.recovery_timeout
                        - (time.time() - (self._last_failure_time or 0))
                    ),
                    event_type="circuit_breaker_rejected",
                )
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is OPEN. "
                    f"Service unavailable after {self._failure_count} failures."
                )

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_trial_in_flight:
                    self._stats.rejected_requests += 1
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN with a trial call "
                        "already in flight."
                    )
                self._half_open_trial_in_flight = True
                return True
            return False

    @staticmethod
    def _may_retry(idempotent: Optional[bool], method: Optional[str]) -> bool:
        """Tell whether a failed attempt may be repeated.

        Args:
            idempotent: Explicit caller declaration; wins when not ``None``.
            method: HTTP method inferred from the failed request, if known.

        Returns:
            ``False`` for POST/PUT/PATCH unless declared idempotent; ``True``
            for other methods and for callables that are not HTTP requests.
        """
        if idempotent is not None:
            return idempotent
        if method is None:
            return True
        return method not in NON_IDEMPOTENT_METHODS

    def _backoff(self, attempt: int, error_text: str) -> bool:
        """Sleep before the next attempt, waking early on shutdown.

        Args:
            attempt: Zero-based index of the attempt that just failed.
            error_text: Already-redacted description of the failure.

        Returns:
            ``True`` if a shutdown was requested and retrying must stop.
        """
        backoff = min(self.config.retry_backoff_base * (2**attempt), self.config.retry_backoff_max)
        log_with_context(
            self.logger,
            logging.WARNING,
            f"Circuit breaker retry {attempt + 1}/{self.config.max_retries}",
            circuit_breaker=self.name,
            attempt=attempt + 1,
            max_retries=self.config.max_retries,
            backoff_seconds=backoff,
            error=error_text,
            event_type="circuit_breaker_retry",
        )
        return wait_for_shutdown(backoff)

    def call(
        self,
        func: Callable[..., Any],
        *args: Any,
        idempotent: Optional[bool] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Execute a function with circuit breaker protection.

        Args:
            func: Function to execute.
            *args: Positional arguments for function.
            idempotent: Whether repeating the call is safe. ``None`` (default)
                infers it from the HTTP method of the failed request, so
                POST/PUT/PATCH are never retried; pass ``True`` for read-only
                lookups sent as POST, ``False`` to disable retries entirely.
                Consumed by the breaker, never forwarded to ``func``.
            **kwargs: Keyword arguments for function.

        Returns:
            Result from function. A 429/5xx ``requests.Response`` result is
            returned as well, after being recorded as a failure.

        Raises:
            CircuitBreakerOpenError: If the circuit is open (or half-open with
                a trial already running).
            Exception: The last exception raised by the function.
        """
        is_trial = self._admit()
        # No retries for the half-open trial: fail fast and reopen.
        max_attempts = 1 if is_trial else max(1, self.config.max_retries)
        call_start = time.time()
        try:
            attempt = 0
            while True:
                last_attempt = attempt >= max_attempts - 1
                try:
                    result = func(*args, **kwargs)
                except Exception as e:
                    if (
                        not last_attempt
                        and self._may_retry(idempotent, _request_method(e))
                        and not self._backoff(attempt, redact_secrets(e))
                    ):
                        attempt += 1
                        continue
                    with self._lock:
                        self._stats.last_call_ms = round((time.time() - call_start) * 1000, 1)
                        self._record_failure(e)
                    raise

                response = _extract_response(result)
                if response is not None and _is_unhealthy_status(response.status_code):
                    failure = UnhealthyResponseError(
                        f"{self.name} answered HTTP {response.status_code}"
                    )
                    if (
                        not last_attempt
                        and self._may_retry(idempotent, _request_method(response))
                        and not self._backoff(attempt, str(failure))
                    ):
                        attempt += 1
                        continue
                    with self._lock:
                        self._stats.last_call_ms = round((time.time() - call_start) * 1000, 1)
                        self._record_failure(failure)
                    return result

                elapsed = time.time() - call_start
                with self._lock:
                    self._record_success()
                    self._stats.last_call_ms = round(elapsed * 1000, 1)
                observe_histogram(METRIC_API_LATENCY_SECONDS, elapsed, api_name=self.name)
                increment_counter(METRIC_API_CALLS_TOTAL, api_name=self.name)
                return result
        finally:
            if is_trial:
                with self._lock:
                    self._half_open_trial_in_flight = False

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for wrapping functions with circuit breaker.

        Usage:
            @circuit_breaker
            def my_api_call():
                return requests.get("https://api.example.com")
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)

        return wrapper

    def reset(self) -> None:
        """Manually reset circuit breaker to CLOSED state."""
        with self._lock:
            log_with_context(
                self.logger,
                logging.INFO,
                f"Circuit breaker manually reset: {self.name}",
                circuit_breaker=self.name,
                old_state=self._state.value,
                event_type="circuit_breaker_manual_reset",
            )

            self._transition_to(CircuitState.CLOSED)
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None
            self._half_open_trial_in_flight = False

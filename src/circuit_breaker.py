"""
Circuit Breaker Pattern Implementation
EPIC-004: API Circuit Breakers

Prevents cascading failures when external APIs are down or slow.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Failure threshold exceeded, requests fail fast
- HALF_OPEN: Testing if service recovered, limited requests allowed

Author: BMAD Dev Team
Date: 2025-11-21
Version: 1.1.0
"""

import time
import logging
from enum import Enum
from typing import Callable, Any, Optional, Dict
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from src.observability.structured_logger import log_with_context, log_error


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Failures before opening
    recovery_timeout: int = 60  # Seconds before trying half-open
    success_threshold: int = 2  # Successes in half-open before closing
    timeout: float = 10.0  # Request timeout in seconds

    # Retry configuration
    max_retries: int = 3
    retry_backoff_base: float = 1.0  # Base seconds for exponential backoff
    retry_backoff_max: float = 30.0  # Max backoff time


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: Optional[datetime] = None
    state_changes: Dict[str, int] = field(
        default_factory=lambda: {"CLOSED": 0, "OPEN": 0, "HALF_OPEN": 0}
    )


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and rejects request."""

    pass


class CircuitBreaker:
    """
    Circuit Breaker implementation for API calls.

    Usage:
        cb = CircuitBreaker("MyAPI", config)

        @cb.call
        def my_api_call():
            return requests.get("https://api.example.com")
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.logger = logger or logging.getLogger(__name__)

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
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

    def _transition_to(self, new_state: CircuitState):
        """Transition to a new state."""
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

    def _record_success(self):
        """Record a successful request."""
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

    def _record_failure(self, error: Exception):
        """Record a failed request."""
        self._stats.total_requests += 1
        self._stats.failed_requests += 1
        self._stats.last_failure_time = datetime.now()
        self._last_failure_time = time.time()
        self._failure_count += 1

        log_error(
            self.logger,
            error,
            {
                "circuit_breaker": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "failure_threshold": self.config.failure_threshold,
                "event_type": "circuit_breaker_failure",
            },
        )

        if self._state == CircuitState.HALF_OPEN:
            # Any failure in half-open immediately opens circuit
            self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.config.failure_threshold:
                self._transition_to(CircuitState.OPEN)

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Result from function

        Raises:
            CircuitBreakerOpenError: If circuit is open
            Exception: Any exception from the function
        """
        # Check if we should attempt reset
        if self._should_attempt_reset():
            self._transition_to(CircuitState.HALF_OPEN)

        # Reject if circuit is open
        if self._state == CircuitState.OPEN:
            self._stats.rejected_requests += 1
            log_with_context(
                self.logger,
                logging.WARNING,
                f"Circuit breaker OPEN: rejecting request to {self.name}",
                circuit_breaker=self.name,
                failure_count=self._failure_count,
                seconds_until_retry=int(
                    self.config.recovery_timeout - (time.time() - (self._last_failure_time or 0))
                ),
                event_type="circuit_breaker_rejected",
            )
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self.name}' is OPEN. "
                f"Service unavailable after {self._failure_count} failures."
            )

        # Attempt the call with retries
        last_exception = None
        for attempt in range(self.config.max_retries):
            try:
                result = func(*args, **kwargs)
                self._record_success()
                return result

            except Exception as e:
                last_exception = e

                # Don't retry if we're in half-open (fail fast)
                if self._state == CircuitState.HALF_OPEN:
                    self._record_failure(e)
                    raise

                # Calculate backoff
                if attempt < self.config.max_retries - 1:
                    backoff = min(
                        self.config.retry_backoff_base * (2**attempt), self.config.retry_backoff_max
                    )

                    log_with_context(
                        self.logger,
                        logging.WARNING,
                        f"Circuit breaker retry {attempt + 1}/{self.config.max_retries}",
                        circuit_breaker=self.name,
                        attempt=attempt + 1,
                        max_retries=self.config.max_retries,
                        backoff_seconds=backoff,
                        error=str(e),
                        event_type="circuit_breaker_retry",
                    )

                    time.sleep(backoff)

        # All retries exhausted
        if last_exception:
            self._record_failure(last_exception)
            raise last_exception

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

    def reset(self):
        """Manually reset circuit breaker to CLOSED state."""
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

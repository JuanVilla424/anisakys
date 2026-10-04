"""Regression tests for circuit breaker safety fixes.

Covers: a lock-protected single trial call in HALF_OPEN, 429/5xx responses
counted as failures, no retries of non-idempotent requests unless declared
idempotent, shutdown-aware backoff, and secret redaction in failure logs.
"""

import logging
import threading
import time
from unittest.mock import Mock, patch

import pytest
import requests

from src.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)


def _response(status: int, method: str = "GET") -> requests.Response:
    """Build a real ``requests.Response`` with an attached request.

    Args:
        status: HTTP status code.
        method: HTTP method of the attached prepared request.

    Returns:
        The response object.
    """
    resp = requests.Response()
    resp.status_code = status
    resp.request = requests.Request(method, "https://api.example.invalid/x").prepare()
    return resp


def _conn_error(method: str) -> requests.ConnectionError:
    """Build a ConnectionError carrying a prepared request like requests does.

    Args:
        method: HTTP method of the failed request.

    Returns:
        The exception instance.
    """
    req = requests.Request(method, "https://api.example.invalid/x?key=SECRET123").prepare()
    return requests.ConnectionError("Max retries exceeded with url: /x?key=SECRET123", request=req)


@pytest.fixture
def config():
    """Fast breaker configuration for tests."""
    return CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=1,
        success_threshold=1,
        max_retries=3,
        retry_backoff_base=0.01,
        retry_backoff_max=0.02,
    )


@pytest.fixture
def breaker(config):
    """Breaker with a mock logger."""
    return CircuitBreaker("TestAPI", config, Mock(spec=logging.Logger))


def _open(breaker: CircuitBreaker) -> None:
    """Drive a breaker to OPEN with failing calls."""

    def boom():
        raise ValueError("down")

    for _ in range(breaker.config.failure_threshold):
        with pytest.raises(ValueError):
            breaker.call(boom, idempotent=False)
    assert breaker.state == CircuitState.OPEN


class TestUnhealthyResponses:
    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    def test_unhealthy_status_counts_as_failure_but_is_returned(self, breaker, status):
        resp = _response(status)
        result = breaker.call(lambda: resp, idempotent=False)
        assert result is resp
        assert breaker.stats.failed_requests == 1
        assert breaker.stats.successful_requests == 0

    def test_tuple_result_with_unhealthy_response_counts_as_failure(self, breaker):
        resp = _response(503)
        result = breaker.call(lambda: (resp, 12), idempotent=False)
        assert result == (resp, 12)
        assert breaker.stats.failed_requests == 1

    def test_repeated_5xx_opens_circuit(self, breaker):
        for _ in range(3):
            breaker.call(lambda: _response(500), idempotent=False)
        assert breaker.state == CircuitState.OPEN

    @pytest.mark.parametrize("status", [200, 204, 404])
    def test_healthy_or_client_status_is_success(self, breaker, status):
        breaker.call(lambda: _response(status))
        assert breaker.stats.successful_requests == 1
        assert breaker.stats.failed_requests == 0

    def test_get_with_5xx_is_retried_then_succeeds(self, breaker):
        responses = iter([_response(503), _response(200)])
        result = breaker.call(lambda: next(responses))
        assert result.status_code == 200
        assert breaker.stats.successful_requests == 1

    def test_post_with_5xx_is_not_retried(self, breaker):
        calls = []

        def post():
            calls.append(1)
            return _response(503, method="POST")

        breaker.call(post)
        assert len(calls) == 1


class TestIdempotency:
    def test_post_connection_error_is_not_retried(self, breaker):
        calls = []

        def post():
            calls.append(1)
            raise _conn_error("POST")

        with pytest.raises(requests.ConnectionError):
            breaker.call(post)
        assert len(calls) == 1

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_other_non_idempotent_methods_are_not_retried(self, breaker, method):
        calls = []

        def send():
            calls.append(1)
            raise _conn_error(method)

        with pytest.raises(requests.ConnectionError):
            breaker.call(send)
        assert len(calls) == 1

    def test_post_marked_idempotent_is_retried(self, breaker):
        calls = []

        def lookup():
            calls.append(1)
            raise _conn_error("POST")

        with pytest.raises(requests.ConnectionError):
            breaker.call(lookup, idempotent=True)
        assert len(calls) == 3

    def test_get_connection_error_is_retried(self, breaker):
        calls = []

        def get():
            calls.append(1)
            raise _conn_error("GET")

        with pytest.raises(requests.ConnectionError):
            breaker.call(get)
        assert len(calls) == 3

    def test_idempotent_false_disables_retries(self, breaker):
        calls = []

        def get():
            calls.append(1)
            raise _conn_error("GET")

        with pytest.raises(requests.ConnectionError):
            breaker.call(get, idempotent=False)
        assert len(calls) == 1

    def test_idempotent_kwarg_is_not_forwarded(self, breaker):
        def func(**kwargs):
            return kwargs

        assert breaker.call(func, idempotent=True, a=1) == {"a": 1}


class TestShutdownAwareBackoff:
    def test_backoff_uses_wait_for_shutdown_not_sleep(self, breaker):
        with (
            patch("src.circuit_breaker.wait_for_shutdown", return_value=False) as wait,
            patch("time.sleep") as sleep,
        ):
            with pytest.raises(requests.ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(_conn_error("GET")))
        assert wait.call_count == 2
        sleep.assert_not_called()

    def test_shutdown_during_backoff_stops_retrying(self, breaker):
        calls = []

        def get():
            calls.append(1)
            raise _conn_error("GET")

        with patch("src.circuit_breaker.wait_for_shutdown", return_value=True):
            with pytest.raises(requests.ConnectionError):
                breaker.call(get)
        assert len(calls) == 1
        assert breaker.stats.failed_requests == 1


class TestHalfOpenSingleTrial:
    def test_only_one_concurrent_trial_in_half_open(self, breaker):
        _open(breaker)
        time.sleep(1.05)

        started = threading.Event()
        release = threading.Event()
        trial_calls = []

        def slow_trial():
            trial_calls.append(1)
            started.set()
            release.wait(5)
            return "ok"

        results = {}

        def run_trial():
            results["trial"] = breaker.call(slow_trial)

        t = threading.Thread(target=run_trial)
        t.start()
        assert started.wait(5)
        assert breaker.state == CircuitState.HALF_OPEN

        # A second caller must be rejected while the trial is in flight.
        with pytest.raises(CircuitBreakerOpenError):
            breaker.call(lambda: "second")

        release.set()
        t.join(5)
        assert results["trial"] == "ok"
        assert len(trial_calls) == 1
        assert breaker.state == CircuitState.CLOSED

    def test_trial_slot_released_after_failure(self, breaker):
        _open(breaker)
        time.sleep(1.05)
        with pytest.raises(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("still down")))
        assert breaker.state == CircuitState.OPEN
        assert breaker._half_open_trial_in_flight is False

    def test_concurrent_closed_calls_keep_consistent_counters(self, config):
        cb = CircuitBreaker("Concurrent", config, Mock(spec=logging.Logger))

        def work():
            for _ in range(200):
                cb.call(lambda: "ok")

        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert cb.stats.successful_requests == 1600
        assert cb.stats.total_requests == 1600


class TestRedaction:
    def test_failure_log_does_not_contain_query_key(self, config, caplog):
        cb = CircuitBreaker("Redact", config, logging.getLogger("cb-redact-test"))

        def post():
            raise _conn_error("POST")

        with caplog.at_level(logging.DEBUG, logger="cb-redact-test"):
            with pytest.raises(requests.ConnectionError):
                cb.call(post)
        assert "SECRET123" not in caplog.text
        assert "REDACTED" in caplog.text

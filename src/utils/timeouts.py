"""Thread-based call timeouts."""

from __future__ import annotations

import threading
from functools import wraps
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class OperationTimeoutError(TimeoutError):
    """Raised when a call wrapped with :func:`timeout` exceeds its deadline.

    Subclasses the built-in :class:`TimeoutError` so existing
    ``except TimeoutError`` handlers keep working.
    """


def timeout(seconds: float = 10) -> Callable[[F], F]:
    """Bound how long the caller waits for a function call.

    The wrapped function runs in a daemon thread; if it has not finished after
    ``seconds`` the caller gets :class:`OperationTimeoutError`. The worker thread
    is not killed (Python cannot do that safely), so only wrap operations that
    are themselves bounded (e.g. DB calls with statement timeouts).

    Args:
        seconds: Maximum time to wait for the call to finish.

    Returns:
        A decorator applying the timeout to the wrapped function.

    Raises:
        OperationTimeoutError: From the wrapped call when the deadline passes.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result: list[Any] = [None]
            error: list[BaseException | None] = [None]

            def target() -> None:
                try:
                    result[0] = func(*args, **kwargs)
                except BaseException as exc:  # re-raised in the caller below
                    error[0] = exc

            worker = threading.Thread(target=target, daemon=True)
            worker.start()
            worker.join(timeout=seconds)
            if worker.is_alive():
                raise OperationTimeoutError(f"Operation timed out after {seconds} seconds")
            if error[0] is not None:
                raise error[0]
            return result[0]

        return wrapper  # type: ignore[return-value]

    return decorator

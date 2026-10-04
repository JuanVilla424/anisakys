"""
Shared shutdown coordination for the Anisakys engine.

A single :class:`threading.Event` is the source of truth. Long-running loops
must poll :func:`is_shutdown_requested` (never a copied module attribute) and
sleep with :func:`wait_for_shutdown` so a stop request interrupts the wait
immediately instead of after the full interval.

Signal handling is graceful-first: the first SIGINT/SIGTERM only requests a
shutdown and lets in-flight work (an SMTP send, a DB transaction) finish; the
process exits once the registered worker threads have been joined. A second
signal forces an immediate exit for operators who really mean it.
"""

from __future__ import annotations

import os
import signal
import threading
from types import FrameType
from typing import List, Optional

from src.logger import logger

_shutdown_event = threading.Event()
_threads_lock = threading.Lock()
_registered_threads: List[threading.Thread] = []
_signal_count = 0
_interrupt_main = False


def request_shutdown() -> None:
    """Request a graceful shutdown of every loop that polls the shared event."""
    _shutdown_event.set()


def is_shutdown_requested() -> bool:
    """Return whether a shutdown has been requested.

    Returns:
        ``True`` once :func:`request_shutdown` has been called.
    """
    return _shutdown_event.is_set()


def wait_for_shutdown(timeout: Optional[float]) -> bool:
    """Sleep for up to ``timeout`` seconds, waking early on shutdown.

    Use instead of ``time.sleep`` inside worker loops.

    Args:
        timeout: Maximum number of seconds to wait; ``None`` waits forever.

    Returns:
        ``True`` if a shutdown was requested (the caller should stop), ``False``
        if the timeout elapsed normally.
    """
    return _shutdown_event.wait(timeout)


def reset_shutdown() -> None:
    """Clear the shutdown request. Intended for tests only."""
    global _signal_count
    _shutdown_event.clear()
    _signal_count = 0


def register_thread(thread: threading.Thread) -> threading.Thread:
    """Track a worker thread so it is joined during graceful shutdown.

    Args:
        thread: The (usually already started) worker thread.

    Returns:
        The same thread, so the call can wrap ``threading.Thread(...)`` inline.
    """
    with _threads_lock:
        _registered_threads.append(thread)
    return thread


def join_registered_threads(timeout_per_thread: float = 30.0) -> List[str]:
    """Join every registered worker thread after a shutdown request.

    Args:
        timeout_per_thread: Seconds to wait for each thread before giving up.

    Returns:
        Names of the threads that were still alive after their timeout.
    """
    with _threads_lock:
        threads = list(_registered_threads)
    stragglers: List[str] = []
    for thread in threads:
        if thread is threading.current_thread():
            continue
        thread.join(timeout=timeout_per_thread)
        if thread.is_alive():
            stragglers.append(thread.name)
    if stragglers:
        logger.warning(f"Threads still running after shutdown timeout: {', '.join(stragglers)}")
    return stragglers


def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
    """Handle SIGINT/SIGTERM: graceful on the first signal, forced on the second.

    Args:
        signum: Signal number received.
        frame: Current stack frame (unused).
    """
    global _signal_count
    _signal_count += 1
    if _signal_count > 1:
        logger.error("Second interrupt received, forcing immediate exit")
        os._exit(130)
    request_shutdown()
    logger.info(
        f"Signal {signum} received, shutting down gracefully "
        "(send it again to force an immediate exit)"
    )
    if _interrupt_main:
        # Unblock a main thread parked in a blocking call (e.g. an HTTP server
        # loop); worker threads still finish their current unit of work.
        raise KeyboardInterrupt


def install_signal_handlers(interrupt_main: bool = False) -> None:
    """Register :func:`signal_handler` for SIGINT and SIGTERM.

    Must be called from the main thread (a Python restriction); calls from
    other threads are ignored with a warning.

    Args:
        interrupt_main: Also raise ``KeyboardInterrupt`` in the main thread on
            the first signal. Needed when the main thread blocks in a call that
            never polls the shutdown event, such as an HTTP server loop.
    """
    global _interrupt_main
    if threading.current_thread() is not threading.main_thread():
        logger.warning("install_signal_handlers() called outside the main thread; skipped")
        return
    _interrupt_main = interrupt_main
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

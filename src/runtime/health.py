"""Liveness of the background-job process, for container healthchecks.

The scheduler role serves no HTTP, so the image's HTTP ``HEALTHCHECK`` cannot
judge it. Instead, every process that runs the background jobs writes a
heartbeat file every :data:`HEARTBEAT_INTERVAL_SECONDS`:

* whether the shared database answers a ``SELECT 1``;
* whether this process is the scheduler ``leader`` or a hot ``standby`` waiting
  for the advisory lock (see :mod:`src.runtime.roles`);
* whether each job loop thread is still alive.

``python -m src.runtime.health`` (the compose healthcheck of the ``scheduler``
service) reads the file and fails when it is missing, unreadable or stale, when
the database does not answer, or when the leader lost a job loop. A standby is
healthy: it is ready to take over.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from src.shutdown import register_thread, wait_for_shutdown

HEARTBEAT_FILE_ENV = "ANISAKYS_HEARTBEAT_FILE"
DEFAULT_HEARTBEAT_FILE = "/tmp/anisakys-heartbeat.json"
HEARTBEAT_INTERVAL_SECONDS = 30
DEFAULT_MAX_AGE_SECONDS = 120

_heartbeat_guard = threading.Lock()
_heartbeat_started = False


def heartbeat_path() -> Path:
    """Where the heartbeat is written and read.

    Returns:
        ``$ANISAKYS_HEARTBEAT_FILE``, else :data:`DEFAULT_HEARTBEAT_FILE`.
    """
    return Path(os.environ.get(HEARTBEAT_FILE_ENV) or DEFAULT_HEARTBEAT_FILE)


def database_answers(engine: Any) -> bool:
    """Whether the shared database answers a trivial query.

    Args:
        engine: SQLAlchemy engine.

    Returns:
        ``False`` on any connection or driver error.
    """
    from sqlalchemy import text

    from src.logger import logger

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:  # pylint: disable=broad-except
        logger.warning(f"Heartbeat: the database does not answer: {e}")
        return False


def collect(
    engine: Any,
    state: str,
    threads: Mapping[str, threading.Thread],
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Build one heartbeat.

    Args:
        engine: Engine of the shared database.
        state: ``leader`` or ``standby``.
        threads: Job loop threads by name.
        now: Epoch seconds (default: now).

    Returns:
        ``{"epoch", "pid", "state", "db_ok", "threads": {name: alive}}``.
    """
    return {
        "epoch": time.time() if now is None else now,
        "pid": os.getpid(),
        "state": state,
        "db_ok": database_answers(engine),
        "threads": {name: thread.is_alive() for name, thread in sorted(threads.items())},
    }


def write_heartbeat(path: Path, payload: Mapping[str, Any]) -> None:
    """Replace the heartbeat file atomically, so a reader never sees half a file.

    Args:
        path: Heartbeat file.
        payload: Heartbeat.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def start_heartbeat(
    engine: Any,
    state_fn: Callable[[], str],
    threads_fn: Callable[[], Mapping[str, threading.Thread]],
    path: Optional[Path] = None,
    interval: float = HEARTBEAT_INTERVAL_SECONDS,
) -> Optional[threading.Thread]:
    """Write a heartbeat now and every ``interval`` seconds until shutdown.

    A second call in the same process is ignored.

    Args:
        engine: Engine of the shared database.
        state_fn: Current scheduler state (``leader`` or ``standby``).
        threads_fn: Current job loop threads by name.
        path: Heartbeat file (default: :func:`heartbeat_path`).
        interval: Seconds between heartbeats.

    Returns:
        The heartbeat thread, or ``None`` when it was already running.
    """
    global _heartbeat_started
    with _heartbeat_guard:
        if _heartbeat_started:
            return None
        _heartbeat_started = True
    target = path or heartbeat_path()

    def beat_until_shutdown() -> None:
        from src.logger import logger

        while True:
            try:
                write_heartbeat(target, collect(engine, state_fn(), threads_fn()))
            except Exception as e:  # pylint: disable=broad-except
                logger.error(f"Heartbeat could not be written to {target}: {e}")
            if wait_for_shutdown(interval):
                return

    thread = threading.Thread(target=beat_until_shutdown, name="health-heartbeat", daemon=True)
    thread.start()
    register_thread(thread)
    return thread


def check(
    path: Path, max_age: float = DEFAULT_MAX_AGE_SECONDS, now: Optional[float] = None
) -> Tuple[bool, str]:
    """Judge a heartbeat file.

    Args:
        path: Heartbeat file.
        max_age: Oldest acceptable heartbeat, in seconds.
        now: Epoch seconds (default: now).

    Returns:
        ``(healthy, reason)``.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, f"no heartbeat yet ({path})"
    except (OSError, ValueError) as e:
        return False, f"unreadable heartbeat ({path}): {e}"
    if not isinstance(payload, dict):
        return False, f"unreadable heartbeat ({path}): not a JSON object"
    try:
        age = (time.time() if now is None else now) - float(payload["epoch"])
    except (KeyError, TypeError, ValueError):
        return False, "heartbeat without a timestamp"
    if age > max_age:
        return False, f"heartbeat is {age:.0f}s old (max {max_age:.0f}s)"
    if not payload.get("db_ok"):
        return False, "the database does not answer"
    state = payload.get("state")
    if state == "standby":
        return True, "standby: waiting for the scheduler leader lock"
    if state != "leader":
        return False, f"unknown scheduler state {state!r}"
    threads = payload.get("threads") or {}
    stopped = sorted(name for name, alive in threads.items() if not alive)
    if stopped:
        return False, f"job loop stopped: {', '.join(stopped)}"
    return True, f"leader: {len(threads)} job loops alive"


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Healthcheck command: print the verdict, exit 0 when healthy.

    Args:
        argv: Arguments (default: ``sys.argv[1:]``).

    Returns:
        ``0`` healthy, ``1`` unhealthy.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.runtime.health",
        description="Healthcheck of the process that runs the background jobs (scheduler role).",
    )
    parser.add_argument(
        "--file",
        default=None,
        help=f"heartbeat file (default: ${HEARTBEAT_FILE_ENV} or {DEFAULT_HEARTBEAT_FILE})",
    )
    parser.add_argument("--max-age", type=float, default=DEFAULT_MAX_AGE_SECONDS)
    args = parser.parse_args(argv)
    healthy, reason = check(Path(args.file) if args.file else heartbeat_path(), args.max_age)
    print(reason)
    return 0 if healthy else 1


def _reset_for_tests() -> None:
    """Allow :func:`start_heartbeat` to run again (tests only)."""
    global _heartbeat_started
    with _heartbeat_guard:
        _heartbeat_started = False


if __name__ == "__main__":
    sys.exit(main())

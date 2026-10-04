"""Process roles: which long-running jobs an Anisakys process owns.

Before phase 0 the API process, the scanner process and the threads-only
process each started their own abuse-reporting loop, takedown monitor,
follow-up worker and GSB re-scan job. With no row locking that meant
duplicate abuse e-mails and a per-process SMTP cap. Now:

========== ============================ ======================================
Role       Serves / runs                Background jobs
========== ============================ ======================================
api        HTTP API only                none
scanner    scanning cycle only          none
scheduler  background jobs only         all of them (one process per database)
all        API or scanner + jobs        all of them (single-process dev, and
                                        the default for backwards compatibility)
========== ============================ ======================================

The role comes from ``--role``, else ``--threads-only`` (= ``scheduler``),
else the ``PROCESS_ROLE`` setting. :func:`start_scheduler_jobs` is the only
place that starts background jobs. It additionally takes a PostgreSQL
advisory lock (``SCHEDULER_LEADER_LOCK``), so a second scheduler started by
mistake waits as a hot standby instead of running every job twice. The lock
lives on a dedicated session; if that session dies the lock is released and a
standby takes over. Row claiming in the reporting pipeline keeps even an
overlap during such a hand-over from sending duplicates.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.config import settings
from src.logger import logger
from src.shutdown import register_thread, wait_for_shutdown

LEADER_LOCK_KEY = "anisakys.scheduler"
STANDBY_RETRY_SECONDS = 60

_start_guard = threading.Lock()
_jobs_started = False
_held_leader_lock: Optional["SchedulerLeaderLock"] = None
# Job loop threads by name and the scheduler state, as the heartbeat reports them.
_job_threads: Dict[str, threading.Thread] = {}
_scheduler_state = "standby"


class ProcessRole(str, Enum):
    """What a process runs."""

    ALL = "all"
    API = "api"
    SCANNER = "scanner"
    SCHEDULER = "scheduler"


class RoleConfigurationError(ValueError):
    """The requested role contradicts other command-line flags."""


def resolve_process_role(
    cli_role: Optional[str] = None,
    threads_only: bool = False,
    start_api: bool = False,
    configured: Optional[str] = None,
) -> ProcessRole:
    """Decide the role of this process.

    Args:
        cli_role: Value of ``--role``, if given.
        threads_only: ``--threads-only`` (legacy alias of ``--role scheduler``).
        start_api: ``--start-api``.
        configured: Role from configuration; defaults to ``PROCESS_ROLE``.

    Returns:
        The role.

    Raises:
        RoleConfigurationError: When the flags contradict each other (e.g.
            ``--threads-only --role api`` or ``--start-api --role scanner``).
    """
    if cli_role:
        role = ProcessRole(cli_role)
        if threads_only and role != ProcessRole.SCHEDULER:
            raise RoleConfigurationError(
                f"--threads-only means --role scheduler; it conflicts with --role {role.value}"
            )
    elif threads_only:
        role = ProcessRole.SCHEDULER
    else:
        role = ProcessRole(configured or settings.PROCESS_ROLE)
    if start_api and role in (ProcessRole.SCANNER, ProcessRole.SCHEDULER):
        raise RoleConfigurationError(f"--start-api cannot run in the '{role.value}' role")
    return role


def runs_background_jobs(role: ProcessRole) -> bool:
    """Whether ``role`` owns the background jobs.

    Args:
        role: Process role.

    Returns:
        ``True`` for ``scheduler`` and ``all``.
    """
    return role in (ProcessRole.ALL, ProcessRole.SCHEDULER)


def serves_api(role: ProcessRole, start_api: bool) -> bool:
    """Whether the process serves the HTTP API.

    Args:
        role: Process role.
        start_api: ``--start-api`` was given.

    Returns:
        ``True`` for ``api``, and for ``all`` with ``--start-api``.
    """
    return role == ProcessRole.API or (role == ProcessRole.ALL and start_api)


def runs_scanner(role: ProcessRole, start_api: bool) -> bool:
    """Whether the process runs the scanning cycle.

    Args:
        role: Process role.
        start_api: ``--start-api`` was given.

    Returns:
        ``True`` for ``scanner``, and for ``all`` without ``--start-api``.
    """
    return role == ProcessRole.SCANNER or (role == ProcessRole.ALL and not start_api)


class SchedulerLeaderLock:
    """Session-level PostgreSQL advisory lock that elects one scheduler."""

    def __init__(self, engine: Engine, key: str = LEADER_LOCK_KEY) -> None:
        """Create an (unacquired) lock.

        Args:
            engine: Engine of the shared database.
            key: Lock name, hashed with ``hashtext``.
        """
        self._engine = engine
        self._key = key
        self._conn: Optional[Connection] = None

    @property
    def held(self) -> bool:
        """Whether this process holds the lock.

        Returns:
            ``True`` after a successful :meth:`try_acquire`.
        """
        return self._conn is not None

    def try_acquire(self) -> bool:
        """Try to become the scheduler, without waiting.

        Returns:
            ``True`` when the lock was acquired (the session stays open).
        """
        if self._conn is not None:
            return True
        conn = self._engine.connect()
        try:
            acquired = bool(
                conn.execute(
                    text("SELECT pg_try_advisory_lock(hashtext(:key))"), {"key": self._key}
                ).scalar()
            )
            conn.commit()
        except Exception:
            conn.close()
            raise
        if not acquired:
            conn.close()
            return False
        self._conn = conn
        return True

    def release(self) -> None:
        """Release the lock and close its session."""
        if self._conn is None:
            return
        try:
            self._conn.execute(
                text("SELECT pg_advisory_unlock(hashtext(:key))"), {"key": self._key}
            )
            self._conn.commit()
        finally:
            self._conn.close()
            self._conn = None


@dataclass
class SchedulerJobs:
    """Objects whose loops the scheduler role runs."""

    report_manager: Any
    takedown_monitor: Any
    db_manager: Any
    auto_analyzer: Optional[Any] = None
    image_scheduler: Optional[Any] = None
    email_scheduler: Optional[Any] = None


def start_scheduler_jobs(
    jobs: SchedulerJobs, role: ProcessRole, leader_lock: Optional[bool] = None
) -> List[str]:
    """Start every background job, if and only if ``role`` owns them.

    This is the single place that starts background jobs; a second call in
    the same process is ignored.

    Args:
        jobs: The job objects.
        role: This process's role.
        leader_lock: Override ``SCHEDULER_LEADER_LOCK``.

    Returns:
        Names of the jobs started (``["scheduler-standby"]`` when another
        process holds the leader lock; empty when the role runs no jobs).
    """
    global _jobs_started, _held_leader_lock
    if not runs_background_jobs(role):
        logger.info(f"Process role '{role.value}': background jobs run in the scheduler role")
        return []
    with _start_guard:
        if _jobs_started:
            logger.warning("Background jobs already started in this process; ignoring")
            return []
        _jobs_started = True

    use_lock = settings.SCHEDULER_LEADER_LOCK if leader_lock is None else leader_lock
    if use_lock:
        lock = SchedulerLeaderLock(jobs.db_manager.engine)
        if not lock.try_acquire():
            logger.warning(
                "Another scheduler holds the leader lock; this process stands by and "
                f"retries every {STANDBY_RETRY_SECONDS}s"
            )
            _spawn("scheduler-standby", lambda: _standby(lock, jobs), job_loop=False)
            _start_heartbeat(jobs)
            return ["scheduler-standby"]
        _held_leader_lock = lock
    names = _launch(jobs)
    _start_heartbeat(jobs)
    return names


def _start_heartbeat(jobs: SchedulerJobs) -> None:
    """Start the liveness heartbeat that the scheduler's container healthcheck reads.

    Args:
        jobs: The job objects (their database engine is checked on every beat).
    """
    # Imported here: `python -m src.runtime.health` must not find it already imported.
    from src.runtime import health

    health.start_heartbeat(
        jobs.db_manager.engine, lambda: _scheduler_state, lambda: dict(_job_threads)
    )


def _standby(lock: SchedulerLeaderLock, jobs: SchedulerJobs) -> None:
    """Wait for the leader lock, then start the jobs.

    Args:
        lock: The unacquired leader lock.
        jobs: The job objects.
    """
    global _held_leader_lock
    while not wait_for_shutdown(STANDBY_RETRY_SECONDS):
        try:
            acquired = lock.try_acquire()
        except Exception as e:
            logger.error(f"Scheduler leader lock check failed: {e}")
            continue
        if acquired:
            _held_leader_lock = lock
            logger.info("Scheduler leader lock acquired; starting background jobs")
            _launch(jobs)
            return


def _spawn(name: str, target: Callable[[], None], job_loop: bool = True) -> None:
    """Start and register a daemon thread.

    Args:
        name: Thread name.
        target: Thread body.
        job_loop: Report the thread's liveness in the heartbeat.
    """
    thread = threading.Thread(target=target, name=name, daemon=True)
    thread.start()
    register_thread(thread)
    if job_loop:
        _job_threads[name] = thread


def _launch(jobs: SchedulerJobs) -> List[str]:
    """Start the job loops.

    Args:
        jobs: The job objects.

    Returns:
        Names of the jobs started.
    """
    global _scheduler_state
    from src.intelligence import AUTO_ANALYSIS_ENABLED
    from src.monitoring import start_gsb_rescan_job

    _scheduler_state = "leader"
    names = ["takedown-monitor", "abuse-reporting", "outbox-dispatch", "followup-worker"]
    _spawn("takedown-monitor", jobs.takedown_monitor.run)
    _spawn("abuse-reporting", jobs.report_manager.report_phishing_sites)
    _spawn("outbox-dispatch", jobs.report_manager.outbox_worker)
    _spawn("followup-worker", jobs.report_manager.followup_worker)

    start_gsb_rescan_job(rescan_interval_hours=12, batch_size=50, max_age_hours=24)
    names.append("gsb-rescan")

    if AUTO_ANALYSIS_ENABLED and jobs.auto_analyzer is not None:
        jobs.auto_analyzer.start_analysis_worker()
        names.append("auto-analysis")
    if jobs.image_scheduler is not None:
        jobs.image_scheduler.start()
        names.append("image-tracking")
    if jobs.email_scheduler is not None:
        jobs.email_scheduler.start()
        names.append("email-monitor")
    if getattr(settings, "CT_MONITOR_ENABLED", False):
        from src.monitoring.ct_monitor import start_ct_monitor_job

        start_ct_monitor_job(
            db_manager=jobs.db_manager,
            stream_url=getattr(settings, "CT_STREAM_URL", None) or None,
            min_score=getattr(settings, "CT_MONITOR_MIN_SCORE", None),
        )
        names.append("ct-monitor")
    if getattr(settings, "FEED_INTEL_ENABLED", False):
        from src.monitoring.feed_intel import start_feed_intel_job

        start_feed_intel_job(db_manager=jobs.db_manager)
        names.append("feed-intel")

    logger.info(f"Background jobs started: {', '.join(names)}")
    return names


def _reset_for_tests() -> None:
    """Forget that jobs were started and drop any held leader lock (tests only)."""
    global _jobs_started, _held_leader_lock, _scheduler_state
    with _start_guard:
        _jobs_started = False
    if _held_leader_lock is not None:
        _held_leader_lock.release()
        _held_leader_lock = None
    _job_threads.clear()
    _scheduler_state = "standby"
    from src.runtime import health

    health._reset_for_tests()

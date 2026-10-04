"""Process roles: exactly one role starts the background jobs.

Before, the API, scanner and threads-only processes each started their own
abuse-reporting loop, takedown monitor, follow-up worker and GSB re-scan, so
reports were sent several times and every process had its own SMTP cap.
"""

from __future__ import annotations

import argparse
import configparser
import shlex
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src import shutdown
from src.runtime import health, roles
from src.runtime.roles import (
    ProcessRole,
    RoleConfigurationError,
    SchedulerJobs,
    SchedulerLeaderLock,
    resolve_process_role,
    runs_background_jobs,
    runs_scanner,
    serves_api,
    start_scheduler_jobs,
)

UNITS = Path(__file__).resolve().parents[2] / "bin"


@pytest.fixture(autouse=True)
def _fresh_runtime(monkeypatch):
    """Reset the runtime; the heartbeat is a mock (tests/runtime/test_health.py covers it)."""
    roles._reset_for_tests()
    shutdown.reset_shutdown()
    heartbeat = MagicMock(return_value=None)
    monkeypatch.setattr(health, "start_heartbeat", heartbeat)
    yield heartbeat
    shutdown.request_shutdown()
    shutdown.join_registered_threads(timeout_per_thread=5)
    shutdown.reset_shutdown()
    roles._reset_for_tests()


def _jobs() -> SchedulerJobs:
    return SchedulerJobs(
        report_manager=MagicMock(),
        takedown_monitor=MagicMock(),
        db_manager=MagicMock(),
        auto_analyzer=MagicMock(),
        image_scheduler=MagicMock(),
        email_scheduler=MagicMock(),
    )


class TestResolution:
    def test_cli_role_wins(self):
        assert resolve_process_role("api", configured="scheduler") == ProcessRole.API

    def test_threads_only_is_the_scheduler_role(self):
        assert resolve_process_role(None, threads_only=True) == ProcessRole.SCHEDULER
        assert resolve_process_role("scheduler", threads_only=True) == ProcessRole.SCHEDULER

    def test_configured_role_is_the_fallback(self):
        assert resolve_process_role(configured="scanner") == ProcessRole.SCANNER
        assert resolve_process_role() == ProcessRole.ALL

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"cli_role": "api", "threads_only": True},
            {"cli_role": "scanner", "start_api": True},
            {"cli_role": "scheduler", "start_api": True},
        ],
    )
    def test_contradictions_are_rejected(self, kwargs):
        with pytest.raises(RoleConfigurationError):
            resolve_process_role(**kwargs)

    def test_only_scheduler_and_all_run_jobs(self):
        assert [r for r in ProcessRole if runs_background_jobs(r)] == [
            ProcessRole.ALL,
            ProcessRole.SCHEDULER,
        ]
        assert serves_api(ProcessRole.API, False) and serves_api(ProcessRole.ALL, True)
        assert not serves_api(ProcessRole.ALL, False)
        assert runs_scanner(ProcessRole.SCANNER, False) and runs_scanner(ProcessRole.ALL, False)
        assert not runs_scanner(ProcessRole.API, True)


class TestStartingJobs:
    @pytest.mark.parametrize("role", [ProcessRole.API, ProcessRole.SCANNER])
    def test_api_and_scanner_roles_start_nothing(self, role):
        jobs = _jobs()
        with patch("src.monitoring.start_gsb_rescan_job") as gsb:
            assert start_scheduler_jobs(jobs, role, leader_lock=False) == []

        gsb.assert_not_called()
        jobs.report_manager.report_phishing_sites.assert_not_called()
        jobs.takedown_monitor.run.assert_not_called()
        jobs.email_scheduler.start.assert_not_called()

    def test_the_leader_reports_its_job_loops_to_the_heartbeat(self, _fresh_runtime):
        jobs = _jobs()
        with (
            patch("src.monitoring.start_gsb_rescan_job"),
            patch("src.intelligence.AUTO_ANALYSIS_ENABLED", False),
        ):
            start_scheduler_jobs(jobs, ProcessRole.SCHEDULER, leader_lock=False)

        _fresh_runtime.assert_called_once()
        engine, state, threads = _fresh_runtime.call_args.args
        assert engine is jobs.db_manager.engine
        assert state() == "leader"
        assert sorted(threads()) == [
            "abuse-reporting",
            "followup-worker",
            "outbox-dispatch",
            "takedown-monitor",
        ]

    def test_a_standby_reports_standby_without_job_loops(self, _fresh_runtime):
        jobs = _jobs()
        with patch.object(SchedulerLeaderLock, "try_acquire", return_value=False):
            names = start_scheduler_jobs(jobs, ProcessRole.SCHEDULER, leader_lock=True)

        assert names == ["scheduler-standby"]
        _, state, threads = _fresh_runtime.call_args.args
        assert state() == "standby" and threads() == {}

    def test_scheduler_role_starts_every_job_once(self, monkeypatch):
        monkeypatch.setattr("src.config.settings.CT_MONITOR_ENABLED", True)
        monkeypatch.setattr("src.config.settings.FEED_INTEL_ENABLED", True)
        jobs = _jobs()
        with (
            patch("src.monitoring.start_gsb_rescan_job") as gsb,
            patch("src.intelligence.AUTO_ANALYSIS_ENABLED", True),
            patch("src.monitoring.ct_monitor.start_ct_monitor_job") as ct,
            patch("src.monitoring.feed_intel.start_feed_intel_job") as feed,
        ):
            names = start_scheduler_jobs(jobs, ProcessRole.SCHEDULER, leader_lock=False)
            again = start_scheduler_jobs(jobs, ProcessRole.SCHEDULER, leader_lock=False)
        shutdown.join_registered_threads(timeout_per_thread=5)

        assert names == [
            "takedown-monitor",
            "abuse-reporting",
            "outbox-dispatch",
            "followup-worker",
            "gsb-rescan",
            "auto-analysis",
            "image-tracking",
            "email-monitor",
            "ct-monitor",
            "feed-intel",
        ]
        assert again == []
        gsb.assert_called_once()
        ct.assert_called_once()
        feed.assert_called_once()
        jobs.report_manager.report_phishing_sites.assert_called_once()
        jobs.report_manager.outbox_worker.assert_called_once()
        jobs.report_manager.followup_worker.assert_called_once()
        jobs.takedown_monitor.run.assert_called_once()
        jobs.auto_analyzer.start_analysis_worker.assert_called_once()
        jobs.image_scheduler.start.assert_called_once()
        jobs.email_scheduler.start.assert_called_once()


class TestLeaderLock:
    def test_only_one_scheduler_holds_the_lock(self, create_test_database):
        engine_a = create_engine(create_test_database)
        engine_b = create_engine(create_test_database)
        first = SchedulerLeaderLock(engine_a, key="anisakys.test.leader")
        second = SchedulerLeaderLock(engine_b, key="anisakys.test.leader")
        try:
            assert first.try_acquire() is True
            assert second.try_acquire() is False
            first.release()
            assert second.try_acquire() is True
        finally:
            first.release()
            second.release()
            engine_a.dispose()
            engine_b.dispose()

    def test_second_scheduler_stands_by_instead_of_running_jobs(self, create_test_database):
        holder_engine = create_engine(create_test_database)
        holder = SchedulerLeaderLock(holder_engine)
        jobs = _jobs()
        jobs.db_manager = SimpleNamespace(engine=create_engine(create_test_database))
        try:
            assert holder.try_acquire()
            with patch("src.monitoring.start_gsb_rescan_job") as gsb:
                names = start_scheduler_jobs(jobs, ProcessRole.SCHEDULER, leader_lock=True)
        finally:
            shutdown.request_shutdown()
            shutdown.join_registered_threads(timeout_per_thread=5)
            holder.release()
            holder_engine.dispose()
            jobs.db_manager.engine.dispose()

        assert names == ["scheduler-standby"]
        gsb.assert_not_called()
        jobs.report_manager.report_phishing_sites.assert_not_called()


class TestEngineAndUnits:
    def _args(self, **overrides) -> argparse.Namespace:
        values = dict(
            timeout=5,
            log_level="INFO",
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            multi_api_scan=True,
            url=None,
            abuse_email=None,
            attachment=None,
            attachments_folder=None,
            cc=None,
            role=None,
        )
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_engine_resolves_and_applies_its_role(self):
        scheduler_engine = main.Engine(self._args(threads_only=True))
        api_engine = main.Engine(self._args(role="api"))

        assert scheduler_engine.role == ProcessRole.SCHEDULER
        assert api_engine.role == ProcessRole.API and api_engine.args.start_api is True
        with patch("src.runtime.roles._launch") as launch:
            assert api_engine._start_background_jobs() == []
        launch.assert_not_called()

    def test_only_the_threads_unit_runs_the_scheduler_role(self):
        roles_by_unit = {}
        for unit in ("anisakys-api", "anisakys-scanner", "anisakys-threads"):
            parser = configparser.ConfigParser(strict=False, interpolation=None)
            parser.read(UNITS / f"{unit}.service")
            argv = shlex.split(parser["Service"]["ExecStart"])
            roles_by_unit[unit] = argv[argv.index("--role") + 1]

        assert roles_by_unit == {
            "anisakys-api": "api",
            "anisakys-scanner": "scanner",
            "anisakys-threads": "scheduler",
        }

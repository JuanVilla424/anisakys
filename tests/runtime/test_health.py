"""Scheduler healthcheck: the heartbeat the background-job process writes, and its judge."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine

from src import shutdown
from src.runtime import health

NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def _fresh():
    health._reset_for_tests()
    shutdown.reset_shutdown()
    yield
    shutdown.request_shutdown()
    shutdown.join_registered_threads(timeout_per_thread=5)
    shutdown.reset_shutdown()
    health._reset_for_tests()


def _write(path: Path, **overrides: Any) -> Path:
    payload: Dict[str, Any] = {
        "epoch": NOW,
        "pid": 1,
        "state": "leader",
        "db_ok": True,
        "threads": {"abuse-reporting": True, "takedown-monitor": True},
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestCheck:
    def test_fresh_leader_with_live_loops_is_healthy(self, tmp_path):
        healthy, reason = health.check(_write(tmp_path / "hb.json"), now=NOW + 10)

        assert healthy and reason == "leader: 2 job loops alive"

    def test_a_standby_is_healthy(self, tmp_path):
        heartbeat = _write(tmp_path / "hb.json", state="standby", threads={})

        healthy, reason = health.check(heartbeat, now=NOW)

        assert healthy and reason == "standby: waiting for the scheduler leader lock"

    @pytest.mark.parametrize(
        "overrides, now, expected",
        [
            ({}, NOW + 121, "heartbeat is 121s old (max 120s)"),
            ({"db_ok": False}, NOW, "the database does not answer"),
            (
                {"threads": {"abuse-reporting": True, "outbox-dispatch": False}},
                NOW,
                "job loop stopped: outbox-dispatch",
            ),
            ({"state": "zombie"}, NOW, "unknown scheduler state 'zombie'"),
            ({"epoch": "soon"}, NOW, "heartbeat without a timestamp"),
        ],
    )
    def test_unhealthy_heartbeats(self, tmp_path, overrides, now, expected):
        healthy, reason = health.check(_write(tmp_path / "hb.json", **overrides), now=now)

        assert not healthy and reason == expected

    def test_missing_or_unreadable_files_are_unhealthy(self, tmp_path):
        healthy, reason = health.check(tmp_path / "absent.json")
        assert not healthy and reason.startswith("no heartbeat yet")

        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        healthy, reason = health.check(broken)
        assert not healthy and reason.startswith("unreadable heartbeat")

        broken.write_text("[1, 2]", encoding="utf-8")
        assert health.check(broken) == (
            False,
            f"unreadable heartbeat ({broken}): not a JSON object",
        )


class TestHeartbeat:
    def test_collect_reports_the_database_and_each_loop(self):
        never_started = threading.Thread(target=lambda: None)

        payload = health.collect(
            create_engine("sqlite://"), "leader", {"outbox-dispatch": never_started}, now=NOW
        )

        assert payload["epoch"] == NOW and payload["state"] == "leader"
        assert payload["db_ok"] is True
        assert payload["threads"] == {"outbox-dispatch": False}

    def test_a_database_error_is_reported_not_raised(self):
        engine = MagicMock()
        engine.connect.side_effect = OSError("connection refused")

        assert health.database_answers(engine) is False

    def test_writes_are_atomic_and_leave_no_temp_files(self, tmp_path):
        target = tmp_path / "run" / "hb.json"

        health.write_heartbeat(target, {"epoch": NOW})
        health.write_heartbeat(target, {"epoch": NOW + 1})

        assert json.loads(target.read_text(encoding="utf-8"))["epoch"] == NOW + 1
        assert [p.name for p in target.parent.iterdir()] == ["hb.json"]

    def test_a_failed_write_removes_its_temp_file(self, tmp_path):
        with pytest.raises(TypeError):
            health.write_heartbeat(tmp_path / "hb.json", {"epoch": object()})

        assert list(tmp_path.iterdir()) == []

    def test_the_thread_beats_until_shutdown_and_starts_once(self, tmp_path):
        target = tmp_path / "hb.json"
        engine = create_engine("sqlite://")

        thread = health.start_heartbeat(engine, lambda: "standby", dict, path=target, interval=0.05)
        again = health.start_heartbeat(engine, lambda: "standby", dict, path=target)
        deadline = time.monotonic() + 5
        while not target.exists() and time.monotonic() < deadline:
            time.sleep(0.02)

        assert thread is not None and again is None
        assert health.check(target) == (True, "standby: waiting for the scheduler leader lock")
        shutdown.request_shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive()

    def test_the_path_comes_from_the_environment(self, monkeypatch, tmp_path):
        monkeypatch.setenv(health.HEARTBEAT_FILE_ENV, str(tmp_path / "x.json"))
        assert health.heartbeat_path() == tmp_path / "x.json"

        monkeypatch.delenv(health.HEARTBEAT_FILE_ENV)
        assert str(health.heartbeat_path()) == health.DEFAULT_HEARTBEAT_FILE


class TestCommand:
    def test_exit_code_and_reason(self, tmp_path, capsys):
        fresh = _write(tmp_path / "hb.json", epoch=time.time())

        assert health.main(["--file", str(fresh)]) == 0
        assert capsys.readouterr().out.strip() == "leader: 2 job loops alive"
        assert health.main(["--file", str(tmp_path / "absent.json")]) == 1
        assert "no heartbeat yet" in capsys.readouterr().out

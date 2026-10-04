"""Tests for the process-wide logging configuration.

Regressions covered:

* ``src/logger.py`` pinned the ``app`` logger to DEBUG with
  ``propagate=False``, so ``LOG_LEVEL`` was ignored;
* a plain FileHandler and a JSON RotatingFileHandler wrote the same file
  from three processes, which corrupts rotation;
* nothing prevented credentials from reaching the logs.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterator, List

import pytest

from src.observability import structured_logger as sl

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolated_logging(monkeypatch) -> Iterator[None]:
    """Start every test unconfigured and restore the root logger afterwards."""
    for name in (
        "LOG_LEVEL",
        "LOG_DIR",
        "LOG_PROCESS_NAME",
        "LOG_MAX_BYTES",
        "LOG_BACKUP_COUNT",
        "LOG_CONSOLE_FORMAT",
    ):
        monkeypatch.delenv(name, raising=False)
    # Settings loaded from .env.test must not leak into these tests.
    monkeypatch.setattr(sl, "_setting", lambda name: os.environ.get(name))
    root = logging.getLogger()
    level = root.level
    sl.reset_logging()
    yield
    sl.reset_logging()
    root.setLevel(level)
    sl.configure_logging()  # back to the suite's bootstrap configuration


def active_config() -> sl.LoggingConfig:
    """The current logging configuration (fails the test if there is none)."""
    config = sl.current_logging_config()
    assert config is not None, "logging is not configured"
    return config


def active_log_file() -> str:
    """Path of the current log file (fails the test if logging is console-only)."""
    log_file = active_config().log_file
    assert log_file is not None, "no log file configured"
    return log_file


def managed() -> List[logging.Handler]:
    """Handlers installed by configure_logging on the root logger."""
    return [h for h in logging.getLogger().handlers if getattr(h, "_anisakys_managed", False)]


def read_json_lines(path: Path) -> List[dict]:
    """Parse a JSON-lines log file."""
    for handler in managed():
        handler.flush()
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class TestLevel:
    def test_level_comes_from_log_level(self, monkeypatch, tmp_path):
        """Regression: LOG_LEVEL used to be ignored (app logger pinned to DEBUG)."""
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        log_file = tmp_path / "app.log"

        sl.configure_logging(log_file=str(log_file))
        app = logging.getLogger("app")
        app.info("dropped")
        app.warning("kept")

        assert logging.getLogger().level == logging.WARNING
        assert app.getEffectiveLevel() == logging.WARNING
        assert [line["message"] for line in read_json_lines(log_file)] == ["kept"]

    def test_default_level_is_info(self):
        sl.configure_logging(log_dir="")

        assert logging.getLogger().level == logging.INFO

    def test_explicit_level_wins_over_environment(self, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "ERROR")

        sl.configure_logging("debug", log_dir="")

        assert logging.getLogger().level == logging.DEBUG

    def test_invalid_level_fails_loudly(self):
        with pytest.raises(ValueError, match="Invalid log level"):
            sl.configure_logging("VERBOSE", log_dir="")

    def test_app_logger_defers_to_root(self):
        """The app logger must not carry its own handlers or level."""
        from src.logger import logger

        assert logger.name == "app"
        assert logger.handlers == []
        assert logger.propagate is True
        assert logger.level == logging.NOTSET


class TestHandlers:
    def test_single_json_rotating_file_and_console(self, tmp_path):
        log_file = tmp_path / "one.log"

        sl.configure_logging(log_file=str(log_file), process_name="api")
        sl.set_correlation_id("cid-123")
        logging.getLogger("app").info("hello")

        handlers = managed()
        file_handlers = [h for h in handlers if isinstance(h, logging.FileHandler)]
        assert len(handlers) == 2
        assert len(file_handlers) == 1 and isinstance(file_handlers[0], RotatingFileHandler)
        (line,) = read_json_lines(log_file)
        assert line["message"] == "hello"
        assert line["correlation_id"] == "cid-123"
        assert line["process"] == "api"
        assert line["pid"] == os.getpid()

    def test_configuration_is_idempotent_and_keeps_foreign_handlers(self, tmp_path):
        foreign = logging.NullHandler()
        logging.getLogger().addHandler(foreign)
        try:
            sl.configure_logging(log_dir=str(tmp_path), process_name="api")
            first = managed()
            sl.configure_logging(log_dir=str(tmp_path), process_name="api")

            assert managed() == first
            assert foreign in logging.getLogger().handlers
        finally:
            logging.getLogger().removeHandler(foreign)

    def test_file_name_is_per_role_and_pid(self, tmp_path):
        sl.configure_logging(log_dir=str(tmp_path), process_name="threads")

        assert Path(active_log_file()) == tmp_path / f"anisakys-threads-{os.getpid()}.log"

    def test_forked_process_reconfigures_to_its_own_file(self, tmp_path, monkeypatch):
        sl.configure_logging(log_dir=str(tmp_path), process_name="api")
        parent_file = active_log_file()

        monkeypatch.setattr(sl.os, "getpid", lambda: 999_999)
        sl.configure_logging(log_dir=str(tmp_path), process_name="api")

        assert active_log_file() != parent_file
        assert active_log_file().endswith("anisakys-api-999999.log")

    def test_empty_log_dir_means_console_only(self):
        sl.configure_logging(log_dir="")

        assert [type(h) for h in managed()] == [logging.StreamHandler]

    def test_file_rotates(self, tmp_path):
        log_file = tmp_path / "rot.log"
        sl.configure_logging(log_file=str(log_file), max_bytes=400, backup_count=2)

        for i in range(30):
            logging.getLogger("app").info("line %d %s", i, "x" * 40)

        assert (tmp_path / "rot.log.1").exists()
        assert not (tmp_path / "rot.log.3").exists()

    def test_concurrent_processes_never_share_a_file(self, tmp_path):
        """Regression: three processes used to append to (and rotate) one file."""
        env = {
            **os.environ,
            "LOG_DIR": str(tmp_path),
            "LOG_PROCESS_NAME": "api",
            "ANISAKYS_ENV_FILE": str(PROJECT_ROOT / ".env.test"),
        }
        code = (
            "import sys; sys.path.insert(0, '.'); "
            "from src.logger import logger; logger.info('from %s', __import__('os').getpid())"
        )
        procs = [
            subprocess.Popen([sys.executable, "-c", code], cwd=PROJECT_ROOT, env=env)
            for _ in range(3)
        ]
        assert all(p.wait(timeout=60) == 0 for p in procs)

        files = sorted(tmp_path.glob("anisakys-api-*.log"))
        assert len(files) == 3
        for path in files:
            pid = path.stem.rsplit("-", 1)[1]
            (line,) = [json.loads(raw) for raw in path.read_text().splitlines()]
            assert line["message"] == f"from {pid}"


class TestProcessName:
    @pytest.mark.parametrize(
        "argv, expected",
        [
            (["anisakys.py", "--start-api"], "api"),
            (["anisakys.py", "--threads-only"], "threads"),
            (["anisakys.py", "--start-screenshot-worker"], "screenshot-worker"),
            (["anisakys.py"], "engine"),
            (["/venv/bin/gunicorn", "app:app"], "api"),
            (["/venv/bin/alembic", "upgrade", "head"], "alembic"),
        ],
    )
    def test_role_is_inferred_from_command_line(self, argv, expected):
        assert sl.default_process_name(argv) == expected

    def test_log_process_name_overrides_inference(self, monkeypatch):
        monkeypatch.setenv("LOG_PROCESS_NAME", "custom")

        sl.configure_logging(log_dir="")

        assert active_config().process_name == "custom"


class TestRedaction:
    @pytest.mark.parametrize(
        "raw, secret",
        [
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload", "eyJhbGciOiJIUzI1NiJ9"),
            ("headers={'Authorization': 'Basic dXNlcjpwYXNz'}", "dXNlcjpwYXNz"),
            ("GET https://vt.test/api?api_key=abc123def&url=x", "abc123def"),
            ("GET https://gsb.test/v4?key=AIzaSyXYZ&x=1", "AIzaSyXYZ"),
            ("refreshing token=tok_live_42", "tok_live_42"),
            ('{"password": "hunter2"}', "hunter2"),
            ("SMTP_PASS=s3cr3t-value", "s3cr3t-value"),
            ("X-API-Key: deadbeefcafe", "deadbeefcafe"),
            ("connecting to postgresql://anisakys:pw0rd@db:5432/x", "pw0rd"),
        ],
    )
    def test_secrets_are_masked(self, raw, secret):
        redacted = sl.redact_secrets(raw)

        assert secret not in redacted
        assert sl.REDACTED in redacted

    @pytest.mark.parametrize(
        "text", ["keywords: paypal,bank", "bypass=true", "max_tokens=5", "token bucket: 5"]
    )
    def test_ordinary_text_is_untouched(self, text):
        assert sl.redact_secrets(text) == text

    def test_redaction_is_idempotent(self):
        once = sl.redact_secrets("api_key=abc password=def")

        assert sl.redact_secrets(once) == once

    def test_secrets_never_reach_console_or_file(self, tmp_path, capsys):
        log_file = tmp_path / "secret.log"
        sl.configure_logging(log_file=str(log_file))
        app = logging.getLogger("app")

        app.info("calling %s", "https://api.test/?api_key=SECRET1")
        try:
            raise RuntimeError("login failed with password=SECRET2")
        except RuntimeError:
            app.exception("boom")
        sl.log_with_context(app, logging.INFO, "args", api_key="SECRET3", url="u?token=SECRET4")

        written = log_file.read_text() + capsys.readouterr().out
        for secret in ("SECRET1", "SECRET2", "SECRET3", "SECRET4"):
            assert secret not in written
        context = read_json_lines(log_file)[-1]["context"]
        assert context["api_key"] == sl.REDACTED

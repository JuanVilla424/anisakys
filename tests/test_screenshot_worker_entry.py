"""
The sandboxed screenshot worker must start without the app Settings/.env,
so its process never holds DB/SMTP/API-key secrets.
"""

import subprocess
import sys
from pathlib import Path

import src.screenshot_worker as screenshot_worker

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_worker_import_does_not_load_settings_or_database():
    """Importing the worker in a clean interpreter must not pull in config/DB modules."""
    code = (
        "import sys; import src.screenshot_worker; "
        "print(','.join(m for m in ('src.config', 'src.database.manager', 'src.main') "
        "if m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""


def test_main_reads_configuration_from_environment(monkeypatch, tmp_path):
    """main() takes socket, screenshots dir and timeout from the unit environment only."""
    calls = {}

    def fake_run_worker(socket_path, screenshots_dir, timeout=30):
        calls.update(socket_path=socket_path, screenshots_dir=screenshots_dir, timeout=timeout)

    monkeypatch.setattr(screenshot_worker, "run_worker", fake_run_worker)
    monkeypatch.setenv("SCREENSHOT_WORKER_SOCKET", str(tmp_path / "run" / "worker.sock"))
    monkeypatch.setenv("SCREENSHOTS_DIR", str(tmp_path / "shots"))
    monkeypatch.setenv("TIMEOUT", "12")

    screenshot_worker.main()

    assert calls == {
        "socket_path": str(tmp_path / "run" / "worker.sock"),
        "screenshots_dir": str(tmp_path / "shots"),
        "timeout": 12,
    }
    assert (tmp_path / "run").is_dir()

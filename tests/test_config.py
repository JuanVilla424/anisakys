"""
Tests for src/config.py -- Settings defaults, notably the unified
SCREENSHOTS_DIR fallback that replaced three previously-divergent
hardcoded paths (/opt/anisakys/... in phishing_api.py and main.py,
tempfile-based in ScreenshotService itself).
"""

import tempfile
from pathlib import Path

from src.config import (
    settings,
    _default_screenshots_dir,
    DEFAULT_SCREENSHOT_WORKER_SOCKET,
)


class TestDefaultScreenshotsDir:
    """The computed fallback used when SCREENSHOTS_DIR isn't configured."""

    def test_is_portable_tempdir_based(self):
        """Should never assume a specific deployment layout like /opt/anisakys."""
        result = _default_screenshots_dir()
        assert result == str(Path(tempfile.gettempdir()) / "anisakys_screenshots")

    def test_does_not_hardcode_opt_anisakys(self):
        """Regression guard for the original hardcoded-path smell."""
        assert "/opt/anisakys" not in _default_screenshots_dir()


class TestSettingsScreenshotsDir:
    """SCREENSHOTS_DIR itself, as seen on the real settings singleton."""

    def test_is_never_none(self):
        """Unlike before, this field always resolves to a real path."""
        assert settings.SCREENSHOTS_DIR is not None
        assert settings.SCREENSHOTS_DIR != ""

    def test_env_override_still_wins_over_default(self):
        """.env.test sets an explicit value -- it must take priority over
        the computed default, confirming Field(default_factory=...) didn't
        change override precedence."""
        assert settings.SCREENSHOTS_DIR == "./.test-screenshots"


class TestDefaultScreenshotWorkerSocket:
    """Fallback bind path for the sandboxed screenshot worker."""

    def test_is_portable_tempdir_based(self):
        assert DEFAULT_SCREENSHOT_WORKER_SOCKET == str(
            Path(tempfile.gettempdir()) / "anisakys" / "screenshot-worker.sock"
        )

    def test_does_not_hardcode_run_anisakys(self):
        """Regression guard: the original literal assumed /run/anisakys
        existed and was writable, a deployment-specific assumption."""
        assert "/run/anisakys" not in DEFAULT_SCREENSHOT_WORKER_SOCKET

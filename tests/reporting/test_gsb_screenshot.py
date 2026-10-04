"""The screenshot must reach the Google Safe Browsing submission.

abuse_manager read ``screenshot_info.get("base64")``, a key no screenshot
service returns (they return ``screenshot_path``), so GSB never got one.
"""

from __future__ import annotations

import base64

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.reporting.abuse_manager import encode_screenshot_for_gsb

PNG = b"\x89PNG\r\n\x1a\nfake-image-bytes"


def fake_capture(path) -> dict:
    """Exactly the keys ScreenshotService/SandboxedScreenshotClient return."""
    return {
        "success": True,
        "screenshot_path": str(path),
        "filename": path.name,
        "size_bytes": len(PNG),
        "page_info": {"title": "Login"},
        "engine": "playwright",
    }


def test_reads_and_encodes_the_screenshot_file(tmp_path):
    shot = tmp_path / "shot.png"
    shot.write_bytes(PNG)

    encoded = encode_screenshot_for_gsb(fake_capture(shot), max_bytes=1024)

    assert base64.b64decode(encoded) == PNG


def test_oversized_screenshot_is_not_submitted(tmp_path):
    shot = tmp_path / "shot.png"
    shot.write_bytes(PNG)

    assert encode_screenshot_for_gsb(fake_capture(shot), max_bytes=4) is None


def test_failed_or_missing_capture_yields_none(tmp_path):
    assert encode_screenshot_for_gsb(None) is None
    assert encode_screenshot_for_gsb({"success": False, "error": "timeout"}) is None
    assert encode_screenshot_for_gsb(fake_capture(tmp_path / "gone.png")) is None

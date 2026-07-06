"""
Sandboxed screenshot worker -- runs as a separate, low-privilege OS process
(bin/anisakys-screenshot-worker.service, User=anisakys-shot with no access
to /opt/anisakys/.env) exposing ScreenshotService over a Unix-socket-only
HTTP endpoint. Contains the render process itself: even if a malicious
phishing page manages to escape the browser sandbox, it inherits only this
worker's minimal, secret-free, network-and-resource-restricted privileges
instead of the main API/reporting process's full access to DB/SMTP/API-key
secrets.

Unix socket, not loopback TCP: the unit's IPAddressDeny= (egress defense for
the sandboxed browser) blocks AF_INET/AF_INET6 traffic on 127.0.0.0/8 in both
directions, which silently hangs a loopback-TCP listener's own inbound
connections too (confirmed empirically, not assumed -- see
src/screenshot_client.py's module docstring). AF_UNIX isn't IP traffic, so
it's unaffected.

ScreenshotService itself (src/screenshot_service.py) is untouched -- its
existing SSRF guards run exactly as before; this module only changes WHERE
(which process/privilege boundary) that code executes.
"""

import base64
import logging
import os
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.serving import run_simple

from src.screenshot_service import ScreenshotService

logger = logging.getLogger(__name__)


def create_worker_app(screenshots_dir: str, timeout: int = 30) -> Flask:
    app = Flask(__name__)
    service = ScreenshotService(screenshots_dir, timeout=timeout)

    @app.route("/capture", methods=["POST"])
    def capture():
        data = request.get_json(silent=True) or {}
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "error": "url required"}), 400

        result = service.capture_screenshot(url, use_async=data.get("use_async", True))
        if not result or not result.get("success"):
            return jsonify(result or {"success": False, "error": "capture_failed"})

        path = Path(result["screenshot_path"])
        try:
            screenshot_b64 = base64.b64encode(path.read_bytes()).decode()
        finally:
            # The worker keeps nothing persistent between requests -- bytes
            # travel back over the response, not a shared filesystem path.
            path.unlink(missing_ok=True)

        return jsonify(
            {
                "success": True,
                "screenshot_b64": screenshot_b64,
                "engine": result.get("engine"),
                "page_info": result.get("page_info", {}),
            }
        )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "engine": service.preferred_engine})

    return app


def run_worker(socket_path: str, screenshots_dir: str, timeout: int = 30):
    """Serve create_worker_app() over a Unix domain socket at socket_path
    (removing any stale socket file left by a previous run first). Port is
    unused for AF_UNIX -- run_simple's signature requires one, but it's
    ignored by Werkzeug once it detects the "unix://" host prefix."""
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    app = create_worker_app(screenshots_dir, timeout=timeout)
    run_simple(f"unix://{socket_path}", 0, app)

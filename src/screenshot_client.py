"""
Client for the sandboxed screenshot worker + config-gated factory.

The screenshot-rendering worker executes attacker-controlled HTML/JS/redirects
from real phishing sites. `assess_url_target()`/`safe_get_with_redirects()`
already refuse to let it *navigate to* a non-public destination (see
src/dns/network_utils.py) -- this client is the other half: it lets the
actual render happen in a separate, sandboxed OS process/user (see
bin/anisakys-screenshot-worker.service) instead of in-process with the
API/reporting code that holds every secret in .env.

Transport is a Unix domain socket, not loopback TCP -- confirmed empirically
(not assumed) that it has to be: the worker's own systemd unit sets
IPAddressDeny= on 127.0.0.0/8 (egress defense for the sandboxed browser), and
that directive blocks ALL AF_INET/AF_INET6 traffic touching those ranges in
BOTH directions -- including the TCP handshake's own response packets for
inbound connections to a loopback-bound listening socket, which silently hung
every request in testing. AF_UNIX sockets aren't IP traffic at all, so
IPAddressAllow=/IPAddressDeny= don't apply to them -- confirmed by testing
the exact same directive set with a Unix socket and getting a real screenshot
back over it. Uses stdlib http.client + socket (no new dependency, and no
reliance on urllib3/requests-unixsocket internals that could break across
version bumps) since the need here is narrow: one POST, JSON in, JSON out.

ScreenshotServiceClient exposes the identical capture_screenshot() signature
and return shape as ScreenshotService (src/screenshot_service.py) so the
three existing call sites need no changes beyond how the object is
constructed -- get_screenshot_service() is that one construction point.
"""

import base64
import http.client
import json
import logging
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.config import settings

logger = logging.getLogger(__name__)


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """http.client.HTTPConnection over an AF_UNIX socket instead of TCP.
    "localhost" is a placeholder for the Host header only -- connect() never
    resolves or uses it, it dials socket_path directly."""

    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class ScreenshotServiceClient:
    """Same public interface as ScreenshotService, backed by a call to the
    sandboxed worker over a Unix socket instead of an in-process browser
    launch."""

    def __init__(self, screenshots_dir: str, worker_socket: str, timeout: int = 30):
        self.screenshots_dir = Path(screenshots_dir)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.worker_socket = worker_socket
        self.timeout = timeout

    def capture_screenshot(
        self, url: str, filename: str = None, use_async: bool = True
    ) -> Optional[Dict[str, Any]]:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(url).netloc.replace(".", "_")
            filename = f"phishing_{domain}_{timestamp}.png"

        try:
            # Headroom over the worker's own internal timeout so the worker's
            # error response wins over a client-side cutoff.
            conn = _UnixSocketHTTPConnection(self.worker_socket, timeout=self.timeout + 20)
            conn.request(
                "POST",
                "/capture",
                body=json.dumps({"url": url, "use_async": use_async}),
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            data = json.loads(resp.read())
            conn.close()
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Screenshot worker unreachable at {self.worker_socket}: {e}")
            return {"success": False, "error": "worker_unreachable", "engine": "sandboxed"}

        if not data.get("success"):
            return data  # already shaped like {"success": False, "error":, "engine":}

        screenshot_path = self.screenshots_dir / filename
        screenshot_path.write_bytes(base64.b64decode(data["screenshot_b64"]))
        return {
            "success": True,
            "screenshot_path": str(screenshot_path),
            "filename": filename,
            "size_bytes": screenshot_path.stat().st_size,
            "page_info": data.get("page_info", {}),
            "engine": data.get("engine"),
        }


def get_screenshot_service(screenshots_dir: str, timeout: int = 30):
    """Single construction point for the 3 existing call sites. Returns the
    sandboxed client when SCREENSHOT_WORKER_SOCKET is configured; otherwise
    returns today's in-process ScreenshotService, unchanged -- local dev/demo
    stays exactly as it is today unless explicitly opted in."""
    worker_socket = getattr(settings, "SCREENSHOT_WORKER_SOCKET", None)
    if worker_socket:
        return ScreenshotServiceClient(screenshots_dir, worker_socket, timeout=timeout)
    from src.screenshot_service import ScreenshotService

    return ScreenshotService(screenshots_dir, timeout=timeout)

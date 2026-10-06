"""Healthcheck of the capture worker: GET /health over its Unix socket.

Runs inside the capture container (``HEALTHCHECK`` in Dockerfile.capture);
exits 0 on HTTP 200, non-zero on anything else.
"""

from __future__ import annotations

import http.client
import os
import socket
import sys


def main() -> int:
    socket_path = os.environ.get("CAPTURE_WORKER_SOCKET") or "/tmp/anisakys/capture-worker.sock"

    class UnixConnection(http.client.HTTPConnection):
        def connect(self) -> None:  # noqa: D102 (see http.client)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(socket_path)

    try:
        conn = UnixConnection("localhost", timeout=4)
        conn.request("GET", "/health")
        response = conn.getresponse()
        conn.close()
    except OSError:
        return 1
    return 0 if response.status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())

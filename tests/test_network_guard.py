"""Tests for the test-suite network guard (tests/conftest.py).

Tests that are not marked ``network`` must behave as if the machine were
offline, while loopback traffic (local servers, the test database) works.
"""

from __future__ import annotations

import socket
import threading

import pytest
import requests


def test_dns_lookups_of_remote_hosts_are_blocked():
    with pytest.raises(socket.gaierror, match="blocked in tests"):
        socket.getaddrinfo("example.com", 443)


def test_connections_to_remote_addresses_are_blocked():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError, match="pytest.mark.network"):
            sock.connect(("93.184.215.14", 80))


def test_udp_datagrams_to_remote_addresses_are_blocked():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(OSError, match="pytest.mark.network"):
            sock.sendto(b"\x00", ("8.8.8.8", 53))


def test_http_clients_fail_fast_offline():
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get("https://example.com", timeout=5)


def test_loopback_traffic_is_allowed():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        accepted = []
        thread = threading.Thread(target=lambda: accepted.append(server.accept()[0]))
        thread.start()
        with socket.create_connection(("localhost", port), timeout=5):
            thread.join(timeout=5)
        assert accepted
        accepted[0].close()


def test_network_marker_is_registered_and_excluded_by_default(pytestconfig):
    markers = " ".join(pytestconfig.getini("markers"))
    assert "network:" in markers and "slow:" in markers
    assert "not network" in " ".join(pytestconfig.getini("addopts"))

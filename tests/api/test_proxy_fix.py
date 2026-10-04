"""TRUSTED_PROXY_HOPS makes the real client IP visible behind a reverse proxy."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from src.reporting.email_detector import EnhancedAbuseEmailDetector

DB_KEY = "ank_proxy-test-key"
CLIENT_IP = "203.0.113.9"
PROXY_IP = "10.0.0.2"


def _client(hops: int):
    """Build a test client for an API configured with ``hops`` trusted proxies."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
        patch("src.api.phishing_api.settings.TRUSTED_PROXY_HOPS", hops),
    ):
        from src.api.phishing_api import PhishingAPI

        db = MagicMock()
        conn = db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.scalar.return_value = 0
        conn.execute.return_value.fetchall.return_value = []
        api = PhishingAPI(db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="master")
        api.app.config["TESTING"] = True
        return api.app.test_client()


def _get_with_forwarded_for(client):
    key_row = {
        "scopes": "read",
        "allowed_ips": "203.0.113.0/24",
        "key_hash": hashlib.sha256(DB_KEY.encode()).hexdigest(),
    }
    with (
        patch("src.auth._lookup_db_key", return_value=key_row),
        patch("src.auth._update_last_used"),
    ):
        return client.get(
            "/api/v1/sites",
            headers={"Authorization": f"Bearer {DB_KEY}", "X-Forwarded-For": CLIENT_IP},
            environ_base={"REMOTE_ADDR": PROXY_IP},
        )


def test_forwarded_client_ip_is_used_when_one_proxy_is_trusted():
    resp = _get_with_forwarded_for(_client(hops=1))

    assert resp.status_code == 200


def test_forwarded_header_is_ignored_by_default():
    resp = _get_with_forwarded_for(_client(hops=0))

    assert resp.status_code == 403


@pytest.mark.parametrize("hops", [1, 0])
def test_rate_limit_key_sees_the_same_client_ip(hops):
    from flask import request

    from src.api.phishing_api import rate_limit_key

    client = _client(hops=hops)
    seen = {}

    @client.application.route("/whoami")
    def whoami():
        seen["ip"] = request.remote_addr
        seen["key"] = rate_limit_key()
        return "ok"

    client.get(
        "/whoami", headers={"X-Forwarded-For": CLIENT_IP}, environ_base={"REMOTE_ADDR": PROXY_IP}
    )

    expected = CLIENT_IP if hops else PROXY_IP
    assert seen == {"ip": expected, "key": expected}

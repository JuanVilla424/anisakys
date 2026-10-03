"""/metrics requires the METRICS_TOKEN or an API key with metrics/read scope."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from src.reporting.email_detector import EnhancedAbuseEmailDetector

METRICS_TOKEN = "scrape-me-0123456789"


@pytest.fixture
def client():
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        api = PhishingAPI(MagicMock(), MagicMock(spec=EnhancedAbuseEmailDetector), api_key="master")
        api.app.config["TESTING"] = True
        yield api.app.test_client()


def _db_key(scopes):
    return {"scopes": scopes, "allowed_ips": None, "key_hash": hashlib.sha256(b"k").hexdigest()}


def _get(client, token=None, key_row=None, metrics_token=METRICS_TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with (
        patch(
            "src.auth.settings.METRICS_TOKEN", SecretStr(metrics_token) if metrics_token else None
        ),
        patch("src.auth._lookup_db_key", return_value=key_row),
        patch("src.auth._update_last_used"),
    ):
        return client.get("/metrics", headers=headers)


def test_anonymous_scrape_is_rejected(client):
    assert _get(client).status_code == 401


def test_metrics_token_grants_access_in_prometheus_format(client):
    resp = _get(client, token=METRICS_TOKEN)

    assert resp.status_code == 200
    assert resp.content_type.startswith("text/plain")
    assert b"# HELP" in resp.data or b"# TYPE" in resp.data


def test_wrong_token_is_rejected(client):
    assert _get(client, token="not-the-token").status_code == 401


def test_token_is_not_accepted_when_metrics_token_is_unset(client):
    assert _get(client, token=METRICS_TOKEN, metrics_token=None).status_code == 401


@pytest.mark.parametrize("scopes", ["metrics", "read", "scan,read", "admin"])
def test_api_keys_with_metrics_or_read_scope_are_accepted(client, scopes):
    assert _get(client, token="db-key", key_row=_db_key(scopes)).status_code == 200


@pytest.mark.parametrize("scopes", ["scan", "report,write"])
def test_api_keys_without_metrics_or_read_scope_get_403(client, scopes):
    assert _get(client, token="db-key", key_row=_db_key(scopes)).status_code == 403


def test_master_key_is_accepted(client):
    assert _get(client, token="master").status_code == 200

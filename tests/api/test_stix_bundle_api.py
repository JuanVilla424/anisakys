"""POST /api/v2/stix/bundle — contract shared with the frontend."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from src.intelligence.stix_export import TLP2_MARKING_IDS
from src.reporting.email_detector import EnhancedAbuseEmailDetector

PATH = "/api/v2/stix/bundle"
MASTER = {"Authorization": "Bearer master"}


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


def _as_key(client, scopes, body):
    row = {"scopes": scopes, "allowed_ips": None, "key_hash": hashlib.sha256(b"k").hexdigest()}
    with (
        patch("src.auth._lookup_db_key", return_value=row),
        patch("src.auth._update_last_used"),
    ):
        return client.post(PATH, json=body, headers={"Authorization": "Bearer db-key"})


BODY = {
    "indicators": [
        {"type": "domain", "value": "evil.example", "labels": ["phishing"]},
        {"type": "url", "value": "https://evil.example/login'"},
    ],
    "name": "Export",
}


def test_returns_a_tlp_amber_bundle_by_default(client):
    resp = client.post(PATH, json=BODY, headers=MASTER)

    assert resp.status_code == 200
    bundle = resp.get_json()["bundle"]
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("indicator") == 2
    assert types.count("identity") == 1
    assert types.count("report") == 1
    marking = next(o for o in bundle["objects"] if o["type"] == "marking-definition")
    assert marking["id"] == TLP2_MARKING_IDS["amber"]


def test_requested_tlp_and_confidence_are_applied(client):
    resp = client.post(PATH, json={**BODY, "tlp": "red", "confidence": 80}, headers=MASTER)

    indicators = [o for o in resp.get_json()["bundle"]["objects"] if o["type"] == "indicator"]
    assert {i["confidence"] for i in indicators} == {80}
    assert {tuple(i["object_marking_refs"]) for i in indicators} == {(TLP2_MARKING_IDS["red"],)}


def test_invalid_indicators_get_400_listing_indexes(client):
    body = {
        "indicators": [{"type": "domain", "value": "ok.example"}, {"type": "hash", "value": ""}]
    }

    resp = client.post(PATH, json=body, headers=MASTER)

    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"].startswith("Invalid indicators: 1 indicator is invalid; first problem")
    assert f"index 1: {data['details'][0]['error']}" in data["error"]
    assert [d["index"] for d in data["details"]] == [1]


def test_several_invalid_indicators_are_counted_in_the_error(client):
    body = {"indicators": [{"type": "hash", "value": "x"}, {"type": "domain", "value": ""}]}

    data = client.post(PATH, json=body, headers=MASTER).get_json()

    assert data["error"].startswith("Invalid indicators: 2 indicators are invalid")
    assert "index 0" in data["error"]
    assert [d["index"] for d in data["details"]] == [0, 1]


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {"indicators": []},
        {"indicators": [{"type": "domain", "value": "a.example"}], "tlp": "pink"},
        {"indicators": [{"type": "domain", "value": "a.example"}], "confidence": 101},
        {"indicators": [{"type": "domain", "value": "a.example"}], "name": ""},
    ],
)
def test_every_400_carries_a_human_readable_error(client, body):
    """The console shows ``error`` to the analyst; it must always be a sentence."""
    if body is None:
        resp = client.post(PATH, data="nope", headers=MASTER, content_type="text/plain")
    else:
        resp = client.post(PATH, json=body, headers=MASTER)

    assert resp.status_code == 400
    error = resp.get_json()["error"]
    assert isinstance(error, str) and len(error.split()) >= 3


def test_non_json_body_is_400(client):
    resp = client.post(PATH, data="nope", headers=MASTER, content_type="text/plain")

    assert resp.status_code == 400


def test_oversized_body_is_413(client):
    with patch("src.api.phishing_api.STIX_BUNDLE_MAX_BODY_BYTES", 10):
        resp = client.post(PATH, json=BODY, headers=MASTER)

    assert resp.status_code == 413


def test_requires_authentication(client):
    assert client.post(PATH, json=BODY).status_code == 401


def test_read_scope_is_enough(client):
    assert _as_key(client, "read", BODY).status_code == 200


def test_keys_without_read_get_403(client):
    assert _as_key(client, "scan", BODY).status_code == 403

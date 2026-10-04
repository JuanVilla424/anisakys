"""GET /api/v1/session: who is calling, with which scopes, never the secret."""

import hashlib
import secrets
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

from src.auth import VALID_SCOPES, effective_scopes
from src.reporting.email_detector import EnhancedAbuseEmailDetector

PATH = "/api/v1/session"
MASTER_KEY = "master-session-key"


def _api(storage_url=None):
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
        patch("src.api.phishing_api.settings.RATELIMIT_STORAGE_URL", storage_url),
    ):
        from src.api.phishing_api import PhishingAPI

        api = PhishingAPI(
            MagicMock(), MagicMock(spec=EnhancedAbuseEmailDetector), api_key=MASTER_KEY
        )
        api.app.config["TESTING"] = True
        return api


@pytest.fixture
def db_key(db_engine):
    """An active ``api_keys`` row in the test database; yields (raw key, name)."""
    raw = "ank_" + secrets.token_urlsafe(32)
    name = f"console-{uuid.uuid4().hex[:8]}"
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO api_keys (key_hash, key_prefix, name, scopes) "
                "VALUES (:h, :p, :n, :s)"
            ),
            {
                "h": hashlib.sha256(raw.encode()).hexdigest(),
                "p": raw[:12],
                "n": name,
                "s": "read,report_send",
            },
        )
    yield raw, name
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM api_keys WHERE name = :n"), {"n": name})


class TestSession:
    def test_master_key_session(self):
        resp = _api().app.test_client().get(PATH, headers={"Authorization": f"Bearer {MASTER_KEY}"})

        assert resp.status_code == 200
        assert resp.get_json() == {
            "key_type": "master",
            "key_name": None,
            "key_prefix": None,
            "scopes": sorted(VALID_SCOPES),
            "rate_limit_storage": "per-process",
        }
        assert resp.headers["Cache-Control"] == "no-store"
        assert MASTER_KEY not in resp.get_data(as_text=True)

    def test_database_key_session_never_echoes_the_secret(self, db_key):
        raw, name = db_key
        client = _api().app.test_client()

        with patch("src.auth._update_last_used"):
            resp = client.get(PATH, headers={"Authorization": f"Bearer {raw}"})

        assert resp.status_code == 200
        body = resp.get_json()
        assert body == {
            "key_type": "database",
            "key_name": name,
            "key_prefix": raw[:8],
            # report_send implies report.
            "scopes": ["read", "report", "report_send"],
            "rate_limit_storage": "per-process",
        }
        serialized = resp.get_data(as_text=True)
        assert raw not in serialized
        assert raw[:12] not in serialized
        assert hashlib.sha256(raw.encode()).hexdigest() not in serialized

    def test_any_valid_key_may_ask(self):
        row = {"scopes": "metrics", "allowed_ips": None, "key_hash": "h", "name": "scraper"}
        with (
            patch("src.auth._lookup_db_key", return_value=row),
            patch("src.auth._update_last_used"),
        ):
            resp = _api().app.test_client().get(PATH, headers={"Authorization": "Bearer x"})

        assert resp.status_code == 200
        assert resp.get_json()["scopes"] == ["metrics"]
        assert resp.get_json()["key_prefix"] is None  # no stored prefix in this row

    def test_requires_a_key(self):
        client = _api().app.test_client()

        assert client.get(PATH).status_code == 401
        with patch("src.auth._lookup_db_key", return_value=None):
            assert client.get(PATH, headers={"Authorization": "Bearer nope"}).status_code == 401


class TestRateLimitStorageMode:
    def test_configured_storage_is_shared(self):
        api = _api()
        api._rate_limit_storage_uri = "redis://redis.internal:6379/0"

        assert api._rate_limit_storage_mode() == "shared"

    def test_unreachable_storage_falls_back_to_per_process(self):
        """flask-limiter degrades to memory when Redis is down; say so."""
        api = _api("redis://127.0.0.1:1/0")

        resp = api.app.test_client().get(PATH, headers={"Authorization": f"Bearer {MASTER_KEY}"})

        assert resp.status_code == 200
        assert resp.get_json()["rate_limit_storage"] == "per-process"


def test_admin_expands_to_every_scope():
    assert effective_scopes({"admin"}) == VALID_SCOPES
    assert effective_scopes({"report_send"}) == {"report", "report_send"}

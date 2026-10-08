"""E-mail monitor threads need the email_admin scope and an allowlisted mailbox."""

import hashlib
import json
from contextlib import contextmanager
from typing import Iterator, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.config import settings
from src.reporting.email_detector import EnhancedAbuseEmailDetector

KEY = "ank_email-admin-tests"
HEADERS = {"Authorization": f"Bearer {KEY}"}


@contextmanager
def allowlist(
    allowed: Optional[str] = None,
    monitored: Optional[str] = None,
    abuse: Optional[str] = None,
) -> Iterator[None]:
    """Temporarily set the three settings feeding the mailbox allowlist."""
    with (
        patch.object(settings, "EMAIL_MONITOR_ALLOWED_MAILBOXES", allowed),
        patch.object(settings, "EMAIL_MONITORED_MAILBOXES", monitored),
        patch.object(settings, "EMAIL_ABUSE_MAILBOX", abuse),
    ):
        yield


@contextmanager
def key_with(scopes: str) -> Iterator[None]:
    """Authenticate requests as a database key holding ``scopes``."""
    row = {
        "scopes": scopes,
        "allowed_ips": None,
        "key_hash": hashlib.sha256(KEY.encode()).hexdigest(),
    }
    with (
        patch("src.auth._lookup_db_key", return_value=row),
        patch("src.auth._update_last_used"),
    ):
        yield


@pytest.fixture
def api():
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        instance = PhishingAPI(
            MagicMock(), MagicMock(spec=EnhancedAbuseEmailDetector), api_key="master"
        )
        instance.app.config["TESTING"] = True
        conn = instance.db_manager.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = (42,)
        conn.execute.return_value.fetchall.return_value = []
        conn.execute.return_value.rowcount = 1
        yield instance


def _conn(api):
    return api.db_manager.engine.begin.return_value.__enter__.return_value


def _create(api, body):
    return api.app.test_client().post("/api/v1/threads/email-monitor", json=body, headers=HEADERS)


class TestCreateEmailMonitor:
    def test_write_scope_is_no_longer_enough(self, api):
        with allowlist(allowed="soc@example.com"), key_with("read,write"):
            resp = _create(api, {"target_mailbox": "soc@example.com"})

        assert resp.status_code == 403
        assert "email_admin" in resp.get_json()["error"]

    def test_mailbox_outside_the_allowlist_is_refused(self, api):
        with allowlist(allowed="soc@example.com"), key_with("email_admin"):
            resp = _create(api, {"target_mailbox": "ceo@example.com"})

        assert resp.status_code == 403
        api.db_manager.engine.begin.assert_not_called()

    def test_nothing_is_allowed_without_configuration(self, api):
        with allowlist(), key_with("email_admin"):
            resp = _create(api, {"target_mailbox": "soc@example.com"})

        assert resp.status_code == 403

    @pytest.mark.parametrize(
        "config",
        [
            {"allowed": "other@example.com, SOC@example.com"},
            {"monitored": "soc@example.com,team@example.com"},
            {"abuse": "soc@example.com"},
            {"allowed": "@example.com"},
            {"allowed": "*@example.com"},
        ],
    )
    def test_allowlisted_mailbox_is_created(self, api, config):
        with allowlist(**config), key_with("email_admin"):
            resp = _create(api, {"target_mailbox": "soc@example.com", "label": "SOC"})

        assert resp.status_code == 201
        params = _conn(api).execute.call_args.args[1]
        assert json.loads(params["details"])["target_mailbox"] == "soc@example.com"

    def test_domain_wide_monitoring_needs_a_domain_entry(self, api):
        with allowlist(allowed="soc@example.com"), key_with("email_admin"):
            resp = _create(api, {"domain": "example.com"})

        assert resp.status_code == 403

    def test_domain_wide_monitoring_with_domain_entry(self, api):
        with allowlist(allowed="@example.com"), key_with("email_admin"):
            resp = _create(api, {"domain": "Example.com", "admin_email": "admin@example.com"})

        assert resp.status_code == 201
        params = _conn(api).execute.call_args.args[1]
        assert json.loads(params["details"])["domain"] == "example.com"

    def test_admin_email_must_belong_to_the_domain(self, api):
        with allowlist(allowed="@example.com"), key_with("email_admin"):
            resp = _create(api, {"domain": "example.com", "admin_email": "admin@evil.example"})

        assert resp.status_code == 400

    @pytest.mark.parametrize(
        "body",
        [
            {"target_mailbox": "not-an-address"},
            {"target_mailbox": ["soc@example.com"]},
            {"target_mailbox": "soc@example.com", "search_interval_hours": "1"},
            {"target_mailbox": "soc@example.com", "search_interval_hours": 0},
        ],
    )
    def test_invalid_input_is_400(self, api, body):
        with allowlist(allowed="soc@example.com"), key_with("email_admin"):
            assert _create(api, body).status_code == 400


class TestExistingEmailMonitorThreads:
    @staticmethod
    def _thread(api, thread_type="email_monitor", mailbox="soc@example.com"):
        """Make the thread lookups (2- or 3-column SELECTs) return one thread."""
        details = json.dumps({"target_mailbox": mailbox})

        def execute(statement, params=None):
            result = MagicMock()
            result.rowcount = 1
            if "image_s3_key" in str(statement):
                result.fetchone.return_value = (thread_type, None, details)
            else:
                result.fetchone.return_value = (thread_type, details)
            return result

        _conn(api).execute.side_effect = execute

    def _email_thread(self, api, mailbox="soc@example.com"):
        self._thread(api, mailbox=mailbox)

    def test_inbox_breakdown_needs_email_admin(self, api):
        with key_with("read"):
            resp = api.app.test_client().get("/api/v1/threads/1/email-inboxes", headers=HEADERS)

        assert resp.status_code == 403

    def test_inbox_breakdown_with_email_admin(self, api):
        with key_with("email_admin"):
            resp = api.app.test_client().get("/api/v1/threads/1/email-inboxes", headers=HEADERS)

        assert resp.status_code == 200

    def test_updating_an_email_monitor_needs_email_admin(self, api):
        self._email_thread(api)
        with allowlist(allowed="soc@example.com"), key_with("write"):
            resp = api.app.test_client().patch(
                "/api/v1/threads/1", json={"status": "active"}, headers=HEADERS
            )

        assert resp.status_code == 403

    def test_updating_an_allowlisted_email_monitor(self, api):
        self._email_thread(api)
        with allowlist(allowed="soc@example.com"), key_with("email_admin"):
            resp = api.app.test_client().patch(
                "/api/v1/threads/1", json={"status": "active"}, headers=HEADERS
            )

        assert resp.status_code == 200

    def test_legacy_thread_for_a_non_allowlisted_mailbox_cannot_be_touched(self, api):
        self._email_thread(api, mailbox="ceo@example.com")
        with allowlist(allowed="soc@example.com"), key_with("email_admin"):
            update = api.app.test_client().patch(
                "/api/v1/threads/1", json={"status": "active"}, headers=HEADERS
            )
            search = api.app.test_client().post("/api/v1/threads/1/search", headers=HEADERS)

        assert update.status_code == 403
        assert search.status_code == 403

    def test_email_admin_alone_cannot_update_other_thread_types(self, api):
        self._thread(api, thread_type="google_ads")
        with key_with("email_admin"):
            resp = api.app.test_client().patch(
                "/api/v1/threads/1", json={"label": "x"}, headers=HEADERS
            )

        assert resp.status_code == 403

    def test_on_demand_mailbox_scan_needs_email_admin(self, api):
        self._email_thread(api)
        with allowlist(allowed="soc@example.com"), key_with("write"):
            resp = api.app.test_client().post("/api/v1/threads/1/search", headers=HEADERS)

        assert resp.status_code == 403


class TestMailboxPolicy:
    def test_mailbox_and_domain_rules(self):
        from src.api.mailbox_policy import (
            allowlist as policy,
            is_domain_allowed,
            is_mailbox_allowed,
        )

        with allowlist(allowed="soc@example.com, @corp.example", abuse="Abuse@Example.com"):
            assert policy() == (
                frozenset({"soc@example.com", "abuse@example.com"}),
                frozenset({"corp.example"}),
            )
            assert is_mailbox_allowed("ABUSE@example.com")
            assert is_mailbox_allowed("anyone@corp.example")
            assert not is_mailbox_allowed("ceo@example.com")
            assert is_domain_allowed("corp.example")
            assert not is_domain_allowed("example.com")

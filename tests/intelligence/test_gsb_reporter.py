"""Tests for src/intelligence/gsb_reporter.py.

Covers: the documented Web Risk ``projects/{project}/uris:submit`` call with
OAuth (success only on a parsed Operation), the disabled-unless-configured
behaviour, and the crx-report channel being reported as unverified.
"""

import importlib
from unittest.mock import MagicMock

import pytest
import requests

from src.intelligence.gsb_reporter import (
    METHOD_CRX_UNVERIFIED,
    METHOD_WEB_RISK,
    GSBReporter,
)

reporter_module = importlib.import_module("src.intelligence.gsb_reporter")

URL = "https://phish.example/login"
PROJECT = "test-project-123"


def _resp(status=200, body=None, json_error=False, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if json_error:
        resp.json.side_effect = ValueError("bad json")
    else:
        resp.json.return_value = body
    return resp


def _operation(name=f"projects/{PROJECT}/operations/op-1"):
    return {
        "name": name,
        "metadata": {
            "@type": "type.googleapis.com/google.cloud.webrisk.v1.SubmitUriMetadata",
            "state": "RUNNING",
        },
        "done": False,
    }


@pytest.fixture
def oauth_session():
    return MagicMock(spec=requests.Session)


def _reporter(oauth_session, **kwargs):
    defaults = dict(
        project=PROJECT,
        credentials=object(),
        session_factory=lambda creds: oauth_session,
        crx_enabled=False,
    )
    defaults.update(kwargs)
    return GSBReporter(**defaults)


class TestWebRiskSubmission:
    def test_posts_to_documented_project_endpoint(self, oauth_session):
        oauth_session.post.return_value = _resp(200, _operation())
        result = _reporter(oauth_session).report_url(URL)

        args, kwargs = oauth_session.post.call_args
        assert args[0] == f"https://webrisk.googleapis.com/v1/projects/{PROJECT}/uris:submit"
        assert "key=" not in args[0]
        assert kwargs["json"]["submission"] == {"uri": URL}
        assert kwargs["json"]["threatInfo"]["abuseType"] == "SOCIAL_ENGINEERING"
        assert kwargs["timeout"] > 0
        assert result["success"] is True
        assert result["method"] == METHOD_WEB_RISK
        assert result["verified"] is True
        assert result["operation"] == f"projects/{PROJECT}/operations/op-1"

    @pytest.mark.parametrize(
        "body",
        [{}, {"done": True}, {"name": "garbage"}, ["not", "an", "object"], None],
    )
    def test_2xx_without_valid_operation_is_not_success(self, oauth_session, body):
        oauth_session.post.return_value = _resp(200, body)
        result = _reporter(oauth_session).report_url(URL)
        assert result["success"] is False
        assert "not a valid submit operation" in result["message"]

    def test_operation_with_error_is_not_success(self, oauth_session):
        body = _operation()
        body["error"] = {"code": 7, "message": "denied"}
        oauth_session.post.return_value = _resp(200, body)
        assert _reporter(oauth_session).report_url(URL)["success"] is False

    def test_unparseable_body_is_not_success(self, oauth_session):
        oauth_session.post.return_value = _resp(200, json_error=True)
        assert _reporter(oauth_session).report_url(URL)["success"] is False

    @pytest.mark.parametrize("status", [204, 400, 403, 500])
    def test_non_200_is_not_success(self, oauth_session, status):
        oauth_session.post.return_value = _resp(status, text="nope")
        result = _reporter(oauth_session).report_url(URL)
        assert result["success"] is False
        if status == 403:
            assert "allowlisted" in result["message"]

    def test_credentials_error_is_reported(self):
        from google.auth.exceptions import DefaultCredentialsError

        def broken_factory(creds):
            raise DefaultCredentialsError("no ADC")

        reporter = GSBReporter(
            project=PROJECT, credentials=object(), session_factory=broken_factory, crx_enabled=False
        )
        result = reporter.report_url(URL)
        assert result["success"] is False
        assert "Credentials unavailable" in result["message"]

    def test_web_risk_disabled_without_project(self, oauth_session, monkeypatch):
        monkeypatch.setattr(reporter_module.settings, "GOOGLE_CLOUD_PROJECT", None)
        reporter = GSBReporter(
            project=None, session_factory=lambda c: oauth_session, crx_enabled=False
        )
        result = reporter.report_url(URL)
        assert reporter.web_risk_enabled is False
        assert result["success"] is False
        oauth_session.post.assert_not_called()

    def test_api_key_alone_does_not_enable_submission(self, monkeypatch, caplog):
        monkeypatch.setattr(reporter_module.settings, "GOOGLE_CLOUD_PROJECT", None)
        monkeypatch.setattr(reporter_module, "_api_key_warning_logged", False)
        reporter = GSBReporter(web_risk_api_key="AIza-test", project=None, crx_enabled=False)
        assert reporter.web_risk_enabled is False
        assert "requires OAuth" in caplog.text


class TestCrxReport:
    def test_2xx_is_reported_as_unverified(self, monkeypatch):
        monkeypatch.setattr(reporter_module.settings, "GOOGLE_CLOUD_PROJECT", None)
        reporter = GSBReporter(project=None, crx_enabled=True)
        reporter.session = MagicMock()
        reporter.session.post.return_value = _resp(204)
        result = reporter.report_url(URL)
        assert result["success"] is True
        assert result["method"] == METHOD_CRX_UNVERIFIED
        assert result["verified"] is False
        assert reporter.session.post.call_args.kwargs["timeout"] > 0

    def test_web_risk_preferred_over_crx(self, oauth_session):
        oauth_session.post.return_value = _resp(200, _operation())
        reporter = _reporter(oauth_session, crx_enabled=True)
        reporter.session = MagicMock()
        result = reporter.report_url(URL)
        assert result["method"] == METHOD_WEB_RISK
        reporter.session.post.assert_not_called()

    def test_crx_used_as_fallback_when_web_risk_fails(self, oauth_session):
        oauth_session.post.return_value = _resp(403, text="denied")
        reporter = _reporter(oauth_session, crx_enabled=True)
        reporter.session = MagicMock()
        reporter.session.post.return_value = _resp(200)
        result = reporter.report_url(URL)
        assert result["success"] is True
        assert result["method"] == METHOD_CRX_UNVERIFIED

    def test_crx_disabled_and_no_web_risk_fails(self, monkeypatch):
        monkeypatch.setattr(reporter_module.settings, "GOOGLE_CLOUD_PROJECT", None)
        reporter = GSBReporter(project=None, crx_enabled=False)
        result = reporter.report_url(URL)
        assert result["success"] is False
        assert "disabled" in result["message"]

    def test_crx_http_error_fails(self, monkeypatch):
        monkeypatch.setattr(reporter_module.settings, "GOOGLE_CLOUD_PROJECT", None)
        reporter = GSBReporter(project=None, crx_enabled=True)
        reporter.session = MagicMock()
        reporter.session.post.return_value = _resp(500, text="err")
        result = reporter.report_url(URL)
        assert result["success"] is False
        assert reporter.stats["failures"] == 1

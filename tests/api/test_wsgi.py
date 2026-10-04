"""Tests for the production WSGI entrypoint and the development server settings."""

import threading
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from src.reporting.email_detector import EnhancedAbuseEmailDetector


@pytest.fixture
def wsgi_module():
    """Import src.api.wsgi with outbound integrations mocked."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        import src.api.wsgi as wsgi

        wsgi._app = None
        yield wsgi
        wsgi._app = None


class TestCreateApp:
    def test_returns_a_flask_app_serving_the_api(self, wsgi_module):
        app = wsgi_module.create_app(api_key="wsgi-key")

        assert isinstance(app, Flask)
        assert getattr(app, "api_key") == "wsgi-key"
        assert "/api/v1/health" in {rule.rule for rule in app.url_map.iter_rules()}

    def test_api_role_gets_no_report_manager_and_no_schedulers(self, wsgi_module):
        with patch.object(wsgi_module, "PhishingAPI") as api_cls:
            wsgi_module.create_app(api_key="k")

        kwargs = api_cls.call_args.kwargs
        assert kwargs["report_manager"] is None
        assert kwargs["scheduler"] is None
        assert kwargs["email_scheduler"] is None

    def test_starts_no_background_threads(self, wsgi_module):
        before = set(threading.enumerate())

        wsgi_module.create_app(api_key="k")

        # The in-memory rate-limit storage arms a threading.Timer to expire its
        # counters; that is per-app housekeeping, not a background job.
        new_threads = set(threading.enumerate()) - before
        assert {t for t in new_threads if not isinstance(t, threading.Timer)} == set()

    def test_falls_back_to_the_configured_master_key(self, wsgi_module):
        with patch.object(wsgi_module.settings, "ANISAKYS_API_KEY", "from-settings"):
            app = wsgi_module.create_app()

        assert getattr(app, "api_key") == "from-settings"

    def test_refuses_to_serve_a_database_behind_the_code(self, wsgi_module):
        """The API role must not start against a schema that misses migrations."""
        stale = RuntimeError("Database schema is behind; run `alembic upgrade head`")
        with patch.object(wsgi_module, "ensure_schema_is_current", side_effect=stale):
            with pytest.raises(RuntimeError, match="alembic upgrade head"):
                wsgi_module.create_app(api_key="k")

    def test_module_level_app_is_created_lazily_once(self, wsgi_module):
        sentinel = MagicMock()
        with patch.object(wsgi_module, "create_app", return_value=sentinel) as factory:
            assert wsgi_module.app is sentinel
            assert wsgi_module.app is sentinel

        factory.assert_called_once_with()

    def test_unknown_module_attribute_raises(self, wsgi_module):
        with pytest.raises(AttributeError):
            wsgi_module.does_not_exist


class TestDevelopmentServer:
    @pytest.fixture
    def api(self):
        with (
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI

            yield PhishingAPI(MagicMock(), MagicMock(spec=EnhancedAbuseEmailDetector), api_key="k")

    def test_run_binds_loopback_by_default_and_never_debugs(self, api):
        with patch.object(api.app, "run") as flask_run:
            api.run(port=9999)

        flask_run.assert_called_once_with(
            host="127.0.0.1", port=9999, debug=False, use_reloader=False
        )

    def test_run_honours_an_explicit_host(self, api):
        with patch.object(api.app, "run") as flask_run:
            api.run(host="0.0.0.0", port=9999)

        assert flask_run.call_args.kwargs["host"] == "0.0.0.0"
        assert flask_run.call_args.kwargs["debug"] is False

    def test_api_bind_host_setting_defaults_to_loopback(self):
        from src.config import Settings

        assert Settings.model_fields["API_BIND_HOST"].default == "127.0.0.1"

    def test_cli_api_host_defaults_to_the_setting(self):
        from src.main import parse_arguments

        with patch("sys.argv", ["anisakys.py", "--start-api"]):
            args = parse_arguments()

        assert args.api_host is None

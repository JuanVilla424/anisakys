"""
Tests for src/auth.py — multi-tenant API key authentication with scopes.
"""

import hashlib
import hmac
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _make_app(master_key: str = "master-key-123") -> Flask:
    app = Flask(__name__)
    app.api_key = master_key
    app.config["TESTING"] = True
    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app():
    return _make_app()


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# Helpers to register test routes
# ---------------------------------------------------------------------------


def _register_routes(app, require_api_key):
    @app.route("/public")
    def public():
        return "ok", 200

    @app.route("/any")
    @require_api_key
    def any_key():
        return "ok", 200

    @app.route("/read")
    @require_api_key(scope="read")
    def read_only():
        return "ok", 200

    @app.route("/scan")
    @require_api_key(scope="scan")
    def scan_only():
        return "ok", 200

    @app.route("/admin")
    @require_api_key(scope="admin")
    def admin_only():
        return "ok", 200


# ---------------------------------------------------------------------------
# Master key tests
# ---------------------------------------------------------------------------


class TestMasterKey:
    def _setup(self):
        app = _make_app("master-secret")
        with patch("src.auth.increment_counter"):
            from src.auth import require_api_key

            _register_routes(app, require_api_key)
        return app.test_client()

    def test_master_key_accepted(self):
        client = self._setup()
        rv = client.get("/any", headers={"Authorization": "Bearer master-secret"})
        assert rv.status_code == 200

    def test_master_key_wrong(self):
        client = self._setup()
        rv = client.get("/any", headers={"Authorization": "Bearer wrong-key"})
        assert rv.status_code == 401

    def test_master_key_no_header(self):
        client = self._setup()
        rv = client.get("/any")
        assert rv.status_code == 401

    def test_master_key_missing_bearer(self):
        client = self._setup()
        rv = client.get("/any", headers={"Authorization": "master-secret"})
        assert rv.status_code == 401

    def test_master_key_grants_all_scopes(self):
        """Master key must bypass scope checks entirely."""
        client = self._setup()
        for endpoint in ("/read", "/scan", "/admin"):
            rv = client.get(endpoint, headers={"Authorization": "Bearer master-secret"})
            assert rv.status_code == 200, f"master key should access {endpoint}"


# ---------------------------------------------------------------------------
# Database key tests
# ---------------------------------------------------------------------------


def _db_row(scopes="read", allowed_ips=None):
    """Return a mock DB row dict as returned by _lookup_db_key."""
    return {"scopes": scopes, "allowed_ips": allowed_ips, "key_hash": _hash("db-key")}


class TestDatabaseKey:
    """Patches must stay active during request, not just during decoration."""

    @staticmethod
    def _app_with_routes(route_map: dict) -> Flask:
        """Build a Flask app with routes specified as {path: (scope, fn_name)}."""
        from src.auth import require_api_key

        app = _make_app("master-secret")
        for path, (scope, fn_name) in route_map.items():

            def _view(s=scope, n=fn_name):
                @require_api_key(scope=s)
                def inner():
                    return "ok", 200

                inner.__name__ = n
                return inner

            app.route(path)(_view())
        return app

    def test_valid_db_key_accepted(self):
        from src.auth import require_api_key

        app = _make_app("master-secret")

        @app.route("/t")
        @require_api_key(scope="read")
        def t():
            return "ok", 200

        with (
            patch("src.auth.increment_counter"),
            patch("src.auth._lookup_db_key", return_value=_db_row("read")),
            patch("src.auth._update_last_used"),
        ):
            rv = app.test_client().get("/t", headers={"Authorization": "Bearer db-key"})
        assert rv.status_code == 200

    def test_invalid_db_key_rejected(self):
        from src.auth import require_api_key

        app = _make_app("master-secret")

        @app.route("/t2")
        @require_api_key(scope="read")
        def t2():
            return "ok", 200

        with (
            patch("src.auth.increment_counter"),
            patch("src.auth._lookup_db_key", return_value=None),
        ):
            rv = app.test_client().get("/t2", headers={"Authorization": "Bearer bad-key"})
        assert rv.status_code == 401

    def test_wrong_scope_returns_403(self):
        from src.auth import require_api_key

        app = _make_app("master-secret")

        @app.route("/t3")
        @require_api_key(scope="scan")
        def t3():
            return "ok", 200

        with (
            patch("src.auth.increment_counter"),
            patch("src.auth._lookup_db_key", return_value=_db_row("read")),
            patch("src.auth._update_last_used"),
        ):
            rv = app.test_client().get("/t3", headers={"Authorization": "Bearer db-key"})
        assert rv.status_code == 403
        assert "scope" in rv.get_json()["error"].lower()

    def test_admin_scope_grants_all(self):
        from src.auth import require_api_key

        app = _make_app("master-secret")

        @app.route("/t4a")
        @require_api_key(scope="read")
        def t4a():
            return "ok", 200

        @app.route("/t4b")
        @require_api_key(scope="scan")
        def t4b():
            return "ok", 200

        with (
            patch("src.auth.increment_counter"),
            patch("src.auth._lookup_db_key", return_value=_db_row("admin")),
            patch("src.auth._update_last_used"),
        ):
            c = app.test_client()
            assert c.get("/t4a", headers={"Authorization": "Bearer db-key"}).status_code == 200
            assert c.get("/t4b", headers={"Authorization": "Bearer db-key"}).status_code == 200

    def test_ip_restriction_allowed(self):
        from src.auth import require_api_key

        app = _make_app("master-secret")

        @app.route("/t5")
        @require_api_key(scope="read")
        def t5():
            return "ok", 200

        with (
            patch("src.auth.increment_counter"),
            patch("src.auth._lookup_db_key", return_value=_db_row("read", allowed_ips="127.0.0.1")),
            patch("src.auth._update_last_used"),
        ):
            rv = app.test_client().get("/t5", headers={"Authorization": "Bearer db-key"})
        assert rv.status_code == 200

    def test_ip_restriction_blocked(self):
        from src.auth import require_api_key

        app = _make_app("master-secret")

        @app.route("/t6")
        @require_api_key(scope="read")
        def t6():
            return "ok", 200

        with (
            patch("src.auth.increment_counter"),
            patch(
                "src.auth._lookup_db_key", return_value=_db_row("read", allowed_ips="10.0.0.0/8")
            ),
            patch("src.auth._update_last_used"),
        ):
            # test client uses 127.0.0.1 which is NOT in 10.0.0.0/8
            rv = app.test_client().get("/t6", headers={"Authorization": "Bearer db-key"})
        assert rv.status_code == 403


# ---------------------------------------------------------------------------
# Scope helper tests
# ---------------------------------------------------------------------------


class TestScopeHelpers:
    def test_scope_allowed_no_requirement(self):
        from src.auth import _scope_allowed

        assert _scope_allowed("read", None) is True

    def test_scope_allowed_match(self):
        from src.auth import _scope_allowed

        assert _scope_allowed("read,scan", "scan") is True

    def test_scope_denied(self):
        from src.auth import _scope_allowed

        assert _scope_allowed("read", "scan") is False

    def test_admin_allows_all(self):
        from src.auth import _scope_allowed

        for s in ("read", "scan", "report", "admin"):
            assert _scope_allowed("admin", s) is True

    def test_hash_key(self):
        from src.auth import _hash_key

        assert _hash_key("test") == hashlib.sha256(b"test").hexdigest()
        assert len(_hash_key("anything")) == 64

    def test_ip_allowed_no_restriction(self):
        from src.auth import _check_ip_allowed

        app = _make_app()
        with app.test_request_context("/"):
            assert _check_ip_allowed(None) is True
            assert _check_ip_allowed("") is True

    def test_ip_allowed_cidr(self):
        from src.auth import _check_ip_allowed

        app = _make_app()
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "192.168.1.5"}):
            assert _check_ip_allowed("192.168.1.0/24") is True
            assert _check_ip_allowed("10.0.0.0/8") is False

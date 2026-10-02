"""
Tests for src/cli/api_keys.py — API key management CLI.
"""

import hashlib
from unittest.mock import MagicMock, call, patch

import pytest


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _make_conn_mock(rows=None):
    """Build a mock sqlalchemy connection that returns rows on SELECT."""
    conn = MagicMock()
    conn.__enter__ = lambda s: s
    conn.__exit__ = MagicMock(return_value=False)
    conn.execute.return_value.fetchone.return_value = None
    conn.execute.return_value.fetchall.return_value = rows or []
    conn.execute.return_value.rowcount = 1
    return conn


def _make_engine(conn_mock):
    engine = MagicMock()
    engine.begin.return_value.__enter__ = lambda s: conn_mock
    engine.begin.return_value.__exit__ = MagicMock(return_value=False)
    engine.connect.return_value.__enter__ = lambda s: conn_mock
    engine.connect.return_value.__exit__ = MagicMock(return_value=False)
    return engine


class TestCmdCreate:
    def _run(self, argv, engine_mock):
        import argparse

        with (
            patch("src.cli.api_keys._get_engine", return_value=engine_mock),
            patch("builtins.print") as mock_print,
        ):
            from src.cli.api_keys import cmd_create

            args = argparse.Namespace(
                name=argv.get("name", "test"),
                scopes=argv.get("scopes", "read"),
                allowed_ips=argv.get("allowed_ips", None),
                description=argv.get("description", None),
            )
            cmd_create(args)
            return mock_print

    def test_create_generates_ank_prefix(self):
        conn = _make_conn_mock()
        engine = _make_engine(conn)
        printed = self._run({"name": "test-key", "scopes": "read"}, engine)
        # Confirm key printed starts with ank_
        output = " ".join(str(c) for c in printed.call_args_list)
        assert "ank_" in output

    def test_create_stores_hash_not_plaintext(self):
        conn = _make_conn_mock()
        engine = _make_engine(conn)
        self._run({"name": "test-key2", "scopes": "scan"}, engine)
        # Find the INSERT execute call
        insert_call = None
        for c in conn.execute.call_args_list:
            sql = str(c[0][0])
            if "INSERT" in sql:
                insert_call = c
                break
        assert insert_call is not None
        params = insert_call[0][1]
        # key_hash must be 64-char hex (SHA-256)
        assert len(params["h"]) == 64
        assert all(c in "0123456789abcdef" for c in params["h"])

    def test_create_invalid_scope_exits(self):
        conn = _make_conn_mock()
        engine = _make_engine(conn)
        import argparse, sys

        with (
            patch("src.cli.api_keys._get_engine", return_value=engine),
            pytest.raises(SystemExit) as exc,
        ):
            from src.cli.api_keys import cmd_create

            args = argparse.Namespace(
                name="bad-scope",
                scopes="badscope",
                allowed_ips=None,
                description=None,
            )
            cmd_create(args)
        assert exc.value.code == 1

    def test_create_duplicate_name_exits(self):
        conn = _make_conn_mock()
        conn.execute.return_value.fetchone.return_value = (1,)  # existing row
        engine = _make_engine(conn)
        import argparse

        with (
            patch("src.cli.api_keys._get_engine", return_value=engine),
            pytest.raises(SystemExit) as exc,
        ):
            from src.cli.api_keys import cmd_create

            args = argparse.Namespace(name="dup", scopes="read", allowed_ips=None, description=None)
            cmd_create(args)
        assert exc.value.code == 1


class TestCmdList:
    def test_list_no_keys(self, capsys):
        conn = _make_conn_mock(rows=[])
        engine = _make_engine(conn)
        with patch("src.cli.api_keys._get_engine", return_value=engine):
            from src.cli.api_keys import cmd_list
            import argparse

            cmd_list(argparse.Namespace())
        out = capsys.readouterr().out
        assert "No API keys" in out

    def test_list_does_not_show_hash(self, capsys):
        from datetime import datetime

        rows = [("ank_abc123", "my-key", "read", None, True, datetime.now(), None, "desc")]
        conn = _make_conn_mock(rows=rows)
        engine = _make_engine(conn)
        with patch("src.cli.api_keys._get_engine", return_value=engine):
            from src.cli.api_keys import cmd_list
            import argparse

            cmd_list(argparse.Namespace())
        out = capsys.readouterr().out
        # prefix shown, no 64-char hash
        assert "ank_abc123" in out
        assert len([w for w in out.split() if len(w) == 64]) == 0


class TestCmdRevoke:
    def test_revoke_by_name(self):
        conn = _make_conn_mock()
        engine = _make_engine(conn)
        import argparse

        with (
            patch("src.cli.api_keys._get_engine", return_value=engine),
            patch("builtins.print"),
        ):
            from src.cli.api_keys import cmd_revoke

            args = argparse.Namespace(name="my-key", prefix=None)
            cmd_revoke(args)
        # Verify UPDATE was called
        update_call = None
        for c in conn.execute.call_args_list:
            sql = str(c[0][0])
            if "UPDATE" in sql:
                update_call = c
                break
        assert update_call is not None

    def test_revoke_not_found_exits(self):
        conn = _make_conn_mock()
        conn.execute.return_value.rowcount = 0
        engine = _make_engine(conn)
        import argparse

        with (
            patch("src.cli.api_keys._get_engine", return_value=engine),
            pytest.raises(SystemExit) as exc,
        ):
            from src.cli.api_keys import cmd_revoke

            args = argparse.Namespace(name="nonexistent", prefix=None)
            cmd_revoke(args)
        assert exc.value.code == 1

    def test_revoke_no_identifier_exits(self):
        import argparse

        with pytest.raises(SystemExit) as exc:
            from src.cli.api_keys import cmd_revoke

            args = argparse.Namespace(name=None, prefix=None)
            cmd_revoke(args)
        assert exc.value.code == 1

"""E-mail monitor threads only read mailboxes on the operator's allowlist.

The scheduler's service account has domain-wide delegation; before this gate
any thread row (e.g. created through the API) made it read that mailbox.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
import src.monitoring.email_scheduler as email_scheduler_module
from src.monitoring.email_scheduler import EmailMonitorScheduler, monitoring_refusal


@pytest.fixture
def policy(monkeypatch):
    """Install a stand-in allowlist module (the real one ships with the API workstream)."""
    module = SimpleNamespace(
        is_mailbox_allowed=lambda mailbox: mailbox == "abuse@corp.example",
        is_domain_allowed=lambda domain: domain == "corp.example",
    )
    monkeypatch.setitem(sys.modules, "src.api.mailbox_policy", module)
    return module


def _scheduler() -> EmailMonitorScheduler:
    scheduler = object.__new__(EmailMonitorScheduler)
    scheduler._run_single_mailbox = MagicMock()
    scheduler._run_domain_wide = MagicMock()
    return scheduler


def test_allowed_mailbox_and_domain_run(policy):
    assert monitoring_refusal({"target_mailbox": "abuse@corp.example"}) is None
    assert monitoring_refusal({"domain": "corp.example"}) is None


def test_mailbox_outside_the_allowlist_is_never_read(policy):
    scheduler = _scheduler()
    with patch.object(email_scheduler_module, "db_engine") as engine:
        scheduler._run_email_monitor(7, {"target_mailbox": "ceo@corp.example"})

    scheduler._run_single_mailbox.assert_not_called()
    statement, params = engine.begin.return_value.__enter__.return_value.execute.call_args.args
    assert "thread_executions" in str(statement)
    assert params["tid"] == 7 and "not on the mailbox allowlist" in params["reason"]


def test_domain_wide_needs_the_domain_on_the_allowlist(policy):
    scheduler = _scheduler()
    with patch.object(email_scheduler_module, "db_engine"):
        scheduler._run_email_monitor(8, {"domain": "other.example"})
        scheduler._run_email_monitor(9, {"domain": "corp.example"})

    scheduler._run_domain_wide.assert_called_once()
    assert scheduler._run_domain_wide.call_args.args[0] == 9


def test_missing_policy_module_fails_closed(monkeypatch):
    monkeypatch.setitem(sys.modules, "src.api.mailbox_policy", None)

    assert "unavailable" in monitoring_refusal({"target_mailbox": "abuse@corp.example"})

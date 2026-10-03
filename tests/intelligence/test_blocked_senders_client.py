"""Tests for src/intelligence/blocked_senders_client.py (tenant configuration)."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.intelligence import blocked_senders_client as bsc


class TestCustomerResource:
    @pytest.mark.parametrize(
        "value, expected",
        [
            (None, "customers/my_customer"),
            ("", "customers/my_customer"),
            ("my_customer", "customers/my_customer"),
            ("C0abc123", "customers/C0abc123"),
            ("customers/C0abc123", "customers/C0abc123"),
        ],
    )
    def test_builds_resource_name(self, value, expected):
        assert bsc.customer_resource(value) == expected

    @pytest.mark.parametrize("value", ['C0" || true || "', "customers/../x", "a b"])
    def test_rejects_filter_injection(self, value):
        with pytest.raises(ValueError):
            bsc.customer_resource(value)

    def test_no_hardcoded_tenant_left(self):
        assert not hasattr(bsc, "CUSTOMER")


def _client(customer_id=None, setting=None):
    svc = MagicMock()
    svc.policies.return_value.list.return_value.execute.return_value = {
        "policies": [{"name": "policies/1", "setting": {"value": {"blockedSenders": []}}}]
    }
    fake_sa = SimpleNamespace(
        Credentials=SimpleNamespace(
            from_service_account_file=MagicMock(
                return_value=MagicMock(with_subject=MagicMock(return_value="creds"))
            )
        )
    )
    oauth2 = ModuleType("google.oauth2")
    setattr(oauth2, "service_account", fake_sa)
    discovery = ModuleType("googleapiclient.discovery")
    setattr(discovery, "build", MagicMock(return_value=svc))
    modules = {
        "google.oauth2": oauth2,
        "google.oauth2.service_account": fake_sa,
        "googleapiclient.discovery": discovery,
    }
    with (
        patch.dict(sys.modules, modules),
        patch.object(bsc.settings, "GOOGLE_WORKSPACE_CUSTOMER_ID", setting),
    ):
        client = bsc.BlockedSendersClient("sa.json", "admin@example.com", customer_id)
    return client, svc


class TestPolicyFilter:
    def test_defaults_to_my_customer(self):
        client, svc = _client(setting="my_customer")
        client._get_policy()
        flt = svc.policies.return_value.list.call_args.kwargs["filter"]
        assert flt.startswith('customer=="customers/my_customer"')
        assert "C00yx3tcp" not in flt

    def test_uses_configured_customer(self):
        client, svc = _client(setting="C0tenant42")
        client._get_policy()
        flt = svc.policies.return_value.list.call_args.kwargs["filter"]
        assert 'customer=="customers/C0tenant42"' in flt

    def test_explicit_argument_wins(self):
        client, _ = _client(customer_id="C0explicit", setting="C0tenant42")
        assert client.customer == "customers/C0explicit"

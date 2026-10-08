"""Tests for validated query parameters (src/api/params.py and their use in the API)."""

import json
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.datastructures import MultiDict

from src.api.params import InvalidParameterError, bool_arg, enum_arg, int_arg, str_arg
from src.reporting.email_detector import EnhancedAbuseEmailDetector

AUTH = {"Authorization": "Bearer test_key"}


class TestIntArg:
    def test_default_when_absent_or_empty(self):
        assert int_arg(MultiDict(), "limit", default=7) == 7
        assert int_arg(MultiDict({"limit": " "}), "limit", default=7) == 7

    def test_parses_and_clamps_to_maximum(self):
        assert int_arg(MultiDict({"limit": "42"}), "limit", default=1, maximum=500) == 42
        assert int_arg(MultiDict({"limit": "9999"}), "limit", default=1, maximum=500) == 500

    def test_rejects_above_maximum_when_not_clamping(self):
        with pytest.raises(InvalidParameterError) as exc:
            int_arg(
                MultiDict({"offset": "11"}), "offset", default=0, maximum=10, clamp_to_maximum=False
            )
        assert exc.value.parameter == "offset"

    @pytest.mark.parametrize("raw", ["abc", "1.5", "-1", "0x10"])
    def test_rejects_non_integers_and_values_below_minimum(self, raw):
        with pytest.raises(InvalidParameterError) as exc:
            int_arg(MultiDict({"limit": raw}), "limit", default=1, minimum=0)
        assert "limit" in exc.value.message


class TestEnumBoolStrArgs:
    def test_enum_is_case_insensitive_and_lower_cases(self):
        assert enum_arg(MultiDict({"status": "UP"}), "status", {"up", "down"}) == "up"
        assert enum_arg(MultiDict(), "status", {"up"}, default="up") == "up"

    def test_enum_rejects_unknown_values_listing_allowed(self):
        with pytest.raises(InvalidParameterError) as exc:
            enum_arg(MultiDict({"status": "sideways"}), "status", {"up", "down"})
        assert exc.value.message == "'status' must be one of: down, up"

    @pytest.mark.parametrize("raw, expected", [("true", True), ("0", False), ("Yes", True)])
    def test_bool_values(self, raw, expected):
        assert bool_arg(MultiDict({"flag": raw}), "flag") is expected

    def test_bool_rejects_garbage(self):
        with pytest.raises(InvalidParameterError):
            bool_arg(MultiDict({"flag": "maybe"}), "flag")

    def test_str_arg_bounds_length(self):
        assert str_arg(MultiDict({"q": "  x "}), "q") == "x"
        assert str_arg(MultiDict({"q": ""}), "q") is None
        with pytest.raises(InvalidParameterError):
            str_arg(MultiDict({"q": "x" * 10}), "q", max_length=5)


@pytest.fixture
def api_client():
    """API client with a mocked DB; master-key auth."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        db = MagicMock()
        api = PhishingAPI(db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key")
        api.app.config["TESTING"] = True
        yield api.app.test_client(), db


class TestEndpointsRejectInvalidParameters:
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/sites?limit=abc",
            "/api/v1/sites?limit=-1",
            "/api/v1/sites?offset=-5",
            "/api/v1/sites?status=sideways",
            "/api/v1/sites?priority=urgent",
            "/api/v1/reports?offset=x",
            "/api/v1/reports?status=lost",
            "/api/v1/activity?limit=-3",
            "/api/v1/threads/1/results?limit=ten",
            "/api/v1/intelligence/iocs?limit=-1",
            "/api/v1/intelligence/iocs?type=hash",
            "/api/v1/intelligence/iocs?threat=severe",
            "/api/v1/intelligence/iocs?search=" + "a" * 201,
            "/api/v1/graph?limit=0",
            "/api/v1/campaigns?limit=0",
            "/api/v1/campaigns?offset=-1",
            "/api/v1/graph?focus=asn:1",
            "/api/v1/threads/1/executions?offset=-1",
            "/api/v1/email/senders?blocked_only=maybe",
            "/api/v1/email/domains?limit=many",
        ],
    )
    def test_invalid_query_parameter_returns_400(self, api_client, path):
        client, db = api_client

        resp = client.get(path, headers=AUTH)

        assert resp.status_code == 400, resp.get_data(as_text=True)
        body = json.loads(resp.data)
        assert body["parameter"] in path
        assert body["error"]
        db.engine.begin.assert_not_called()

    def test_oversized_limit_is_clamped_not_rejected(self, api_client):
        client, db = api_client
        conn = db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.scalar.return_value = 0
        conn.execute.return_value.fetchall.return_value = []

        resp = client.get("/api/v1/sites?limit=100000", headers=AUTH)

        assert resp.status_code == 200
        assert json.loads(resp.data)["limit"] == 500

    def test_update_thread_rejects_non_integer_interval(self, api_client):
        client, db = api_client

        resp = client.patch(
            "/api/v1/threads/1", json={"search_interval_hours": "soon"}, headers=AUTH
        )

        assert resp.status_code == 400
        assert "search_interval_hours" in json.loads(resp.data)["error"]
        db.engine.begin.assert_not_called()

"""GET /api/v1/health pings the database and answers 503 when it is down."""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import OperationalError

from src.reporting.email_detector import EnhancedAbuseEmailDetector

DSN = "postgresql://anisakys:s3cret@db.internal:5432/anisakys"


@pytest.fixture
def api():
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        instance = PhishingAPI(MagicMock(), MagicMock(spec=EnhancedAbuseEmailDetector), api_key="k")
        instance.app.config["TESTING"] = True
        yield instance


def _unreachable_db(api):
    api.db_manager.engine.connect.side_effect = OperationalError(
        "SELECT 1", {}, Exception(f"could not connect to {DSN}")
    )


def test_healthy_database_returns_200(api):
    resp = api.app.test_client().get("/api/v1/health")

    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["status"] == "healthy"
    assert body["checks"] == {"database": "healthy"}
    api.db_manager.engine.connect.assert_called_once()


def test_unreachable_database_returns_503_without_leaking_details(api):
    _unreachable_db(api)

    resp = api.app.test_client().get("/api/v1/health")

    assert resp.status_code == 503
    body = json.loads(resp.data)
    assert body["status"] == "unhealthy"
    assert body["checks"] == {"database": "unhealthy"}
    text = resp.get_data(as_text=True)
    assert "s3cret" not in text and "db.internal" not in text and "could not" not in text


def test_degraded_is_still_200(api):
    api._health_checker.register("cache", lambda: {"status": "degraded", "message": "slow"})

    resp = api.app.test_client().get("/api/v1/health")

    assert resp.status_code == 200
    assert json.loads(resp.data)["status"] == "degraded"


def test_hanging_database_ping_times_out(api):
    release = threading.Event()
    api.db_manager.engine.connect.side_effect = lambda: release.wait(10)

    with patch("src.api.phishing_api.HEALTH_DB_TIMEOUT_SECONDS", 0.2):
        resp = api.app.test_client().get("/api/v1/health")
    release.set()

    assert resp.status_code == 503


def test_results_are_cached_to_bound_database_connections(api):
    client = api.app.test_client()

    for _ in range(5):
        assert client.get("/api/v1/health").status_code == 200

    assert api.db_manager.engine.connect.call_count == 1


def test_health_needs_no_authentication(api):
    assert api.app.test_client().get("/api/v1/health").status_code == 200

"""Stored captures (captures table) and GET /api/v1/sites/<id>/capture, on real PostgreSQL."""

import uuid
from typing import Any, Dict, Iterator, Tuple, cast
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

from src.capture import service
from src.capture.service import latest_capture, record_scan_capture, store_scan_capture

AUTH = {"Authorization": "Bearer test_key"}


@pytest.fixture
def scan_api(migrated_db_url: str) -> Iterator[Tuple[Any, Any]]:
    """A ``PhishingAPI`` on the migrated schema whose validator the test controls.

    Args:
        migrated_db_url: URL of the isolated, migrated schema.

    Yields:
        Tuple of (PhishingAPI, DatabaseManager).
    """
    from src.database.manager import DatabaseManager
    from src.reporting.email_detector import EnhancedAbuseEmailDetector

    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        db_manager = DatabaseManager(db_url=migrated_db_url)
        detector = MagicMock(spec=EnhancedAbuseEmailDetector)
        detector.get_enhanced_abuse_email.return_value = []
        api = PhishingAPI(db_manager, detector, api_key="test_key")
        api.app.config["TESTING"] = True
        yield api, db_manager
        db_manager.engine.dispose()


def _site(db_manager) -> Tuple[int, str]:
    url = f"https://capture-{uuid.uuid4().hex[:10]}.example/login"
    with db_manager.engine.begin() as conn:
        site_id = conn.execute(
            text(
                "INSERT INTO phishing_sites (url, site_status, first_seen, last_seen) "
                "VALUES (:url, 'up', '2026-10-04 08:00:00', '2026-10-04 08:00:00') RETURNING id"
            ),
            {"url": url},
        ).scalar_one()
    return int(site_id), url


def _scan(url: str, **capture: Any) -> Dict[str, Any]:
    """A comprehensive-scan result as MultiAPIValidator returns it (only what is stored)."""
    return {
        "url": url,
        "capture": {
            "status": "ok",
            "error": None,
            "final_url": url,
            "http_status": 200,
            "tls_valid": False,
            "server_ip": "203.0.113.7",
            "redirect_chain": [{"url": url, "status": 200}],
            "favicon_url": None,
            "elapsed_ms": 812.0,
            **capture,
        },
        "capture_hashes": {
            "html_sha256": "a" * 64,
            "html_tlsh": "T1" + "0" * 70,
            "screenshot_phash": None,
            "favicon_mmh3": -1234567,
            "favicon_phash": "f" * 16,
        },
        "page_features": {"credential_form": True, "password_fields": 1, "kit_traits": {}},
        "visual_brand": {"top_brand": "nequi", "brand_domain_mismatch": True},
    }


class TestStorage:
    def test_a_scan_capture_is_stored_and_read_back(self, pg_api):
        _, db_manager, _ = pg_api
        site_id, url = _site(db_manager)

        with db_manager.engine.begin() as conn:
            capture_id = store_scan_capture(conn, _scan(url), site_id)
        with db_manager.engine.connect() as conn:
            stored = latest_capture(conn, site_id)

        assert stored is not None and stored["id"] == capture_id
        assert stored["status"] == "ok" and stored["http_status"] == 200
        assert stored["tls_valid"] is False and stored["server_ip"] == "203.0.113.7"
        assert stored["redirect_chain"] == [{"url": url, "status": 200}]
        assert stored["hashes"]["favicon_mmh3"] == -1234567
        assert stored["features"] == {
            "credential_form": True,
            "password_fields": 1,
            "kit_traits": {},
        }
        assert stored["visual_brand"] == {"top_brand": "nequi", "brand_domain_mismatch": True}
        assert stored["captured_at"]

    def test_a_site_keeps_only_its_newest_captures(self, pg_api, monkeypatch):
        _, db_manager, _ = pg_api
        monkeypatch.setattr(service, "MAX_CAPTURES_PER_SITE", 2)
        site_id, url = _site(db_manager)

        with db_manager.engine.begin() as conn:
            ids = [store_scan_capture(conn, _scan(url, http_status=s), site_id) for s in (1, 2, 3)]
        with db_manager.engine.connect() as conn:
            kept = conn.execute(
                text("SELECT id FROM captures WHERE site_id = :s ORDER BY id"), {"s": site_id}
            ).scalars()
            assert list(kept) == ids[1:]
            assert latest_capture(conn, site_id)["http_status"] == 3  # type: ignore[index]

    def test_scans_without_a_capture_store_nothing(self, pg_api):
        _, db_manager, _ = pg_api
        site_id, url = _site(db_manager)

        with db_manager.engine.begin() as conn:
            assert store_scan_capture(conn, {"url": url}, site_id) is None
            assert store_scan_capture(conn, _scan(url, status="weird"), site_id) is None
            assert record_scan_capture(conn, url, {"url": url}) is None
        with db_manager.engine.connect() as conn:
            assert latest_capture(conn, site_id) is None

    def test_record_needs_a_site_and_never_fails_the_caller(self, pg_api):
        _, db_manager, _ = pg_api
        site_id, url = _site(db_manager)

        with db_manager.engine.begin() as conn:
            assert record_scan_capture(conn, "https://no-site.example/", _scan(url)) is None
            conn.execute(
                text("UPDATE phishing_sites SET priority = 'high' WHERE id = :s"), {"s": site_id}
            )
            # A value the database refuses: the savepoint rolls back, the caller goes on.
            assert record_scan_capture(conn, url, _scan(url, http_status="not a number")) is None
        with db_manager.engine.connect() as conn:
            priority = conn.execute(
                text("SELECT priority FROM phishing_sites WHERE id = :s"), {"s": site_id}
            ).scalar_one()
            assert priority == "high" and latest_capture(conn, site_id) is None

        with db_manager.engine.begin() as conn:
            assert record_scan_capture(conn, url, _scan(url)) is not None
        with db_manager.engine.connect() as conn:
            assert latest_capture(conn, site_id) is not None

    def _fusion_columns(self, db_manager, site_id):
        with db_manager.engine.connect() as conn:
            return conn.execute(
                text(
                    "SELECT fusion_probability, fusion_coverage, detector_version "
                    "FROM phishing_sites WHERE id = :s"
                ),
                {"s": site_id},
            ).first()

    def test_a_scan_with_fusion_reaches_the_site_row(self, pg_api):
        _, db_manager, _ = pg_api
        site_id, url = _site(db_manager)
        scan = _scan(url)
        scan["fusion"] = {
            "model_id": "fusion-v1",
            "probability": 0.93,
            "coverage": 0.7,
            "level": "high",
            "confidence": 93,
            "floors_applied": [],
            "active": True,
        }

        with db_manager.engine.begin() as conn:
            store_scan_capture(conn, scan, site_id)
        probability, coverage, version = self._fusion_columns(db_manager, site_id)
        assert probability == pytest.approx(0.93)
        assert coverage == pytest.approx(0.7)
        assert version == "fusion-v1:active"

    def test_a_shadow_fusion_is_marked_and_no_fusion_stays_null(self, pg_api):
        _, db_manager, _ = pg_api
        site_id, url = _site(db_manager)
        scan = _scan(url)
        scan["fusion"] = {
            "model_id": "fusion-v1",
            "probability": 0.31,
            "coverage": 0.7,
            "level": "low",
            "confidence": 69,
            "floors_applied": [],
            "active": False,
        }
        with db_manager.engine.begin() as conn:
            store_scan_capture(conn, scan, site_id)
        _, _, version = self._fusion_columns(db_manager, site_id)
        assert version == "fusion-v1:shadow"

        plain = _scan(url, http_status=301)
        with db_manager.engine.begin() as conn:
            store_scan_capture(conn, plain, site_id)
        probability, coverage, version = self._fusion_columns(db_manager, site_id)
        assert probability is None and coverage is None and version is None


class TestApi:
    def test_unknown_site_and_site_without_capture(self, pg_api):
        client, db_manager, headers = pg_api
        site_id, _ = _site(db_manager)

        missing = client.get("/api/v1/sites/999999/capture", headers=headers)
        empty = client.get(f"/api/v1/sites/{site_id}/capture", headers=headers)
        anonymous = client.get(f"/api/v1/sites/{site_id}/capture")

        assert missing.status_code == 404
        assert empty.status_code == 200 and empty.get_json() == {"capture": None}
        assert anonymous.status_code == 401

    def test_a_scan_through_the_api_keeps_its_capture(self, scan_api):
        api, db_manager = scan_api
        url = f"https://scan-{uuid.uuid4().hex[:10]}.example/login"
        cast(MagicMock, api.multi_api_validator).comprehensive_scan.return_value = {
            **_scan(url),
            "domain": url.split("/")[2],
            "aggregated_threat_level": "high",
            "confidence_score": 90,
        }
        client = api.app.test_client()

        with patch("src.api.phishing_api.assess_url_target", return_value="unresolved"):
            scanned = client.post(
                "/api/v1/multi-scan", json={"url": url, "include_screenshot": False}, headers=AUTH
            )
        assert scanned.status_code == 200
        with db_manager.engine.connect() as conn:
            site_id = conn.execute(
                text("SELECT id FROM phishing_sites WHERE url = :u"), {"u": url}
            ).scalar_one()

        body = client.get(f"/api/v1/sites/{site_id}/capture", headers=AUTH).get_json()
        assert body["capture"]["visual_brand"]["top_brand"] == "nequi"
        assert body["capture"]["features"]["credential_form"] is True
        assert body["capture"]["final_url"] == url

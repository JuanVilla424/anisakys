"""Threat accounting after the UI-data batch: benign labels excluded from
counts and TTD, priority derived from the verdict on every scan write."""

import datetime
from typing import Any, Iterator
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

AUTH = {"Authorization": "Bearer test_key"}


@pytest.fixture
def scan_api(migrated_db_url: str) -> Iterator[Any]:
    """A ``PhishingAPI`` on the migrated schema whose validator the test controls."""
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


def _site(db_manager, **columns: Any) -> int:
    from tests.api.test_labels_api_pg import _site as base_site

    return base_site(db_manager, **columns)


class TestDerivedPriority:
    @pytest.mark.parametrize(
        ("level", "label", "expected"),
        [
            ("critical", None, "high"),
            ("high", None, "high"),
            ("medium", None, "medium"),
            ("low", None, "low"),
            ("clean", None, "low"),
            ("unknown", None, "low"),
            (None, None, "low"),
            # An analyst's label always wins over the verdict.
            ("critical", "benign", "low"),
            ("clean", "phishing", "high"),
        ],
    )
    def test_mapping(self, level, label, expected):
        from src.labels import derived_priority

        assert derived_priority(level, label) == expected


class TestScanWritesPriority:
    def _scan(self, url: str, level: str) -> dict:
        return {
            "url": url,
            "virustotal": {},
            "urlvoid": {},
            "phishtank": {},
            "aggregated_threat_level": level,
            "confidence_score": 90,
        }

    def test_a_clean_verdict_writes_low_and_a_critical_one_high(self, scan_api):
        api, db_manager = scan_api
        url = "https://priority-scan.example/login"
        client = api.app.test_client()

        for level, expected in (("clean", "low"), ("critical", "high")):
            api.multi_api_validator.comprehensive_scan.return_value = self._scan(url, level)
            with patch("src.api.phishing_api.assess_url_target", return_value="unresolved"):
                scanned = client.post(
                    "/api/v1/multi-scan",
                    json={"url": url, "include_screenshot": False},
                    headers=AUTH,
                )
            assert scanned.status_code == 200
        with db_manager.engine.connect() as conn:
            priority = conn.execute(
                text("SELECT priority FROM phishing_sites WHERE url = :u"), {"u": url}
            ).scalar_one()
        assert priority == "high"  # the last (critical) scan's verdict


class TestCountsExcludeBenign:
    def test_active_threats_and_badge_skip_analyst_dismissed_sites(self, scan_api):
        api, db_manager = scan_api
        client = api.app.test_client()

        # The schema is shared across the module's tests: assert deltas, so
        # whatever the other tests left in the table does not break this one.
        before = client.get("/api/v1/stats", headers=AUTH).get_json()["active_sites"]
        _site(
            db_manager, url="https://benign-up.example/", site_status="up", label_verdict="benign"
        )
        _site(db_manager, url="https://threat-up.example/", site_status="up")
        _site(db_manager, url="https://gone.example/", site_status="down")

        stats = client.get("/api/v1/stats", headers=AUTH).get_json()
        assert stats["active_sites"] == before + 1  # only the unlabelled live site

        nav = client.get("/api/v1/nav/counts", headers=AUTH).get_json()
        assert nav["threats"] == before + 1

    def test_campaigns_skip_registrars_with_only_benign_live_sites(self, scan_api):
        api, db_manager = scan_api
        client = api.app.test_client()

        before = client.get("/api/v1/nav/counts", headers=AUTH).get_json()["campaigns"]
        _site(
            db_manager,
            url="https://a-benign.example/",
            site_status="up",
            label_verdict="benign",
            registrar_name="OnlyBenign Registrar",
        )
        _site(
            db_manager,
            url="https://b-benign.example/",
            site_status="up",
            label_verdict="benign",
            registrar_name="OnlyBenign Registrar",
        )

        nav = client.get("/api/v1/nav/counts", headers=AUTH).get_json()
        assert nav["campaigns"] == before  # nothing new: only benign sites live


class TestTimeToDetectExcludesBenign:
    def test_a_dismissed_site_does_not_dwarf_the_median(self, migrated_db_url):
        from src.database.manager import DatabaseManager
        from src.observability.operational import compute_operational_metrics

        db_manager = DatabaseManager(db_url=migrated_db_url)
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            naive = lambda days: (now - datetime.timedelta(days=days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )  # noqa: E731
            # A benign-labelled site registered in 1995 (would add ~31 years),
            # a clean-verdict one (an abstention, not a detection) and a real
            # detection: registered 10 days ago, seen by us 8 days ago.
            _site(
                db_manager,
                url="https://old-benign.example/",
                site_status="up",
                label_verdict="benign",
                registration_date="1995-08-20",
                first_seen=naive(1),
            )
            _site(
                db_manager,
                url="https://old-but-clean.example/",
                site_status="up",
                multi_api_threat_level="clean",
                registration_date="1995-08-20",
                first_seen=naive(1),
            )
            _site(
                db_manager,
                url="https://fresh-detection.example/",
                site_status="up",
                registration_date=naive(10),
                first_seen=naive(8),
            )
            metrics = compute_operational_metrics(db_manager.engine, days=30, now=now)
        finally:
            db_manager.engine.dispose()
        ttd = metrics["durations_hours"]["time_to_detect"]
        assert ttd["count"] == 1  # only the real detection
        # 8 days minus 10 days before it = 2 days = 48 hours (not ~272,000).
        assert ttd["median"] == pytest.approx(48.0, abs=1.0)

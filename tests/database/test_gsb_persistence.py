"""DB tests for the GSB query methods of DatabaseManager.

An unchecked GSB lookup (API error, timeout, unconfigured key) must never be
persisted as "safe" nor reset the 24h rescan clock.
"""

import json

import pytest
from sqlalchemy import text

from src.database.manager import DATABASE_URL, DatabaseManager
from tests.support.isolated_schema import isolated_schema

URL = "https://gsb-phish.example/login"
OLD_CHECK = "2026-01-01 00:00:00"


@pytest.fixture
def manager():
    with isolated_schema(DATABASE_URL) as (engine, url):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO phishing_sites (url, site_status, gsb_safe, gsb_threat_type,"
                    " gsb_last_check, gsb_result) VALUES (:u, 'up', 0, 'SOCIAL_ENGINEERING',"
                    " :t, :r)"
                ),
                {"u": URL, "t": OLD_CHECK, "r": json.dumps({"status": "listed"})},
            )
        yield DatabaseManager(db_url=url)


def _row(manager):
    with manager.engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT gsb_safe, gsb_threat_type, gsb_last_check::text, gsb_result"
                " FROM phishing_sites WHERE url = :u"
            ),
            {"u": URL},
        ).one()


class TestUpdateGsbResult:
    def test_unchecked_result_is_not_persisted(self, manager):
        errored = {"checked": False, "status": "error", "safe": None, "error": "API error: 503"}
        result = manager.update_gsb_result(URL, errored, previous_safe=False)
        assert result["updated"] is False
        safe, threat, last_check, _ = _row(manager)
        assert safe == 0
        assert threat == "SOCIAL_ENGINEERING"
        assert last_check == OLD_CHECK

    def test_checked_result_is_persisted_with_most_severe_threat(self, manager):
        listed = {
            "checked": True,
            "status": "listed",
            "safe": False,
            "threats_found": [
                {"threat_type": "SOCIAL_ENGINEERING"},
                {"threat_type": "MALWARE"},
            ],
        }
        result = manager.update_gsb_result(URL, listed, previous_safe=True)
        assert result["updated"] is True
        assert result["threat_type"] == "MALWARE"
        _, threat, last_check, _ = _row(manager)
        assert threat == "MALWARE"
        assert last_check != OLD_CHECK


class TestUpdateAnalysisResultsGsb:
    def test_errored_gsb_keeps_stored_columns(self, manager):
        results = {
            "aggregated_threat_level": "high",
            "confidence_score": 80,
            "google_safe_browsing": {"checked": False, "status": "error", "safe": None},
        }
        assert manager.update_analysis_results(URL, results, {"auto_report": False})
        safe, threat, last_check, gsb_result = _row(manager)
        assert safe == 0
        assert threat == "SOCIAL_ENGINEERING"
        assert last_check == OLD_CHECK
        assert json.loads(gsb_result) == {"status": "listed"}

    def test_checked_gsb_is_written(self, manager):
        results = {
            "aggregated_threat_level": "low",
            "confidence_score": 50,
            "google_safe_browsing": {"checked": True, "status": "not_listed", "safe": True},
        }
        assert manager.update_analysis_results(URL, results, {"auto_report": False})
        safe, threat, last_check, _ = _row(manager)
        assert safe == 1
        assert threat is None
        assert last_check != OLD_CHECK

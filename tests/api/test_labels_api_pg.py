"""Analyst labels, the approval queue and operational metrics through the API.

POST/GET /api/v1/sites/<id>/labels, GET /api/v1/labels, GET
/api/v1/reports/approvals, the ``label`` filter of GET /api/v1/sites and GET
/api/v1/metrics/operational, on real PostgreSQL.
"""

import hashlib
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator
from unittest.mock import patch

from sqlalchemy import text

DB_KEY = "ank_labels-api-tests"
DB_HEADERS = {"Authorization": f"Bearer {DB_KEY}"}


@contextmanager
def key_with(scopes: str, name: str = "analyst-key") -> Iterator[None]:
    """Authenticate DB_KEY as a database key holding ``scopes``."""
    row = {
        "scopes": scopes,
        "allowed_ips": None,
        "key_hash": hashlib.sha256(DB_KEY.encode()).hexdigest(),
        "name": name,
        "key_prefix": "ank_label",
    }
    with (
        patch("src.auth._lookup_db_key", return_value=row),
        patch("src.auth._update_last_used"),
    ):
        yield


def _site(db_manager, **columns: Any) -> int:
    values: Dict[str, Any] = {
        "url": f"https://api-{uuid.uuid4().hex[:10]}.example/verify",
        "site_status": "up",
        "multi_api_threat_level": "medium",
        "api_confidence_score": 72,
        "first_seen": "2026-10-02 08:00:00",
        "last_seen": "2026-10-03 08:00:00",
        **columns,
    }
    names = ", ".join(values)
    params = ", ".join(f":{name}" for name in values)
    with db_manager.engine.begin() as conn:
        return int(
            conn.execute(
                text(f"INSERT INTO phishing_sites ({names}) VALUES ({params}) RETURNING id"),
                values,
            ).scalar_one()
        )


def _label(client, site_id: int, headers, **body: Any):
    return client.post(f"/api/v1/sites/{site_id}/labels", json=body, headers=headers)


class TestPostLabel:
    def test_master_key_confirms_a_site(self, pg_api):
        client, db, master = pg_api
        site_id = _site(db)

        resp = _label(client, site_id, master, action="confirm", brand="Nequi", note="live")

        assert resp.status_code == 201
        body = resp.get_json()
        assert body["label"]["verdict"] == "phishing"
        assert body["label"]["action"] == "confirm"
        assert body["label"]["brand"] == "Nequi"
        assert body["label"]["labeled_by"] == "master"
        assert body["label"]["detector_snapshot"]["multi_api_threat_level"] == "medium"
        assert body["label"]["created_at"].endswith("+00:00")
        assert body["site"]["label_verdict"] == "phishing"
        assert body["site"]["requires_manual_review"] is False
        assert body["released_from_approval"] is False

    def test_write_key_can_dismiss_and_is_named_in_the_label(self, pg_api):
        client, db, _ = pg_api
        site_id = _site(db)

        with key_with("read,write", name="soc-analyst"):
            resp = _label(client, site_id, DB_HEADERS, action="dismiss")

        assert resp.status_code == 201
        assert resp.get_json()["label"]["labeled_by"] == "soc-analyst"
        assert resp.get_json()["site"]["label_verdict"] == "benign"

    def test_report_needs_report_send(self, pg_api):
        client, db, _ = pg_api
        site_id = _site(db)

        with key_with("read,write,report"):
            resp = _label(client, site_id, DB_HEADERS, action="report")

        assert resp.status_code == 403
        assert "report_send" in resp.get_json()["error"]

    def test_report_send_key_can_report_but_not_confirm(self, pg_api):
        client, db, _ = pg_api
        site_id = _site(db)

        with key_with("report_send"):
            reported = _label(client, site_id, DB_HEADERS, action="report")
            confirmed = _label(client, site_id, DB_HEADERS, action="confirm")

        assert reported.status_code == 201
        assert reported.get_json()["site"]["manual_flag"] is True
        assert confirmed.status_code == 403
        assert "write" in confirmed.get_json()["error"]

    def test_read_key_is_refused(self, pg_api):
        client, db, _ = pg_api
        with key_with("read"):
            resp = _label(client, _site(db), DB_HEADERS, action="confirm")

        assert resp.status_code == 403

    def test_invalid_bodies_are_rejected(self, pg_api):
        client, db, master = pg_api
        site_id = _site(db)

        bad_action = _label(client, site_id, master, action="approve")
        long_note = _label(client, site_id, master, action="confirm", note="x" * 1001)
        bad_brand = _label(client, site_id, master, action="confirm", brand=7)
        not_object = client.post(f"/api/v1/sites/{site_id}/labels", json=[1], headers=master)

        assert bad_action.status_code == 400 and bad_action.get_json()["parameter"] == "action"
        assert long_note.status_code == 400 and long_note.get_json()["parameter"] == "note"
        assert bad_brand.status_code == 400 and bad_brand.get_json()["parameter"] == "brand"
        assert not_object.status_code == 400

    def test_unknown_site_is_404(self, pg_api):
        client, _db, master = pg_api

        resp = _label(client, 987654321, master, action="confirm")

        assert resp.status_code == 404


class TestReadLabels:
    def test_site_history_is_newest_first(self, pg_api):
        client, db, master = pg_api
        site_id = _site(db)
        _label(client, site_id, master, action="confirm")
        _label(client, site_id, master, action="dismiss")

        resp = client.get(f"/api/v1/sites/{site_id}/labels", headers=master)

        assert resp.status_code == 200
        actions = [item["action"] for item in resp.get_json()["items"]]
        assert actions == ["dismiss", "confirm"]

    def test_label_listing_filters_and_validates(self, pg_api):
        client, db, master = pg_api
        _label(client, _site(db), master, action="dismiss")

        benign = client.get("/api/v1/labels?verdict=benign", headers=master)
        invalid = client.get("/api/v1/labels?verdict=maybe", headers=master)

        assert benign.status_code == 200
        body = benign.get_json()
        assert body["total"] >= 1 and body["limit"] == 50 and body["offset"] == 0
        assert {item["verdict"] for item in body["items"]} == {"benign"}
        assert invalid.status_code == 400 and invalid.get_json()["parameter"] == "verdict"


class TestApprovals:
    def test_submission_without_report_send_waits_until_an_analyst_reports_it(self, pg_api):
        client, _db, master = pg_api
        url = f"https://pending-{uuid.uuid4().hex[:8]}.example/login"

        with (
            key_with("report", name="partner-feed"),
            patch("src.api.phishing_api.assess_url_target", return_value="public"),
        ):
            submitted = client.post("/api/v1/report", json={"url": url}, headers=DB_HEADERS)
        queue = client.get("/api/v1/reports/approvals?limit=200", headers=master).get_json()

        assert submitted.status_code == 202
        item = next(i for i in queue["items"] if i["url"] == url)
        assert item["requested_by"] == "partner-feed"
        assert item["requested_at"].endswith("+00:00")

        approved = _label(client, item["site_id"], master, action="report")
        queue_after = client.get("/api/v1/reports/approvals?limit=200", headers=master)

        assert approved.status_code == 201
        assert approved.get_json()["released_from_approval"] is True
        assert url not in {i["url"] for i in queue_after.get_json()["items"]}


class TestSitesLabelFilter:
    def test_sites_expose_and_filter_on_the_label(self, pg_api):
        client, db, master = pg_api
        labelled = _site(db)
        unlabelled = _site(db)
        _label(client, labelled, master, action="confirm")

        phishing = client.get("/api/v1/sites?label=phishing&limit=500", headers=master)
        open_ = client.get("/api/v1/sites?label=unlabeled&limit=500", headers=master)
        invalid = client.get("/api/v1/sites?label=maybe", headers=master)

        phishing_items = {i["id"]: i for i in phishing.get_json()["items"]}
        assert phishing_items[labelled]["label_verdict"] == "phishing"
        assert phishing_items[labelled]["labeled_at"].endswith("+00:00")
        assert unlabelled not in phishing_items
        open_ids = {i["id"] for i in open_.get_json()["items"]}
        assert unlabelled in open_ids and labelled not in open_ids
        assert invalid.status_code == 400


class TestOperationalMetrics:
    def test_returns_the_metrics_document(self, pg_api):
        client, _db, master = pg_api

        resp = client.get("/api/v1/metrics/operational?days=7", headers=master)

        assert resp.status_code == 200
        body = resp.get_json()
        assert body["window_days"] == 7
        assert set(body["durations_hours"]) == {
            "time_to_detect",
            "time_to_report",
            "time_to_first_outage",
            "time_to_last_outage",
            "lead_over_feeds",
        }
        assert "approvals_waiting" in body["queues"]

    def test_days_are_validated_and_scope_is_enforced(self, pg_api):
        client, _db, master = pg_api

        out_of_range = client.get("/api/v1/metrics/operational?days=0", headers=master)
        with key_with("scan"):
            forbidden = client.get("/api/v1/metrics/operational", headers=DB_HEADERS)
        with key_with("metrics"):
            allowed = client.get("/api/v1/metrics/operational", headers=DB_HEADERS)

        assert out_of_range.status_code == 400
        assert forbidden.status_code == 403
        assert allowed.status_code == 200

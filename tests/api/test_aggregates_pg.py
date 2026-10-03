"""Integration tests for aggregate endpoints (graph, campaigns) on real PostgreSQL."""

import uuid
from typing import Optional

from sqlalchemy import text


def _insert_site(
    db_manager,
    url: str,
    *,
    registrar: Optional[str] = None,
    ip: Optional[str] = None,
    status: str = "up",
    last_seen: str = "2026-01-02 00:00:00",
) -> None:
    """Insert one phishing_sites row into the migrated schema.

    Args:
        db_manager: DatabaseManager bound to the isolated schema.
        url: Site URL (unique).
        registrar: Registrar name.
        ip: Resolved IP address.
        status: site_status value.
        last_seen: last_seen timestamp literal.
    """
    with db_manager.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO phishing_sites (url, registrar_name, resolved_ip, site_status, "
                "first_seen, last_seen, api_confidence_score, multi_api_threat_level) "
                "VALUES (:url, :reg, :ip, :status, '2026-01-01', :last_seen, 80, 'high')"
            ),
            {"url": url, "reg": registrar, "ip": ip, "status": status, "last_seen": last_seen},
        )


class TestGraphFocusOnPostgres:
    def test_registrar_focus_finds_rows_beyond_the_limit(self, pg_api):
        client, db_manager, headers = pg_api
        tag = uuid.uuid4().hex[:8]
        registrar = f"Mixed Case Registrar {tag}"
        _insert_site(
            db_manager, f"https://old-{tag}.example/", registrar=registrar, last_seen="2020-01-01"
        )
        for i in range(3):
            _insert_site(db_manager, f"https://new-{i}-{tag}.example/", last_seen="2026-06-01")

        resp = client.get(
            "/api/v1/graph",
            query_string={"focus": f"registrar:{registrar.upper()}", "limit": 1},
            headers=headers,
        )

        assert resp.status_code == 200, resp.get_json()
        ids = {n["id"] for n in resp.get_json()["nodes"]}
        assert ids == {f"registrar:{registrar}", f"domain:old-{tag}.example"}


class TestCampaignsOnPostgres:
    def test_clusters_come_from_one_query_with_recent_threats(self, pg_api):
        client, db_manager, headers = pg_api
        tag = uuid.uuid4().hex[:8]
        registrar = f"Cluster Registrar {tag}"
        for i in range(3):
            _insert_site(
                db_manager,
                f"https://c{i}-{tag}.example/",
                registrar=registrar,
                ip=f"198.51.100.{i + 1}",
                status="down" if i == 0 else "up",
            )
        _insert_site(db_manager, f"https://lonely-{tag}.example/", registrar=f"Solo {tag}")

        resp = client.get("/api/v1/campaigns", headers=headers)

        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        item = next(c for c in body["items"] if c["registrar"] == registrar)
        assert item["sites"] == 3
        assert item["takedowns"] == 1
        assert item["confidence"] == 80
        assert sorted(item["resolved_ips"]) == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
        assert {t["url"] for t in item["threats"]} == {
            f"https://c{i}-{tag}.example/" for i in range(3)
        }
        threat = item["threats"][0]
        assert set(threat) == {"url", "status", "first_seen", "threat_level"}
        assert threat["first_seen"] == "2026-01-01 00:00:00"
        assert not any(c["registrar"] == f"Solo {tag}" for c in body["items"])

    def test_campaign_ids_are_stable_hashes_of_the_registrar(self, pg_api):
        from src.api.phishing_api import campaign_id

        client, db_manager, headers = pg_api
        tag = uuid.uuid4().hex[:8]
        registrar = f"Stable Registrar {tag}"
        for i in range(2):
            _insert_site(db_manager, f"https://s{i}-{tag}.example/", registrar=registrar)

        first = client.get("/api/v1/campaigns", headers=headers).get_json()
        # A newer, more active cluster changes the ordering but not the IDs.
        for i in range(3):
            _insert_site(
                db_manager,
                f"https://n{i}-{tag}.example/",
                registrar=f"Newer {tag}",
                last_seen="2026-09-01",
            )
        second = client.get("/api/v1/campaigns", headers=headers).get_json()

        expected = campaign_id("registrar", registrar)
        assert expected.startswith("CAMP-") and len(expected) == 15
        for body in (first, second):
            item = next(c for c in body["items"] if c["registrar"] == registrar)
            assert item["id"] == expected


def test_campaigns_issue_a_single_query():
    """The endpoint used to run one extra query per registrar group (N+1)."""
    from unittest.mock import MagicMock, patch

    from src.reporting.email_detector import EnhancedAbuseEmailDetector

    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        db = MagicMock()
        api = PhishingAPI(db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="k")
    conn = db.engine.begin.return_value.__enter__.return_value
    conn.execute.return_value.fetchall.return_value = [
        ("Reg A", 2, 1, 1, None, None, ["192.0.2.1"], 50.0, []),
        ("Reg B", 3, 0, 3, None, None, None, None, '[{"url": "u"}]'),
    ]

    resp = api.app.test_client().get("/api/v1/campaigns", headers={"Authorization": "Bearer k"})

    assert resp.status_code == 200
    assert conn.execute.call_count == 1
    assert resp.get_json()["items"][1]["threats"] == [{"url": "u"}]


class TestIocsOnPostgres:
    def test_abuse_desk_mailboxes_are_not_exported_as_email_iocs(self, pg_api):
        client, db_manager, headers = pg_api
        tag = uuid.uuid4().hex[:8]
        _insert_site(db_manager, f"https://ioc-{tag}.example/", ip="198.51.100.77")
        with db_manager.engine.begin() as conn:
            conn.execute(
                text("UPDATE phishing_sites SET all_abuse_emails = :e WHERE url = :u"),
                {
                    "e": "abuse@registrar.example, abuse@hoster.example",
                    "u": f"https://ioc-{tag}.example/",
                },
            )

        email = client.get("/api/v1/intelligence/iocs?type=email", headers=headers).get_json()
        domains = client.get("/api/v1/intelligence/iocs?type=domain&limit=500", headers=headers)

        assert email["items"] == []
        assert email["counts"]["email"] == 0
        assert domains.status_code == 200
        assert f"ioc-{tag}.example" in {i["value"] for i in domains.get_json()["items"]}
        serialized = domains.get_data(as_text=True) + str(email)
        assert "abuse@registrar.example" not in serialized

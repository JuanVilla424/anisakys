"""Console read endpoints on real PostgreSQL: unknown values stay unknown.

Every test runs against the isolated, migrated schema of ``pg_api`` (see
``tests/api/conftest.py``); rows are tagged with a random token so tests in
this module do not see each other's data.
"""

import uuid
from typing import Any, Dict

from sqlalchemy import text


def _tag() -> str:
    return uuid.uuid4().hex[:8]


def _insert(db_manager, table: str, values: Dict[str, Any]) -> int:
    """Insert one row and return its id.

    Args:
        db_manager: DatabaseManager bound to the isolated schema.
        table: Table name (a constant in these tests).
        values: Column -> value.

    Returns:
        The new row's ``id``.
    """
    columns = ", ".join(values)
    placeholders = ", ".join(f":{name}" for name in values)
    with db_manager.engine.begin() as conn:
        return int(
            conn.execute(
                text(f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING id"),
                values,
            ).scalar_one()
        )


def _site(db_manager, url: str, **columns: Any) -> int:
    values: Dict[str, Any] = {
        "url": url,
        "first_seen": "2026-01-01 10:00:00",
        "last_seen": "2026-01-02 10:00:00",
    }
    values.update(columns)
    return _insert(db_manager, "phishing_sites", values)


def _sites_by_url(client, headers, search: str) -> Dict[str, Dict[str, Any]]:
    resp = client.get("/api/v1/sites", query_string={"search": search}, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return {item["url"]: item for item in resp.get_json()["items"]}


class TestSites:
    def test_takedown_date_and_timestamps_carry_a_utc_offset(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        _site(
            db_manager,
            f"https://down-{tag}.example/",
            site_status="down",
            takedown_date="2026-02-03 04:05:06",
        )
        _site(db_manager, f"https://up-{tag}.example/")

        items = _sites_by_url(client, headers, tag)

        down = items[f"https://down-{tag}.example/"]
        assert down["takedown_date"] == "2026-02-03T04:05:06+00:00"
        assert down["first_seen"] == "2026-01-01T10:00:00+00:00"
        assert down["last_seen"] == "2026-01-02T10:00:00+00:00"
        assert items[f"https://up-{tag}.example/"]["takedown_date"] is None

    def test_null_columns_are_null_not_invented_defaults(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        _site(
            db_manager,
            f"https://nulls-{tag}.example/",
            source=None,
            priority=None,
            is_cloudflare=None,
        )

        item = _sites_by_url(client, headers, tag)[f"https://nulls-{tag}.example/"]

        assert item["source"] is None  # was "manual"
        assert item["priority"] is None  # was "medium"
        assert item["is_cloudflare"] is None  # was false
        # gsb_safe defaults to 1 in the schema, but GSB never checked the site.
        assert item["gsb_safe"] is None  # was true

    def test_stored_values_are_returned_as_stored(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        _site(
            db_manager,
            f"https://known-{tag}.example/",
            source="certstream",
            priority="high",
            is_cloudflare=0,
            gsb_safe=0,
            gsb_last_check="2026-01-05 00:00:00",
        )

        item = _sites_by_url(client, headers, tag)[f"https://known-{tag}.example/"]

        assert item["source"] == "certstream"
        assert item["priority"] == "high"
        assert item["is_cloudflare"] is False
        assert item["gsb_safe"] is False


class TestSiteSources:
    def test_counts_per_source_include_null(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        before = client.get("/api/v1/sites/sources", headers=headers).get_json()
        null_before = next((s["count"] for s in before if s["source"] is None), 0)
        for i in range(2):
            _site(db_manager, f"https://src-{i}-{tag}.example/", source=f"feed-{tag}")
        _site(db_manager, f"https://nosrc-{tag}.example/", source=None)

        resp = client.get("/api/v1/sites/sources", headers=headers)

        assert resp.status_code == 200
        body = resp.get_json()
        assert {"source": f"feed-{tag}", "count": 2} in body
        assert {"source": None, "count": null_before + 1} in body
        assert all(set(entry) == {"source", "count"} for entry in body)
        counts = [entry["count"] for entry in body]
        assert counts == sorted(counts, reverse=True)

    def test_requires_read_scope(self, pg_api):
        client, _, _ = pg_api

        assert client.get("/api/v1/sites/sources").status_code == 401


class TestThreads:
    def _thread_with_results(self, db_manager) -> int:
        tag = _tag()
        thread_id = _insert(
            db_manager,
            "analysis_threads",
            {
                "thread_type": "google_ads",
                "label": f"thread-{tag}",
                "status": "active",
                "started_at": "2026-03-01 08:00:00",
                "last_searched_at": "2026-03-02 09:30:00",
                # The stored counter drifts (feed/CT monitors increment it).
                "results_count": 42,
            },
        )
        older = _insert(
            db_manager,
            "thread_executions",
            {
                "thread_id": thread_id,
                "execution_type": "scheduled",
                "status": "completed",
                "started_at": "2026-03-01 08:00:00",
                "completed_at": "2026-03-01 08:05:00",
                "results_count": 2,
            },
        )
        _insert(
            db_manager,
            "thread_executions",
            {
                "thread_id": thread_id,
                "execution_type": "scheduled",
                "status": "completed",
                "started_at": "2026-03-02 09:00:00",
                "completed_at": "2026-03-02 09:30:00",
                "results_count": 1,
            },
        )
        _insert(
            db_manager,
            "thread_executions",
            {"thread_id": thread_id, "execution_type": "manual", "status": "running"},
        )
        for i, status in enumerate(("new", "threat", "discarded")):
            _insert(
                db_manager,
                "thread_results",
                {
                    "thread_id": thread_id,
                    "result_type": "ad",
                    "found_url": f"https://r{i}-{tag}.example/",
                    "status": status,
                    "execution_id": older,
                    "first_detected_at": "2026-03-01 08:01:00",
                    "last_detected_at": f"2026-03-0{i + 1} 08:01:00",
                },
            )
        return thread_id

    def test_counters_are_distinct_and_documented(self, pg_api):
        client, db_manager, headers = pg_api
        thread_id = self._thread_with_results(db_manager)

        threads = client.get("/api/v1/threads", headers=headers).get_json()["items"]
        results = client.get(f"/api/v1/threads/{thread_id}/results", headers=headers).get_json()

        thread = next(t for t in threads if t["id"] == thread_id)
        # Shown results (discarded one excluded) == the results endpoint's total.
        assert thread["results_count"] == 2
        assert thread["results_count"] == results["total"]
        # Every recorded result, discarded included (not the drifting column).
        assert thread["total_results"] == 3
        # The most recent completed execution recorded 1 result.
        assert thread["last_execution_results"] == 1

    def test_thread_without_executions_has_null_last_execution_results(self, pg_api):
        client, db_manager, headers = pg_api
        thread_id = _insert(
            db_manager,
            "analysis_threads",
            {"thread_type": "ct_monitor", "label": f"ct-{_tag()}", "status": "active"},
        )

        threads = client.get("/api/v1/threads", headers=headers).get_json()["items"]

        thread = next(t for t in threads if t["id"] == thread_id)
        assert thread["last_execution_results"] is None
        assert thread["results_count"] == 0 and thread["total_results"] == 0
        assert thread["completed_at"] is None

    def test_timestamps_carry_a_utc_offset(self, pg_api):
        client, db_manager, headers = pg_api
        thread_id = self._thread_with_results(db_manager)

        threads = client.get("/api/v1/threads", headers=headers).get_json()["items"]
        results = client.get(f"/api/v1/threads/{thread_id}/results", headers=headers).get_json()

        thread = next(t for t in threads if t["id"] == thread_id)
        assert thread["started_at"] == "2026-03-01T08:00:00+00:00"
        assert thread["last_searched_at"] == "2026-03-02T09:30:00+00:00"
        newest = results["items"][0]
        assert newest["last_detected_at"] == "2026-03-02T08:01:00+00:00"
        assert newest["first_detected_at"] == "2026-03-01T08:01:00+00:00"


class TestActivity:
    def test_missing_timestamps_are_null_and_sorted_last(self, pg_api):
        client, db_manager, headers = pg_api
        tag = _tag()
        site_id = _site(
            db_manager,
            f"https://undated-{tag}.example/",
            first_seen=None,
            multi_api_threat_level="unknown",
            priority=None,
        )
        _insert(
            db_manager,
            "abuse_reports",
            {
                "site_url": f"https://undated-{tag}.example/",
                "recipients": "[]",
                "report_id": f"ANISAKYS-20260101-{tag.upper()}",
                "report_date": None,
                "status": "sent",
            },
        )
        _site(db_manager, f"https://dated-{tag}.example/", first_seen="2026-05-05 05:05:05")

        resp = client.get("/api/v1/activity", query_string={"limit": 100}, headers=headers)

        assert resp.status_code == 200
        events = resp.get_json()
        by_id = {e["id"]: e for e in events}
        undated = by_id[f"det-{site_id}"]
        assert undated["timestamp"] is None  # was the time of the request
        assert undated["severity"] is None  # "unknown" verdict; was "medium" fallback
        assert undated["detail"].endswith("priority: unknown")
        assert by_id[f"rpt-ANISAKYS-20260101-{tag.upper()}"]["timestamp"] is None
        stamps = [e["timestamp"] for e in events]
        dated = [s for s in stamps if s is not None]
        assert stamps == dated + [None] * (len(stamps) - len(dated))
        assert dated == sorted(dated, reverse=True)
        assert all(s.endswith("+00:00") for s in dated)

    def test_limit_one_returns_the_newest_event(self, pg_api):
        """limit // 2 per source used to fetch nothing at all for limit=1."""
        client, db_manager, headers = pg_api
        tag = _tag()
        site_id = _site(db_manager, f"https://newest-{tag}.example/", first_seen="2030-01-01")

        events = client.get("/api/v1/activity?limit=1", headers=headers).get_json()

        assert [e["id"] for e in events] == [f"det-{site_id}"]
        assert events[0]["timestamp"] == "2030-01-01T00:00:00+00:00"

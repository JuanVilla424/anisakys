"""
Tests for src/monitoring/takedown.py

Covers: the N-consecutive-failures rule (decide_transition), the monitor loop
(shutdown, first-cycle event, loop guard), and DB integration against a
throw-away schema built from migrations 001 + 005: no auto-resolution on a
single probe, confirmation after N failing cycles, challenges/parking never
counted as takedowns, resurrection history, last_seen on every alive
observation, short per-site transactions without network I/O inside them,
rate-limited RDAP, the connectivity canary and concurrent-change safety;
plus save_offset / get_offset file I/O.
"""

import datetime
import threading
from contextlib import contextmanager
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

import src.monitoring.takedown as takedown_module
from src.database.manager import DATABASE_URL, DatabaseManager
from src.detection.liveness import ProbeClass, ProbeResult, SiteProbe
from src.monitoring.takedown import (
    SiteState,
    TakedownMonitor,
    decide_transition,
    get_offset,
    save_offset,
)
from tests.support.isolated_schema import isolated_schema

NOW = datetime.datetime(2026, 10, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
IP_A = "93.184.215.14"
IP_B = "93.184.215.15"


def _result(cls, code=None):
    return ProbeResult(cls, "desktop_chrome", code, cls.value)


def _probe(cls, code=None, ips=(IP_A,)):
    result = _result(cls, code)
    return SiteProbe(result, (result,), tuple(ips))


UP = _result(ProbeClass.UP, 200)
NXDOMAIN = _result(ProbeClass.NXDOMAIN)
CONN = _result(ProbeClass.CONNECTION_ERROR)
HTTP_404 = _result(ProbeClass.HTTP_ERROR, 404)
HTTP_500 = _result(ProbeClass.HTTP_ERROR, 500)
WAF = _result(ProbeClass.WAF_CHALLENGE, 403)
PARKED = _result(ProbeClass.PARKED, 200)
SSRF = _result(ProbeClass.SSRF_BLOCKED)


def _state(status="up", failures=0, parked=0, takedown=None):
    return SiteState(1, "https://phish.example/", status, takedown, failures, parked)


# ---------------------------------------------------------------------------
# decide_transition (pure)
# ---------------------------------------------------------------------------


class TestDecideTransition:
    def test_alive_resets_and_marks_up(self):
        t = decide_transition(_state("down", 5, 0, NOW), UP, 3, NOW)
        assert (t.status, t.takedown_date, t.consecutive_failures, t.seen_alive) == (
            "up",
            None,
            0,
            True,
        )

    @pytest.mark.parametrize("failure", [NXDOMAIN, CONN, HTTP_404])
    def test_failures_below_threshold_keep_status(self, failure):
        t = decide_transition(_state("up", 1), failure, 3, NOW)
        assert t.status == "up"
        assert t.consecutive_failures == 2

    @pytest.mark.parametrize("failure", [NXDOMAIN, CONN, HTTP_404])
    def test_threshold_confirms_down(self, failure):
        t = decide_transition(_state("up", 2), failure, 3, NOW)
        assert t.status == "down"
        assert t.takedown_date == NOW

    def test_down_keeps_original_takedown_date(self):
        earlier = NOW - datetime.timedelta(days=3)
        t = decide_transition(_state("down", 7, 0, earlier), NXDOMAIN, 3, NOW)
        assert t.status == "down"
        assert t.takedown_date == earlier

    def test_waf_challenge_never_down(self):
        t = decide_transition(_state("up", 2), WAF, 3, NOW)
        assert t.status == "up"
        assert t.consecutive_failures == 0
        assert t.seen_alive is True

    def test_parked_is_its_own_status_after_threshold(self):
        t1 = decide_transition(_state("up", 2, 1), PARKED, 3, NOW)
        assert t1.status == "up" and t1.consecutive_parked == 2 and t1.consecutive_failures == 0
        t2 = decide_transition(_state("up", 0, 2), PARKED, 3, NOW)
        assert t2.status == "parked"

    @pytest.mark.parametrize("inconclusive", [HTTP_500, SSRF])
    def test_inconclusive_resets_counters(self, inconclusive):
        t = decide_transition(_state("up", 2, 2), inconclusive, 3, NOW)
        assert (t.status, t.consecutive_failures, t.consecutive_parked) == ("up", 0, 0)

    def test_threshold_of_one(self):
        assert decide_transition(_state("up"), NXDOMAIN, 1, NOW).status == "down"


# ---------------------------------------------------------------------------
# Loop behaviour (no DB)
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db():
    return MagicMock()


class TestTakedownMonitorInit:
    def test_stores_db_manager_and_timeout(self, mock_db):
        mon = TakedownMonitor(db_manager=mock_db, timeout=30)
        assert mon.db_manager is mock_db
        assert mon.timeout == 30

    def test_default_check_interval_is_3600(self, mock_db):
        assert TakedownMonitor(db_manager=mock_db, timeout=10).check_interval == 3600

    def test_accepts_custom_check_interval(self, mock_db):
        mon = TakedownMonitor(db_manager=mock_db, timeout=10, check_interval=1800)
        assert mon.check_interval == 1800

    def test_stores_optional_monitoring_event(self, mock_db):
        event = threading.Event()
        mon = TakedownMonitor(db_manager=mock_db, timeout=10, monitoring_event=event)
        assert mon.monitoring_event is event

    def test_threshold_defaults_to_setting(self, mock_db, monkeypatch):
        monkeypatch.setattr(takedown_module.settings, "TAKEDOWN_CONSECUTIVE_FAILURES", 5)
        assert TakedownMonitor(db_manager=mock_db, timeout=10).failure_threshold == 5

    def test_canaries_parsed_from_setting(self, mock_db, monkeypatch):
        monkeypatch.setattr(
            takedown_module.settings, "TAKEDOWN_CANARY_URLS", " https://a.example , ,https://b"
        )
        mon = TakedownMonitor(db_manager=mock_db, timeout=10)
        assert mon.canary_urls == ["https://a.example", "https://b"]


class TestTakedownMonitorRun:
    def test_exits_immediately_when_shutdown_requested(self, mock_db, monkeypatch):
        monkeypatch.setattr(takedown_module, "is_shutdown_requested", lambda: True)
        prober = MagicMock()
        TakedownMonitor(db_manager=mock_db, timeout=10, prober=prober).run()
        assert not mock_db.engine.connect.called
        prober.assert_not_called()

    def test_sets_monitoring_event_even_if_first_cycle_fails(self, mock_db, monkeypatch):
        monkeypatch.setattr(takedown_module, "is_shutdown_requested", lambda: False)
        event = threading.Event()
        mon = TakedownMonitor(db_manager=mock_db, timeout=10, monitoring_event=event)
        with (
            patch.object(mon, "run_cycle", side_effect=RuntimeError("db gone")),
            patch("src.monitoring.takedown.wait_for_shutdown", side_effect=StopIteration),
        ):
            with pytest.raises(StopIteration):
                mon.run()
        assert event.is_set()

    def test_loop_survives_cycle_errors(self, mock_db, monkeypatch):
        monkeypatch.setattr(takedown_module, "is_shutdown_requested", lambda: False)
        mon = TakedownMonitor(db_manager=mock_db, timeout=10)
        waits = iter([False, StopIteration()])

        def fake_wait(_):
            item = next(waits)
            if isinstance(item, Exception):
                raise item
            return item

        with (
            patch.object(mon, "run_cycle", side_effect=RuntimeError("boom")) as cycle,
            patch("src.monitoring.takedown.wait_for_shutdown", side_effect=fake_wait),
        ):
            with pytest.raises(StopIteration):
                mon.run()
        assert cycle.call_count == 2


# ---------------------------------------------------------------------------
# DB integration
# ---------------------------------------------------------------------------


class TrackingEngine:
    """Engine proxy that records whether a connection/transaction is open."""

    def __init__(self, engine):
        self._engine = engine
        self.open = 0

    @contextmanager
    def begin(self):
        with self._engine.begin() as conn:
            self.open += 1
            try:
                yield conn
            finally:
                self.open -= 1

    @contextmanager
    def connect(self):
        with self._engine.connect() as conn:
            self.open += 1
            try:
                yield conn
            finally:
                self.open -= 1


class ScriptedProber:
    """Return scripted probes per URL and assert no DB work is in progress."""

    def __init__(self, engine: TrackingEngine, script: Dict[str, List[SiteProbe]]):
        self.engine = engine
        self.script = script
        self.calls: List[str] = []

    def __call__(self, url, timeout):
        assert self.engine.open == 0, "network probe issued while a DB transaction is open"
        self.calls.append(url)
        return self.script[url].pop(0)


@pytest.fixture
def schema():
    with isolated_schema(DATABASE_URL, ("001_baseline_schema.py", "005_takedown_status.py")) as (
        engine,
        url,
    ):
        manager = DatabaseManager(db_url=url)
        tracking = TrackingEngine(manager.engine)
        manager.engine = tracking  # type: ignore[assignment]
        yield manager, engine, tracking


def _add_site(engine, url, status="up", reports=("sent",)):
    with engine.begin() as conn:
        site_id = conn.execute(
            text("INSERT INTO phishing_sites (url, site_status) VALUES (:u, :s) RETURNING id"),
            {"u": url, "s": status},
        ).scalar_one()
        for i, report_status in enumerate(reports):
            conn.execute(
                text(
                    "INSERT INTO abuse_reports (site_url, site_id, recipients, report_id, status)"
                    " VALUES (:u, :i, 'abuse@host.example', :r, :s)"
                ),
                {"u": url, "i": site_id, "r": f"{url}-{i}", "s": report_status},
            )
    return site_id


def _site(engine, url):
    with engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT site_status, takedown_date, consecutive_failures, consecutive_parked,"
                    " last_probe_class, last_seen, resolved_ip, asn_provider, ip_checked_at"
                    " FROM phishing_sites WHERE url = :u"
                ),
                {"u": url},
            )
            .mappings()
            .one()
        )


def _report_statuses(engine, url):
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT status FROM abuse_reports WHERE site_url = :u ORDER BY id"), {"u": url}
        ).fetchall()
    return [r[0] for r in rows]


def _events(engine, url):
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT old_status, new_status, probe_class FROM site_status_events"
                " WHERE site_url = :u ORDER BY id"
            ),
            {"u": url},
        ).fetchall()
    return [tuple(r) for r in rows]


def _monitor(manager, prober, ip_lookup=None, threshold=3, workers=2):
    return TakedownMonitor(
        db_manager=manager,
        timeout=5,
        failure_threshold=threshold,
        max_workers=workers,
        canary_urls=[],
        prober=prober,
        ip_lookup=ip_lookup or (lambda ip: "Example Hosting"),
    )


URL = "https://phish.example/login"


class TestTakedownIntegration:
    def test_takedown_confirmed_only_after_n_failing_cycles(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL, reports=("sent", "acknowledged", "rejected"))
        prober = ScriptedProber(tracking, {URL: [_probe(ProbeClass.NXDOMAIN, ips=())] * 3})
        mon = _monitor(manager, prober)

        for cycle in (1, 2):
            mon.run_cycle()
            row = _site(engine, URL)
            assert row["site_status"] == "up"
            assert row["consecutive_failures"] == cycle
            assert _report_statuses(engine, URL) == ["sent", "acknowledged", "rejected"]

        stats = mon.run_cycle()
        row = _site(engine, URL)
        assert stats["transitions"] == 1
        assert row["site_status"] == "down"
        assert row["takedown_date"] is not None
        assert row["last_probe_class"] == "nxdomain"
        assert _report_statuses(engine, URL) == ["resolved", "resolved", "rejected"]
        assert _events(engine, URL) == [("up", "down", "nxdomain")]

    def test_waf_challenge_never_takes_site_down(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        prober = ScriptedProber(tracking, {URL: [_probe(ProbeClass.WAF_CHALLENGE, 403)] * 5})
        mon = _monitor(manager, prober)
        for _ in range(5):
            mon.run_cycle()
        row = _site(engine, URL)
        assert row["site_status"] == "up"
        assert row["consecutive_failures"] == 0
        assert row["last_seen"] is not None
        assert _report_statuses(engine, URL) == ["sent"]

    def test_parked_site_gets_parked_status_and_reports_stay_open(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        prober = ScriptedProber(tracking, {URL: [_probe(ProbeClass.PARKED, 200)] * 3})
        mon = _monitor(manager, prober)
        for _ in range(3):
            mon.run_cycle()
        assert _site(engine, URL)["site_status"] == "parked"
        assert _report_statuses(engine, URL) == ["sent"]
        assert _events(engine, URL) == [("up", "parked", "parked")]

    def test_inconclusive_cycle_breaks_the_streak(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        script = [
            _probe(ProbeClass.CONNECTION_ERROR),
            _probe(ProbeClass.CONNECTION_ERROR),
            _probe(ProbeClass.HTTP_ERROR, 500),
            _probe(ProbeClass.HTTP_ERROR, 404),
            _probe(ProbeClass.HTTP_ERROR, 404),
        ]
        prober = ScriptedProber(tracking, {URL: script})
        mon = _monitor(manager, prober)
        for _ in range(5):
            mon.run_cycle()
        row = _site(engine, URL)
        assert row["site_status"] == "up"
        assert row["consecutive_failures"] == 2

    def test_resurrection_is_recorded(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        script = [_probe(ProbeClass.NXDOMAIN, ips=())] * 3 + [_probe(ProbeClass.UP, 200)]
        prober = ScriptedProber(tracking, {URL: script})
        mon = _monitor(manager, prober)
        for _ in range(4):
            mon.run_cycle()
        row = _site(engine, URL)
        assert row["site_status"] == "up"
        assert row["takedown_date"] is None
        assert row["consecutive_failures"] == 0
        assert _events(engine, URL) == [("up", "down", "nxdomain"), ("down", "up", "up")]

    def test_last_seen_updated_on_every_alive_observation(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        prober = ScriptedProber(tracking, {URL: [_probe(ProbeClass.UP, 200)] * 2})
        mon = _monitor(manager, prober)
        t1, t2 = NOW, NOW + datetime.timedelta(minutes=20)
        mon.check_site(mon._load_sites()[0], now=t1)
        # last_seen is a legacy naive TIMESTAMP column (UTC session): compare wall-clock.
        assert _site(engine, URL)["last_seen"] == t1.replace(tzinfo=None)
        mon.check_site(mon._load_sites()[0], now=t2)
        assert _site(engine, URL)["last_seen"] == t2.replace(tzinfo=None)
        assert _events(engine, URL) == []

    def test_failure_does_not_touch_last_seen(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        script = [_probe(ProbeClass.UP, 200), _probe(ProbeClass.CONNECTION_ERROR)]
        mon = _monitor(manager, ScriptedProber(tracking, {URL: script}))
        mon.check_site(mon._load_sites()[0], now=NOW)
        mon.check_site(mon._load_sites()[0], now=NOW + datetime.timedelta(hours=1))
        assert _site(engine, URL)["last_seen"] == NOW.replace(tzinfo=None)

    def test_rdap_only_on_ip_change_or_once_a_day(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        lookups: List[str] = []

        def ip_lookup(ip):
            assert tracking.open == 0, "RDAP issued while a DB transaction is open"
            lookups.append(ip)
            return f"Provider for {ip}"

        script = [
            _probe(ProbeClass.UP, 200, ips=(IP_A,)),
            _probe(ProbeClass.UP, 200, ips=(IP_A,)),
            _probe(ProbeClass.UP, 200, ips=(IP_B,)),
            _probe(ProbeClass.UP, 200, ips=(IP_B,)),
            _probe(ProbeClass.UP, 200, ips=(IP_B,)),
        ]
        mon = _monitor(manager, ScriptedProber(tracking, {URL: script}), ip_lookup=ip_lookup)
        times = [
            NOW,
            NOW + datetime.timedelta(hours=1),
            NOW + datetime.timedelta(hours=2),
            NOW + datetime.timedelta(hours=3),
            NOW + datetime.timedelta(hours=27),
        ]
        for when in times:
            mon.check_site(mon._load_sites()[0], now=when)
        assert lookups == [IP_A, IP_B, IP_B]
        row = _site(engine, URL)
        assert row["resolved_ip"] == IP_B
        assert row["asn_provider"] == f"Provider for {IP_B}"

    def test_rdap_failure_keeps_previous_provider(self, schema):
        from ipwhois.exceptions import HTTPLookupError

        manager, engine, tracking = schema
        _add_site(engine, URL)
        calls = iter(["First Provider", HTTPLookupError("down")])

        def ip_lookup(ip):
            item = next(calls)
            if isinstance(item, Exception):
                raise item
            return item

        script = [_probe(ProbeClass.UP, 200, ips=(IP_A,)), _probe(ProbeClass.UP, 200, ips=(IP_B,))]
        mon = _monitor(manager, ScriptedProber(tracking, {URL: script}), ip_lookup=ip_lookup)
        mon.check_site(mon._load_sites()[0], now=NOW)
        mon.check_site(mon._load_sites()[0], now=NOW + datetime.timedelta(hours=1))
        row = _site(engine, URL)
        assert row["resolved_ip"] == IP_B
        assert row["asn_provider"] == "First Provider"

    def test_canary_failure_skips_cycle(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        prober = ScriptedProber(tracking, {URL: []})
        mon = _monitor(manager, prober)
        mon.canary_urls = ["https://canary.example/"]
        with patch.object(takedown_module, "network_is_healthy", return_value=False):
            stats = mon.run_cycle()
        assert stats["skipped"] == 1
        assert prober.calls == []
        assert _site(engine, URL)["last_probe_class"] is None

    def test_concurrent_status_change_is_not_overwritten(self, schema):
        manager, engine, tracking = schema
        _add_site(engine, URL)
        prober = ScriptedProber(tracking, {URL: [_probe(ProbeClass.UP, 200)]})
        mon = _monitor(manager, prober)
        state = mon._load_sites()[0]
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE phishing_sites SET site_status = 'resolved' WHERE url = :u"),
                {"u": URL},
            )
        assert mon.check_site(state, now=NOW) == "skipped"
        assert _site(engine, URL)["site_status"] == "resolved"

    def test_cycle_checks_all_sites_in_parallel_workers(self, schema):
        manager, engine, tracking = schema
        urls = [f"https://p{i}.example/" for i in range(6)]
        for url in urls:
            _add_site(engine, url, reports=())

        class LockedProber(ScriptedProber):
            def __call__(self, url, timeout):
                return self.script[url][0]

        prober = LockedProber(tracking, {u: [_probe(ProbeClass.UP, 200)] for u in urls})
        stats = _monitor(manager, prober, workers=3).run_cycle()
        assert stats["sites"] == 6
        assert stats["checked"] == 6
        assert stats["errors"] == 0
        for url in urls:
            assert _site(engine, url)["last_probe_class"] == "up"


# ---------------------------------------------------------------------------
# save_offset / get_offset
# ---------------------------------------------------------------------------


@pytest.fixture
def offset_file(monkeypatch, tmp_path):
    """Inject OFFSET_FILE into the module using a writable temp path."""
    path = str(tmp_path / "offset.txt")
    monkeypatch.setattr(takedown_module, "OFFSET_FILE", path, raising=False)
    return path


class TestSaveAndGetOffset:
    def test_save_offset_writes_integer_to_file(self, offset_file):
        save_offset(42)
        with open(offset_file) as f:
            assert f.read() == "42"

    def test_get_offset_reads_and_returns_integer(self, offset_file):
        with open(offset_file, "w") as f:
            f.write("100")
        assert get_offset() == 100

    def test_get_offset_returns_zero_when_file_missing(self, monkeypatch):
        monkeypatch.setattr(
            takedown_module, "OFFSET_FILE", "/nonexistent/path/offset.txt", raising=False
        )
        assert get_offset() == 0

    def test_save_then_get_roundtrip(self, offset_file):
        save_offset(777)
        assert get_offset() == 777

    def test_get_offset_handles_float_string(self, offset_file):
        with open(offset_file, "w") as f:
            f.write("42.0")
        assert get_offset() == 42

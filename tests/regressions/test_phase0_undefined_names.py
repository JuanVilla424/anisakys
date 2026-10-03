"""Regression tests for runtime NameErrors that were silently swallowed.

Each test exercises a code path that used to reference a name that was never
imported (pyflakes F821). The surrounding ``except Exception`` blocks hid the
failures, so these tests assert on the observable effect (a persisted row, a
tracked report, a completed loop) rather than on the import itself.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
import src.detection.scanner as scanner_module
import src.reporting.abuse_manager as abuse_manager_module
import src.shutdown as shutdown
from src.detection.analyzer import AutoPhishingAnalyzer
from src.detection.scanner import PhishingScanner


@pytest.fixture(autouse=True)
def _reset_shutdown():
    shutdown.reset_shutdown()
    yield
    shutdown.reset_shutdown()


def _bare_scanner(**attrs) -> PhishingScanner:
    """Build a PhishingScanner without running its heavy constructor."""
    scanner = object.__new__(PhishingScanner)
    defaults = dict(
        timeout=5,
        keywords=["paypal"],
        domains=[".com"],
        allowed_sites=[],
        batch_size=10,
        total_queries=100,
        db_manager=None,
        redirect_analyzer=None,
        multi_api_validator=MagicMock(),
    )
    defaults.update(attrs)
    for key, value in defaults.items():
        setattr(scanner, key, value)
    return scanner


class TestScannerCycle:
    """scanner.py used gc/json/text/datetime/log_with_context without imports."""

    def test_scan_cycle_processes_ten_batches_without_crashing(self):
        """Exit criterion: the scanner survives 10 consecutive batches."""
        scanner = _bare_scanner()
        batches = {"count": 0}

        def next_batch():
            batches["count"] += 1
            if batches["count"] >= 10:
                shutdown.request_shutdown()
            return [f"site{batches['count']}.com"]

        with (
            patch.object(scanner, "get_dynamic_target_sites", side_effect=next_batch),
            patch.object(scanner, "scan_site"),
            patch.object(scanner_module, "get_offset", return_value=0),
        ):
            scanner.run_scan_cycle()

        assert batches["count"] == 10

    def test_redirect_chain_and_immediate_analysis_are_persisted(self, monkeypatch):
        """The INSERT into redirect_chains and the immediate-analysis UPDATE
        both used to die on NameError before reaching the database."""
        chain = SimpleNamespace(
            original_url="https://paypal-login.example",
            final_url="https://paypal-login.example/verify",
            hop_count=1,
            chain_urls=["https://paypal-login.example", "https://paypal-login.example/verify"],
            status_codes=[302, 200],
            risk_score=40,
            has_cloudflare=False,
            has_suspicious_tld=False,
            has_url_shortener=False,
            has_cross_domain=False,
            has_loop=False,
            total_time_ms=12,
        )
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (42,)
        db_manager = MagicMock()
        db_manager.engine.begin.return_value.__enter__.return_value = conn
        db_manager.store_detected_phishing_site.return_value = True
        validator = MagicMock()
        validator.comprehensive_scan.return_value = {
            "aggregated_threat_level": "high",
            "confidence_score": 90,
            "virustotal": {},
            "urlvoid": {},
            "phishtank": {},
        }
        scanner = _bare_scanner(
            db_manager=db_manager,
            redirect_analyzer=MagicMock(analyze=MagicMock(return_value=chain)),
            multi_api_validator=validator,
        )
        response = MagicMock(status_code=200, text="<form>PayPal login password</form>")
        monkeypatch.setattr(scanner_module, "AUTO_ANALYSIS_ENABLED", True)
        with (
            patch.object(scanner, "get_candidate_urls", return_value=[chain.original_url]),
            patch.object(scanner_module.requests, "get", return_value=response),
            patch.object(scanner_module.PhishingUtils, "store_scan_result"),
            patch.object(scanner_module.PhishingUtils, "log_positive_result"),
        ):
            scanner.scan_site("paypal-login.example")

        statements = [str(call.args[0]) for call in conn.execute.call_args_list]
        insert = [s for s in statements if "INSERT INTO redirect_chains" in s]
        assert insert, "redirect chain was never written"
        assert "CAST(:chain_urls AS JSONB)" in insert[0]
        assert any("UPDATE phishing_sites" in s for s in statements), "immediate analysis lost"
        insert_params = next(
            call.args[1]
            for call in conn.execute.call_args_list
            if "INSERT INTO redirect_chains" in str(call.args[0])
        )
        assert insert_params["site_id"] == 42
        assert insert_params["chain_urls"].startswith("[")


class TestAutoReportDecision:
    """analyzer.py referenced thresholds, json, datetime and AttachmentConfig
    without importing them."""

    def test_manual_site_decision_uses_thresholds(self):
        decision = AutoPhishingAnalyzer._make_auto_report_decision(
            {"aggregated_threat_level": "high", "confidence_score": 99},
            ["login"],
            {"source": "external_api", "manual_flag": 1, "auto_detected": 0},
        )
        assert decision["auto_report"] is True

    def test_auto_detected_site_still_requires_manual_review(self):
        decision = AutoPhishingAnalyzer._make_auto_report_decision(
            {"aggregated_threat_level": "critical", "confidence_score": 100},
            ["login"],
            {"source": "auto_detection", "manual_flag": 0, "auto_detected": 1},
        )
        assert decision["auto_report"] is False
        assert decision["manual_review"] is True

    def test_process_auto_reports_sends_and_marks_site(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (
            '{"malicious": 3}',
            "{}",
            "{}",
            "high",
            95,
        )
        db_manager = MagicMock()
        db_manager.engine.begin.return_value.__enter__.return_value = conn
        db_manager.get_auto_report_eligible_sites.return_value = [
            {
                "url": "https://phish.example/login",
                "threat_level": "high",
                "confidence_score": 95,
                "keywords": "login",
            }
        ]
        detector = MagicMock()
        detector.get_enhanced_abuse_email.return_value = ["abuse@registrar.example"]
        report_manager = MagicMock()
        report_manager.send_abuse_report.return_value = True
        with patch("src.detection.analyzer.MultiAPIValidator"):
            analyzer = AutoPhishingAnalyzer(db_manager, detector)
        with patch(
            "src.detection.analyzer.AttachmentConfig.get_all_attachments", return_value=[]
        ):
            processed = analyzer.process_auto_reports(report_manager)

        assert processed == 1
        sent_results = report_manager.send_abuse_report.call_args.kwargs["multi_api_results"]
        assert sent_results["virustotal"] == {"malicious": 3}


class TestReportTracking:
    """abuse_manager.py called create_report_record/timeout without imports, so
    every sent report vanished from SLA tracking."""

    def test_sent_report_is_tracked(self):
        with (
            patch.object(abuse_manager_module, "MultiAPIValidator"),
            patch.object(abuse_manager_module, "GrinderReportClient"),
            patch.object(abuse_manager_module, "get_screenshot_service"),
            patch.object(abuse_manager_module, "ReportTracker"),
            patch.object(
                abuse_manager_module, "report_phishing_url", return_value={"success": False}
            ),
            patch.object(abuse_manager_module.smtplib, "SMTP") as smtp,
            patch("psycopg2.connect"),
            patch.object(
                abuse_manager_module.AttachmentConfig, "get_all_attachments", return_value=[]
            ),
        ):
            detector = MagicMock()
            detector.validate_email.return_value = True
            detector.validate_abuse_email_domain.return_value = True
            manager = abuse_manager_module.AbuseReportManager(
                MagicMock(), detector, cc_emails=[], timeout=5
            )
            manager.screenshot_service.capture_screenshot.return_value = {"success": False}
            sent = manager.send_abuse_report(
                ["abuse@registrar.example"], "https://phish.example/login", "whois", test_mode=False
            )

        assert sent is True
        assert smtp.return_value.__enter__.return_value.sendmail.called
        assert manager.report_tracker.track_report.called

    def test_serialize_for_json_is_available_to_manual_reports(self):
        assert abuse_manager_module.serialize_for_json({"a": [1]}) == {"a": [1]}


class TestStatsEndpoint:
    """/api/v1/stats referenced GRINDER0X_API_URL without importing it, so the
    endpoint returned 500 whenever Grinder integration was enabled."""

    def test_stats_returns_200_with_grinder_enabled(self, monkeypatch):
        from src.database.manager import DatabaseManager
        from src.reporting.email_detector import EnhancedAbuseEmailDetector

        def allow_all(f=None, *, scope=None):
            return f if f is not None else (lambda func: func)

        with (
            patch("src.api.phishing_api.require_api_key", allow_all),
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI

            db_manager = MagicMock(spec=DatabaseManager)
            db_manager.engine = MagicMock()
            conn = db_manager.engine.begin.return_value.__enter__.return_value
            conn.execute.return_value.scalar.return_value = 0
            conn.execute.return_value.fetchall.return_value = []
            api = PhishingAPI(db_manager, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="k")
        monkeypatch.setattr("src.api.phishing_api.GRINDER_INTEGRATION_ENABLED", True)
        monkeypatch.setattr("src.api.phishing_api.GRINDER0X_API_URL", "https://grinder.example")
        response = api.app.test_client().get("/api/v1/stats")

        assert response.status_code == 200
        assert response.get_json()["grinder_integration"]["api_url"] == "https://grinder.example"


class TestResetOffsetCommand:
    """main.py called save_offset() for --reset-offset without importing it."""

    def test_reset_offset_is_importable_from_main(self):
        from src import main as main_module

        assert callable(main_module.save_offset)

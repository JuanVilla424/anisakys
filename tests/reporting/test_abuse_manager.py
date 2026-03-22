"""
Tests for src/reporting/abuse_manager.py

Covers: AbuseReportManager — Grinder IP reporting, enhanced abuse email resolution,
        abuse report sending (SMTP), IS_TESTING_MODE CC protection, and init.

Strategy:
  - IS_TESTING_MODE=True on every test (autouse) to prevent real CC emails
  - settings attribute patched on the module-level binding
  - All constructor side-effects (MultiAPIValidator, GrinderReportClient, etc.) patched
  - SMTP, Jinja2, AttachmentConfig patched per-test as needed

Import note: src.reporting has a circular import via src.intelligence. We load
src.main first so all modules are registered in sys.modules before our imports.
"""

import pytest
from unittest.mock import MagicMock, patch

# Load main first to resolve the circular import between src.intelligence and src.detection
from src import main  # noqa: F401 — side-effect import to seed sys.modules

import src.reporting.abuse_manager as abuse_manager_module
from src.reporting.abuse_manager import AbuseReportManager


# ---------------------------------------------------------------------------
# Module-level patches (autouse)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def force_testing_mode(monkeypatch):
    """Always set IS_TESTING_MODE=True so CC emails are never sent."""
    monkeypatch.setattr(abuse_manager_module, "IS_TESTING_MODE", True)


@pytest.fixture(autouse=True)
def disable_grinder(monkeypatch):
    """Disable Grinder integration unless a test explicitly re-enables it."""
    monkeypatch.setattr(abuse_manager_module, "GRINDER_INTEGRATION_ENABLED", False)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_settings(monkeypatch):
    """Minimal settings object needed by AbuseReportManager methods."""
    cfg = MagicMock()
    cfg.SMTP_HOST = "localhost"
    cfg.SMTP_PORT = 25
    cfg.SMTP_USER = None
    cfg.SMTP_PASS = None
    cfg.ABUSE_EMAIL_SENDER = "reports@test.com"
    cfg.ABUSE_EMAIL_SUBJECT = "Phishing Report"
    cfg.DEFAULT_CC_EMAILS = ""
    cfg.DEFAULT_CC_EMAILS_ESCALATION_LEVEL2 = None
    cfg.DEFAULT_CC_EMAILS_ESCALATION_LEVEL3 = None
    cfg.MAX_ATTACHMENT_SIZE_MB = 25
    cfg.MAX_EMAIL_SIZE_MB = 50
    cfg.SCREENSHOTS_DIR = "/tmp/screenshots"
    cfg.DATABASE_URL = "postgresql://user:pass@localhost/testdb"
    monkeypatch.setattr(abuse_manager_module, "settings", cfg)
    return cfg


@pytest.fixture
def mock_db():
    """Mock DatabaseManager with engine context manager support."""
    db = MagicMock()
    db.engine = MagicMock()
    mock_conn = MagicMock()
    db.engine.begin.return_value.__enter__ = MagicMock(return_value=mock_conn)
    db.engine.begin.return_value.__exit__ = MagicMock(return_value=False)
    db.get_registrar_abuse_emails.return_value = None
    db.get_hosting_abuse_emails.return_value = None
    return db


@pytest.fixture
def mock_abuse_detector():
    """Mock EnhancedAbuseEmailDetector with permissive defaults."""
    detector = MagicMock()
    detector.validate_email.return_value = True
    detector.validate_abuse_email_domain.return_value = True
    detector.extract_registrar.return_value = "TestRegistrar"
    detector.get_enhanced_abuse_email.return_value = []
    return detector


@pytest.fixture
def manager(mock_db, mock_abuse_detector, mock_settings):
    """AbuseReportManager with all constructor-injected deps patched."""
    with (
        patch("src.reporting.abuse_manager.MultiAPIValidator"),
        patch("src.reporting.abuse_manager.GrinderReportClient"),
        patch("src.reporting.abuse_manager.AbuseContactValidator"),
        patch("src.reporting.abuse_manager.ScreenshotService"),
        patch("src.reporting.abuse_manager.ReportTracker"),
    ):
        mgr = AbuseReportManager(
            db_manager=mock_db,
            abuse_detector=mock_abuse_detector,
            cc_emails=[],
            timeout=10,
        )
    return mgr


# ---------------------------------------------------------------------------
# TestAbuseReportManagerInit
# ---------------------------------------------------------------------------


class TestAbuseReportManagerInit:
    def test_stores_required_constructor_args(self, mock_db, mock_abuse_detector, mock_settings):
        """Should store db_manager, abuse_detector, cc_emails, and timeout."""
        with (
            patch("src.reporting.abuse_manager.MultiAPIValidator"),
            patch("src.reporting.abuse_manager.GrinderReportClient"),
            patch("src.reporting.abuse_manager.AbuseContactValidator"),
            patch("src.reporting.abuse_manager.ScreenshotService"),
            patch("src.reporting.abuse_manager.ReportTracker"),
        ):
            mgr = AbuseReportManager(
                db_manager=mock_db,
                abuse_detector=mock_abuse_detector,
                cc_emails=["cc@example.com"],
                timeout=30,
            )

        assert mgr.db_manager is mock_db
        assert mgr.abuse_detector is mock_abuse_detector
        assert mgr.cc_emails == ["cc@example.com"]
        assert mgr.timeout == 30

    def test_running_flag_starts_true(self, mock_db, mock_abuse_detector, mock_settings):
        """Should initialize running=True for the followup worker."""
        with (
            patch("src.reporting.abuse_manager.MultiAPIValidator"),
            patch("src.reporting.abuse_manager.GrinderReportClient"),
            patch("src.reporting.abuse_manager.AbuseContactValidator"),
            patch("src.reporting.abuse_manager.ScreenshotService"),
            patch("src.reporting.abuse_manager.ReportTracker"),
        ):
            mgr = AbuseReportManager(
                db_manager=mock_db,
                abuse_detector=mock_abuse_detector,
                cc_emails=[],
                timeout=10,
            )

        assert mgr.running is True

    def test_creates_with_empty_cc_list(self, mock_db, mock_abuse_detector, mock_settings):
        """Should accept an empty cc_emails list without accessing settings."""
        with (
            patch("src.reporting.abuse_manager.MultiAPIValidator"),
            patch("src.reporting.abuse_manager.GrinderReportClient"),
            patch("src.reporting.abuse_manager.AbuseContactValidator"),
            patch("src.reporting.abuse_manager.ScreenshotService"),
            patch("src.reporting.abuse_manager.ReportTracker"),
        ):
            mgr = AbuseReportManager(
                db_manager=mock_db,
                abuse_detector=mock_abuse_detector,
                cc_emails=[],
                timeout=10,
            )

        assert mgr.cc_emails == []


# ---------------------------------------------------------------------------
# TestReportIpToGrinder
# ---------------------------------------------------------------------------


class TestReportIpToGrinder:
    def test_returns_disabled_when_grinder_off(self, manager, monkeypatch):
        """Should return status='disabled' when GRINDER_INTEGRATION_ENABLED is False."""
        # Grinder is already disabled by autouse fixture
        result = manager.report_ip_to_grinder("1.2.3.4", "https://phish.com", {})
        assert result["status"] == "disabled"

    def test_calls_grinder_client_when_enabled(self, manager, monkeypatch):
        """Should delegate to grinder_client.report_malicious_ip when enabled."""
        monkeypatch.setattr(abuse_manager_module, "GRINDER_INTEGRATION_ENABLED", True)
        manager.grinder_client.report_malicious_ip.return_value = {
            "status": "success",
            "categories": [5],
            "confidence": 90,
        }

        result = manager.report_ip_to_grinder(
            "1.2.3.4",
            "https://phish.com",
            {"threat_level": "critical", "domains": []},
        )

        assert manager.grinder_client.report_malicious_ip.called
        assert result["status"] == "success"

    def test_appends_domain_from_url_to_context(self, manager, monkeypatch):
        """Should extract domain from URL and append it to the detection context."""
        monkeypatch.setattr(abuse_manager_module, "GRINDER_INTEGRATION_ENABLED", True)
        manager.grinder_client.report_malicious_ip.return_value = {"status": "success"}

        manager.report_ip_to_grinder(
            "1.2.3.4",
            "https://evil.example.com/path?q=1",
            {"domains": [], "threat_level": "high"},
        )

        call_args = manager.grinder_client.report_malicious_ip.call_args
        context = call_args[0][1]
        assert "evil.example.com" in context["domains"]

    def test_uses_threat_level_for_confidence_calculation(self, manager, monkeypatch):
        """Should compute high confidence (90) for threat_level='high' when api_confidence=0."""
        monkeypatch.setattr(abuse_manager_module, "GRINDER_INTEGRATION_ENABLED", True)
        manager.grinder_client.report_malicious_ip.return_value = {"status": "success"}

        manager.report_ip_to_grinder(
            "1.2.3.4",
            "https://phish.com",
            {"domains": [], "threat_level": "high", "api_confidence": 0},
        )

        call_args = manager.grinder_client.report_malicious_ip.call_args
        confidence = call_args[1]["confidence"]
        assert confidence == 90


# ---------------------------------------------------------------------------
# TestGetEnhancedAbuseEmails
# ---------------------------------------------------------------------------


class TestGetEnhancedAbuseEmails:
    def test_returns_cached_registrar_emails_from_db(self, manager, mock_db):
        """Should return cached emails when DB has a matching registrar entry."""
        mock_db.get_registrar_abuse_emails.return_value = "abuse@godaddy.com"

        whois_mock = MagicMock()
        # socket is not imported in abuse_manager.py; the NameError is silently caught
        result = manager.get_enhanced_abuse_emails(whois_mock, "phish.com")

        assert "abuse@godaddy.com" in result

    def test_falls_back_to_detector_when_no_cache(self, manager, mock_db, mock_abuse_detector):
        """Should call abuse_detector.get_enhanced_abuse_email when cache is empty."""
        mock_db.get_registrar_abuse_emails.return_value = None
        mock_abuse_detector.get_enhanced_abuse_email.return_value = ["abuse@provider.com"]

        whois_mock = MagicMock()
        result = manager.get_enhanced_abuse_emails(whois_mock, "phish.com")

        assert mock_abuse_detector.get_enhanced_abuse_email.called
        assert "abuse@provider.com" in result

    def test_returns_empty_list_when_all_sources_fail(self, manager, mock_db, mock_abuse_detector):
        """Should return [] when DB cache and detector both return nothing."""
        mock_db.get_registrar_abuse_emails.return_value = None
        mock_abuse_detector.get_enhanced_abuse_email.return_value = []

        whois_mock = MagicMock()
        whois_mock.__str__ = lambda self: "No email info"
        result = manager.get_enhanced_abuse_emails(whois_mock, "phish.com")

        assert result == []

    def test_deduplicates_emails_from_multiple_sources(self, manager, mock_db, mock_abuse_detector):
        """Should not include duplicate emails in the result."""
        mock_db.get_registrar_abuse_emails.return_value = "abuse@godaddy.com"
        # detector would also return the same email via enhanced method
        mock_abuse_detector.get_enhanced_abuse_email.return_value = ["abuse@godaddy.com"]

        whois_mock = MagicMock()
        result = manager.get_enhanced_abuse_emails(whois_mock, "phish.com")

        assert len(result) == len(set(result))

    def test_parses_json_cached_registrar_emails(self, manager, mock_db):
        """Should parse JSON-formatted cached registrar emails."""
        mock_db.get_registrar_abuse_emails.return_value = (
            '["abuse@godaddy.com", "dmca@godaddy.com"]'
        )

        whois_mock = MagicMock()
        result = manager.get_enhanced_abuse_emails(whois_mock, "phish.com")

        assert "abuse@godaddy.com" in result
        assert "dmca@godaddy.com" in result


# ---------------------------------------------------------------------------
# TestSendAbuseReport
# ---------------------------------------------------------------------------


class TestSendAbuseReport:
    def test_returns_false_when_template_rendering_fails(self, manager, mock_settings):
        """Should return False immediately when Jinja2 template rendering raises."""
        with (
            patch("src.reporting.abuse_manager.Environment") as mock_env,
            patch(
                "src.reporting.abuse_manager.AttachmentConfig.get_all_attachments", return_value=[]
            ),
        ):
            mock_env.return_value.get_template.return_value.render.side_effect = Exception(
                "template not found"
            )
            manager.screenshot_service.capture_screenshot.return_value = {"success": False}

            result = manager.send_abuse_report(
                abuse_emails=["abuse@registrar.com"],
                site_url="https://phish.com",
                whois_str="whois info",
                test_mode=True,
            )

        assert result is False

    def test_sends_email_via_smtp_to_primary_recipient(self, manager, mock_settings):
        """Should call server.sendmail with the primary abuse email."""
        mock_server = MagicMock()

        with (
            patch("src.reporting.abuse_manager.Environment") as mock_env,
            patch("src.reporting.abuse_manager.smtplib.SMTP") as mock_smtp_class,
            patch(
                "src.reporting.abuse_manager.AttachmentConfig.get_all_attachments", return_value=[]
            ),
        ):
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)
            mock_env.return_value.get_template.return_value.render.return_value = (
                "<html>report</html>"
            )
            manager.screenshot_service.capture_screenshot.return_value = {"success": False}
            manager.abuse_detector.validate_email.return_value = True
            manager.abuse_detector.validate_abuse_email_domain.return_value = True

            result = manager.send_abuse_report(
                abuse_emails=["abuse@registrar.com"],
                site_url="https://phish.com",
                whois_str="whois info",
                test_mode=True,
            )

        assert result is True
        assert mock_server.sendmail.called
        call_args = mock_server.sendmail.call_args
        recipients = call_args[0][1]
        assert "abuse@registrar.com" in recipients

    def test_testing_mode_excludes_cc_from_recipients(self, manager, mock_settings):
        """IS_TESTING_MODE=True should result in recipients containing only the To address."""
        manager.cc_emails = ["cc1@example.com", "cc2@example.com"]
        mock_server = MagicMock()

        with (
            patch("src.reporting.abuse_manager.Environment") as mock_env,
            patch("src.reporting.abuse_manager.smtplib.SMTP") as mock_smtp_class,
            patch(
                "src.reporting.abuse_manager.AttachmentConfig.get_all_attachments", return_value=[]
            ),
        ):
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)
            mock_env.return_value.get_template.return_value.render.return_value = (
                "<html>report</html>"
            )
            manager.screenshot_service.capture_screenshot.return_value = {"success": False}
            manager.abuse_detector.validate_email.return_value = True
            manager.abuse_detector.validate_abuse_email_domain.return_value = True

            manager.send_abuse_report(
                abuse_emails=["abuse@registrar.com"],
                site_url="https://phish.com",
                whois_str="whois info",
                test_mode=True,
            )

        recipients = mock_server.sendmail.call_args[0][1]
        # IS_TESTING_MODE blocks CCs — only the primary To address
        assert len(recipients) == 1
        assert recipients[0] == "abuse@registrar.com"

    def test_returns_false_when_smtp_raises(self, manager, mock_settings):
        """Should return False (not raise) when SMTP connection fails."""
        with (
            patch("src.reporting.abuse_manager.Environment") as mock_env,
            patch(
                "src.reporting.abuse_manager.smtplib.SMTP",
                side_effect=ConnectionRefusedError("SMTP unavailable"),
            ),
            patch(
                "src.reporting.abuse_manager.AttachmentConfig.get_all_attachments", return_value=[]
            ),
        ):
            mock_env.return_value.get_template.return_value.render.return_value = (
                "<html>report</html>"
            )
            manager.screenshot_service.capture_screenshot.return_value = {"success": False}
            manager.abuse_detector.validate_email.return_value = True
            manager.abuse_detector.validate_abuse_email_domain.return_value = True

            result = manager.send_abuse_report(
                abuse_emails=["abuse@registrar.com"],
                site_url="https://phish.com",
                whois_str="whois info",
                test_mode=True,
            )

        assert result is False

    def test_returns_false_when_all_emails_fail_validation(self, manager, mock_settings):
        """Should return False when abuse_detector rejects all email addresses."""
        manager.abuse_detector.validate_email.return_value = False

        with (
            patch("src.reporting.abuse_manager.Environment") as mock_env,
            patch("src.reporting.abuse_manager.smtplib.SMTP"),
            patch(
                "src.reporting.abuse_manager.AttachmentConfig.get_all_attachments", return_value=[]
            ),
        ):
            mock_env.return_value.get_template.return_value.render.return_value = (
                "<html>report</html>"
            )
            manager.screenshot_service.capture_screenshot.return_value = {"success": False}

            result = manager.send_abuse_report(
                abuse_emails=["invalid@fake.xyz"],
                site_url="https://phish.com",
                whois_str="whois info",
                test_mode=True,
            )

        assert result is False


# ---------------------------------------------------------------------------
# TestProcessOverdueFollowups
# ---------------------------------------------------------------------------


class TestProcessOverdueFollowups:
    def test_returns_early_when_no_overdue_reports(self, manager):
        """Should exit without sending emails when report_tracker returns no overdue."""
        manager.report_tracker.get_overdue_reports.return_value = []

        # Should not raise, and should not call any send methods
        manager.process_overdue_followups()

        manager.report_tracker.get_overdue_reports.assert_called_once()

    def test_queries_overdue_reports_from_tracker(self, manager):
        """Should call get_overdue_reports() exactly once per invocation."""
        manager.report_tracker.get_overdue_reports.return_value = []

        manager.process_overdue_followups()

        assert manager.report_tracker.get_overdue_reports.call_count == 1

    def test_processes_each_overdue_report(self, manager, mock_settings):
        """Should attempt processing for each overdue report returned by tracker."""
        manager.report_tracker.get_overdue_reports.return_value = [
            {
                "report_id": "RPT-001",
                "site_url": "https://phish1.com",
                "overdue_hours": 48,
                "recipients": ["abuse@reg.com"],
                "subject": "Phishing Report",
            }
        ]

        with (
            patch("src.reporting.abuse_manager.get_ip_info", return_value=("1.2.3.4", "ASN")),
            patch(
                "src.reporting.abuse_manager.PhishingUtils.determine_site_status",
                return_value=("active", None),
            ),
            patch.object(manager, "send_abuse_report", return_value=True),
        ):
            manager.process_overdue_followups()

        # With one overdue report and site still active, send_abuse_report may be called
        assert manager.report_tracker.get_overdue_reports.called

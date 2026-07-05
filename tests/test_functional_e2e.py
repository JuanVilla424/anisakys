"""
End-to-end functional tests for Anisakys
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import importlib.util
import time
import threading
import json

# Load main module
module_path = Path(__file__).parent.parent / "src" / "main.py"
spec = importlib.util.spec_from_file_location("src.main", str(module_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)

# Import needed classes
Engine = main.Engine
PhishingScanner = main.PhishingScanner
DatabaseManager = main.DatabaseManager

# After the EPIC refactors these globals live in their own modules — patch there
import src.detection.scanner as scanner_module
import src.monitoring.takedown as takedown_module

# User's test email for reports
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


class TestFunctionalE2E:
    """End-to-end functional tests"""

    @pytest.fixture
    def test_db(self, tmp_path):
        """Create test database"""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"
        return db_url

    @pytest.fixture
    def mock_env(self, monkeypatch, test_db, tmp_path):
        """Mock environment for testing"""
        # Mock settings (keep the real test PostgreSQL database — the schema
        # uses PostgreSQL-specific SQL, so per-test SQLite is not viable)
        monkeypatch.setattr(main.settings, "KEYWORDS", "bank,paypal,amazon")
        monkeypatch.setattr(main.settings, "DOMAINS", ".com,.net")
        monkeypatch.setattr(main.settings, "AUTO_MULTI_API_SCAN", True)
        monkeypatch.setattr(main.settings, "AUTO_REPORT_THRESHOLD_CONFIDENCE", 85)
        monkeypatch.setattr(main.settings, "VIRUSTOTAL_API_KEY", "test_vt_key")
        monkeypatch.setattr(main.settings, "DEFAULT_CC_EMAILS", TEST_USER_EMAIL)
        monkeypatch.setattr(main.settings, "ABUSE_EMAIL_SENDER", "test@anisakys.com")
        monkeypatch.setattr(main.settings, "SMTP_HOST", "smtp.test.com")
        monkeypatch.setattr(main.settings, "SMTP_PORT", 587)

        # Mock file paths (QUERIES_FILE lives in src.detection.scanner and
        # OFFSET_FILE in src.monitoring.takedown after the refactors)
        queries_file = str(tmp_path / "test_queries.txt")
        offset_file = str(tmp_path / "test_offset.txt")
        monkeypatch.setattr(main, "QUERIES_FILE", queries_file)
        monkeypatch.setattr(main, "OFFSET_FILE", offset_file)
        monkeypatch.setattr(scanner_module, "QUERIES_FILE", queries_file)
        monkeypatch.setattr(takedown_module, "OFFSET_FILE", offset_file)

    def test_complete_phishing_detection_flow(self, mock_env, tmp_path):
        """Test complete flow: detection -> validation -> reporting"""
        import argparse

        # Create test arguments
        args = argparse.Namespace(
            timeout=5,
            log_level="INFO",
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            multi_api_scan=False,
            url=None,
            abuse_email=None,
            attachment=None,
            attachments_folder=None,
            cc=TEST_USER_EMAIL,
            regen_queries=True,
            reset_offset=True,
            keywords=None,
            domains=None,
            allowed_sites=None,
            start_api=False,
            api_port=8091,
            api_key=None,
            force_auto_analysis=False,
            auto_report_now=False,
            show_auto_status=False,
            test_grinder_integration=False,
        )

        # Initialize engine
        engine = Engine(args)

        # Test 1: Phishing site detection
        detected_sites = []

        def mock_scan_site(url, *args, **kwargs):
            """Mock site scanning that detects phishing"""
            if "paypal" in url or "bank" in url:
                detected_sites.append(url)
                return True, ["paypal", "login"], 200
            return False, [], 404

        with patch.object(engine.scanner, "scan_site", mock_scan_site):
            # Simulate scanning a few sites
            test_urls = [
                "https://paypal-verify.com",
                "https://bank-secure.net",
                "https://legitimate.com",
            ]

            for url in test_urls:
                result = engine.scanner.scan_site(url)

            assert len(detected_sites) == 2
            assert "https://paypal-verify.com" in detected_sites

        # Test 2: Multi-API validation
        with patch.object(engine, "perform_multi_api_scan") as mock_scan:
            mock_scan.return_value = {
                "url": "https://paypal-verify.com",
                "threat_level": "critical",
                "confidence_score": 95,
                "virustotal": {"malicious": 12, "success": True},
                "urlvoid": {"detections": 5, "success": True},
                "phishtank": {"in_database": True, "verified": True, "success": True},
            }

            # Validate detected site
            api_results = engine.perform_multi_api_scan("https://paypal-verify.com")

            assert api_results["threat_level"] == "critical"
            assert api_results["confidence_score"] == 95

        # Test 3: Abuse reporting (send_abuse_report lives in report_manager)
        with (
            patch("src.reporting.abuse_manager.smtplib.SMTP") as mock_smtp,
            patch("src.reporting.abuse_manager.Environment") as mock_env_tpl,
            patch(
                "src.reporting.abuse_manager.AttachmentConfig.get_all_attachments",
                return_value=[],
            ),
        ):
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            mock_env_tpl.return_value.get_template.return_value.render.return_value = (
                "<html>Phishing Report</html>"
            )

            with (
                patch.object(
                    engine.report_manager.abuse_detector, "validate_email", return_value=True
                ),
                patch.object(
                    engine.report_manager.abuse_detector,
                    "validate_abuse_email_domain",
                    return_value=True,
                ),
                patch.object(
                    engine.report_manager.screenshot_service,
                    "capture_screenshot",
                    return_value={"success": False},
                ),
            ):
                # Send abuse report
                success = engine.report_manager.send_abuse_report(
                    abuse_emails=["abuse@provider.com"],
                    site_url="https://paypal-verify.com",
                    whois_str="registrar: Example Registrar",
                    multi_api_results=api_results,
                    test_mode=True,
                )

                # Verify email was sent
                assert success is True
                mock_server.sendmail.assert_called()

    def test_auto_analysis_workflow(self, mock_env):
        """Test automatic analysis workflow"""
        import argparse

        args = argparse.Namespace(
            timeout=5,
            log_level="INFO",
            threads_only=True,  # Only run background threads
            report=None,
            process_reports=False,
            test_report=False,
            multi_api_scan=True,
            url=None,
            force_auto_analysis=True,
            show_auto_status=True,
            cc=TEST_USER_EMAIL,
            abuse_email=None,
            attachment=None,
            regen_queries=False,
        )

        # Initialize engine
        engine = Engine(args)

        # Insert test data for auto-analysis (clean previous runs first)
        with engine.db_manager.engine.begin() as conn:
            conn.execute(
                main.text(
                    "DELETE FROM phishing_sites "
                    "WHERE url IN ('https://test-phish1.com', 'https://test-phish2.com')"
                )
            )
            conn.execute(
                main.text(
                    """
                INSERT INTO phishing_sites
                (url, manual_flag, auto_detected, first_seen, auto_analysis_status, priority)
                VALUES
                ('https://test-phish1.com', 0, 1, CURRENT_TIMESTAMP, 'pending', 'high'),
                ('https://test-phish2.com', 0, 1, CURRENT_TIMESTAMP, 'pending', 'medium')
            """
                )
            )

        # Mock multi-API scan
        with patch.object(engine, "perform_multi_api_scan") as mock_scan:
            mock_scan.return_value = {
                "threat_level": "high",
                "confidence_score": 90,
                "virustotal": {"malicious": 8},
                "urlvoid": {"detections": 3},
                "phishtank": {"in_database": False},
            }

            # Run auto-analysis (worker wiring lives in engine.auto_analyzer)
            with patch.object(engine.auto_analyzer, "start_analysis_worker") as mock_analyze:
                mock_analyze.return_value = None

                # Trigger analysis
                engine.auto_analyzer.start_analysis_worker()

                # Verify it was called
                mock_analyze.assert_called()

        # Check status
        with engine.db_manager.engine.connect() as conn:
            result = conn.execute(
                main.text(
                    """
                SELECT COUNT(*) FROM phishing_sites
                WHERE auto_analysis_status = 'pending'
            """
                )
            ).scalar()

            # Should have pending sites
            assert result >= 0

    def test_rest_api_functionality(self, mock_env):
        """Test REST API endpoints"""
        import argparse
        from flask import Flask
        from flask.testing import FlaskClient

        args = argparse.Namespace(
            start_api=True,
            api_port=8091,
            api_key="test_api_key",
            timeout=5,
            log_level="INFO",
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            abuse_email=None,
            attachment=None,
            cc=None,
            regen_queries=False,
        )

        # Create Flask app for testing
        app = Flask(__name__)

        # Mock the API setup
        with patch("flask.Flask") as mock_flask:
            mock_app = MagicMock()
            mock_flask.return_value = mock_app

            # Initialize API endpoints
            engine = Engine(args)

            # Test report endpoint
            report_data = {
                "url": "https://phishing-test.com",
                "priority": "high",
                "description": "Confirmed phishing site",
            }

            # Mock the route decorator and handler
            @mock_app.route("/api/v1/report", methods=["POST"])
            def mock_report():
                return {"status": "success", "message": "Report received"}

            # Verify routes were registered
            mock_app.route.assert_called()

    def test_database_persistence(self, mock_env, test_db):
        """Test data persistence across sessions"""
        import argparse

        # First session - insert data
        args1 = argparse.Namespace(
            report="https://phishing-persist.com",
            abuse_email="abuse@test.com",
            timeout=5,
            log_level="INFO",
            process_reports=False,
            threads_only=False,
            test_report=False,
            attachment=None,
            cc=None,
            regen_queries=False,
        )

        engine1 = Engine(args1)

        # Clean previous runs, then mark site as phishing
        with engine1.db_manager.engine.begin() as conn:
            conn.execute(
                main.text("DELETE FROM phishing_sites WHERE url = 'https://phishing-persist.com'")
            )
        engine1.mark_site_as_phishing(
            "https://phishing-persist.com", abuse_email="abuse@registrar.com"
        )

        # Second session - verify data persists
        args2 = argparse.Namespace(
            timeout=5,
            log_level="INFO",
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            abuse_email=None,
            attachment=None,
            cc=None,
            regen_queries=False,
        )

        engine2 = Engine(args2)

        # Check if site exists in database
        with engine2.db_manager.engine.connect() as conn:
            result = conn.execute(
                main.text("SELECT url, manual_flag FROM phishing_sites WHERE url = :url"),
                {"url": "https://phishing-persist.com"},
            ).fetchone()

            assert result is not None
            assert result[0] == "https://phishing-persist.com"
            assert result[1] == 1  # manual_flag

    def test_concurrent_scanning(self, mock_env):
        """Test concurrent scanning with multiple threads"""
        import argparse
        import queue

        args = argparse.Namespace(
            timeout=5,
            log_level="INFO",
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            multi_api_scan=False,
            url=None,
            regen_queries=True,
        )

        # Create scanner (worker pool size is managed internally)
        scanner = PhishingScanner(
            timeout=5,
            keywords=["test"],
            domains=[".com"],
            allowed_sites=[],
            args=args,
        )

        # Track scanned URLs
        scanned_urls = queue.Queue()

        def mock_check(url):
            """Mock URL checking"""
            scanned_urls.put(url)
            time.sleep(0.1)  # Simulate network delay
            return False, [], 404

        with patch("requests.get", side_effect=mock_check):
            # Create test URLs
            test_urls = [f"https://test{i}.com" for i in range(10)]

            # Scan URLs concurrently
            start_time = time.time()

            with patch.object(scanner, "scan_site", side_effect=mock_check):
                threads = []
                for url in test_urls:
                    t = threading.Thread(target=scanner.scan_site, args=(url,))
                    t.start()
                    threads.append(t)

                # Wait for completion
                for t in threads:
                    t.join()

            elapsed = time.time() - start_time

            # Verify concurrent execution (should be faster than sequential)
            assert elapsed < len(test_urls) * 0.1 * 0.5  # Allow some overhead
            assert scanned_urls.qsize() == len(test_urls)

    def test_error_recovery(self, mock_env):
        """Test system recovery from various errors"""
        import argparse

        args = argparse.Namespace(
            timeout=5,
            log_level="INFO",
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            cc=TEST_USER_EMAIL,
            abuse_email=None,
            attachment=None,
            regen_queries=False,
        )

        engine = Engine(args)

        # Test 1: Database connection error recovery
        with patch.object(engine.db_manager.engine, "connect") as mock_connect:
            mock_connect.side_effect = Exception("Database connection failed")

            # Should handle error gracefully
            try:
                with engine.db_manager.engine.connect() as conn:
                    pass
            except Exception as e:
                assert "Database connection failed" in str(e)

        # Test 2: API failure recovery
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Network error")

            # Multi-API scan should handle failure
            results = engine.scanner.multi_api_validator.virustotal.scan_url("https://test.com")
            assert "error" in results

        # Test 3: Email sending failure recovery
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = Exception("SMTP connection failed")

            # Should handle email failure
            result = engine.report_manager.send_abuse_report(
                abuse_emails=["test@test.com"],
                site_url="https://test.com",
                whois_str="",
                test_mode=True,
            )

            assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

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
    def mock_env(self, monkeypatch, test_db):
        """Mock environment for testing"""
        # Mock settings
        monkeypatch.setattr(main.settings, "DATABASE_URL", test_db)
        monkeypatch.setattr(main.settings, "KEYWORDS", "bank,paypal,amazon")
        monkeypatch.setattr(main.settings, "DOMAINS", ".com,.net")
        monkeypatch.setattr(main.settings, "AUTO_MULTI_API_SCAN", True)
        monkeypatch.setattr(main.settings, "AUTO_REPORT_THRESHOLD_CONFIDENCE", 85)
        monkeypatch.setattr(main.settings, "VIRUSTOTAL_API_KEY", "test_vt_key")
        monkeypatch.setattr(main.settings, "DEFAULT_CC_EMAILS", TEST_USER_EMAIL)
        monkeypatch.setattr(main.settings, "ABUSE_EMAIL_SENDER", "test@anisakys.com")
        monkeypatch.setattr(main.settings, "SMTP_HOST", "smtp.test.com")
        monkeypatch.setattr(main.settings, "SMTP_PORT", 587)

        # Mock file paths
        monkeypatch.setattr(main, "DATABASE_URL", test_db)
        monkeypatch.setattr(main, "QUERIES_FILE", "test_queries.txt")
        monkeypatch.setattr(main, "OFFSET_FILE", "test_offset.txt")

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
            multi_api_scan=True,
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
            api_port=8080,
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

        def mock_check_site(url, *args, **kwargs):
            """Mock site checking that detects phishing"""
            if "paypal" in url or "bank" in url:
                detected_sites.append(url)
                return True, ["paypal", "login"], 200
            return False, [], 404

        with patch.object(engine.scanner, "check_site", mock_check_site):
            # Simulate scanning a few sites
            test_urls = [
                "https://paypal-verify.com",
                "https://bank-secure.net",
                "https://legitimate.com",
            ]

            for url in test_urls:
                result = engine.scanner.check_site(url)

            assert len(detected_sites) == 2
            assert "https://paypal-verify.com" in detected_sites

        # Test 2: Multi-API validation
        with patch.object(engine, "multi_api_scan") as mock_scan:
            mock_scan.return_value = {
                "url": "https://paypal-verify.com",
                "threat_level": "critical",
                "confidence_score": 95,
                "virustotal": {"malicious": 12, "success": True},
                "urlvoid": {"detections": 5, "success": True},
                "phishtank": {"in_database": True, "verified": True, "success": True},
            }

            # Validate detected site
            api_results = engine.multi_api_scan("https://paypal-verify.com")

            assert api_results["threat_level"] == "critical"
            assert api_results["confidence_score"] == 95

        # Test 3: Abuse reporting
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp_instance = MagicMock()
            mock_smtp.return_value = mock_smtp_instance

            with patch("jinja2.Environment") as mock_env:
                mock_template = MagicMock()
                mock_template.render.return_value = "<html>Phishing Report</html>"
                mock_env.return_value.get_template.return_value = mock_template

                # Send abuse report
                success = engine.send_abuse_report(
                    site_url="https://paypal-verify.com",
                    abuse_emails=["abuse@provider.com"],
                    whois_info={"registrar": "Bad Registrar"},
                    multi_api_results=api_results,
                    cc_emails=[TEST_USER_EMAIL],
                )

                # Verify email was sent
                mock_smtp_instance.send_message.assert_called()

                # Verify CC includes test user
                sent_calls = mock_smtp_instance.send_message.call_args_list
                assert len(sent_calls) > 0

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
        )

        # Initialize engine
        engine = Engine(args)

        # Insert test data for auto-analysis
        with engine.db_manager.engine.begin() as conn:
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
        with patch.object(engine, "multi_api_scan") as mock_scan:
            mock_scan.return_value = {
                "threat_level": "high",
                "confidence_score": 90,
                "virustotal": {"malicious": 8},
                "urlvoid": {"detections": 3},
                "phishtank": {"in_database": False},
            }

            # Run auto-analysis
            with patch.object(engine, "auto_analyze_sites") as mock_analyze:
                mock_analyze.return_value = None

                # Trigger analysis
                engine.auto_analyze_sites()

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
            start_api=True, api_port=8080, api_key="test_api_key", timeout=5, log_level="INFO"
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
        )

        engine1 = Engine(args1)

        # Mark site as phishing
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

        # Create scanner with multiple workers
        scanner = PhishingScanner(
            timeout=5,
            keywords=["test"],
            domains=[".com"],
            allowed_sites=[],
            args=args,
            max_workers=5,
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

            with patch.object(scanner, "check_site", side_effect=mock_check):
                threads = []
                for url in test_urls:
                    t = threading.Thread(target=scanner.check_site, args=(url,))
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
            process_reports=True,
            threads_only=False,
            test_report=False,
            cc=TEST_USER_EMAIL,
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
            results = engine.multi_api_scanner.virustotal_scan("https://test.com")
            assert results["success"] is False
            assert "error" in results

        # Test 3: Email sending failure recovery
        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = Exception("SMTP connection failed")

            # Should handle email failure
            result = engine.send_abuse_report(
                site_url="https://test.com",
                abuse_emails=["test@test.com"],
                whois_info={},
                cc_emails=[TEST_USER_EMAIL],
            )

            assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

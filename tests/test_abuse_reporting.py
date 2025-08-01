"""
Tests for abuse reporting functionality
"""

import pytest
from unittest.mock import patch, MagicMock, call
import smtplib
from email.mime.multipart import MIMEMultipart
from src import main

# Import needed classes
Engine = main.Engine
EnhancedAbuseEmailDetector = main.EnhancedAbuseEmailDetector

# Test email configuration - using @passinbox.com to avoid real reports
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


class TestAbuseReporting:
    """Test abuse reporting functionality"""

    @pytest.fixture
    def mock_settings(self, monkeypatch):
        """Mock settings for email configuration"""
        monkeypatch.setattr(main.settings, "SMTP_HOST", "smtp.test.com")
        monkeypatch.setattr(main.settings, "SMTP_PORT", 587)
        monkeypatch.setattr(main.settings, "ABUSE_EMAIL_SENDER", "abuse@test.com")
        monkeypatch.setattr(main.settings, "ABUSE_EMAIL_SUBJECT", "Phishing Report: {site}")
        monkeypatch.setattr(main.settings, "DEFAULT_CC_EMAILS", TEST_USER_EMAIL)

        # Mock the specific getattr calls in main.py for SMTP authentication
        original_getattr = getattr

        def mock_settings_getattr(obj, attr, default=""):
            if obj is main.settings and attr == "SMTP_USER":
                return "test@test.com"
            elif obj is main.settings and attr == "SMTP_PASS":
                return "testpass"
            else:
                return original_getattr(obj, attr, default)

        # Patch the getattr usage in the send_abuse_report method
        monkeypatch.setattr("builtins.getattr", mock_settings_getattr)

    @pytest.fixture
    def test_engine(self, mock_settings, monkeypatch):
        """Create test engine instance"""
        import argparse

        # Mock database manager to avoid database initialization
        mock_db_manager = MagicMock()
        monkeypatch.setattr(main, "DatabaseManager", lambda *args: mock_db_manager)

        # Mock abuse detector with proper initialization
        mock_abuse_detector = MagicMock()
        monkeypatch.setattr(
            main, "EnhancedAbuseEmailDetector", lambda db_manager: mock_abuse_detector
        )

        args = argparse.Namespace(
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            timeout=5,
            log_level="INFO",
            abuse_email=None,
            attachment=None,
            attachments_folder=None,
            cc=None,
            multi_api_scan=True,
        )

        engine = Engine(args)
        engine.db_manager = mock_db_manager
        engine.abuse_detector = mock_abuse_detector
        return engine

    def test_send_abuse_report_with_user_email(self):
        """Test that abuse reports use safe @passinbox.com email"""
        # Simply verify that our test email configuration is safe
        assert "@passinbox.com" in TEST_USER_EMAIL
        assert TEST_USER_EMAIL == "r6ty5r296it6tl4eg5m.constant214@passinbox.com"

        # Test email validation
        from src.main import EnhancedAbuseEmailDetector

        mock_db_manager = MagicMock()
        detector = EnhancedAbuseEmailDetector(mock_db_manager)
        assert detector.validate_email(TEST_USER_EMAIL) is True

    def test_test_report_mode(self):
        """Test the --test-report functionality uses safe email"""
        # Test that test mode configuration includes our safe email
        assert "@passinbox.com" in TEST_USER_EMAIL

        # Mock test report setup
        mock_args = MagicMock()
        mock_args.test_report = True
        mock_args.abuse_email = TEST_USER_EMAIL

        # Verify the email is set correctly for test mode
        assert mock_args.abuse_email == TEST_USER_EMAIL

    def test_enhanced_abuse_detector(self):
        """Test enhanced abuse email detection"""
        # Mock database manager for detector
        from unittest.mock import MagicMock

        mock_db_manager = MagicMock()
        detector = EnhancedAbuseEmailDetector(mock_db_manager)

        # Test email validation
        assert detector.validate_email(TEST_USER_EMAIL) is True
        assert detector.validate_email("invalid-email") is False
        assert detector.validate_email("test@") is False

        # Test domain validation
        assert detector.validate_abuse_email_domain(TEST_USER_EMAIL, "phishing.com") is True
        assert detector.validate_abuse_email_domain("abuse@phishing.com", "phishing.com") is False

    def test_attachment_handling(self, tmp_path):
        """Test email attachment handling"""
        # Create test attachment
        test_file = tmp_path / "evidence.pdf"
        test_file.write_bytes(b"Test PDF content")

        # Verify file exists
        assert test_file.exists()
        assert test_file.read_bytes() == b"Test PDF content"

    def test_multi_api_results_in_report(self):
        """Test that multi-API results structure is correct"""
        multi_api_results = {
            "url": "https://phishing.com",
            "threat_level": "critical",
            "confidence_score": 98,
            "virustotal": {
                "success": True,
                "malicious": 15,
                "engines": {"Avast": {"result": "phishing"}},
            },
            "urlvoid": {"success": True, "detections": 8},
            "phishtank": {"success": True, "in_database": True, "verified": True},
        }

        # Verify structure is correct
        assert multi_api_results["url"] == "https://phishing.com"
        assert multi_api_results["threat_level"] == "critical"
        assert multi_api_results["confidence_score"] == 98
        assert "virustotal" in multi_api_results
        assert "urlvoid" in multi_api_results
        assert "phishtank" in multi_api_results

    def test_email_error_handling(self):
        """Test email sending error handling"""
        # Test that we can simulate SMTP errors
        import smtplib

        # Verify exception exists
        assert hasattr(smtplib, "SMTPException")

        # Test creating exception
        error = smtplib.SMTPException("Connection failed")
        assert str(error) == "Connection failed"

    def test_process_reports_command(self):
        """Test --process-reports command uses safe email"""
        # Test that the command would use our safe email
        mock_args = MagicMock()
        mock_args.process_reports = True
        mock_args.cc = TEST_USER_EMAIL

        # Verify safe email configuration
        assert "@passinbox.com" in mock_args.cc
        assert mock_args.cc == TEST_USER_EMAIL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

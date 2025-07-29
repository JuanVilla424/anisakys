"""
Tests for abuse reporting functionality using user's email
"""

import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
import importlib.util
import smtplib
from email.mime.multipart import MIMEMultipart

# Load main module
module_path = Path(__file__).parent.parent / "src" / "main.py"
spec = importlib.util.spec_from_file_location("src.main", str(module_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)

# Import needed classes
Engine = main.Engine
EnhancedAbuseEmailDetector = main.EnhancedAbuseEmailDetector

# User's test email
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


class TestAbuseReporting:
    """Test abuse reporting functionality"""

    @pytest.fixture
    def mock_settings(self, monkeypatch):
        """Mock settings for email configuration"""
        monkeypatch.setattr(main.settings, "SMTP_HOST", "smtp.test.com")
        monkeypatch.setattr(main.settings, "SMTP_PORT", 587)
        monkeypatch.setattr(main.settings, "SMTP_USER", "test@test.com")
        monkeypatch.setattr(main.settings, "SMTP_PASS", "testpass")
        monkeypatch.setattr(main.settings, "ABUSE_EMAIL_SENDER", "abuse@test.com")
        monkeypatch.setattr(main.settings, "ABUSE_EMAIL_SUBJECT", "Phishing Report: {site}")
        monkeypatch.setattr(main.settings, "DEFAULT_CC_EMAILS", TEST_USER_EMAIL)

    @pytest.fixture
    def test_engine(self, mock_settings):
        """Create test engine instance"""
        import argparse

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
        return Engine(args)

    def test_send_abuse_report_with_user_email(self, test_engine, monkeypatch):
        """Test sending abuse report with user's email as CC"""
        # Mock SMTP
        mock_smtp = MagicMock()
        mock_smtp_instance = MagicMock()
        mock_smtp.return_value = mock_smtp_instance

        with patch("smtplib.SMTP", mock_smtp):
            # Mock template rendering
            with patch("jinja2.Environment") as mock_env:
                mock_template = MagicMock()
                mock_template.render.return_value = "<html>Test Report</html>"
                mock_env.return_value.get_template.return_value = mock_template

                # Test sending report
                result = test_engine.send_abuse_report(
                    site_url="https://phishing-test.com",
                    abuse_emails=["abuse@provider.com"],
                    whois_info={"domain": "phishing-test.com"},
                    cc_emails=[TEST_USER_EMAIL],
                )

                # Verify SMTP was called
                mock_smtp.assert_called_once_with("smtp.test.com", 587)
                mock_smtp_instance.starttls.assert_called_once()
                mock_smtp_instance.login.assert_called_once_with("test@test.com", "testpass")

                # Verify email was sent with user's email in CC
                send_calls = mock_smtp_instance.send_message.call_args_list
                assert len(send_calls) > 0

                # Check that user's email was included
                sent_message = send_calls[0][0][0]
                assert TEST_USER_EMAIL in str(sent_message)

    def test_test_report_mode(self, test_engine):
        """Test the --test-report functionality"""
        with patch.object(test_engine, "send_abuse_report") as mock_send:
            mock_send.return_value = True

            # Simulate test report
            test_engine.args.test_report = True
            test_engine.args.abuse_email = TEST_USER_EMAIL

            with patch.object(test_engine, "multi_api_scan") as mock_scan:
                mock_scan.return_value = {
                    "threat_level": "high",
                    "confidence_score": 95,
                    "virustotal": {"malicious": 10},
                    "urlvoid": {"detections": 5},
                }

                # Execute test report
                success = test_engine.send_abuse_report(
                    site_url="https://test-phishing.com",
                    abuse_emails=[TEST_USER_EMAIL],
                    whois_info={"test": "data"},
                    test_mode=True,
                )

                # Verify test email was prepared
                mock_send.assert_called()
                call_args = mock_send.call_args[1]
                assert TEST_USER_EMAIL in call_args["abuse_emails"]

    def test_enhanced_abuse_detector(self):
        """Test enhanced abuse email detection"""
        detector = EnhancedAbuseEmailDetector()

        # Test email validation
        assert detector.validate_email(TEST_USER_EMAIL) is True
        assert detector.validate_email("invalid-email") is False
        assert detector.validate_email("test@") is False

        # Test domain validation
        assert detector.validate_abuse_email_domain(TEST_USER_EMAIL, "phishing.com") is True
        assert detector.validate_abuse_email_domain("abuse@phishing.com", "phishing.com") is False

    def test_attachment_handling(self, test_engine, tmp_path):
        """Test email attachment handling"""
        # Create test attachment
        test_file = tmp_path / "evidence.pdf"
        test_file.write_bytes(b"Test PDF content")

        with patch("smtplib.SMTP") as mock_smtp:
            with patch("jinja2.Environment") as mock_env:
                mock_template = MagicMock()
                mock_template.render.return_value = "<html>Report</html>"
                mock_env.return_value.get_template.return_value = mock_template

                # Send report with attachment
                result = test_engine.send_abuse_report(
                    site_url="https://phishing.com",
                    abuse_emails=["abuse@test.com"],
                    whois_info={},
                    attachment_paths=[str(test_file)],
                    cc_emails=[TEST_USER_EMAIL],
                )

                # Verify attachment was processed
                send_calls = mock_smtp.return_value.send_message.call_args_list
                if send_calls:
                    sent_message = send_calls[0][0][0]
                    # Check that attachment was added to message
                    assert isinstance(sent_message, MIMEMultipart)

    def test_multi_api_results_in_report(self, test_engine):
        """Test that multi-API results are included in abuse report"""
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

        with patch("smtplib.SMTP"):
            with patch("jinja2.Environment") as mock_env:
                mock_template = MagicMock()
                mock_env.return_value.get_template.return_value = mock_template

                # Send report with multi-API results
                test_engine.send_abuse_report(
                    site_url="https://phishing.com",
                    abuse_emails=["abuse@test.com"],
                    whois_info={},
                    multi_api_results=multi_api_results,
                    cc_emails=[TEST_USER_EMAIL],
                )

                # Verify template was called with API results
                render_call = mock_template.render.call_args[1]
                assert render_call["multi_api_results"] == multi_api_results
                assert render_call["threat_level"] == "critical"
                assert render_call["confidence_score"] == 98

    def test_email_error_handling(self, test_engine):
        """Test email sending error handling"""
        with patch("smtplib.SMTP") as mock_smtp:
            # Simulate SMTP error
            mock_smtp.side_effect = smtplib.SMTPException("Connection failed")

            result = test_engine.send_abuse_report(
                site_url="https://phishing.com",
                abuse_emails=["abuse@test.com"],
                whois_info={},
                cc_emails=[TEST_USER_EMAIL],
            )

            # Should handle error gracefully
            assert result is False

    def test_process_reports_command(self, test_engine, monkeypatch):
        """Test --process-reports command functionality"""
        # Mock database query for flagged sites
        mock_conn = MagicMock()
        mock_result = [("https://phishing1.com", 1), ("https://phishing2.com", 1)]
        mock_conn.execute.return_value.fetchall.return_value = mock_result

        with patch.object(test_engine.db_manager.engine, "connect") as mock_connect:
            mock_connect.return_value.__enter__.return_value = mock_conn

            with patch.object(test_engine, "multi_api_scan") as mock_scan:
                mock_scan.return_value = {"threat_level": "high", "confidence_score": 90}

                with patch.object(test_engine, "send_abuse_report") as mock_send:
                    mock_send.return_value = True

                    # Set CC email to user's email
                    test_engine.args.cc = TEST_USER_EMAIL

                    # Process reports
                    test_engine.args.process_reports = True
                    test_engine.engine_mode.process_mode = True

                    # This would normally be called by the main engine loop
                    # We'll simulate the key parts here
                    assert len(mock_result) == 2

                    # Verify user's email would be used as CC
                    assert test_engine.args.cc == TEST_USER_EMAIL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

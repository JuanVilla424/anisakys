#!/usr/bin/env python3
"""
Real SMTP test without mocks for debugging
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import settings
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# User test email - CLEANUP REQUIRED: Remove test emails sent to this address
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


def test_smtp_connection():
    """Test direct SMTP connection"""
    print("🧪 DIRECT SMTP CONNECTION TEST")
    print("=" * 45)

    print(f"📧 SMTP Configuration:")
    print(f"   - Host: {settings.SMTP_HOST}")
    print(f"   - Puerto: {settings.SMTP_PORT}")
    print(f"   - Sender: {settings.ABUSE_EMAIL_SENDER}")

    try:
        print(f"\n🔌 Connecting to SMTP...")

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            print(f"✅ Successful connection")

            # Try login if credentials exist
            smtp_user = getattr(settings, "SMTP_USER", "")
            smtp_pass = getattr(settings, "SMTP_PASS", "")

            if smtp_user and smtp_pass:
                print(f"🔐 Attempting login with user: {smtp_user}")
                server.login(smtp_user, smtp_pass)
                print(f"✅ Successful login")
            else:
                print(f"ℹ️  No SMTP credentials configured")

            # Create test email
            print(f"\n📧 Creating test email...")

            msg = MIMEMultipart()
            msg["Subject"] = "Anisakys ICANN Compliance SMTP Test"
            msg["From"] = settings.ABUSE_EMAIL_SENDER
            msg["To"] = TEST_USER_EMAIL

            html_content = f"""
            <html>
            <body>
                <h2>Anisakys SMTP Test</h2>
                <p>This is a test email to verify SMTP functionality.</p>
                <p><strong>Recipient:</strong> {TEST_USER_EMAIL}</p>
                <p><strong>Implemented ICANN features:</strong></p>
                <ul>
                    <li>✅ Automatic screenshots</li>
                    <li>✅ Abuse contact validation</li>
                    <li>✅ Report tracking</li>
                    <li>✅ 2 business day SLA</li>
                    <li>✅ Template compliance ICANN 2024</li>
                </ul>
                <p>If you receive this email, the SMTP system is working correctly.</p>
            </body>
            </html>
            """

            msg.attach(MIMEText(html_content, "html"))

            print(f"📤 Sending test email...")
            server.send_message(msg)
            print(f"✅ Email sent successfully to {TEST_USER_EMAIL}")

            return True

    except ConnectionRefusedError:
        print(f"❌ Connection refused - SMTP server not available")
        return False
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Authentication error: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ Error SMTP: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_real_abuse_report():
    """Test real abuse report without mocks"""
    print(f"\n🧪 REAL REPORT TEST WITHOUT MOCKS")
    print("=" * 45)

    from src.main import Engine, set_testing_mode

    set_testing_mode(True)  # Block CCs for security
    import argparse

    # Arguments for real report
    args = argparse.Namespace(
        timeout=10,
        log_level="DEBUG",
        report=None,
        process_reports=False,
        threads_only=False,
        test_report=False,  # FALSE = real report
        multi_api_scan=False,  # FALSE for faster execution
        url=None,
        abuse_email=TEST_USER_EMAIL,  # User email
        attachment=None,
        attachments_folder=None,
        cc=None,  # No CC for simplicity
        regen_queries=False,
        reset_offset=False,
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

    try:
        print(f"🔧 Initializing Engine...")
        engine = Engine(args)

        # Real URL for screenshot - CLEANUP REQUIRED: Remove any generated screenshots
        test_url = "https://httpbin.org/html"
        print(f"📧 Test URL: {test_url}")
        print(f"📧 Recipient: {TEST_USER_EMAIL}")

        # Create AbuseReportManager
        from src.main import AbuseReportManager, set_testing_mode

        set_testing_mode(True)  # Block CCs for security

        report_manager = AbuseReportManager(
            db_manager=engine.db_manager,
            abuse_detector=engine.abuse_detector,
            cc_emails=None,  # No CC
            timeout=engine.timeout,
        )

        # Add ICANN services
        report_manager.abuse_contact_validator = engine.abuse_contact_validator
        report_manager.screenshot_service = engine.screenshot_service
        report_manager.report_tracker = engine.report_tracker

        print(f"📤 Sending REAL report...")

        # REAL sending (no mocks) - CLEANUP REQUIRED: Remove abuse report records from database
        result = report_manager.send_abuse_report(
            abuse_emails=[TEST_USER_EMAIL],
            site_url=test_url,
            whois_str="WHOIS info for httpbin.org test site",
            test_mode=False,  # REAL
        )

        print(f"\n📊 Result: {'✅ Successful' if result else '❌ Failed'}")

        if result:
            print(f"🎉 Report sent! Check your email: {TEST_USER_EMAIL}")
        else:
            print(f"❌ Error sending report")

        return result

    except Exception as e:
        print(f"❌ Error in real report: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Main function"""
    print("🚀 REAL SMTP DEBUG - ANISAKYS ICANN COMPLIANCE")
    print("=" * 55)

    # Test 1: Basic SMTP connection
    smtp_ok = test_smtp_connection()

    # Test 2: Real report if SMTP works
    if smtp_ok:
        print(f"\n" + "=" * 55)
        report_ok = test_real_abuse_report()
    else:
        print(f"\n❌ Skipping report test because SMTP failed")
        report_ok = False

    # Final result
    print(f"\n🏁 FINAL RESULT")
    print("=" * 20)
    print(f"📧 Direct SMTP: {'✅ OK' if smtp_ok else '❌ FAILED'}")
    print(f"📋 Real report: {'✅ OK' if report_ok else '❌ FAILED'}")

    if smtp_ok and report_ok:
        print(f"\n🎉 SYSTEM WORKING!")
        print(f"📧 Check your email: {TEST_USER_EMAIL}")
        print(f"📥 May take a few minutes to arrive")
    else:
        print(f"\n⚠️  Check SMTP configuration")

    return smtp_ok and report_ok


if __name__ == "__main__":
    success = main()

    # Auto cleanup test data
    try:
        from cleanup_test_data import (
            cleanup_database_records,
            cleanup_screenshot_files,
            cleanup_cache_data,
        )

        print("\n🧹 Cleaning test data...")
        cleanup_database_records()
        cleanup_screenshot_files()
        cleanup_cache_data()
        print("✅ Test data cleaned")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")

    sys.exit(0 if success else 1)

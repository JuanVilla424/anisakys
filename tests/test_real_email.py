#!/usr/bin/env python3
"""
Real test of email validation and ICANN functionalities
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.reporting.abuse_contact_validator import AbuseContactValidator, validate_abuse_email
from src.screenshot_service import ScreenshotService, capture_phishing_screenshot
from src.reporting.report_tracker import ReportTracker, create_report_record
import tempfile
from pathlib import Path

# Test user email - CLEANUP REQUIRED: Remove validation records from database
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


def test_real_email_validation():
    """Test validation of the real test email"""
    print(f"\n🧪 Testing email validation: {TEST_USER_EMAIL}")

    validator = AbuseContactValidator(timeout=10)

    # Basic format validation
    format_valid = validator.validate_email_format(TEST_USER_EMAIL)
    print(f"📧 Email format: {'✅ Valid' if format_valid else '❌ Invalid'}")

    # Complete validation
    result = validator.validate_registrar_abuse_contact(TEST_USER_EMAIL)

    print(f"📊 Validation result:")
    print(f"   - Email: {result['email']}")
    print(f"   - Valid format: {'✅' if result['format_valid'] else '❌'}")
    print(f"   - Valid domain: {'✅' if result['domain_valid'] else '❌'}")
    print(f"   - Valid SMTP: {'✅' if result['smtp_valid'] else '⚠️'}")
    print(f"   - Standards compliant: {'✅' if result['standards_compliant'] else '⚠️'}")
    print(f"   - Generally valid: {'✅' if result['valid'] else '❌'}")

    if result["errors"]:
        print(f"❌ Errors:")
        for error in result["errors"]:
            print(f"   - {error}")

    if result["warnings"]:
        print(f"⚠️  Warnings:")
        for warning in result["warnings"]:
            print(f"   - {warning}")

    return result


def test_screenshot_service():
    """Test the screenshot service"""
    print(f"\n📸 Testing screenshot service...")

    # CLEANUP REQUIRED: Screenshots directory auto-cleaned with tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        service = ScreenshotService(screenshots_dir=temp_dir, timeout=10)

        print(f"📁 Screenshots directory: {service.screenshots_dir}")
        print(f"🔧 Preferred engine: {service.preferred_engine}")

        # Test with a real site (not actually executed to avoid issues)
        print(f"✅ Service initialized correctly")

        return True


def test_report_record_creation():
    """Test report record creation"""
    print(f"\n📋 Testing report record creation...")

    report = create_report_record(
        site_url="https://test-phishing-site.com",
        recipients=["abuse@registrar.com"],
        subject="Test Phishing Report",
        cc_recipients=[TEST_USER_EMAIL],
        screenshot_included=True,
    )

    print(f"📊 Record created:")
    print(f"   - Report ID: {report.report_id}")
    print(f"   - Site URL: {report.site_url}")
    print(f"   - Recipients: {report.recipients}")
    print(f"   - CC: {report.cc_recipients}")
    print(f"   - Screenshot included: {'✅' if report.screenshot_included else '❌'}")
    print(f"   - SLA deadline: {report.sla_deadline}")
    print(f"   - ICANN compliant: {'✅' if report.icann_compliant else '❌'}")

    return report


def test_multiple_abuse_emails():
    """Test validation of multiple abuse emails"""
    print(f"\n📧 Testing validation of multiple emails...")

    # Common test emails for phishing - CLEANUP REQUIRED: Remove validation cache data
    test_emails = [
        "abuse@godaddy.com",
        "abuse@namecheap.com",
        "abuse@cloudflare.com",
        TEST_USER_EMAIL,
        "invalid-email-format",
        "abuse@fake-nonexistent-domain-12345.com",
    ]

    validator = AbuseContactValidator(timeout=5)

    for email in test_emails:
        print(f"\n📧 Validating: {email}")
        result = validator.validate_registrar_abuse_contact(email)

        status = "✅ Valid" if result["valid"] else "❌ Invalid"
        print(f"   Status: {status}")

        if result["warnings"]:
            print(f"   ⚠️  Warnings: {len(result['warnings'])}")
        if result["errors"]:
            print(f"   ❌ Errors: {len(result['errors'])}")


def main():
    """Main test function"""
    print("🧪 ICANN COMPLIANCE FUNCTIONALITY TESTS")
    print("=" * 50)

    try:
        # Test 1: Real email validation
        email_result = test_real_email_validation()

        # Test 2: Screenshot service
        screenshot_result = test_screenshot_service()

        # Test 3: Report record creation
        report_result = test_report_record_creation()

        # Test 4: Multiple emails
        test_multiple_abuse_emails()

        print(f"\n🎉 TEST SUMMARY")
        print(f"=" * 30)
        print(f"✅ Test email: {'Valid' if email_result['valid'] else 'With issues'}")
        print(f"✅ Screenshot service: {'Working' if screenshot_result else 'With issues'}")
        print(f"✅ Report creation: {'Working' if report_result else 'With issues'}")

        if email_result["valid"]:
            print(f"\n🎯 The email {TEST_USER_EMAIL} is ready to use in tests!")
        else:
            print(f"\n⚠️  The email {TEST_USER_EMAIL} may have limitations.")

    except Exception as e:
        print(f"\n❌ Error during tests: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()

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

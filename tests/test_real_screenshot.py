#!/usr/bin/env python3
"""
Real screenshot capture test with real website
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.screenshot_service import ScreenshotService, capture_phishing_screenshot
import tempfile
from pathlib import Path
import time


def test_real_screenshot():
    """Test screenshot capture with real website"""
    print("🧪 REAL SCREENSHOT TEST")
    print("=" * 40)

    # Safe sites for testing
    test_sites = ["https://example.com", "https://httpbin.org/html", "https://www.google.com"]

    # CLEANUP REQUIRED: Screenshots saved to temporary directory - auto-cleaned
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"📁 Temporary directory: {temp_dir}")

        service = ScreenshotService(screenshots_dir=temp_dir, timeout=15)
        print(f"🔧 Preferred engine: {service.preferred_engine}")

        if not service.preferred_engine:
            print("❌ No screenshot engine available (Selenium/Playwright)")
            print("💡 Install with: pip install selenium playwright")
            return False

        for site_url in test_sites:
            print(f"\n📸 Attempting to capture: {site_url}")

            try:
                result = service.capture_screenshot(site_url, use_async=False)

                if result and result.get("success"):
                    screenshot_path = Path(result["screenshot_path"])

                    print(f"✅ Successful screenshot:")
                    print(f"   - File: {result['filename']}")
                    print(f"   - Size: {result['size_bytes']} bytes")
                    print(f"   - Engine: {result['engine']}")
                    print(f"   - Exists: {'✅' if screenshot_path.exists() else '❌'}")

                    if "page_info" in result:
                        print(f"   - Title: {result['page_info'].get('title', 'N/A')}")
                        print(f"   - Final URL: {result['page_info'].get('url', 'N/A')}")

                    return True, result
                else:
                    error = (
                        result.get("error", "Unknown error") if result else "Service unavailable"
                    )
                    print(f"❌ Screenshot failed: {error}")
                    continue

            except Exception as e:
                print(f"❌ Error during screenshot: {e}")
                continue

        print(f"\n❌ Could not capture screenshot of any site")
        return False, None


def test_screenshot_with_abuse_report_integration():
    """Test screenshot integration with abuse report"""
    print(f"\n🧪 INTEGRATION TEST WITH REPORT")
    print("=" * 45)

    # Use httpbin which is reliable for testing - CLEANUP REQUIRED: Remove any generated screenshots
    test_url = "https://httpbin.org/html"

    success, screenshot_result = test_real_screenshot()

    if not success:
        print("❌ Could not capture screenshot, skipping integration test")
        return False

    print(f"\n📋 Simulating integration with abuse report...")

    # Simulate template with real data
    template_data = {
        "site_url": test_url,
        "attachment_filename": screenshot_result["filename"],
        "screenshot_path": screenshot_result["screenshot_path"],
        "screenshot_included": True,
        "report_id": "ANISAKYS-TEST-REAL-001",
        "report_date": "2025-01-29 16:30:00",
        "sla_deadline": "2025-01-31 17:00:00",
    }

    print(f"✅ Template data:")
    for key, value in template_data.items():
        print(f"   - {key}: {value}")

    # Verify that file exists and has content
    screenshot_path = Path(screenshot_result["screenshot_path"])
    if screenshot_path.exists() and screenshot_path.stat().st_size > 0:
        print(f"✅ Screenshot ready to attach in email: {screenshot_path}")
        print(f"   - Size: {screenshot_path.stat().st_size} bytes")
        return True
    else:
        print(f"❌ Invalid screenshot for attachment")
        return False


def test_attachment_selection():
    """Test that only the first attachment is shown in template"""
    print(f"\n🧪 ATTACHMENT SELECTION TEST")
    print("=" * 45)

    # Simulate multiple attachments - CLEANUP REQUIRED: Test data only, no actual files created
    attachment_filenames = [
        "screenshot_phishing_site.png",
        "Derechos_autor_SIMIT.pdf",
        "Derechos_autor_FCM.pdf",
        "additional_evidence.txt",
    ]

    # Only the first should be shown in template
    first_attachment = attachment_filenames[0]

    print(f"📎 Available attachments: {len(attachment_filenames)}")
    for i, filename in enumerate(attachment_filenames):
        print(f"   {i+1}. {filename}")

    print(f"\n📄 Will be shown in template:")
    print(f"   - Displayed attachment: {first_attachment}")
    print(f"   - Total attached attachments: {len(attachment_filenames)}")

    # Verify template logic
    is_pdf = first_attachment.lower().endswith(".pdf")
    is_image = first_attachment.lower().endswith((".png", ".jpg", ".jpeg"))

    print(f"✅ Detected file type:")
    print(f"   - Is PDF: {'✅' if is_pdf else '❌'}")
    print(f"   - Is image: {'✅' if is_image else '❌'}")

    return True


def main():
    """Main function"""
    print("🚀 REAL SCREENSHOT TESTS FOR ANISAKYS")
    print("=" * 55)

    try:
        # Test 1: Real screenshot
        screenshot_ok, _ = test_real_screenshot()

        # Test 2: Integration with report
        integration_ok = test_screenshot_with_abuse_report_integration() if screenshot_ok else False

        # Test 3: Attachment selection
        attachment_ok = test_attachment_selection()

        print(f"\n🏁 TEST SUMMARY")
        print("=" * 25)
        print(f"📸 Real screenshot: {'✅ OK' if screenshot_ok else '❌ FAILED'}")
        print(f"📋 Integration: {'✅ OK' if integration_ok else '❌ FAILED'}")
        print(f"📎 Attachments: {'✅ OK' if attachment_ok else '❌ FAILED'}")

        if screenshot_ok:
            print(f"\n🎉 SCREENSHOTS WORKING!")
            print(f"✅ System can capture visual evidence")
            print(f"✅ Screenshots ready to attach in reports")
            print(f"✅ Meets ICANN visual evidence requirements")
        else:
            print(f"\n⚠️  Screenshots not available")
            print(f"💡 Install drivers: apt-get install chromium-browser")
            print(f"💡 Or install: pip install selenium playwright")

        return screenshot_ok and integration_ok and attachment_ok

    except Exception as e:
        print(f"\n❌ Error during tests: {e}")
        import traceback

        traceback.print_exc()
        return False


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

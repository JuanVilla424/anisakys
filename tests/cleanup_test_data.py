#!/usr/bin/env python3
"""
Test Data Cleanup Script
========================

This script cleans up test data created during real integration tests.
Run this after executing the real test files that create actual data.

Usage:
    python tests/cleanup_test_data.py

What it cleans:
- Abuse reports created during tests
- Screenshot files generated during tests
- Temporary phishing site records
- Cache files and temporary data
"""

import sys
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import glob

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from src.config import settings
    from sqlalchemy import create_engine, text

    DATABASE_URL = getattr(settings, "DATABASE_URL", None)
except Exception as e:
    print(f"⚠️  Could not load database config: {e}")
    DATABASE_URL = None

TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


def cleanup_database_records():
    """Clean up ONLY test records created during test runs - VERY CONSERVATIVE"""
    if not DATABASE_URL:
        print("⚠️  No database URL configured, skipping database cleanup")
        return False

    try:
        engine = create_engine(DATABASE_URL)

        with engine.begin() as conn:
            # ONLY clean abuse reports sent to the SPECIFIC test email address
            # AND containing test report IDs generated during tests
            result = conn.execute(
                text(
                    """
                    DELETE FROM abuse_reports
                    WHERE recipients = :exact_email
                    AND (
                        report_id LIKE 'ANISAKYS-%-TEST-%'
                        OR site_url IN ('https://httpbin.org/html', 'https://example.com')
                    )
                """
                ),
                {"exact_email": f'["{TEST_USER_EMAIL}"]'},
            )
            deleted_reports = result.rowcount

            # ONLY clean phishing sites that were EXPLICITLY created during tests
            # with very specific test patterns from our test files
            result = conn.execute(
                text(
                    """
                    DELETE FROM phishing_sites
                    WHERE (
                        url = 'https://httpbin.org/html'
                        OR url = 'https://example.com'
                        OR url LIKE 'https://test-phishing-site.com'
                        OR (url LIKE '%temp-%' AND description LIKE 'Test record%')
                    )
                    AND manual_flag = 1
                """
                )
            )
            deleted_sites = result.rowcount

            print(f"🗄️  Database cleanup complete (CONSERVATIVE MODE):")
            print(f"   - Removed {deleted_reports} test abuse report records")
            print(f"   - Removed {deleted_sites} test phishing site records")
            print(f"   - Scan results left untouched for safety")

            return deleted_reports > 0 or deleted_sites > 0

    except Exception as e:
        print(f"❌ Database cleanup failed: {e}")
        return False


def cleanup_screenshot_files():
    """Clean up ONLY screenshot files generated during TODAY'S tests - VERY CONSERVATIVE"""
    cleaned_files = 0

    # Get today's date string for safety
    today_str = datetime.now().strftime("%Y%m%d")

    # ONLY look in current project directory, not system-wide
    project_root = Path(__file__).parent.parent

    # Very specific patterns that match our test files EXACTLY
    test_patterns = [
        f"phishing_httpbin_org_{today_str}_*.png",  # From test_real_smtp.py
        f"phishing_example_com_{today_str}_*.png",  # From test_complete_icann_report.py
    ]

    # Only look in specific directories within project
    safe_dirs = [project_root / "screenshots", project_root / "attachments"]

    for screenshot_dir in safe_dirs:
        if screenshot_dir.exists():
            for pattern in test_patterns:
                for file_path in screenshot_dir.glob(pattern):
                    try:
                        # Extra safety: only delete if created in last 24 hours
                        file_age = datetime.now().timestamp() - file_path.stat().st_mtime
                        if file_age < 86400:  # 24 hours
                            file_path.unlink()
                            cleaned_files += 1
                            print(f"🗑️  Removed TODAY'S test screenshot: {file_path}")
                        else:
                            print(f"⚠️  Skipped old file (>24h): {file_path}")
                    except Exception as e:
                        print(f"⚠️  Could not remove {file_path}: {e}")

    # ONLY clean temp directories that explicitly contain our test patterns
    # and were created today
    temp_patterns = ["/tmp/tmp*httpbin*", "/tmp/tmp*example*"]
    for pattern in temp_patterns:
        for temp_path in glob.glob(pattern):
            try:
                temp_dir = Path(temp_path)
                if temp_dir.exists():
                    # Only if created in last 24 hours
                    dir_age = datetime.now().timestamp() - temp_dir.stat().st_mtime
                    if dir_age < 86400:
                        shutil.rmtree(temp_dir)
                        print(f"🗑️  Removed TODAY'S temp directory: {temp_dir}")
                    else:
                        print(f"⚠️  Skipped old temp dir (>24h): {temp_dir}")
            except Exception as e:
                print(f"⚠️  Could not remove temp directory {temp_path}: {e}")

    print(f"📸 Screenshot cleanup complete (CONSERVATIVE): Removed {cleaned_files} files")
    return cleaned_files > 0


def cleanup_cache_data():
    """Clean up ONLY test-related cache files - VERY CONSERVATIVE"""
    cleaned_items = 0

    # ONLY remove cache files that are definitely from tests
    # and only from tests directory
    tests_dir = Path(__file__).parent

    cache_patterns = [
        "__pycache__/test_real_*.pyc",  # Only our specific test files
        ".pytest_cache/",  # Pytest cache (safe to remove)
    ]

    for pattern in cache_patterns:
        for cache_item in tests_dir.glob(pattern):
            try:
                if cache_item.is_file():
                    cache_item.unlink()
                    cleaned_items += 1
                    print(f"🗑️  Removed test cache file: {cache_item}")
                elif cache_item.is_dir():
                    shutil.rmtree(cache_item)
                    cleaned_items += 1
                    print(f"🗑️  Removed test cache directory: {cache_item}")
            except Exception as e:
                print(f"⚠️  Could not remove cache item {cache_item}: {e}")

    print(f"💾 Cache cleanup complete (CONSERVATIVE): Removed {cleaned_items} items")
    return cleaned_items > 0


def preview_cleanup():
    """Show what WOULD be deleted without actually deleting anything"""
    print("👀 PREVIEW MODE - SHOWING WHAT WOULD BE DELETED")
    print("=" * 60)

    # Preview database records
    if DATABASE_URL:
        try:
            engine = create_engine(DATABASE_URL)
            with engine.connect() as conn:
                # Preview abuse reports
                result = conn.execute(
                    text(
                        """
                        SELECT report_id, site_url, created_at
                        FROM abuse_reports
                        WHERE recipients = :exact_email
                        AND (
                            report_id LIKE 'ANISAKYS-%-TEST-%'
                            OR site_url IN ('https://httpbin.org/html', 'https://example.com')
                        )
                    """
                    ),
                    {"exact_email": f'["{TEST_USER_EMAIL}"]'},
                )
                reports = result.fetchall()
                print(f"📧 Would delete {len(reports)} abuse report records:")
                for report in reports:
                    print(f"   - {report.report_id} ({report.site_url}) from {report.created_at}")

                # Preview phishing sites
                result = conn.execute(
                    text(
                        """
                        SELECT url, first_seen
                        FROM phishing_sites
                        WHERE (
                            url = 'https://httpbin.org/html'
                            OR url = 'https://example.com'
                            OR url LIKE 'https://test-phishing-site.com'
                            OR (url LIKE '%temp-%' AND description LIKE 'Test record%')
                        )
                        AND manual_flag = 1
                    """
                    )
                )
                sites = result.fetchall()
                print(f"🌐 Would delete {len(sites)} phishing site records:")
                for site in sites:
                    print(f"   - {site.url} from {site.first_seen}")

        except Exception as e:
            print(f"❌ Could not preview database: {e}")

    # Preview screenshot files
    today_str = datetime.now().strftime("%Y%m%d")
    project_root = Path(__file__).parent.parent

    screenshot_count = 0
    for screenshot_dir in [project_root / "screenshots", project_root / "attachments"]:
        if screenshot_dir.exists():
            for pattern in [
                f"phishing_httpbin_org_{today_str}_*.png",
                f"phishing_example_com_{today_str}_*.png",
            ]:
                for file_path in screenshot_dir.glob(pattern):
                    file_age = datetime.now().timestamp() - file_path.stat().st_mtime
                    if file_age < 86400:
                        print(f"📸 Would delete screenshot: {file_path}")
                        screenshot_count += 1

    print(f"\n📊 SUMMARY:")
    print(f"   📧 Database records: {len(reports) if 'reports' in locals() else 0}")
    print(f"   🌐 Phishing sites: {len(sites) if 'sites' in locals() else 0}")
    print(f"   📸 Screenshot files: {screenshot_count}")
    print(f"\n⚠️  This is PREVIEW only - nothing was deleted!")


def main():
    """Main cleanup function - automatic cleanup after tests"""

    print("🧹 Cleaning test data...")

    # Auto cleanup without confirmation
    cleanup_database_records()
    cleanup_screenshot_files()
    cleanup_cache_data()

    print("✅ Test data cleanup completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

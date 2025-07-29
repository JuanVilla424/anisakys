#!/usr/bin/env python3
"""
Test runner for Anisakys with functional tests
"""
import os
import sys
import pytest
import subprocess
from pathlib import Path

# User email for test reports
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"


def setup_test_environment():
    """Setup test environment"""
    print("🔧 Setting up test environment...")

    # Ensure test database exists
    os.environ["DATABASE_URL"] = "postgresql://postgres:j*3_7f-jh.s5.as@localhost:5332/test_db"

    # Set test email
    os.environ["DEFAULT_CC_EMAILS"] = TEST_USER_EMAIL

    # Create test fixtures directory
    fixtures_dir = Path("tests/fixtures")
    fixtures_dir.mkdir(exist_ok=True)

    print(f"📧 Test reports will be sent to: {TEST_USER_EMAIL}")
    print("✅ Test environment ready")


def run_unit_tests():
    """Run unit tests"""
    print("\n🧪 Running unit tests...")

    test_files = [
        "tests/test_database_upgrade.py",
        "tests/test_multi_api_validation.py",
        "tests/test_abuse_reporting.py",
    ]

    for test_file in test_files:
        print(f"\n📋 Testing: {test_file}")
        result = pytest.main([test_file, "-v", "--tb=short"])
        if result != 0:
            print(f"❌ Tests failed in {test_file}")
            return False

    print("\n✅ All unit tests passed!")
    return True


def run_functional_tests():
    """Run functional end-to-end tests"""
    print("\n🚀 Running functional tests...")

    result = pytest.main(
        ["tests/test_functional_e2e.py", "-v", "--tb=short", "-s"]  # Show print statements
    )

    if result == 0:
        print("\n✅ All functional tests passed!")
        return True
    else:
        print("\n❌ Functional tests failed")
        return False


def run_integration_test():
    """Run a real integration test"""
    print("\n🔗 Running integration test...")

    # Test the actual command that was failing
    print("Testing: python anisakys.py --process-reports")

    try:
        # Activate virtual environment and run command
        result = subprocess.run(
            [
                "bash",
                "-c",
                "source venv/bin/activate && python anisakys.py --test-report --abuse-email "
                + TEST_USER_EMAIL,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            print("✅ Integration test passed!")
            print(f"📧 Test report should be sent to: {TEST_USER_EMAIL}")
            return True
        else:
            print("❌ Integration test failed")
            print(f"Error: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("⏱️  Integration test timed out")
        return False
    except Exception as e:
        print(f"❌ Integration test error: {e}")
        return False


def main():
    """Main test runner"""
    print("🔍 Anisakys Test Suite")
    print("=" * 50)

    # Setup
    setup_test_environment()

    # Run tests
    all_passed = True

    # Unit tests
    if not run_unit_tests():
        all_passed = False

    # Functional tests
    if not run_functional_tests():
        all_passed = False

    # Integration test (optional - requires real environment)
    if "--integration" in sys.argv:
        if not run_integration_test():
            all_passed = False

    # Summary
    print("\n" + "=" * 50)
    if all_passed:
        print("✅ All tests passed successfully!")
        print(f"📧 Test emails configured for: {TEST_USER_EMAIL}")
        return 0
    else:
        print("❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

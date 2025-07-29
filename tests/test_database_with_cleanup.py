"""
Example test showing proper cleanup of individual records
"""

import pytest
from sqlalchemy import text
from pathlib import Path
import importlib.util
from tests.conftest import temporary_test_data

# Load main module
module_path = Path(__file__).parent.parent / "src" / "main.py"
spec = importlib.util.spec_from_file_location("src.main", str(module_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)


class TestDatabaseWithCleanup:
    """Tests that demonstrate proper record cleanup"""

    def test_with_test_data_manager(self, test_data_manager):
        """Test using TestDataManager for automatic cleanup"""
        # Create a test phishing site
        test_url = test_data_manager.create_phishing_site("-example")

        # Verify it exists
        with test_data_manager.engine.connect() as conn:
            result = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE url = :url"), {"url": test_url}
            ).scalar()
            assert result == 1

        # The record will be automatically cleaned up when test ends

    def test_with_context_manager(self, db_engine, unique_test_id):
        """Test using context manager for single record"""
        # Use context manager for automatic cleanup
        with temporary_test_data(db_engine, unique_test_id) as test_url:
            # Verify record exists
            with db_engine.connect() as conn:
                result = conn.execute(
                    text("SELECT COUNT(*) FROM phishing_sites WHERE url = :url"), {"url": test_url}
                ).scalar()
                assert result == 1

        # Verify record is cleaned up
        with db_engine.connect() as conn:
            result = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE url = :url"), {"url": test_url}
            ).scalar()
            assert result == 0

    def test_multiple_records_cleanup(self, test_data_manager):
        """Test creating and cleaning multiple records"""
        # Create multiple test records
        urls = []
        for i in range(3):
            url = test_data_manager.create_phishing_site(f"-multi-{i}")
            urls.append(url)

        # Verify all exist
        with test_data_manager.engine.connect() as conn:
            for url in urls:
                result = conn.execute(
                    text("SELECT COUNT(*) FROM phishing_sites WHERE url = :url"), {"url": url}
                ).scalar()
                assert result == 1

        # All will be cleaned up automatically

    def test_scan_results_cleanup(self, test_data_manager):
        """Test scan results table cleanup"""
        # Create scan result
        scan_url = test_data_manager.create_scan_result()

        # Verify it exists
        with test_data_manager.engine.connect() as conn:
            result = conn.execute(
                text("SELECT COUNT(*) FROM scan_results WHERE url = :url"), {"url": scan_url}
            ).scalar()
            assert result == 1

        # Will be cleaned up automatically

    def test_transaction_rollback(self, db_session, unique_test_id):
        """Test using transaction rollback for cleanup"""
        test_url = f"https://rollback-test-{unique_test_id}.com"

        # Insert within transaction
        db_session.execute(
            text(
                """
                INSERT INTO phishing_sites (url, manual_flag, first_seen)
                VALUES (:url, 1, CURRENT_TIMESTAMP)
            """
            ),
            {"url": test_url},
        )

        # Verify it exists in this session
        result = db_session.execute(
            text("SELECT COUNT(*) FROM phishing_sites WHERE url = :url"), {"url": test_url}
        ).scalar()
        assert result == 1

        # Transaction will rollback automatically, cleaning the record


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Simple test for multi-API functionality in Engine class
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path
import importlib.util
import argparse

# Load main module
module_path = Path(__file__).parent.parent / "src" / "main.py"
spec = importlib.util.spec_from_file_location("src.main", str(module_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)

# Import Engine class
Engine = main.Engine


class TestMultiAPIEngine:
    """Test multi-API functionality in Engine"""

    @pytest.fixture
    def test_engine(self, monkeypatch):
        """Create test engine instance"""
        # Mock settings
        monkeypatch.setattr(main.settings, "DATABASE_URL", "sqlite:///test.db")
        monkeypatch.setattr(main.settings, "VIRUSTOTAL_API_KEY", "test_key")

        args = argparse.Namespace(
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            timeout=5,
            log_level="INFO",
            multi_api_scan=False,
            url=None,
        )
        return Engine(args)

    def test_engine_has_multi_api_methods(self, test_engine):
        """Test that Engine has multi-API methods"""
        assert hasattr(test_engine, "perform_multi_api_scan")
        assert callable(getattr(test_engine, "perform_multi_api_scan"))

    @patch("requests.get")
    def test_simple_multi_api_flow(self, mock_get, test_engine):
        """Test basic multi-API scan flow"""
        # Mock VirusTotal response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 27,
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        # Test URL
        test_url = "https://test-site.com"

        # This would normally be called internally
        # We're just verifying the method exists
        test_engine.perform_multi_api_scan(test_url)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

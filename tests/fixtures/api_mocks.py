"""API mocking fixtures for external services.

Provides mock responses for:
- VirusTotal API
- URLVoid API
- PhishTank API
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from typing import Dict, Optional


class MockVirusTotalClient:
    """Mock VirusTotal API client for testing."""

    def __init__(self, scenario="phishing"):
        """Initialize mock with predefined scenario.

        Args:
            scenario: One of 'phishing', 'clean', 'timeout', 'error'
        """
        self.scenario = scenario
        self.call_count = 0

    async def scan_url(self, url: str) -> Dict:
        """Mock URL scanning."""
        self.call_count += 1

        if self.scenario == "timeout":
            raise TimeoutError("VirusTotal API timeout")

        if self.scenario == "error":
            raise Exception("VirusTotal API error")

        if self.scenario == "phishing":
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 45,
                            "suspicious": 8,
                            "harmless": 15,
                            "timeout": 2
                        },
                        "total_votes": {"malicious": 35, "harmless": 2}
                    }
                }
            }

        # Clean scenario
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 68,
                        "timeout": 2
                    },
                    "total_votes": {"malicious": 0, "harmless": 150}
                }
            }
        }


class MockURLVoidClient:
    """Mock URLVoid API client for testing."""

    def __init__(self, scenario="phishing"):
        self.scenario = scenario
        self.call_count = 0

    async def check_url(self, url: str) -> Dict:
        """Mock URL checking."""
        self.call_count += 1

        if self.scenario == "timeout":
            raise TimeoutError("URLVoid API timeout")

        if self.scenario == "error":
            raise Exception("URLVoid API error")

        if self.scenario == "phishing":
            return {
                "data": {
                    "report": {
                        "blacklists": {
                            "detections": 15,
                            "engines_count": 30
                        },
                        "domain_age": {"creation_date": "2026-01-01"}
                    }
                }
            }

        # Clean scenario
        return {
            "data": {
                "report": {
                    "blacklists": {
                        "detections": 0,
                        "engines_count": 30
                    },
                    "domain_age": {"creation_date": "1997-09-15"}
                }
            }
        }


class MockPhishTankClient:
    """Mock PhishTank API client for testing."""

    def __init__(self, scenario="phishing"):
        self.scenario = scenario
        self.call_count = 0

    async def check_url(self, url: str) -> Dict:
        """Mock URL checking."""
        self.call_count += 1

        if self.scenario == "timeout":
            raise TimeoutError("PhishTank API timeout")

        if self.scenario == "error":
            raise Exception("PhishTank API error")

        if self.scenario == "phishing":
            return {
                "results": {
                    "in_database": True,
                    "verified": True,
                    "valid": True,
                    "phish_id": "123456"
                }
            }

        # Clean scenario
        return {
            "results": {
                "in_database": False,
                "verified": False,
                "valid": False
            }
        }


@pytest.fixture
def mock_virustotal_phishing():
    """Mock VirusTotal API with phishing response."""
    return MockVirusTotalClient(scenario="phishing")


@pytest.fixture
def mock_virustotal_clean():
    """Mock VirusTotal API with clean response."""
    return MockVirusTotalClient(scenario="clean")


@pytest.fixture
def mock_virustotal_timeout():
    """Mock VirusTotal API with timeout."""
    return MockVirusTotalClient(scenario="timeout")


@pytest.fixture
def mock_urlvoid_phishing():
    """Mock URLVoid API with phishing response."""
    return MockURLVoidClient(scenario="phishing")


@pytest.fixture
def mock_urlvoid_clean():
    """Mock URLVoid API with clean response."""
    return MockURLVoidClient(scenario="clean")


@pytest.fixture
def mock_urlvoid_timeout():
    """Mock URLVoid API with timeout."""
    return MockURLVoidClient(scenario="timeout")


@pytest.fixture
def mock_phishtank_verified():
    """Mock PhishTank API with verified phishing response."""
    return MockPhishTankClient(scenario="phishing")


@pytest.fixture
def mock_phishtank_not_found():
    """Mock PhishTank API with not found response."""
    return MockPhishTankClient(scenario="clean")


@pytest.fixture
def mock_phishtank_timeout():
    """Mock PhishTank API with timeout."""
    return MockPhishTankClient(scenario="timeout")


@pytest.fixture
def mock_all_apis_phishing(monkeypatch, mock_virustotal_phishing, mock_urlvoid_phishing, mock_phishtank_verified):
    """Mock all three APIs with phishing responses.

    This fixture patches the actual API clients used in the application
    with mock implementations.
    """
    def get_vt_client(*args, **kwargs):
        return mock_virustotal_phishing

    def get_uv_client(*args, **kwargs):
        return mock_urlvoid_phishing

    def get_pt_client(*args, **kwargs):
        return mock_phishtank_verified

    monkeypatch.setattr("src.integrations.virustotal.VirusTotalClient", get_vt_client)
    monkeypatch.setattr("src.integrations.urlvoid.URLVoidClient", get_uv_client)
    monkeypatch.setattr("src.integrations.phishtank.PhishTankClient", get_pt_client)

    return {
        "virustotal": mock_virustotal_phishing,
        "urlvoid": mock_urlvoid_phishing,
        "phishtank": mock_phishtank_verified
    }


@pytest.fixture
def mock_all_apis_clean(monkeypatch, mock_virustotal_clean, mock_urlvoid_clean, mock_phishtank_not_found):
    """Mock all three APIs with clean responses."""
    def get_vt_client(*args, **kwargs):
        return mock_virustotal_clean

    def get_uv_client(*args, **kwargs):
        return mock_urlvoid_clean

    def get_pt_client(*args, **kwargs):
        return mock_phishtank_not_found

    monkeypatch.setattr("src.integrations.virustotal.VirusTotalClient", get_vt_client)
    monkeypatch.setattr("src.integrations.urlvoid.URLVoidClient", get_uv_client)
    monkeypatch.setattr("src.integrations.phishtank.PhishTankClient", get_pt_client)

    return {
        "virustotal": mock_virustotal_clean,
        "urlvoid": mock_urlvoid_clean,
        "phishtank": mock_phishtank_not_found
    }


@pytest.fixture
def mock_partial_api_failure(monkeypatch, mock_virustotal_phishing, mock_urlvoid_timeout, mock_phishtank_timeout):
    """Mock scenario where only VirusTotal responds, others timeout.

    Tests degraded operation mode.
    """
    def get_vt_client(*args, **kwargs):
        return mock_virustotal_phishing

    def get_uv_client(*args, **kwargs):
        return mock_urlvoid_timeout

    def get_pt_client(*args, **kwargs):
        return mock_phishtank_timeout

    monkeypatch.setattr("src.integrations.virustotal.VirusTotalClient", get_vt_client)
    monkeypatch.setattr("src.integrations.urlvoid.URLVoidClient", get_uv_client)
    monkeypatch.setattr("src.integrations.phishtank.PhishTankClient", get_pt_client)

    return {
        "virustotal": mock_virustotal_phishing,
        "urlvoid": mock_urlvoid_timeout,
        "phishtank": mock_phishtank_timeout
    }


@pytest.fixture
def mock_screenshot_service(monkeypatch, tmp_path):
    """Mock screenshot capture service.

    Creates a dummy screenshot file instead of using headless browser.
    """
    async def mock_capture_screenshot(url: str) -> Optional[str]:
        """Mock screenshot capture that creates a dummy file."""
        if "timeout" in url or "localhost:99999" in url:
            return None  # Simulate capture failure

        # Create dummy screenshot file
        screenshot_path = tmp_path / "screenshots" / f"{hash(url)}.png"
        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        screenshot_path.write_bytes(b"FAKE_PNG_DATA")

        return str(screenshot_path)

    monkeypatch.setattr("src.services.screenshot_service.capture_screenshot", mock_capture_screenshot)
    return mock_capture_screenshot


@pytest.fixture
def mock_celery_task(monkeypatch):
    """Mock Celery tasks for batch scanning tests.

    Executes tasks synchronously instead of async.
    """
    class MockTask:
        def __init__(self, func):
            self.func = func

        def delay(self, *args, **kwargs):
            """Execute task synchronously."""
            return self.apply(*args, **kwargs)

        def apply(self, *args, **kwargs):
            """Execute task and return result."""
            result = self.func(*args, **kwargs)
            return MockAsyncResult(result)

    class MockAsyncResult:
        def __init__(self, result):
            self._result = result
            self.id = "mock-task-id-123"

        def get(self, timeout=None):
            return self._result

        @property
        def state(self):
            return "SUCCESS"

        @property
        def ready(self):
            return True

    def mock_celery_task_decorator(func):
        return MockTask(func)

    monkeypatch.setattr("celery.task", mock_celery_task_decorator)
    return mock_celery_task_decorator

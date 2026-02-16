"""Test data fixtures for Sprint 1 tests.

This module provides realistic test data for:
- Phishing URLs
- Legitimate URLs
- API responses (VirusTotal, URLVoid, PhishTank)
- Scan results
- User authentication data
"""

import pytest
from datetime import datetime, timedelta
from typing import Dict, List


@pytest.fixture
def sample_phishing_urls() -> List[str]:
    """Sample known phishing URLs for testing.

    These URLs simulate common phishing patterns targeting major brands.
    """
    return [
        "http://paypal-verify-account.suspicious.com",
        "https://amazon-security-alert.phishing.net",
        "http://facebook-login-secure.fake-site.org",
        "https://bank-of-america-alert.scam.ru",
        "http://microsoft-office365-signin.malicious.top",
        "https://apple-id-locked.phish.ml",
        "http://netflix-payment-update.bad-domain.tk",
        "https://chase-secure-login.evil.cc",
        "http://wells-fargo-verify.suspicious.pw",
        "https://crypto-wallet-restore.phishing.xyz"
    ]


@pytest.fixture
def sample_legitimate_urls() -> List[str]:
    """Sample legitimate URLs that should pass validation.

    These are known safe domains for testing false-positive scenarios.
    """
    return [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.mozilla.org",
        "https://www.python.org",
        "https://www.stackoverflow.com",
        "https://www.reddit.com",
        "https://www.medium.com",
        "https://www.youtube.com",
        "https://www.linkedin.com"
    ]


@pytest.fixture
def invalid_url_formats() -> List[str]:
    """Invalid URL formats that should be rejected during validation."""
    return [
        "not-a-url",
        "htp://missing-t.com",  # Typo in protocol
        "javascript:alert('xss')",
        "file:///etc/passwd",
        "",
        None,
        "http://",
        "ftp://not-supported.com",
        "://no-protocol.com",
        "http://192.168.1.1:99999",  # Invalid port
        "http://domain with spaces.com",
        "http://.com",
        "http://domain..com",  # Double dots
    ]


@pytest.fixture
def mock_virustotal_phishing_response() -> Dict:
    """Mock VirusTotal response for a phishing URL.

    Simulates high threat detection (45/70 engines flagged).
    """
    return {
        "data": {
            "id": "http://paypal-verify.phishing.com",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 15,
                    "malicious": 45,
                    "suspicious": 8,
                    "timeout": 2,
                    "undetected": 0
                },
                "last_analysis_results": {
                    "Google Safebrowsing": {"category": "phishing", "result": "malicious"},
                    "Kaspersky": {"category": "phishing", "result": "malicious"},
                    "Fortinet": {"category": "phishing", "result": "malicious"}
                },
                "last_analysis_date": int(datetime.utcnow().timestamp()),
                "reputation": -50,
                "total_votes": {
                    "harmless": 2,
                    "malicious": 35
                }
            }
        }
    }


@pytest.fixture
def mock_virustotal_clean_response() -> Dict:
    """Mock VirusTotal response for a legitimate URL.

    Simulates clean scan (0/70 engines flagged).
    """
    return {
        "data": {
            "id": "https://www.google.com",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 68,
                    "malicious": 0,
                    "suspicious": 0,
                    "timeout": 2,
                    "undetected": 0
                },
                "last_analysis_results": {
                    "Google Safebrowsing": {"category": "harmless", "result": "clean"},
                    "Kaspersky": {"category": "harmless", "result": "clean"}
                },
                "last_analysis_date": int(datetime.utcnow().timestamp()),
                "reputation": 95,
                "total_votes": {
                    "harmless": 150,
                    "malicious": 0
                }
            }
        }
    }


@pytest.fixture
def mock_urlvoid_phishing_response() -> Dict:
    """Mock URLVoid response for a phishing URL.

    Simulates detection on 15/30 blacklists.
    """
    return {
        "data": {
            "report": {
                "blacklists": {
                    "engines": {
                        "15": {
                            "detected": True,
                            "engine": "Phishtank"
                        }
                    },
                    "detections": 15,
                    "engines_count": 30,
                    "detection_rate": "50%"
                },
                "domain_age": {
                    "creation_date": "2026-01-01",
                    "age": "2 days"
                },
                "ip": {
                    "address": "185.220.101.45",
                    "country_name": "Russia"
                }
            }
        }
    }


@pytest.fixture
def mock_urlvoid_clean_response() -> Dict:
    """Mock URLVoid response for a legitimate URL.

    Simulates no blacklist detections.
    """
    return {
        "data": {
            "report": {
                "blacklists": {
                    "engines": {},
                    "detections": 0,
                    "engines_count": 30,
                    "detection_rate": "0%"
                },
                "domain_age": {
                    "creation_date": "1997-09-15",
                    "age": "28 years"
                },
                "ip": {
                    "address": "142.250.80.46",
                    "country_name": "United States"
                }
            }
        }
    }


@pytest.fixture
def mock_phishtank_verified_response() -> Dict:
    """Mock PhishTank response for a verified phishing URL."""
    return {
        "results": {
            "in_database": True,
            "phish_id": "123456",
            "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=123456",
            "verified": True,
            "verified_at": datetime.utcnow().isoformat(),
            "valid": True
        }
    }


@pytest.fixture
def mock_phishtank_not_found_response() -> Dict:
    """Mock PhishTank response for a URL not in database."""
    return {
        "results": {
            "in_database": False,
            "verified": False,
            "valid": False
        }
    }


@pytest.fixture
def sample_scan_result_phishing() -> Dict:
    """Complete scan result for a phishing URL."""
    return {
        "url": "http://paypal-verify.phishing.com",
        "url_hash": "a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4",
        "threat_level": "critical",
        "confidence_score": 85.5,
        "virustotal_data": {
            "positives": 45,
            "total": 70,
            "permalink": "https://virustotal.com/gui/url/...",
            "scan_date": datetime.utcnow().isoformat()
        },
        "urlvoid_data": {
            "blacklists": 15,
            "total_checks": 30,
            "risk_score": 85
        },
        "phishtank_data": {
            "in_database": True,
            "verified": True,
            "phish_id": "123456"
        },
        "scan_timestamp": datetime.utcnow().isoformat(),
        "screenshot_url": "/screenshots/abc123.png"
    }


@pytest.fixture
def sample_scan_result_clean() -> Dict:
    """Complete scan result for a legitimate URL."""
    return {
        "url": "https://www.google.com",
        "url_hash": "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
        "threat_level": "safe",
        "confidence_score": 2.0,
        "virustotal_data": {
            "positives": 0,
            "total": 70,
            "permalink": "https://virustotal.com/gui/url/...",
            "scan_date": datetime.utcnow().isoformat()
        },
        "urlvoid_data": {
            "blacklists": 0,
            "total_checks": 30,
            "risk_score": 5
        },
        "phishtank_data": {
            "in_database": False,
            "verified": False
        },
        "scan_timestamp": datetime.utcnow().isoformat(),
        "screenshot_url": "/screenshots/def456.png"
    }


@pytest.fixture
def sample_user_credentials() -> Dict:
    """Sample user credentials for authentication testing."""
    return {
        "valid": {
            "email": "analyst@anisakys.com",
            "password": "SecurePassword123!",
            "role": "analyst"
        },
        "admin": {
            "email": "admin@anisakys.com",
            "password": "AdminPass456!",
            "role": "admin"
        },
        "viewer": {
            "email": "viewer@anisakys.com",
            "password": "ViewerPass789!",
            "role": "viewer"
        },
        "invalid": {
            "email": "invalid@example.com",
            "password": "WrongPassword"
        }
    }


@pytest.fixture
def sample_api_keys() -> Dict:
    """Sample API keys for testing authentication."""
    return {
        "valid": "sk_test_1234567890abcdef1234567890abcdef",
        "expired": "sk_test_expired_1234567890abcdef12345",
        "revoked": "sk_test_revoked_1234567890abcdef12345",
        "invalid": "invalid_key_format",
        "admin": "sk_test_admin_1234567890abcdef123456"
    }


@pytest.fixture
def xss_attack_payloads() -> List[str]:
    """Common XSS attack payloads for security testing."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
    ]


@pytest.fixture
def sql_injection_payloads() -> List[str]:
    """Common SQL injection attack payloads for security testing."""
    return [
        "' OR '1'='1",
        "'; DROP TABLE scans;--",
        "' UNION SELECT * FROM users--",
        "admin'--",
        "1' AND '1'='1",
        "1' OR '1' = '1",
        "' OR 1=1--",
        "' OR 'a'='a",
        "1'; EXEC sp_MSForEachTable 'DROP TABLE ?';--",
        "1' WAITFOR DELAY '00:00:05'--",
    ]


@pytest.fixture
def edge_case_confidence_scores() -> List[Dict]:
    """Edge cases for confidence score calculation testing."""
    return [
        {"vt_positives": 0, "vt_total": 70, "uv_blacklists": 0, "pt_verified": False, "expected": 0.0},
        {"vt_positives": 70, "vt_total": 70, "uv_blacklists": 30, "pt_verified": True, "expected": 100.0},
        {"vt_positives": 35, "vt_total": 70, "uv_blacklists": 15, "pt_verified": False, "expected": 50.0},
        {"vt_positives": 1, "vt_total": 70, "uv_blacklists": 0, "pt_verified": False, "expected": 1.43},
        {"vt_positives": 69, "vt_total": 70, "uv_blacklists": 29, "pt_verified": True, "expected": 99.0},
    ]

"""
Intelligence module for Anisakys Phishing Detection Engine.

Provides threat intelligence integrations with multiple APIs.
"""

from src.intelligence.abuse_contact_resolver import AbuseContactResolver
from src.auth import require_api_key
from src.intelligence.grinder import (
    GrinderReportClient,
    GRINDER0X_API_URL,
    GRINDER0X_API_KEY,
    GRINDER_INTEGRATION_ENABLED,
    ABUSEIPDB_CATEGORIES,
)
from src.intelligence.virustotal import VirusTotalIntegration, VIRUSTOTAL_API_KEY
from src.intelligence.urlvoid import URLVoidIntegration, URLVOID_API_KEY
from src.intelligence.phishtank import PhishTankIntegration, PHISHTANK_API_KEY
from src.intelligence.google_safe_browsing import (
    GoogleSafeBrowsingIntegration,
    google_safe_browsing,
)
from src.intelligence.gsb_reporter import (
    GSBReporter,
    get_gsb_reporter,
    report_phishing_url,
)
from src.intelligence.multi_api_validator import (
    MultiAPIValidator,
    AUTO_MULTI_API_SCAN,
    AUTO_REPORT_THRESHOLD_CONFIDENCE,
    MANUAL_REVIEW_THRESHOLD_CONFIDENCE,
    AUTO_ANALYSIS_ENABLED,
)

__all__ = [
    # Existing
    "AbuseContactResolver",
    # Grinder
    "GrinderReportClient",
    "require_api_key",
    "GRINDER0X_API_URL",
    "GRINDER0X_API_KEY",
    "GRINDER_INTEGRATION_ENABLED",
    "ABUSEIPDB_CATEGORIES",
    # VirusTotal
    "VirusTotalIntegration",
    "VIRUSTOTAL_API_KEY",
    # URLVoid
    "URLVoidIntegration",
    "URLVOID_API_KEY",
    # PhishTank
    "PhishTankIntegration",
    "PHISHTANK_API_KEY",
    # Google Safe Browsing
    "GoogleSafeBrowsingIntegration",
    "google_safe_browsing",
    # GSB Reporter
    "GSBReporter",
    "get_gsb_reporter",
    "report_phishing_url",
    # Multi-API
    "MultiAPIValidator",
    "AUTO_MULTI_API_SCAN",
    "AUTO_REPORT_THRESHOLD_CONFIDENCE",
    "MANUAL_REVIEW_THRESHOLD_CONFIDENCE",
    "AUTO_ANALYSIS_ENABLED",
]

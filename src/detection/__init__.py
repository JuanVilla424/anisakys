"""
Detection module for Anisakys Phishing Detection Engine.

Provides phishing detection, scanning, and analysis capabilities.
"""

from src.detection.redirect_analyzer import RedirectAnalyzer, RedirectChain
from src.detection.analyzer import AutoPhishingAnalyzer
from src.detection.utils import PhishingUtils
from src.detection.scanner import PhishingScanner
from src.detection.url_analyzer import URLAnalyzer, url_analyzer
from src.detection.google_ads_detector import GoogleAdsPhishingDetector

__all__ = [
    "RedirectAnalyzer",
    "RedirectChain",
    "AutoPhishingAnalyzer",
    "PhishingUtils",
    "PhishingScanner",
    "URLAnalyzer",
    "url_analyzer",
    "GoogleAdsPhishingDetector",
]

"""
Detection module for Anisakys Phishing Detection Engine.

Provides phishing detection, scanning, and analysis capabilities.

The exports below are resolved on first use (PEP 562): importing a light submodule
such as ``src.detection.normalize`` or ``src.detection.imagehash`` must not load the
scanner and the analyzer, which import ``src.intelligence``, whose validator imports
those light submodules (a circular import otherwise).
"""

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.detection.analyzer import AutoPhishingAnalyzer
    from src.detection.google_ads_detector import GoogleAdsPhishingDetector
    from src.detection.redirect_analyzer import RedirectAnalyzer, RedirectChain
    from src.detection.scanner import PhishingScanner
    from src.detection.url_analyzer import URLAnalyzer, url_analyzer
    from src.detection.utils import PhishingUtils

_EXPORTS = {
    "RedirectAnalyzer": "src.detection.redirect_analyzer",
    "RedirectChain": "src.detection.redirect_analyzer",
    "AutoPhishingAnalyzer": "src.detection.analyzer",
    "PhishingUtils": "src.detection.utils",
    "PhishingScanner": "src.detection.scanner",
    "URLAnalyzer": "src.detection.url_analyzer",
    "url_analyzer": "src.detection.url_analyzer",
    "GoogleAdsPhishingDetector": "src.detection.google_ads_detector",
}

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


def __getattr__(name: str) -> Any:
    """Import an export the first time it is used.

    Args:
        name: Attribute requested from the package.

    Returns:
        The exported object.

    Raises:
        AttributeError: For names the package does not export (submodules are then
            imported by the regular import machinery).
    """
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value

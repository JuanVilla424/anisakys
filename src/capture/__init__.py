"""Page capture for detection (HTML, redirect chain, favicon, screenshot) and its storage."""

from src.capture.service import (
    PageCapture,
    capture_hashes,
    favicon_urls,
    fetch_page,
    latest_capture,
    record_scan_capture,
    store_scan_capture,
)

__all__ = [
    "PageCapture",
    "capture_hashes",
    "favicon_urls",
    "fetch_page",
    "latest_capture",
    "record_scan_capture",
    "store_scan_capture",
]

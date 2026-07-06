"""
MISP client for Anisakys Phishing Detection Engine.

Uses the official pymisp SDK rather than hand-rolling MISP's REST API --
unlike TAXII 2.1's small, standardized surface, MISP's event/attribute/tag
model is its own large, bespoke API, not worth reimplementing.

No production MISP instance exists yet to test against live -- verified via
mocked tests only (see tests/intelligence/test_misp_client.py).
"""

from typing import Any, Dict, List, Optional

from src.config import settings
from src.logger import logger

MISP_URL = getattr(settings, "MISP_URL", None)
MISP_API_KEY = getattr(settings, "MISP_API_KEY", None)

# indicator "type" (matching GraphView.vue's own domain/ip node-type
# distinction, see anisakys-frontend GraphView.vue buildStixBundle()) ->
# MISP attribute type.
_MISP_ATTRIBUTE_TYPES = {
    "domain": "domain",
    "ip": "ip-dst",
    "url": "url",
}


class MISPClient:
    """Pushes phishing indicators to MISP as a new event."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.url = url or MISP_URL
        self.api_key = api_key or MISP_API_KEY
        self.verify_ssl = verify_ssl

    def _get_client(self):
        """Lazy-construct the real PyMISP client on first use -- PyMISP's
        constructor makes an HTTP call to the server, so this must not
        happen at import time or object-construction time, only when a
        push is actually attempted."""
        if not self.url or not self.api_key:
            return None
        from pymisp import PyMISP

        try:
            return PyMISP(self.url, self.api_key, self.verify_ssl)
        except Exception as e:
            logger.error(f"❌ MISP client init failed: {e}")
            return None

    def push_indicators(
        self, indicators: List[Dict[str, Any]], event_info: str
    ) -> Optional[Dict[str, Any]]:
        """Push a list of {"type": "domain"|"ip"|"url", "value": ...}
        indicators to MISP as one new event. Returns None (logged) if MISP
        isn't configured or the push fails -- degrades gracefully rather
        than raising, matching this session's other new external clients.
        """
        client = self._get_client()
        if not client:
            logger.warning("⚠️  MISP not configured, skipping push")
            return None

        from pymisp import MISPEvent

        event = MISPEvent()
        event.info = event_info
        for indicator in indicators:
            attribute_type = _MISP_ATTRIBUTE_TYPES.get(indicator.get("type", ""))
            if not attribute_type:
                logger.warning(f"⚠️  Unknown indicator type, skipping: {indicator.get('type')}")
                continue
            event.add_attribute(attribute_type, indicator["value"])

        try:
            result = client.add_event(event, pythonify=True)
            logger.info(f"✅ Pushed MISP event: {event_info} ({len(indicators)} indicators)")
            return result
        except Exception as e:
            logger.error(f"❌ MISP push failed: {e}")
            return None

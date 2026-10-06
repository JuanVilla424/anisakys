"""Client profiles of the multi-profile browser capture worker (phase 2, WS3).

Cloaking is detected by differences between what the same URL serves to
different clients, so every profile fixes the whole observable fingerprint:
user agent, viewport, locale/timezone, touch and the ``Sec-`` / ``Accept``
headers a real browser of that class sends.

The bot profile exists to be treated differently: phishkits and WAFs commonly
serve a benign page to bots (scanners, crawlers) and the lure to humans. A
divergence between it and the human profiles is itself a signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

DESKTOP_ES_CO_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
IPHONE_ES_CO_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
)
BOT_UA = "Mozilla/5.0 (compatible; AnisakysCapture/1.0; +https://anisakys.example/bot)"


@dataclass(frozen=True)
class CaptureProfile:
    """One client the capture worker impersonates."""

    name: str
    user_agent: str
    viewport: Dict[str, int]
    locale: str = "es-CO"
    timezone_id: str = "America/Bogota"
    is_mobile: bool = False
    has_touch: bool = False
    device_scale_factor: float = 1.0
    headers: Dict[str, str] = field(default_factory=dict)
    # Set per deployment through CAPTURE_PROXIES (profile name -> proxy URL):
    # a profile without a proxy measures from the host's own geography.
    proxy: Optional[str] = None


_ES_CO_ACCEPT = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif," "image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "es-CO,es;q=0.9,en;q=0.8",
}

PROFILES: Dict[str, CaptureProfile] = {
    "desktop": CaptureProfile(
        name="desktop",
        user_agent=DESKTOP_ES_CO_UA,
        viewport={"width": 1920, "height": 1080},
        headers=_ES_CO_ACCEPT,
    ),
    "mobile": CaptureProfile(
        name="mobile",
        user_agent=IPHONE_ES_CO_UA,
        viewport={"width": 390, "height": 844},
        is_mobile=True,
        has_touch=True,
        device_scale_factor=3.0,
        headers=_ES_CO_ACCEPT,
    ),
    "bot": CaptureProfile(
        name="bot",
        user_agent=BOT_UA,
        viewport={"width": 1280, "height": 800},
        headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
    ),
}

# The profile whose capture feeds the detection pipeline (content features,
# brand identification): the one a Colombian victim would be using.
PRIMARY_PROFILE = "desktop"


def profiles_with_proxies(proxies: Optional[Dict[str, str]]) -> Dict[str, CaptureProfile]:
    """The profiles, each with its proxy when one is configured.

    Args:
        proxies: ``{profile name: proxy URL}`` (``CAPTURE_PROXIES``); profiles
            without an entry run proxyless -- the report then says geography
            was not measured, never that it matches.

    Returns:
        The profiles to run, proxy-bound where configured.
    """
    proxies = proxies or {}
    bound = {}
    for name, profile in PROFILES.items():
        proxy = proxies.get(name) or proxies.get("*")
        bound[name] = (
            profile if not proxy else CaptureProfile(**{**profile.__dict__, "proxy": proxy})
        )
    return bound

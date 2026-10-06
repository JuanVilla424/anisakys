"""Content features of a captured page (phase 2, WS4).

Everything here is computed from a :class:`src.capture.service.PageCapture` (HTML, headers,
redirect chain, screenshot) without new network access:

* forms: password, one-time-code and payment-card fields, where they submit;
* kit traits: versioned patterns in ``src/detection/kits/signatures.json``;
* tracking identifiers (GA4/UA, GTM, Meta Pixel) for clustering;
* brand mentions and lure vocabulary from the brand catalogue (token boundaries);
* redirect chain shape (length, registrable domain changes);
* QR codes in the screenshot and their URLs.

The calibrated fusion (src/detection/fusion.py) consumes the flat feature dictionary.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

from src.capture.service import PageCapture
from src.detection.imagehash import ImageRejected, load_image
from src.detection.normalize import BrandCatalog, normalize_host

SIGNATURES_FILE = Path(__file__).resolve().parent / "kits" / "signatures.json"
MAX_TEXT_CHARS = 20_000
_OTP_NAMES = re.compile(r"otp|one.?time|c[oó]digo|token|clave.?din[aá]mica|sms.?code|2fa|mfa", re.I)
_CARD_NAMES = re.compile(r"card.?num|cc.?num|tarjeta|cvv|cvc|csc|expir|vencimiento", re.I)
_TRACKERS = {
    "ga4": re.compile(r"\bG-[A-Z0-9]{8,12}\b"),
    "ua": re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "gtm": re.compile(r"\bGTM-[A-Z0-9]{4,9}\b"),
    "meta_pixel": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"),
}
_WORDS = re.compile(r"[a-záéíóúñü0-9]+", re.I)


@lru_cache(maxsize=1)
def _signatures() -> Dict[str, Any]:
    data = json.loads(SIGNATURES_FILE.read_text(encoding="utf-8"))
    data["compiled"] = [
        (trait["id"], trait.get("weight", "medium"), re.compile(trait["pattern"], re.I))
        for trait in data.get("traits", [])
    ]
    return data


def signatures_version() -> str:
    """Version of the kit trait file.

    Returns:
        The ``version`` field of ``signatures.json``.
    """
    return str(_signatures().get("version", "unknown"))


def kit_traits(html: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Kit traits present in a page.

    Args:
        html: Page HTML.
        headers: Response headers (lower-case names).

    Returns:
        ``{trait id: weight}`` for every trait found.
    """
    haystack = html + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    return {
        tid: weight
        for tid, weight, pattern in _signatures()["compiled"]
        if pattern.search(haystack)
    }


def _field_text(field) -> str:
    parts = [
        field.get(attr) or ""
        for attr in ("name", "id", "placeholder", "aria-label", "autocomplete")
    ]
    return " ".join(str(p) for p in parts)


def form_features(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
    """Credential, OTP and card fields, and where forms submit.

    Args:
        soup: Parsed page.
        page_url: URL of the page (for relative actions).

    Returns:
        Counts and the submit targets.
    """
    page_host = normalize_host(page_url)
    page_registrable = page_host.registrable if page_host else ""
    password = otp = card = 0
    external, targets = 0, []
    for field in soup.find_all("input"):
        kind = str(field.get("type") or "text").lower()
        text = _field_text(field)
        if kind == "password":
            password += 1
        elif "one-time-code" in text.lower() or _OTP_NAMES.search(text):
            otp += 1
        elif text.lower().startswith("cc-") or "cc-" in text.lower() or _CARD_NAMES.search(text):
            card += 1
    forms = soup.find_all("form")
    for form in forms:
        action = str(form.get("action") or "").strip()
        if not action or action.startswith("#") or action.lower().startswith("javascript:"):
            continue
        host = normalize_host(action if "://" in action else "")
        if host and host.registrable != page_registrable:
            external += 1
            if host.registrable not in targets:
                targets.append(host.registrable)
    return {
        "form_count": len(forms),
        "password_fields": password,
        "otp_fields": otp,
        "card_fields": card,
        "external_form_actions": external,
        "form_action_domains": targets[:10],
        "credential_form": password > 0 or otp > 0 or card > 0,
    }


def tracker_ids(html: str) -> Dict[str, List[str]]:
    """Analytics and pixel identifiers found in the page.

    Args:
        html: Page HTML.

    Returns:
        ``{kind: sorted unique ids}`` for the kinds present.
    """
    found: Dict[str, List[str]] = {}
    for kind, pattern in _TRACKERS.items():
        ids = sorted({m if isinstance(m, str) else m[0] for m in pattern.findall(html)})
        if ids:
            found[kind] = ids[:20]
    return found


def brand_mentions(title: str, text: str, catalog: BrandCatalog) -> Dict[str, Any]:
    """Brands named in the page title or text, and lure words.

    Args:
        title: Page title.
        text: Visible text (truncated).
        catalog: Brand catalogue.

    Returns:
        ``{"title_brands", "text_brands", "lure_hits"}``.
    """
    title_words = set(_WORDS.findall(title.lower()))
    text_lower = text.lower()
    text_words = set(_WORDS.findall(text_lower))
    title_brands, text_brands, lures = set(), set(), 0
    for brand in catalog.brands:
        names = {brand.slug.lower(), brand.name.lower(), *(a.lower() for a in brand.aliases)}
        names = {n for n in names if len(n) >= 3}
        if names & title_words:
            title_brands.add(brand.slug)
        if names & text_words:
            text_brands.add(brand.slug)
        lures += sum(1 for keyword in brand.lure_keywords if keyword and keyword in text_lower)
    return {
        "title_brands": sorted(title_brands),
        "text_brands": sorted(text_brands),
        "lure_hits": lures,
    }


def redirect_features(capture: PageCapture) -> Dict[str, Any]:
    """Shape of the redirect chain.

    Args:
        capture: The capture.

    Returns:
        ``{"redirect_hops", "cross_domain_redirect", "final_domain_differs"}``.
    """
    registrables = []
    for hop in capture.redirect_chain:
        host = normalize_host(str(hop.get("url", "")))
        if host and (not registrables or registrables[-1] != host.registrable):
            registrables.append(host.registrable)
    start = normalize_host(capture.url)
    final = normalize_host(capture.final_url or capture.url)
    return {
        "redirect_hops": max(len(capture.redirect_chain) - 1, 0),
        "cross_domain_redirect": len(registrables) > 1,
        "final_domain_differs": bool(start and final and start.registrable != final.registrable),
    }


def qr_urls(screenshot: Optional[bytes]) -> List[str]:
    """URLs encoded in QR codes visible in the screenshot.

    Args:
        screenshot: Screenshot bytes.

    Returns:
        Decoded http(s) URLs (at most 5).
    """
    if not screenshot:
        return []
    try:
        import zxingcpp

        image = load_image(screenshot)
    except (ImportError, ImageRejected, OSError):
        return []
    urls: List[str] = []
    try:
        results = zxingcpp.read_barcodes(image.convert("RGB"))
    except Exception:  # pylint: disable=broad-except
        return []
    for result in results:
        value = (getattr(result, "text", "") or "").strip()
        if value.lower().startswith(("http://", "https://")) and value not in urls:
            urls.append(value)
    return urls[:5]


def page_text(html: str) -> Tuple[str, str]:
    """Title and visible text of a page (scripts, styles and templates left out).

    Args:
        html: The page.

    Returns:
        ``(title, text)``, capped at 300 and :data:`MAX_TEXT_CHARS` characters.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
    for hidden in soup(["script", "style", "noscript", "template"]):
        hidden.decompose()
    return title, soup.get_text(" ", strip=True)[:MAX_TEXT_CHARS]


def page_features(capture: PageCapture, catalog: BrandCatalog) -> Dict[str, Any]:
    """Every content feature of a capture.

    Args:
        capture: The capture.
        catalog: Brand catalogue.

    Returns:
        A flat dictionary (JSON-serialisable); empty-page captures still return the
        transport features (status, TLS, redirects).
    """
    features: Dict[str, Any] = {
        "capture_status": capture.status,
        "http_status": capture.http_status,
        "tls_valid": capture.tls_valid,
        "signatures_version": signatures_version(),
        **redirect_features(capture),
    }
    if not capture.html:
        return features
    soup = BeautifulSoup(capture.html, "html.parser")
    title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
    text = soup.get_text(" ", strip=True)[:MAX_TEXT_CHARS]
    headers = capture.headers or {}
    features.update(
        {
            "title": title,
            "text_chars": len(text),
            "missing_hsts": "strict-transport-security" not in headers,
            "missing_csp": "content-security-policy" not in headers,
            **form_features(soup, capture.final_url or capture.url),
            "kit_traits": kit_traits(capture.html, headers),
            "trackers": tracker_ids(capture.html),
            **brand_mentions(title, text, catalog),
            "qr_urls": qr_urls(capture.screenshot),
        }
    )
    return features

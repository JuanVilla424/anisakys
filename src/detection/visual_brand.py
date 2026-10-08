"""Reference-based brand identification and brand↔domain consistency (phase 2, WS5).

A page "is about" a brand when it shows that brand's own visuals or names it:

* its favicon is byte-identical to a reference favicon of the brand (MurmurHash3, the
  Shodan-compatible hash) or perceptually close to one of its reference favicons or logos;
* the page title or text names the brand (token boundaries, from features.py).

References are the images added to each brand from the console. A brand identified on a
host that is not one of the brand's official domains is the core phishing signal; on an
official domain the page is consistent.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from src.detection.imagehash import hamming
from src.detection.normalize import BrandCatalog, Host

# Bits (of 64) within which two perceptual hashes are taken as the same picture.
MAX_PHASH_DISTANCE = 8
_TEXT_SCORES = {"title": 0.6, "text": 0.35}


def identify_brands(
    hashes: Mapping[str, Any],
    features: Mapping[str, Any],
    host: Optional[Host],
    catalog: BrandCatalog,
) -> Dict[str, Any]:
    """Which brands a captured page shows, and whether its domain belongs to them.

    Args:
        hashes: ``capture_hashes`` output (``favicon_mmh3``, ``favicon_phash``...).
        features: ``page_features`` output (``title_brands``, ``text_brands``,
            ``credential_form``).
        host: Normalised host the page was served from (final URL).
        catalog: Brand catalogue (with reference assets).

    Returns:
        ``{"brands": [{"brand", "score", "methods"}], "top_brand", "top_score",
        "official_brand", "brand_domain_mismatch", "credential_form_for_other_brand"}``.
    """
    candidates: Dict[str, Dict[str, Any]] = {}

    def note(brand: str, score: float, method: str) -> None:
        entry = candidates.setdefault(brand, {"brand": brand, "score": 0.0, "methods": []})
        entry["score"] = max(entry["score"], round(score, 3))
        if method not in entry["methods"]:
            entry["methods"].append(method)

    favicon_mmh3 = hashes.get("favicon_mmh3")
    favicon_phash = hashes.get("favicon_phash")
    for brand in catalog.brands:
        for asset in brand.assets:
            if favicon_mmh3 is not None and asset.kind == "favicon" and asset.mmh3 == favicon_mmh3:
                note(brand.slug, 1.0, "favicon_exact")
                continue
            distance = hamming(favicon_phash, asset.phash)
            if distance is not None and distance <= MAX_PHASH_DISTANCE:
                note(brand.slug, 1 - distance / 64, f"favicon_matches_{asset.kind}")
    for brand in features.get("title_brands") or []:
        note(str(brand), _TEXT_SCORES["title"], "title")
    for brand in features.get("text_brands") or []:
        note(str(brand), _TEXT_SCORES["text"], "text")

    ranked: List[Dict[str, Any]] = sorted(
        candidates.values(), key=lambda c: (-c["score"], c["brand"])
    )
    official = catalog.official_brand(host)
    top = ranked[0] if ranked else None
    mismatch = bool(top and top["brand"] != official and top["score"] >= _TEXT_SCORES["title"])
    return {
        "brands": ranked[:5],
        "top_brand": top["brand"] if top else None,
        "top_score": top["score"] if top else 0.0,
        "official_brand": official,
        "brand_domain_mismatch": mismatch,
        "credential_form_for_other_brand": mismatch and bool(features.get("credential_form")),
    }

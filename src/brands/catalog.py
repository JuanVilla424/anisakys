"""The brand catalogue the detector uses: built-in brands plus the ones added from the console.

The built-in list is ``KNOWN_BRANDS`` (``src/detection/url_analyzer.py``), exactly as the
detector used it before phase 2. Brands added from the console extend it; a console brand
with the same slug as a built-in one adds its aliases, domains and reference images to it.
The database is read at most once per :data:`CATALOG_TTL_SECONDS` per process; when it
cannot be read, detection keeps working with the built-in brands.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

from sqlalchemy.engine import Engine

from src.detection.normalize import Brand, BrandCatalog

CATALOG_TTL_SECONDS = 60

_lock = threading.Lock()
_cached: Optional[Tuple[float, BrandCatalog]] = None


def builtin_brands() -> List[Brand]:
    """The built-in brands (``KNOWN_BRANDS``).

    Returns:
        One :class:`Brand` per entry, slug = name, no aliases or assets.
    """
    from src.detection.url_analyzer import KNOWN_BRANDS

    return [
        Brand(slug=slug, name=slug, aliases=(), official_domains=tuple(domains))
        for slug, domains in KNOWN_BRANDS.items()
    ]


def merge(builtin: Sequence[Brand], console: Sequence[Brand]) -> BrandCatalog:
    """Merge the built-in and the console brands.

    Args:
        builtin: Built-in brands.
        console: Active brands from the database.

    Returns:
        The catalogue; a console brand with a built-in slug extends it.
    """
    brands: Dict[str, Brand] = {brand.slug: brand for brand in builtin}
    for brand in console:
        base = brands.get(brand.slug)
        if base is None:
            brands[brand.slug] = brand
            continue
        brands[brand.slug] = Brand(
            slug=brand.slug,
            name=brand.name or base.name,
            aliases=tuple(dict.fromkeys(base.aliases + brand.aliases)),
            official_domains=tuple(dict.fromkeys(base.official_domains + brand.official_domains)),
            assets=base.assets + brand.assets,
            priority=brand.priority,
            lure_keywords=tuple(dict.fromkeys(base.lure_keywords + brand.lure_keywords)),
        )
    return BrandCatalog(list(brands.values()))


def _default_engine() -> Engine:
    from src.database.manager import db_engine

    return db_engine


def current_catalog(engine: Optional[Engine] = None, now: Optional[float] = None) -> BrandCatalog:
    """The detection catalogue, cached for :data:`CATALOG_TTL_SECONDS`.

    Args:
        engine: Engine of the shared database (default: the application engine).
        now: Monotonic seconds (tests).

    Returns:
        Built-in brands merged with the active console brands.
    """
    global _cached
    clock = time.monotonic() if now is None else now
    with _lock:
        if _cached is not None and clock - _cached[0] < CATALOG_TTL_SECONDS:
            return _cached[1]
    console: List[Brand] = []
    try:
        from src.brands.repository import BrandRepository

        console = [
            r.to_catalog() for r in BrandRepository(engine or _default_engine()).active_brands()
        ]
    except Exception as e:  # pylint: disable=broad-except
        from src.logger import logger

        logger.warning(
            f"Brand catalogue: the database could not be read, built-in brands only: {e}"
        )
    catalog = merge(builtin_brands(), console)
    with _lock:
        _cached = (clock, catalog)
    return catalog


def invalidate() -> None:
    """Forget the cached catalogue (after a brand changes)."""
    global _cached
    with _lock:
        _cached = None

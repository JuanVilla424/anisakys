"""
API module for Anisakys Phishing Detection Engine.

Provides REST API for external phishing reports.

``PhishingAPI`` is loaded lazily (PEP 562) so that
importing a submodule such as ``src.api.wsgi`` or ``src.api.params`` does not
pull in the whole API (and its integration clients) as a side effect; this
also lets ``src.api.wsgi`` control the import order of ``src.detection`` and
``src.intelligence``, which depend on each other.
"""

from typing import TYPE_CHECKING, Any

from src.utils.timeouts import OperationTimeoutError, timeout

if TYPE_CHECKING:  # static analysers see the lazy exports
    from src.api.phishing_api import PhishingAPI

# Backwards-compatible alias: the API used to define its own TimeoutError.
TimeoutError = OperationTimeoutError  # noqa: A001

_LAZY_EXPORTS = frozenset({"PhishingAPI"})

__all__ = [
    "PhishingAPI",
    "OperationTimeoutError",
    "TimeoutError",
    "timeout",
]


def __getattr__(name: str) -> Any:
    """Resolve the lazily exported names on first access.

    Args:
        name: Attribute requested from the package.

    Returns:
        The object exported by ``src.api.phishing_api``.

    Raises:
        AttributeError: If ``name`` is not exported by this package.
    """
    if name in _LAZY_EXPORTS:
        from src.api import phishing_api

        return getattr(phishing_api, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

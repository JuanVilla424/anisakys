"""
API key authentication with multi-tenant scopes for Anisakys.

Provides the require_api_key decorator used by all protected API endpoints.
Supports two authentication methods:
  1. Master key — single static key from ANISAKYS_API_KEY env var (admin scope)
  2. Database key — keys stored in the api_keys table with per-key scopes

Scopes (see SCOPE_DESCRIPTIONS; "admin" is a wildcard):
  read     — GET endpoints: status, stats, lists, graph, IOCs
  scan     — POST scan endpoints: multi-scan, gsb/check, scan/domain
  report   — POST report endpoints: report, gsb/report; update report status
  write    — create/update threads, thread results, sender reputation, blocklist
  email_admin — create/update e-mail monitor threads, read per-mailbox results
  metrics  — scrape the Prometheus /metrics endpoint
  admin    — All endpoints (wildcard)

Usage:
    >>> from src.auth import require_api_key
    >>> @require_api_key
    ... def my_endpoint(): ...
    >>>
    >>> @require_api_key(scope="read")
    ... def read_only_endpoint(): ...
    >>>
    >>> @require_api_key(scope=("metrics", "read"))  # any of these scopes
    ... def metrics_endpoint(): ...
"""

import hashlib
import hmac
import ipaddress
import logging
import threading
import time
from functools import wraps
from typing import Callable, Dict, FrozenSet, Iterable, Optional, Tuple, Union

from flask import Response, current_app, g, has_request_context, jsonify, request

from src.config import settings
from src.observability.metrics import METRIC_AUTH_TOTAL, increment_counter

logger = logging.getLogger(__name__)

# Single source of truth for scopes: the CLI (src.cli.api_keys) validates and
# documents keys against this mapping.
SCOPE_DESCRIPTIONS: Dict[str, str] = {
    "read": "GET endpoints: status, stats, sites, reports, graph, IOCs, campaigns",
    "scan": "on-demand scans: multi-scan, gsb/check, scan/domain",
    "report": "submit URLs (/report, gsb/report) and update abuse-report status",
    "write": "create/update threads and results, sender reputation and blocklist",
    "email_admin": (
        "create/update e-mail monitor threads and read per-mailbox results "
        "(only allowlisted mailboxes)"
    ),
    "metrics": "scrape the Prometheus /metrics endpoint",
    "admin": "every endpoint (wildcard)",
}
VALID_SCOPES = frozenset(SCOPE_DESCRIPTIONS)

ScopeRequirement = Union[None, str, Iterable[str]]

# Throttle last_used_at updates: only write to DB if >60s since last update per key
_last_used_cache: dict = {}
_last_used_lock = threading.Lock()
_AUDIT_THROTTLE_SECONDS = 60


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _check_ip_allowed(allowed_ips: Optional[str]) -> bool:
    if not allowed_ips:
        return True
    remote = request.remote_addr
    if not remote:
        return False
    try:
        remote_addr = ipaddress.ip_address(remote)
        for entry in allowed_ips.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if remote_addr in network:
                    return True
            except ValueError:
                pass
        return False
    except ValueError:
        return False


def parse_scopes(raw: Union[str, Iterable[str], None]) -> FrozenSet[str]:
    """Normalise a key's scopes into a set.

    Args:
        raw: Comma-separated scopes as stored in ``api_keys.scopes``, or an
            iterable of scope names.

    Returns:
        The non-empty, whitespace-stripped scope names.
    """
    if raw is None:
        return frozenset()
    items = raw.split(",") if isinstance(raw, str) else raw
    return frozenset(s.strip() for s in items if s and s.strip())


def _required_scopes(required_scope: ScopeRequirement) -> FrozenSet[str]:
    """Normalise a scope requirement (one scope or any-of alternatives).

    Args:
        required_scope: None, a scope name, or an iterable of alternatives.

    Returns:
        The set of acceptable scopes (empty when nothing is required).
    """
    if required_scope is None:
        return frozenset()
    if isinstance(required_scope, str):
        return frozenset({required_scope})
    return frozenset(required_scope)


def _scope_allowed(key_scopes: Union[str, Iterable[str]], required_scope: ScopeRequirement) -> bool:
    """Tell whether a key's scopes satisfy a requirement.

    Args:
        key_scopes: The key's scopes (comma-separated string or iterable).
        required_scope: None (any valid key), a scope, or any-of alternatives.

    Returns:
        True when nothing is required, the key is admin, or it holds one of the
        acceptable scopes.
    """
    required = _required_scopes(required_scope)
    if not required:
        return True
    scopes = parse_scopes(key_scopes)
    return "admin" in scopes or bool(scopes & required)


def has_scope(scope: str) -> bool:
    """Tell whether the API key authenticating the current request holds ``scope``.

    Only meaningful inside a view protected by :func:`require_api_key`; the
    master key holds every scope.

    Args:
        scope: Scope name to test.

    Returns:
        True when the authenticated key grants ``scope``; False otherwise or
        outside an authenticated request.
    """
    if not has_request_context():
        return False
    scopes = getattr(g, "api_key_scopes", None)
    if scopes is None:
        return False
    return _scope_allowed(scopes, scope)


def _update_last_used(key_hash: str) -> None:
    now = time.time()
    with _last_used_lock:
        if now - _last_used_cache.get(key_hash, 0) < _AUDIT_THROTTLE_SECONDS:
            return
        _last_used_cache[key_hash] = now

    def _write():
        try:
            from src.database import db_engine
            from sqlalchemy import text

            with db_engine.begin() as conn:
                conn.execute(
                    text("UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = :h"),
                    {"h": key_hash},
                )
        except Exception:
            pass

    threading.Thread(target=_write, daemon=True).start()


def _lookup_db_key(key: str):
    """Return (scopes, allowed_ips) for an active key, or None if not found."""
    key_hash = _hash_key(key)
    try:
        from src.database import db_engine
        from sqlalchemy import text

        with db_engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT scopes, allowed_ips FROM api_keys "
                    "WHERE key_hash = :h AND active = TRUE AND revoked_at IS NULL"
                ),
                {"h": key_hash},
            ).fetchone()
        if row:
            return {"scopes": row[0], "allowed_ips": row[1], "key_hash": key_hash}
    except Exception as exc:
        logger.error(f"Auth DB lookup error: {exc}")
    return None


def _describe_requirement(scope: ScopeRequirement) -> str:
    """Render a scope requirement for error messages and logs.

    Args:
        scope: None, a scope name, or any-of alternatives.

    Returns:
        E.g. ``"read"`` or ``"metrics or read"``.
    """
    return " or ".join(sorted(_required_scopes(scope))) or "any"


def authenticate_request(scope: ScopeRequirement = None) -> Optional[Tuple[Response, int]]:
    """Authenticate the current request's Bearer API key against ``scope``.

    On success the key's scopes are recorded on ``flask.g`` (``api_key_scopes``,
    ``api_key_is_master``) so views can make finer decisions with
    :func:`has_scope`.

    Args:
        scope: None (any valid key), a scope, or an iterable of acceptable
            alternative scopes.

    Returns:
        None when the request may proceed, else a ``(response, status)`` error.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning(f"Auth: missing Bearer header from {request.remote_addr}")
        increment_counter(METRIC_AUTH_TOTAL, method="none", status="failed")
        return jsonify({"error": "Authorization header required with Bearer token"}), 401

    provided_key = auth_header[7:]

    # --- Master key check (no DB, immediate admin access) ---
    expected_key = getattr(current_app, "api_key", None)
    if expected_key and hmac.compare_digest(provided_key.encode(), expected_key.encode()):
        logger.debug(f"Auth: master key accepted from {request.remote_addr}")
        increment_counter(METRIC_AUTH_TOTAL, method="master", status="success")
        g.api_key_scopes = frozenset({"admin"})
        g.api_key_is_master = True
        return None

    # --- Database key check ---
    key_data = _lookup_db_key(provided_key)
    if key_data is None:
        logger.warning(f"Auth: invalid key from {request.remote_addr}")
        increment_counter(METRIC_AUTH_TOTAL, method="api_key", status="failed")
        return jsonify({"error": "Invalid API key"}), 401

    if not _check_ip_allowed(key_data["allowed_ips"]):
        logger.warning(
            f"Auth: IP {request.remote_addr} not in allowed_ips for key {provided_key[:12]}"
        )
        increment_counter(METRIC_AUTH_TOTAL, method="api_key", status="failed")
        return jsonify({"error": "IP address not allowed for this API key"}), 403

    if not _scope_allowed(key_data["scopes"], scope):
        required = _describe_requirement(scope)
        logger.warning(
            f"Auth: scope '{required}' denied for key {provided_key[:12]} "
            f"(scopes: {key_data['scopes']})"
        )
        increment_counter(METRIC_AUTH_TOTAL, method="api_key", status="failed")
        return jsonify({"error": f"Insufficient scope. Required: {required}"}), 403

    _update_last_used(key_data["key_hash"])
    logger.debug(f"Auth: DB key accepted from {request.remote_addr}, scope={scope}")
    increment_counter(METRIC_AUTH_TOTAL, method="api_key", status="success")
    g.api_key_scopes = parse_scopes(key_data["scopes"])
    g.api_key_is_master = False
    return None


def require_api_key(f: Optional[Callable] = None, *, scope: ScopeRequirement = None):
    """
    Decorator that requires a valid API key.

    Can be used with or without arguments:
        @require_api_key
        @require_api_key(scope="read")
        @require_api_key(scope=("metrics", "read"))   # any of the listed scopes

    Args:
        f: The view when used without parentheses.
        scope: None (any valid key), a scope, or alternatives (any of them).

    Returns:
        The decorated view (or a decorator when called with arguments).
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            denied = authenticate_request(scope)
            if denied is not None:
                return denied
            return func(*args, **kwargs)

        return wrapper

    # Support both @require_api_key and @require_api_key(scope="...")
    if f is not None:
        # Called as @require_api_key (no parentheses)
        return decorator(f)
    # Called as @require_api_key(scope="...")
    return decorator


def require_metrics_access(func: Callable) -> Callable:
    """Protect the Prometheus endpoint.

    Accepts either the dedicated ``METRICS_TOKEN`` (a static bearer token for
    scrapers, compared in constant time) or an API key holding the ``metrics``
    or ``read`` scope (or the master key). Anything else gets 401/403.

    Args:
        func: The metrics view.

    Returns:
        The protected view.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        metrics_token = settings.METRICS_TOKEN
        auth_header = request.headers.get("Authorization", "")
        if metrics_token is not None and auth_header.startswith("Bearer "):
            expected = metrics_token.get_secret_value()
            if expected and hmac.compare_digest(auth_header[7:].encode(), expected.encode()):
                increment_counter(METRIC_AUTH_TOTAL, method="metrics_token", status="success")
                return func(*args, **kwargs)
        denied = authenticate_request(("metrics", "read"))
        if denied is not None:
            return denied
        return func(*args, **kwargs)

    return wrapper

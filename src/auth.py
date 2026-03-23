"""
API key authentication with multi-tenant scopes for Anisakys.

Provides the require_api_key decorator used by all protected API endpoints.
Supports two authentication methods:
  1. Master key — single static key from ANISAKYS_API_KEY env var (admin scope)
  2. Database key — keys stored in the api_keys table with per-key scopes

Scopes:
  read    — GET endpoints: status, stats, gsb/status
  scan    — POST scan endpoints: multi-scan, gsb/check
  report  — POST report endpoints: report, gsb/report
  admin   — All endpoints (wildcard)

Usage:
    >>> from src.auth import require_api_key
    >>> @require_api_key
    ... def my_endpoint(): ...
    >>>
    >>> @require_api_key(scope="read")
    ... def read_only_endpoint(): ...
"""

import hashlib
import hmac
import ipaddress
import logging
import threading
import time
from functools import wraps
from typing import Optional

from flask import current_app, jsonify, request

from src.observability.metrics import METRIC_AUTH_TOTAL, increment_counter

logger = logging.getLogger(__name__)

VALID_SCOPES = frozenset({"read", "scan", "report", "admin"})

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


def _scope_allowed(key_scopes: str, required_scope: Optional[str]) -> bool:
    if required_scope is None:
        return True
    scopes = {s.strip() for s in key_scopes.split(",")}
    return "admin" in scopes or required_scope in scopes


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


def require_api_key(f=None, *, scope: Optional[str] = None):
    """
    Decorator that requires a valid API key.

    Can be used with or without arguments:
        @require_api_key
        @require_api_key(scope="read")
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
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
                return func(*args, **kwargs)

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
                logger.warning(
                    f"Auth: scope '{scope}' denied for key {provided_key[:12]} "
                    f"(scopes: {key_data['scopes']})"
                )
                increment_counter(METRIC_AUTH_TOTAL, method="api_key", status="failed")
                return jsonify({"error": f"Insufficient scope. Required: {scope}"}), 403

            _update_last_used(key_data["key_hash"])
            logger.debug(f"Auth: DB key accepted from {request.remote_addr}, scope={scope}")
            increment_counter(METRIC_AUTH_TOTAL, method="api_key", status="success")
            return func(*args, **kwargs)

        return wrapper

    # Support both @require_api_key and @require_api_key(scope="read")
    if f is not None:
        # Called as @require_api_key (no parentheses)
        return decorator(f)
    # Called as @require_api_key(scope="...")
    return decorator

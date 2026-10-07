"""
Phishing API for Anisakys Phishing Detection Engine.

REST API for external phishing reports with multi-API integration
and Grinder integration.
"""

import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import math
import re
import socket
import threading
import time
import tomllib
from pathlib import Path
from urllib.parse import urlsplit
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import validators
from flask import Flask, Response, current_app, g, jsonify, request
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import logging as flask_logging

from src.config import settings
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from stix2.exceptions import STIXError
from src.auth import (
    _hash_key,
    current_key_session,
    has_scope,
    require_api_key,
    require_metrics_access,
)
from src.api.mailbox_policy import is_domain_allowed, is_mailbox_allowed
from src.api.errors import (
    current_request_id,
    install_request_ids,
    internal_error,
    scrub_provider_errors,
)
from src.api.params import (
    InvalidParameterError,
    bool_arg,
    enum_arg,
    int_arg,
    str_arg,
)
from src.api.serializers import (
    STORED_THREAT_LEVELS,
    as_utc,
    iso_utc,
    severest_threat_level,
    threat_level_or_none,
)
from src.intelligence import (
    MultiAPIValidator,
    GrinderReportClient,
    GRINDER0X_API_URL,
    GRINDER_INTEGRATION_ENABLED,
)
from src.brands import (
    BrandConflictError,
    BrandNotFoundError,
    BrandRecord,
    BrandRepository,
    BrandValidationError,
)
from src.brands import invalidate as invalidate_brand_catalog
from src.brands.repository import MAX_ASSET_BYTES
from src.capture.service import latest_capture, record_scan_capture
from src.labels import (
    MAX_NOTE_LENGTH,
    MAX_TAG_LENGTH,
    derived_priority,
    Label,
    LabelAction,
    LabelRepository,
    LabelVerdict,
    SiteNotFoundError,
)
from src.logger import logger
from src.observability.health import (
    STATUS_HEALTHY,
    STATUS_UNHEALTHY,
    check_database,
    create_health_checker,
)
from src.observability.operational import (
    DEFAULT_WINDOW_DAYS,
    MAX_WINDOW_DAYS,
    compute_operational_metrics,
    register_operational_collector,
)
from src.reporting.db import short_transaction
from src.reporting.outbox import ManualTaskOutcome, OutboxRepository, OutboxRow, OutboxStatus
from src.reporting.report_tracker import ReportStatus, ReportTracker
from src.shutdown import register_thread
from src.utils.timeouts import OperationTimeoutError, timeout
from src.dns.network_utils import assess_url_target, is_cloudflare_ip
from src.screenshot_service import PLAYWRIGHT_AVAILABLE, SELENIUM_AVAILABLE
from src.screenshot_client import get_screenshot_service
from src.monitoring.gsb_rescan import get_gsb_rescan_job

if TYPE_CHECKING:
    from src.monitoring.email_scheduler import EmailMonitorScheduler
    from src.monitoring.scheduler import ImageTrackingScheduler

# Initialize screenshot service (sandboxed client if SCREENSHOT_WORKER_SOCKET
# is configured, otherwise the in-process ScreenshotService as before --
# either way, the local PLAYWRIGHT_AVAILABLE/SELENIUM_AVAILABLE check only
# matters for the in-process fallback; the client needs neither).
SCREENSHOTS_DIR = Path(settings.SCREENSHOTS_DIR)
screenshot_service = (
    get_screenshot_service(str(SCREENSHOTS_DIR))
    if (
        getattr(settings, "SCREENSHOT_WORKER_SOCKET", None)
        or PLAYWRIGHT_AVAILABLE
        or SELENIUM_AVAILABLE
    )
    else None
)


def _load_app_version() -> str:
    """Read the app version once from pyproject.toml (the single source of
    truth bump2version keeps in sync) -- avoids yet another hardcoded copy
    that would drift on the next version bump."""
    try:
        pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)
        # PEP 621 metadata; [tool.poetry] kept as a fallback for older checkouts.
        return pyproject.get("project", {}).get("version") or pyproject["tool"]["poetry"]["version"]
    except Exception:
        return "unknown"


APP_VERSION = _load_app_version()


def rate_limit_key() -> str:
    """Rate-limit bucket key for flask-limiter.

    Runs BEFORE require_api_key (the limiter decorator wraps the auth
    decorator, so it fires first on every request) — it must parse the
    Authorization header itself and cannot assume auth has run yet.

    Master key -> one shared operator bucket; any other Bearer token ->
    bucketed by its own hash (so one leaked/rotated key can't dilute its
    limit across IPs); no Bearer header -> caller IP, preserving today's
    behavior for exempt/unauthenticated routes (health, metrics).

    Bucketing an invalid token by its own hash is an accepted, low-severity
    tradeoff: require_api_key() still 401s it immediately afterwards, so
    rotating garbage tokens never unlocks any real backend work — it only
    means the cheap 401-rejection path isn't globally IP-throttled for
    spoofed tokens.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        master_key = getattr(current_app, "api_key", None)
        if master_key and hmac.compare_digest(token.encode(), master_key.encode()):
            return "apikey:master"
        return f"apikey:{_hash_key(token)}"
    return get_remote_address()


def thread_rate_limit_key() -> str:
    """Rate-limit bucket key for per-thread endpoints (API key + thread id).

    The console polls ``/threads/<id>/results`` once per visible thread, so a
    single bucket per key would let a busy threads view starve itself; each
    thread gets its own bucket and a per-key limit caps the total.

    Returns:
        ``rate_limit_key()`` suffixed with the request's ``thread_id``.
    """
    thread_id = (request.view_args or {}).get("thread_id")
    return f"{rate_limit_key()}:thread:{thread_id}"


def _pin_retry_after(response: Response) -> Response:
    """Make a 429's ``Retry-After`` header equal the ``retry_after`` in its body.

    flask-limiter rewrites ``Retry-After`` from the window reset time and
    truncates to whole seconds, which can come out one second below (or at 0)
    the value :meth:`PhishingAPI._rate_limited` put in the JSON body.

    Args:
        response: The outgoing response.

    Returns:
        The response, with ``Retry-After`` pinned on rate-limited responses.
    """
    retry_after = g.get("rate_limit_retry_after")
    if response.status_code == 429 and retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)
    return response


def parse_recipients(raw: Optional[str]) -> List[str]:
    """Decode the ``abuse_reports.recipients`` column into a list of addresses.

    ReportTracker stores recipients JSON-encoded (``["a@x", "b@y"]``); rows
    written by older versions hold a plain comma-separated string. Both
    formats are accepted.

    Args:
        raw: Raw column value (JSON array, JSON string, legacy CSV or None).

    Returns:
        The non-empty, whitespace-stripped recipient addresses in stored order.
    """
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        decoded = raw.split(",")
    if isinstance(decoded, str):
        decoded = decoded.split(",")
    if not isinstance(decoded, list):
        return []
    return [item.strip() for item in decoded if isinstance(item, str) and item.strip()]


# Accepted values of enum-like query parameters.
SITE_STATUSES = frozenset({"up", "down"})
PRIORITIES = frozenset({"critical", "high", "medium", "low"})
LABEL_ACTIONS = frozenset(action.value for action in LabelAction)
LABEL_VERDICTS = frozenset(verdict.value for verdict in LabelVerdict)
# GET /api/v1/sites ``label`` filter: a verdict, or sites nobody labelled yet.
SITE_LABEL_FILTERS = LABEL_VERDICTS | {"unlabeled"}
# Statuses an analyst may set with PATCH /api/v1/reports/<id>.
REPORT_UPDATE_STATUSES = frozenset(
    {"sent", "acknowledged", "in_progress", "resolved", "rejected", "timeout", "bounced", "pending"}
)
# Statuses GET /api/v1/reports can filter on: the above plus those only the
# reporting pipeline sets (queued, failed, pending_manual).
REPORT_STATUSES = REPORT_UPDATE_STATUSES | {"queued", "failed", "pending_manual"}
IOC_TYPES = frozenset({"domain", "ip", "email"})
IOC_SEARCH_MAX_LENGTH = 200

# Host part of phishing_sites.url, as used for domain IOCs and graph nodes.
IOC_DOMAIN_SQL = "SPLIT_PART(SPLIT_PART(url, '://', 2), '/', 1)"

# Stored threat levels from no verdict to most severe; an IP's threat is the
# highest-ranked level among the sites resolving to it.
_IOC_THREAT_ORDER = ("unknown", "clean", "low", "medium", "high", "critical")
_IOC_SEVEREST_THREAT_SQL = "(ARRAY[{levels}])[MAX(CASE multi_api_threat_level {cases} END)]".format(
    levels=", ".join(f"'{level}'" for level in _IOC_THREAT_ORDER),
    cases=" ".join(
        f"WHEN '{level}' THEN {rank}" for rank, level in enumerate(_IOC_THREAT_ORDER, 1)
    ),
)

IOC_ORDER_BY: Dict[str, str] = {
    "domain": "last_seen DESC NULLS LAST, value, threat NULLS LAST, source NULLS LAST",
    "ip": "hits DESC, value",
}


def _ioc_query(ioc_type: str, *, search: bool, threat: bool) -> str:
    """Build the ``WITH iocs AS (...)`` clause of GET /api/v1/intelligence/iocs.

    Filters are bound parameters (``:search`` lower-cased, ``:threat``); only
    constant SQL fragments are interpolated.

    Args:
        ioc_type: ``"domain"`` or ``"ip"``.
        search: Whether to filter on ``:search`` (substring of the value).
        threat: Whether to filter on ``:threat`` (the item's threat level).

    Returns:
        A CTE defining ``iocs(value, first_seen, last_seen, threat, source|cloudflare, hits)``.
    """
    if ioc_type == "ip":
        where = "resolved_ip IS NOT NULL AND resolved_ip <> ''"
        if search:
            where += " AND STRPOS(LOWER(resolved_ip), :search) > 0"
        outer = "WHERE threat = :threat" if threat else ""
        return f"""
            WITH grouped AS (
                SELECT resolved_ip AS value,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen,
                       {_IOC_SEVEREST_THREAT_SQL} AS threat,
                       bool_or(is_cloudflare = 1) AS cloudflare,
                       COUNT(*) AS hits
                FROM phishing_sites
                WHERE {where}
                GROUP BY resolved_ip
            ),
            iocs AS (SELECT * FROM grouped {outer})
        """
    where = f"url IS NOT NULL AND {IOC_DOMAIN_SQL} <> ''"
    if search:
        where += f" AND STRPOS(LOWER({IOC_DOMAIN_SQL}), :search) > 0"
    if threat:
        where += " AND multi_api_threat_level = :threat"
    return f"""
        WITH iocs AS (
            SELECT {IOC_DOMAIN_SQL} AS value,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen,
                   multi_api_threat_level AS threat,
                   source,
                   COUNT(*) AS hits
            FROM phishing_sites
            WHERE {where}
            GROUP BY value, multi_api_threat_level, source
        )
    """


def _ioc_item(ioc_type: str, row: Any, position: int) -> Dict[str, Any]:
    """Serialise one row of the IOC query.

    Args:
        ioc_type: ``"domain"`` or ``"ip"``.
        row: ``(value, first_seen, last_seen, threat, source|cloudflare, hits, total)``.
        position: 1-based position across pages (used in the legacy ``id``).

    Returns:
        The IOC item.
    """
    value, first_seen, last_seen, threat, extra, hits = row[:6]
    if ioc_type == "ip":
        source = None
        tags = [] if extra is None else ["cloudflare" if extra else "direct"]
    else:
        source, tags = extra, []
    return {
        "id": f"{'IP' if ioc_type == 'ip' else 'D'}-{position}",
        "type": ioc_type,
        "value": value,
        "first_seen": iso_utc(first_seen),
        "last_seen": iso_utc(last_seen),
        "threat": threat,
        "source": source,
        "hits": int(hits),
        "tags": tags,
    }


# FROM/WHERE clause selecting the thread_results the console shows: not
# discarded, not from a whitelisted sender, the own Workspace domain
# (:own_domain, '' when unset) or Google's own domains. Callers append
# "AND tr.thread_id = ...". GET /threads (results_count) and
# GET /threads/<id>/results (total) share it so the two always agree.
VISIBLE_THREAD_RESULTS_SQL = """
    FROM thread_results tr
    LEFT JOIN email_sender_reputation esr
        ON tr.result_type = 'email_threat'
        AND LOWER(tr.extra_data->>'sender') = esr.sender_email
    WHERE tr.status != 'discarded'
    AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
    AND (:own_domain = '' OR tr.result_type != 'email_threat'
         OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
    AND (tr.result_type != 'email_threat'
         OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com'))
"""

# Largest accepted pagination offset (deep OFFSET scans are never legitimate here).
MAX_OFFSET = 1_000_000


def _offset_arg() -> int:
    """Read the ``offset`` pagination parameter of the current request.

    Returns:
        The offset (0 when absent).

    Raises:
        InvalidParameterError: If it is not an integer in ``[0, MAX_OFFSET]``.
    """
    return int_arg(
        request.args, "offset", default=0, minimum=0, maximum=MAX_OFFSET, clamp_to_maximum=False
    )


def _invalid_parameter_response(exc: InvalidParameterError) -> Tuple[Response, int]:
    """Turn a query-parameter validation error into a 400 response.

    Args:
        exc: The validation error raised by a ``src.api.params`` helper.

    Returns:
        A ``(response, 400)`` tuple naming the offending parameter.
    """
    return jsonify({"error": exc.message, "parameter": exc.parameter}), 400


# SQL expression (lower-cased, trimmed) matched against each focus type of
# GET /api/v1/graph. Keys are the node-type prefixes used in node IDs.
GRAPH_FOCUS_SQL: Dict[str, str] = {
    "domain": "LOWER(SPLIT_PART(SPLIT_PART(url, '://', 2), '/', 1))",
    "ip": "LOWER(BTRIM(resolved_ip))",
    "registrar": "LOWER(BTRIM(registrar_name))",
    "kit": "LOWER(BTRIM(detected_kit_type))",
}


def parse_graph_focus(raw: Optional[str]) -> Optional[Tuple[str, str]]:
    """Parse the ``focus`` query parameter of GET /api/v1/graph.

    Both the node type and the value are matched case-insensitively, so the
    value is lower-cased here and compared against lower-cased columns/IDs.

    Args:
        raw: Raw parameter such as ``"registrar:Acme Inc"``; empty means no focus.

    Returns:
        ``(node_type, lowercased_value)`` or None when no focus was requested.

    Raises:
        ValueError: If the parameter is not ``<type>:<value>`` with a known type.
    """
    if raw is None or not raw.strip():
        return None
    node_type, _, value = raw.strip().partition(":")
    node_type, value = node_type.strip().lower(), value.strip().lower()
    if node_type not in GRAPH_FOCUS_SQL or not value:
        raise ValueError(
            "focus must be '<type>:<value>' with type one of: " + ", ".join(sorted(GRAPH_FOCUS_SQL))
        )
    return node_type, value


def is_shared_infrastructure_ip(ip: str, flagged_cloudflare: bool = False) -> bool:
    """Tell whether an IP belongs to shared CDN/proxy infrastructure.

    Many unrelated sites resolve to the same Cloudflare edge addresses, so such
    IPs are hubs that do not imply a relationship between the domains.

    Args:
        ip: Resolved IP address as stored in ``phishing_sites.resolved_ip``.
        flagged_cloudflare: Whether the scanner already flagged it as Cloudflare.

    Returns:
        True when the address is (or was flagged as) shared infrastructure.
    """
    if flagged_cloudflare:
        return True
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return is_cloudflare_ip(ip)


def _merge_flag(current: Optional[bool], candidate: Optional[bool]) -> Optional[bool]:
    """Combine two tri-state flags (True wins; None only when nothing is known).

    Args:
        current: Flag accumulated so far.
        candidate: Flag of the next row (None = unknown).

    Returns:
        The combined flag.
    """
    if candidate is None:
        return current
    return candidate if current is None else (current or candidate)


def _hosting_label(cloudflare: Optional[bool]) -> Optional[str]:
    """Render the ``Hosting`` meta of a graph node.

    Args:
        cloudflare: Whether the scanner flagged the address as Cloudflare
            (None when ``is_cloudflare`` was never recorded).

    Returns:
        ``"Cloudflare"``, ``"Direct"`` or None when unknown.
    """
    if cloudflare is None:
        return None
    return "Cloudflare" if cloudflare else "Direct"


def _widen_span(entity: Dict[str, Any], first: Any, last: Any) -> None:
    """Extend an entity's first/last-seen span with a row's span (None = unknown).

    Args:
        entity: Accumulator with ``first`` and ``last`` keys.
        first: The row's earliest ``first_seen``.
        last: The row's latest ``last_seen``.
    """
    if first is not None and (entity["first"] is None or first < entity["first"]):
        entity["first"] = first
    if last is not None and (entity["last"] is None or last > entity["last"]):
        entity["last"] = last


def _without_none(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Build a node ``meta`` mapping, dropping unknown (None) values.

    Args:
        pairs: ``(label, value)`` pairs in display order.

    Returns:
        The pairs whose value is known.
    """
    return {k: v for k, v in pairs if v is not None}


def _kit_edge_confidence(kit_confidence: Any) -> Optional[float]:
    """Scale a stored kit-fingerprint score (0-100) to an edge confidence (0-1).

    Args:
        kit_confidence: ``phishing_sites.kit_confidence`` (None when not scored).

    Returns:
        The score divided by 100 (two decimals), or None when not recorded.
    """
    if kit_confidence is None:
        return None
    return round(min(max(float(kit_confidence), 0.0), 100.0) / 100, 2)


def build_graph(rows: List[Any], focus: Optional[Tuple[str, str]]) -> Dict[str, Any]:
    """Build the nodes, edges and entity counts of GET /api/v1/graph.

    Only stored facts are reported; anything the database does not record is
    ``null`` or omitted, never a placeholder:

    * domain ``severity`` is the severest stored ``multi_api_threat_level`` of
      its rows (``unknown`` is no verdict -> null); IP, registrar and kit nodes
      have no stored severity, so theirs is null;
    * ``detected_as`` edges carry the stored kit-fingerprint confidence
      (``kit_confidence`` / 100); no confidence is recorded for DNS or WHOIS
      relations, so ``resolves_to`` and ``registered_with`` carry null;
    * ``meta`` timestamps are ISO-8601 with an explicit UTC offset
      (see ``src.api.serializers``) and ``Hosting`` is omitted when
      ``is_cloudflare`` was never recorded.

    Args:
        rows: Source rows ``(domain, resolved_ip, registrar_name, threat_level,
            avg_confidence, cloudflare, first_seen, last_seen, hits, kit_type,
            kit_confidence, ...)``.
        focus: Parsed ``focus`` parameter; restricts the result to the 1-hop
            neighbourhood of that node.

    Returns:
        ``{"nodes": [...], "edges": [...], "meta": {"domains", "ips",
        "registrars", "kits"}}``; the counts are of the returned nodes.
    """
    domains: Dict[str, Dict[str, Any]] = {}
    ips: Dict[str, Dict[str, Any]] = {}
    registrars: Dict[str, Dict[str, Any]] = {}
    kits: Dict[str, Dict[str, Any]] = {}
    edges: Dict[Tuple[str, str, str], Optional[float]] = {}

    for r in rows:
        domain = (r[0] or "").strip()
        if not domain:
            continue
        ip = (r[1] or "").strip() or None
        reg = (r[2] or "").strip() or None
        conf = round(float(r[4])) if r[4] is not None else None
        cloud = None if r[5] is None else bool(r[5])
        first, last, hits = r[6], r[7], int(r[8] or 0)
        kit = (r[9] or "").strip() or None

        d = domains.setdefault(
            domain,
            {
                "severity": None,
                "conf": None,
                "cloudflare": None,
                "first": None,
                "last": None,
                "hits": 0,
            },
        )
        d["severity"] = severest_threat_level([d["severity"], r[3]])
        if conf is not None:
            d["conf"] = conf if d["conf"] is None else max(d["conf"], conf)
        d["cloudflare"] = _merge_flag(d["cloudflare"], cloud)
        d["hits"] += hits
        _widen_span(d, first, last)

        if ip:
            ipp = ips.setdefault(ip, {"cloudflare": None, "first": None, "last": None, "hits": 0})
            ipp["cloudflare"] = _merge_flag(ipp["cloudflare"], cloud)
            ipp["hits"] += hits
            _widen_span(ipp, first, last)
            edges.setdefault((f"domain:{domain}", f"ip:{ip}", "resolves_to"), None)

        if reg:
            rg = registrars.setdefault(reg, {"sites": 0, "first": None, "last": None})
            rg["sites"] += hits
            _widen_span(rg, first, last)
            edges.setdefault((f"domain:{domain}", f"registrar:{reg}", "registered_with"), None)

        if kit:
            kt = kits.setdefault(kit, {"sites": 0, "first": None, "last": None})
            kt["sites"] += hits
            _widen_span(kt, first, last)
            key = (f"domain:{domain}", f"kit:{kit}", "detected_as")
            score = _kit_edge_confidence(r[10])
            previous = edges.get(key)
            if previous is None or (score is not None and score > previous):
                edges[key] = score

    node_list: List[Dict[str, Any]] = []
    for dom, m in domains.items():
        node_list.append(
            {
                "id": f"domain:{dom}",
                "label": dom,
                "type": "domain",
                "severity": m["severity"],
                "meta": _without_none(
                    [
                        ("Hosting", _hosting_label(m["cloudflare"])),
                        ("Hits", m["hits"]),
                        ("Confidence", f"{m['conf']}%" if m["conf"] is not None else None),
                        ("First seen", iso_utc(m["first"])),
                        ("Last seen", iso_utc(m["last"])),
                    ]
                ),
            }
        )
    for ip, m in ips.items():
        node_list.append(
            {
                "id": f"ip:{ip}",
                "label": ip,
                "type": "ip",
                "severity": None,
                "shared_infrastructure": is_shared_infrastructure_ip(ip, bool(m["cloudflare"])),
                "meta": _without_none(
                    [
                        ("Hosting", _hosting_label(m["cloudflare"])),
                        ("Hits", m["hits"]),
                        ("First seen", iso_utc(m["first"])),
                        ("Last seen", iso_utc(m["last"])),
                    ]
                ),
            }
        )
    for node_type, entities in (("registrar", registrars), ("kit", kits)):
        for name, m in entities.items():
            node_list.append(
                {
                    "id": f"{node_type}:{name}",
                    "label": name,
                    "type": node_type,
                    "severity": None,
                    "meta": _without_none(
                        [
                            ("Sites", m["sites"]),
                            ("First seen", iso_utc(m["first"])),
                            ("Last seen", iso_utc(m["last"])),
                        ]
                    ),
                }
            )

    edge_list = [
        {"id": f"e{i}", "source": s, "target": t, "relation": rel, "confidence": edges[(s, t, rel)]}
        for i, (s, t, rel) in enumerate(sorted(edges))
    ]

    # Optional focus → 1-hop neighborhood. Node IDs keep the stored case
    # (e.g. registrar names), so match them case-insensitively.
    if focus:
        focus_key = f"{focus[0]}:{focus[1]}"
        focus_ids = {n["id"] for n in node_list if n["id"].lower() == focus_key}
        keep = set(focus_ids)
        kept_edges = []
        for e in edge_list:
            if e["source"] in focus_ids or e["target"] in focus_ids:
                keep.add(e["source"])
                keep.add(e["target"])
                kept_edges.append(e)
        node_list = [n for n in node_list if n["id"] in keep]
        edge_list = kept_edges

    meta = {
        plural: sum(1 for n in node_list if n["type"] == node_type)
        for node_type, plural in (
            ("domain", "domains"),
            ("ip", "ips"),
            ("registrar", "registrars"),
            ("kit", "kits"),
        )
    }
    return {"nodes": node_list, "edges": edge_list, "meta": meta}


def integration_health(
    integration: Any, name: str, display_name: str, configured: bool
) -> Dict[str, Any]:
    """Describe one integration for GET /api/v1/integrations from real data only.

    Circuit breakers live in each API process and start ``closed`` with no
    calls, which says nothing about the provider. So:

    * no breaker -> ``status``/``circuit_breaker``/``error_rate`` unknown;
    * ``open`` -> ``offline``; ``half_open`` -> ``degraded``;
    * ``closed`` -> ``online`` once at least one call was recorded, else
      ``unknown``;
    * ``error_rate`` is failed/total calls, null before the first call;
    * ``last_success`` is null: the breaker does not record when a call last
      succeeded (its ``last_state_change`` is reported as ``state_changed_at``).

    Args:
        integration: Client object (may expose ``circuit_breaker``), or None.
        name: Stable identifier.
        display_name: Label for the console.
        configured: Whether the integration has the configuration it needs.

    Returns:
        ``{"name", "display_name", "status", "circuit_breaker", "last_call_ms",
        "last_success", "state_changed_at", "error_rate", "configured"}``.
    """
    entry: Dict[str, Any] = {
        "name": name,
        "display_name": display_name,
        "status": "unknown",
        "circuit_breaker": None,
        "last_call_ms": None,
        "last_success": None,
        "state_changed_at": None,
        "error_rate": None,
        "configured": configured,
    }
    breaker = getattr(integration, "circuit_breaker", None)
    if breaker is None:
        return entry
    state = breaker.state.value  # 'closed' / 'open' / 'half_open'
    stats = breaker.stats
    total = stats.total_requests or 0
    if state == "open":
        status = "offline"
    elif state == "half_open":
        status = "degraded"
    else:
        status = "online" if total > 0 else "unknown"
    entry.update(
        {
            "status": status,
            "circuit_breaker": state,
            "last_call_ms": stats.last_call_ms,
            # datetime.now() of this process: naive local time.
            "state_changed_at": iso_utc(stats.last_state_change, naive_is_local=True),
            "error_rate": round((stats.failed_requests or 0) / total, 3) if total else None,
        }
    )
    return entry


# Longest analyst note accepted by POST /api/v1/reports/tasks/<id>/complete.
REPORT_TASK_NOTE_MAX_LENGTH = 1000


def manual_task_json(row: OutboxRow) -> Dict[str, Any]:
    """Serialise an analyst task (an outbox row of a manual channel).

    Args:
        row: Outbox row with channel ``web_form`` or ``manual_review``.

    Returns:
        ``{"id", "report_id", "site_url", "channel", "provider", "form_url",
        "reason", "subject", "text", "status", "created_at", "outcome",
        "note", "completed_by", "completed_at"}``; ``provider`` is null for
        ``manual_review`` (there is no contact), the last four are null while
        the task is open.
    """
    payload = row.payload or {}
    recorded = payload.get("analyst")
    analyst: Dict[str, Any] = recorded if isinstance(recorded, dict) else {}
    return {
        "id": row.id,
        "report_id": row.report_id,
        "site_url": row.site_url,
        "channel": row.channel,
        "provider": row.recipient if row.channel == "web_form" else None,
        "form_url": row.form_url,
        "reason": payload.get("reason"),
        "subject": payload.get("subject"),
        "text": payload.get("text"),
        "status": row.status,
        "created_at": iso_utc(row.created_at),
        "outcome": analyst.get("outcome"),
        "note": analyst.get("note"),
        "completed_by": analyst.get("completed_by"),
        "completed_at": iso_utc(analyst.get("completed_at")),
    }


def label_json(label: Label) -> Dict[str, Any]:
    """Serialise an analyst label.

    Args:
        label: Stored label.

    Returns:
        ``{"id", "site_id", "url", "registrable_domain", "verdict", "action",
        "brand", "kit", "note", "labeled_by", "detector_snapshot",
        "created_at"}``; ``detector_snapshot`` is what the detector had
        concluded when the label was written.
    """
    return {
        "id": label.id,
        "site_id": label.site_id,
        "url": label.url,
        "registrable_domain": label.registrable_domain,
        "verdict": label.verdict,
        "action": label.action,
        "brand": label.brand,
        "kit": label.kit,
        "note": label.note,
        "labeled_by": label.labeled_by,
        "detector_snapshot": label.detector_snapshot,
        "created_at": iso_utc(label.created_at),
    }


def labeled_site_json(site: Dict[str, Any]) -> Dict[str, Any]:
    """Serialise the state of a site right after it was labelled.

    Args:
        site: Row with the columns ``LabelRepository`` returns.

    Returns:
        ``{"id", "url", "label_verdict", "labeled_at", "manual_flag",
        "requires_manual_review", "auto_report_eligible", "site_status",
        "abuse_report_sent"}``.
    """
    return {
        "id": site["id"],
        "url": site["url"],
        "label_verdict": site["label_verdict"],
        "labeled_at": iso_utc(site["labeled_at"]),
        "manual_flag": bool(site["manual_flag"]),
        "requires_manual_review": bool(site["requires_manual_review"]),
        "auto_report_eligible": bool(site["auto_report_eligible"]),
        "site_status": site["site_status"] or "unknown",
        "abuse_report_sent": bool(site["abuse_report_sent"]),
    }


def approval_json(row: Dict[str, Any]) -> Dict[str, Any]:
    """Serialise a submission waiting for analyst approval.

    Args:
        row: Row from ``LabelRepository.pending_approvals``.

    Returns:
        ``{"site_id", "url", "source", "priority", "description",
        "abuse_email", "site_status", "first_seen", "last_seen",
        "requested_at", "requested_by"}``.
    """
    return {
        "site_id": row["id"],
        "url": row["url"],
        "source": row["source"],
        "priority": row["priority"],
        "description": row["description"],
        "abuse_email": row["abuse_email"],
        "site_status": row["site_status"] or "unknown",
        "first_seen": iso_utc(row["first_seen"]),
        "last_seen": iso_utc(row["last_seen"]),
        "requested_at": iso_utc(row["approval_requested_at"]),
        "requested_by": row["approval_requested_by"],
    }


def brand_asset_json(asset: Dict[str, Any]) -> Dict[str, Any]:
    """Serialise a reference image of a brand (hashes only, the image is not kept).

    Args:
        asset: Row of ``brand_assets``.

    Returns:
        ``{"id", "kind", "source_url", "sha256", "mmh3", "phash", "dhash", "width",
        "height", "created_at"}``.
    """
    return {
        "id": asset["id"],
        "kind": asset["kind"],
        "source_url": asset["source_url"],
        "sha256": asset["sha256"],
        "mmh3": asset["mmh3"],
        "phash": asset["phash"],
        "dhash": asset["dhash"],
        "width": asset["width"],
        "height": asset["height"],
        "created_at": iso_utc(asset["created_at"]),
    }


def brand_json(record: BrandRecord) -> Dict[str, Any]:
    """Serialise a brand of the catalogue.

    Args:
        record: The brand.

    Returns:
        Brand fields, ``domains`` and ``assets``.
    """
    return {
        "slug": record.slug,
        "name": record.name,
        "category": record.category,
        "country": record.country,
        "priority": record.priority,
        "aliases": record.aliases,
        "lure_keywords": record.lure_keywords,
        "takedown_preferences": record.takedown_preferences,
        "active": record.active,
        "created_at": iso_utc(record.created_at),
        "updated_at": iso_utc(record.updated_at),
        "domains": [
            {"domain": d["domain"], "kind": d["kind"], "login_url": d["login_url"]}
            for d in record.domains
        ],
        "assets": [brand_asset_json(asset) for asset in record.assets],
    }


def _brand_error(error: Exception):
    """Map a brand repository error to its HTTP response.

    Args:
        error: Validation, not-found or conflict error.

    Returns:
        ``(response, status)``.
    """
    if isinstance(error, BrandValidationError):
        return jsonify({"error": error.message, "parameter": error.field}), 400
    if isinstance(error, BrandNotFoundError):
        return jsonify({"error": "Brand not found"}), 404
    return jsonify({"error": str(error)}), 409


def campaign_id(kind: str, key: str) -> str:
    """Return a stable campaign identifier for a grouping key.

    IDs used to be positional (``CAMP-001`` for the first row), so the same
    cluster changed ID whenever the ordering changed.

    Args:
        kind: Grouping dimension (e.g. ``"registrar"``).
        key: Grouping value exactly as grouped in SQL.

    Returns:
        ``CAMP-`` followed by 10 upper-case hex chars of the key's SHA-256.
    """
    digest = hashlib.sha256(f"{kind}:{key}".encode("utf-8")).hexdigest()
    return f"CAMP-{digest[:10].upper()}"


def email_monitor_target_allowed(details: Any) -> bool:
    """Tell whether an e-mail monitor thread targets an allowlisted mailbox/domain.

    Args:
        details: The thread's ``details`` (JSON text or already-decoded dict).

    Returns:
        True when its ``domain`` (domain-wide mode) or ``target_mailbox`` is
        allowlisted; False for anything else, including malformed details.
    """
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            return False
    if not isinstance(details, dict):
        return False
    domain, mailbox = details.get("domain"), details.get("target_mailbox")
    if domain:
        return isinstance(domain, str) and is_domain_allowed(domain)
    if mailbox:
        return isinstance(mailbox, str) and is_mailbox_allowed(mailbox)
    return False


def _thread_access_denied(thread_type: Any, details: Any) -> Optional[Tuple[Response, int]]:
    """Enforce per-thread-type scopes inside routes that accept several scopes.

    Args:
        thread_type: ``analysis_threads.thread_type`` of the target thread.
        details: Its ``details`` column.

    Returns:
        A 403 response when the caller may not act on the thread, else None.
    """
    if thread_type == "email_monitor":
        if not has_scope("email_admin"):
            return jsonify({"error": "Insufficient scope. Required: email_admin"}), 403
        if not email_monitor_target_allowed(details):
            return jsonify({"error": "Mailbox is not on the e-mail monitoring allowlist"}), 403
        return None
    if not has_scope("write"):
        return jsonify({"error": "Insufficient scope. Required: write"}), 403
    return None


# POST /api/v2/stix/bundle limits: request size and reported validation errors.
STIX_BUNDLE_MAX_BODY_BYTES = 8 * 1024 * 1024
STIX_BUNDLE_MAX_ERRORS = 100


def stix_request_error_message(exc: Any) -> str:
    """Build the client-facing ``error`` text of a rejected STIX bundle request.

    Clients show ``error`` to the analyst and may ignore ``details``; a bare
    "Invalid indicators" does not say which indicator to fix, so the count and
    the first offending indicator are spelled out.

    Args:
        exc: The ``BundleRequestError`` raised by ``validate_bundle_request``
            (``message`` plus per-indicator ``details``).

    Returns:
        A human-readable sentence; ``exc.message`` itself when there are no
        per-indicator details.
    """
    details = getattr(exc, "details", None) or []
    message = str(getattr(exc, "message", "") or "Invalid STIX bundle request")
    if not details:
        return message
    first = details[0]
    count = len(details)
    noun = "indicator is" if count == 1 else "indicators are"
    return (
        f"{message}: {count} {noun} invalid; first problem at index "
        f"{first.get('index')}: {first.get('error')}"
    )


MEMORY_STORAGE_URI = "memory://"

# Health probe tuning: max wait for the DB ping, and how long a result is reused.
HEALTH_DB_TIMEOUT_SECONDS = 3.0
HEALTH_CACHE_SECONDS = 5.0


def rate_limit_storage_uri() -> str:
    """Return the rate-limit storage URI configured in ``RATELIMIT_STORAGE_URL``.

    Without it, counters are kept in process memory: every gunicorn worker then
    enforces its own copy of each limit, so the effective limit is multiplied by
    the number of workers. That is logged as a warning at startup. The URI is
    never logged because it may embed a Redis password.

    Returns:
        The configured storage URI, or ``"memory://"`` when unset.
    """
    uri = (settings.RATELIMIT_STORAGE_URL or "").strip()
    if not uri or uri.startswith(MEMORY_STORAGE_URI):
        logger.warning(
            "⚠️  RATELIMIT_STORAGE_URL is not set: rate limits are kept in memory and "
            "enforced per process (each gunicorn worker counts separately); use a "
            "redis:// URI in production"
        )
        return MEMORY_STORAGE_URI
    logger.info(f"🚦 Rate-limit counters stored in {urlsplit(uri).scheme} storage")
    return uri


class PhishingAPI:
    """REST API for external phishing reports with multi-API integration and Grinder integration."""

    def __init__(
        self,
        db_manager,
        abuse_detector,
        api_key: Optional[str] = None,
        report_manager=None,
        scheduler: Optional["ImageTrackingScheduler"] = None,
        email_scheduler: Optional["EmailMonitorScheduler"] = None,
    ):
        """
        Initialize the Phishing API with authentication support and Grinder integration.

        Args:
            db_manager: Database manager instance
            abuse_detector: Abuse email detector instance
            api_key (str, optional): API key for authentication
            report_manager: AbuseReportManager instance for immediate report sending
            scheduler: ImageTrackingScheduler instance for on-demand searches
            email_scheduler: EmailMonitorScheduler instance for email threat monitoring
        """
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.report_manager = report_manager
        self.scheduler = scheduler
        self.email_scheduler = email_scheduler
        self.multi_api_validator = MultiAPIValidator()
        self.grinder_client = GrinderReportClient()
        self.api_key = api_key

        # Initialize Flask app
        self.app = Flask(__name__)
        self.app.config["JSON_SORT_KEYS"] = False
        self.app.api_key = api_key  # type: ignore[attr-defined]  # read by src.auth

        # Configure Flask logging to be less verbose
        flask_logging.getLogger("werkzeug").setLevel(flask_logging.WARNING)

        # Behind nginx/a load balancer the socket peer is the proxy. Trust exactly
        # TRUSTED_PROXY_HOPS X-Forwarded-For/-Proto entries so request.remote_addr
        # (used by per-key allowed_ips and the rate-limit key) is the real client;
        # with 0 (default) the headers are ignored and cannot be spoofed.
        proxy_hops = settings.TRUSTED_PROXY_HOPS
        if proxy_hops > 0:
            self.app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
                self.app.wsgi_app, x_for=proxy_hops, x_proto=proxy_hops
            )
            logger.info(f"🔁 Trusting {proxy_hops} reverse-proxy hop(s) for client IP/scheme")

        # Rate limiting — bucketed by API key (falls back to IP when no
        # Bearer header is present). Counters live in RATELIMIT_STORAGE_URL
        # (Redis in production, shared by every gunicorn worker); if that store
        # becomes unreachable the limiter degrades to per-process memory
        # instead of failing every request.
        # Responses carry X-RateLimit-Limit/-Remaining/-Reset and Retry-After;
        # a 429 is JSON {"error", "retry_after"} (see _rate_limited). Flask runs
        # after_request hooks in reverse registration order, so _pin_retry_after
        # is registered before the limiter's own header hook to run after it.
        storage_uri = rate_limit_storage_uri()
        self._rate_limit_storage_uri = storage_uri
        self.app.after_request(_pin_retry_after)
        self.limiter = Limiter(
            app=self.app,
            key_func=rate_limit_key,
            default_limits=["200 per day", "50 per hour", "10 per minute"],
            storage_uri=storage_uri,
            in_memory_fallback_enabled=storage_uri != MEMORY_STORAGE_URI,
            headers_enabled=True,
        )
        self.app.register_error_handler(RateLimitExceeded, self._rate_limited)

        install_request_ids(self.app)

        # Health probe: a real database ping (src.observability.health).
        self._health_checker = create_health_checker(check_disk=False)
        self._health_checker.register("database", self._check_database)
        self._health_lock = threading.Lock()
        self._health_cache: Optional[Tuple[float, Dict[str, Any]]] = None
        self.app.register_error_handler(InvalidParameterError, _invalid_parameter_response)
        self.setup_routes()
        # Pipeline timings and queue depth on /metrics, computed from the database.
        engine = getattr(self.db_manager, "engine", None)
        if engine is not None:
            register_operational_collector(engine)

        # Test Grinder connection on startup
        if GRINDER_INTEGRATION_ENABLED:
            connection_test = self.grinder_client.test_connection()
            if connection_test["status"] == "success":
                logger.info("🔗 Grinder integration ready for IP reporting")
            else:
                logger.warning(f"⚠️  Grinder connection issue: {connection_test['message']}")

    def setup_routes(self):
        """Setup API routes with authentication and Grinder integration."""

        @self.app.route("/api/v1/report", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope="report")
        def report_phishing():
            """Submit a phishing URL.

            Keys with the ``report_send`` scope (or the master key) flag the
            site for reporting: abuse contacts are resolved and the abuse report
            is sent without further review. Keys with only ``report`` record the
            submission as pending analyst approval (202): it is never reported
            or made auto-report-eligible until an analyst approves it, e.g. by
            re-submitting it with a ``report_send`` key.

            Every URL passes the SSRF guard before anything is stored or queued.

            Returns:
                200 (flagged for reporting), 202 (pending approval), 400 on
                invalid input, 403 when the URL targets a non-public address.
            """
            try:
                data = request.get_json(silent=True)

                if not data or not isinstance(data, dict):
                    return jsonify({"error": "No JSON data provided"}), 400

                url = data.get("url")
                if not url:
                    return jsonify({"error": "URL is required"}), 400

                # Validate URL
                if not isinstance(url, str) or not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                abuse_email = data.get("abuse_email")
                source = data.get("source", "external_api")
                priority = data.get("priority", "medium")
                description = data.get("description", "")
                if not isinstance(source, str) or not 0 < len(source) <= 64:
                    return jsonify({"error": "source must be a string of 1-64 characters"}), 400
                if priority not in PRIORITIES:
                    return (
                        jsonify(
                            {"error": f"priority must be one of: {', '.join(sorted(PRIORITIES))}"}
                        ),
                        400,
                    )
                if not isinstance(description, str) or len(description) > 5000:
                    return jsonify({"error": "description must be a string (max 5000)"}), 400
                if abuse_email is not None and not isinstance(abuse_email, str):
                    return jsonify({"error": "Invalid abuse email format"}), 400

                # SSRF guard before anything is persisted or queued: the URL is
                # later fetched/resolved server-side (WHOIS, scans, screenshots).
                target_class = assess_url_target(url)
                if target_class == "invalid":
                    return jsonify({"error": "Invalid URL format"}), 400
                if target_class == "blocked":
                    logger.warning(f"🛑 Refusing report of non-public target: {url}")
                    return jsonify({"error": "URL resolves to a non-public address"}), 403

                # Log all API requests with source information
                logger.info(
                    f"📥 API report received - URL: {url}, Source: '{source}', Priority: {priority}"
                )

                # Log if this is from Grinder
                if source.lower() == "grinder":
                    logger.info(f"📥 Confirmed GRINDER report for {url}")

                # Validate abuse_email if provided
                if abuse_email and not self.abuse_detector.validate_email(abuse_email):
                    return jsonify({"error": "Invalid abuse email format"}), 400

                if not has_scope("report_send"):
                    session = current_key_session() or {}
                    try:
                        pending = self.record_pending_submission(
                            url,
                            abuse_email,
                            source,
                            priority,
                            description,
                            requested_by=session.get("key_name") or session.get("key_type"),
                        )
                    except SQLAlchemyError as e:
                        return internal_error(
                            "report_phishing",
                            e,
                            message="Failed to record submission",
                            extra={"url": url},
                        )
                    return jsonify(pending), 202

                # Process the report (persists synchronously; abuse-contact lookup and the
                # immediate abuse report continue in the background)
                try:
                    result = self.process_phishing_report(
                        url, abuse_email, source, priority, description
                    )
                except Exception as e:
                    return internal_error(
                        "report_phishing", e, message="Failed to process report", extra={"url": url}
                    )
                if result.get("status") == "error":
                    return jsonify({**result, "request_id": current_request_id()}), 500

                # If successful, also try to report the IP to Grinder
                # IMPORTANT: Don't report back to Grinder if this report came from Grinder
                if source.lower() == "grinder":
                    logger.info(
                        f"⏭️ Skipping Grinder reporting for {url} - report came from Grinder"
                    )
                elif result.get("status") in ["created", "updated"] and GRINDER_INTEGRATION_ENABLED:
                    try:
                        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                        ip_address = socket.gethostbyname(domain)

                        detection_context = {
                            "method": "external_report",
                            "domains": [domain],
                            "severity": "high" if priority == "high" else "medium",
                            "threat_level": "high",
                            "keywords": ["external_report"],
                            "api_confidence": 85,  # Default confidence for external reports
                        }

                        grinder_result = self.grinder_client.report_malicious_ip(
                            ip_address, detection_context, confidence=85
                        )

                        if grinder_result.get("status") == "success":
                            result["grinder_report"] = grinder_result
                            logger.info(
                                f"✅ Successfully reported IP {ip_address} to Grinder via API"
                            )
                        else:
                            logger.warning(f"⚠️  Failed to report IP to Grinder: {grinder_result}")
                            result["grinder_report"] = {
                                "status": grinder_result.get("status", "error"),
                                "message": "Grinder report failed",
                            }

                    except Exception as e:
                        logger.warning(
                            f"⚠️  Could not report IP to Grinder "
                            f"[request_id={current_request_id()}]: {e}"
                        )
                        result["grinder_report"] = {
                            "status": "error",
                            "message": "Grinder report failed",
                        }

                return jsonify(result), 200

            except Exception as e:
                return internal_error("report_phishing", e)

        @self.app.route("/api/v1/multi-scan", methods=["POST"])
        # Key-based bucketing (see rate_limit_key) means one leaked/shared key
        # can no longer dilute its limit across IPs — cap the heaviest route
        # (multi-API validation + headless render + DB writes) per day too.
        @self.limiter.limit("3 per minute")
        @self.limiter.limit("100 per day")
        @require_api_key(scope="scan")
        def multi_api_scan():
            """Perform multi-API validation scan with authentication."""
            try:
                data = request.get_json()

                if not data:
                    return jsonify({"error": "No JSON data provided"}), 400

                url = data.get("url")
                # Accept the canonical `include_screenshot`; keep `screenshot`
                # as a legacy alias so older clients keep working.
                include_screenshot = data.get("include_screenshot", data.get("screenshot", True))

                if not url:
                    return jsonify({"error": "URL is required"}), 400

                # Validate URL
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                # SSRF guard: never let an attacker-supplied URL point us at an
                # internal address. Refuse private targets outright; screenshots
                # (a direct render) run only when the host is provably public.
                target_class = assess_url_target(url)
                if target_class == "blocked":
                    logger.warning(f"🛑 Refusing multi-scan of non-public target: {url}")
                    return (
                        jsonify({"error": "URL resolves to a non-public address"}),
                        403,
                    )

                # Perform comprehensive scan with ALL APIs (URL analysis, VirusTotal, URLVoid, PhishTank, Google Safe Browsing)
                scan_result = self.multi_api_validator.comprehensive_scan(url)

                # Resolve abuse emails for this domain
                try:
                    _domain = scan_result.get("domain", "")
                    _registrar = scan_result.get("registrar_name")
                    abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                        _domain, registrar=_registrar
                    )
                    scan_result["all_abuse_emails"] = (
                        ", ".join(abuse_emails) if abuse_emails else None
                    )
                except Exception as ae_err:
                    logger.warning(f"⚠️ Abuse email resolution failed: {ae_err}")
                    scan_result["all_abuse_emails"] = None

                # Capture screenshot if requested and service available.
                # The headless browser is a direct render of the page, so it
                # only ever navigates to a provably-public host.
                screenshot_data = None
                if include_screenshot and screenshot_service and target_class == "public":
                    try:
                        logger.info(f"📸 Capturing screenshot for {url}")
                        screenshot_result = screenshot_service.capture_screenshot(
                            url, use_async=False
                        )
                        if screenshot_result and screenshot_result.get("success"):
                            # Read screenshot and convert to base64
                            screenshot_path = screenshot_result.get("screenshot_path")
                            if screenshot_path and Path(screenshot_path).exists():
                                with open(screenshot_path, "rb") as f:
                                    screenshot_bytes = f.read()
                                screenshot_data = {
                                    "base64": base64.b64encode(screenshot_bytes).decode("utf-8"),
                                    "filename": screenshot_result.get("filename"),
                                    "size_bytes": screenshot_result.get("size_bytes"),
                                    "page_title": screenshot_result.get("page_info", {}).get(
                                        "title"
                                    ),
                                    "final_url": screenshot_result.get("page_info", {}).get("url"),
                                }
                                logger.info(f"📸 Screenshot captured successfully for {url}")
                        else:
                            logger.warning(
                                f"⚠️ Screenshot capture failed for {url}: {screenshot_result}"
                            )
                    except Exception as ss_error:
                        logger.error(f"❌ Screenshot error for {url}: {ss_error}")

                scan_result["screenshot"] = screenshot_data

                # Save results to database. The report-status read-back must use
                # the same open transaction: the connection is closed (and every
                # execute on it fails) as soon as the ``with`` block exits.
                try:
                    now_utc = datetime.datetime.now(datetime.timezone.utc)
                    timestamp = now_utc.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )  # legacy naive column: UTC (D16)

                    with self.db_manager.engine.begin() as conn:
                        # Check if URL exists
                        existing = conn.execute(
                            text("SELECT id FROM phishing_sites WHERE url = :url"), {"url": url}
                        ).fetchone()

                        if existing:
                            # Update existing record
                            conn.execute(
                                text("""
                                    UPDATE phishing_sites SET
                                        last_seen = :timestamp,
                                        virustotal_result = :vt_result,
                                        urlvoid_result = :uv_result,
                                        phishtank_result = :pt_result,
                                        multi_api_threat_level = :threat_level,
                                        api_confidence_score = :confidence,
                                        priority = :priority,
                                        auto_analysis_status = 'completed',
                                        registration_date = COALESCE(:reg_date, registration_date),
                                        registrar_name = COALESCE(:registrar, registrar_name),
                                        registrant_org = COALESCE(:registrant_org, registrant_org),
                                        domain_age_days = COALESCE(:domain_age, domain_age_days),
                                        all_abuse_emails = COALESCE(:all_abuse_emails, all_abuse_emails),
                                        detected_kit_type = COALESCE(:kit_type, detected_kit_type),
                                        kit_confidence = COALESCE(:kit_confidence, kit_confidence),
                                        kit_indicators = COALESCE(:kit_indicators, kit_indicators)
                                    WHERE url = :url
                                """),
                                {
                                    "timestamp": timestamp,
                                    "vt_result": json.dumps(scan_result.get("virustotal", {})),
                                    "uv_result": json.dumps(scan_result.get("urlvoid", {})),
                                    "pt_result": json.dumps(scan_result.get("phishtank", {})),
                                    "threat_level": scan_result.get("aggregated_threat_level"),
                                    "confidence": scan_result.get("confidence_score"),
                                    "priority": derived_priority(
                                        scan_result.get("aggregated_threat_level"),
                                        scan_result.get("label_verdict"),
                                    ),
                                    "reg_date": scan_result.get("registration_date"),
                                    "registrar": scan_result.get("registrar_name"),
                                    "registrant_org": scan_result.get("registrant_org"),
                                    "domain_age": scan_result.get("domain_age_days"),
                                    "all_abuse_emails": scan_result.get("all_abuse_emails"),
                                    "kit_type": scan_result.get("detected_kit_type"),
                                    "kit_confidence": scan_result.get("kit_confidence"),
                                    "kit_indicators": (
                                        json.dumps(scan_result["kit_indicators"])
                                        if scan_result.get("kit_indicators")
                                        else None
                                    ),
                                    "url": url,
                                },
                            )
                        else:
                            # Insert new record
                            conn.execute(
                                text("""
                                    INSERT INTO phishing_sites (
                                        url, first_seen, last_seen, source,
                                        virustotal_result, urlvoid_result, phishtank_result,
                                        multi_api_threat_level, api_confidence_score, priority,
                                        auto_analysis_status, registration_date, registrar_name, registrant_org, domain_age_days,
                                        all_abuse_emails, detected_kit_type, kit_confidence, kit_indicators
                                    ) VALUES (
                                        :url, :timestamp, :timestamp, 'api_scan',
                                        :vt_result, :uv_result, :pt_result,
                                        :threat_level, :confidence, :priority,
                                        'completed', :reg_date, :registrar, :registrant_org, :domain_age,
                                        :all_abuse_emails, :kit_type, :kit_confidence, :kit_indicators
                                    )
                                """),
                                {
                                    "url": url,
                                    "timestamp": timestamp,
                                    "vt_result": json.dumps(scan_result.get("virustotal", {})),
                                    "uv_result": json.dumps(scan_result.get("urlvoid", {})),
                                    "pt_result": json.dumps(scan_result.get("phishtank", {})),
                                    "threat_level": scan_result.get("aggregated_threat_level"),
                                    "confidence": scan_result.get("confidence_score"),
                                    "priority": derived_priority(
                                        scan_result.get("aggregated_threat_level"),
                                        scan_result.get("label_verdict"),
                                    ),
                                    "reg_date": scan_result.get("registration_date"),
                                    "registrar": scan_result.get("registrar_name"),
                                    "registrant_org": scan_result.get("registrant_org"),
                                    "domain_age": scan_result.get("domain_age_days"),
                                    "all_abuse_emails": scan_result.get("all_abuse_emails"),
                                    "kit_type": scan_result.get("detected_kit_type"),
                                    "kit_confidence": scan_result.get("kit_confidence"),
                                    "kit_indicators": (
                                        json.dumps(scan_result["kit_indicators"])
                                        if scan_result.get("kit_indicators")
                                        else None
                                    ),
                                },
                            )

                        # The capture, its features and the brand identification (drawer).
                        record_scan_capture(conn, url, scan_result)

                        # Get report status info for response
                        report_info = conn.execute(
                            text("""
                                SELECT last_report_sent, abuse_report_sent, all_abuse_emails
                                FROM phishing_sites WHERE url = :url
                                """),
                            {"url": url},
                        ).fetchone()
                    logger.info(f"✅ Scan results saved for {url}")

                    if report_info:
                        scan_result["last_report_sent"] = (
                            str(report_info[0]) if report_info[0] else None
                        )
                        scan_result["abuse_report_sent"] = bool(report_info[1])
                        scan_result["all_abuse_emails"] = report_info[2]

                except Exception as db_error:
                    logger.error(f"❌ Failed to save scan results: {db_error}")

                # Provider clients embed raw exception text in their results.
                return jsonify(scrub_provider_errors(scan_result)), 200

            except Exception as e:
                return internal_error("multi_api_scan", e)

        @self.app.route("/api/v1/status/<path:url>", methods=["GET"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="read")
        def get_report_status(url):
            """Get the status of a reported URL with authentication."""
            try:
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text("""
                            SELECT url, manual_flag, first_seen, last_seen,
                                   reported, abuse_report_sent, site_status,
                                   takedown_date, abuse_email, source, priority,
                                   last_report_sent, all_abuse_emails
                            FROM phishing_sites
                            WHERE url = :url
                        """),
                        {"url": url},
                    ).fetchone()

                    if not result:
                        return jsonify({"error": "URL not found"}), 404

                    return (
                        jsonify(
                            {
                                "url": result[0],
                                "flagged": bool(result[1]),
                                "first_seen": result[2],
                                "last_seen": result[3],
                                "reported": bool(result[4]),
                                "abuse_report_sent": bool(result[5]),
                                "site_status": result[6],
                                "takedown_date": result[7],
                                "abuse_email": result[8],
                                "source": result[9] if len(result) > 9 else None,
                                "priority": result[10] if len(result) > 10 else None,
                                "last_report_sent": str(result[11]) if result[11] else None,
                                "all_abuse_emails": result[12] if len(result) > 12 else None,
                            }
                        ),
                        200,
                    )

            except Exception as e:
                return internal_error("get_report_status", e)

        @self.app.route("/api/v1/grinder/test", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope="admin")
        def test_grinder_integration():
            """Test Grinder integration with authentication."""
            try:
                if not GRINDER_INTEGRATION_ENABLED:
                    return (
                        jsonify(
                            {"status": "disabled", "message": "Grinder integration not configured"}
                        ),
                        200,
                    )

                connection_test = self.grinder_client.test_connection()

                if connection_test.get("status") == "success":
                    return jsonify(connection_test), 200
                logger.warning(
                    f"⚠️  Grinder connection test failed [request_id={current_request_id()}]: "
                    f"{connection_test.get('message')}"
                )
                return (
                    jsonify(
                        {
                            "status": connection_test.get("status", "error"),
                            "message": "Grinder connection test failed",
                            "request_id": current_request_id(),
                        }
                    ),
                    500,
                )

            except Exception as e:
                return internal_error("test_grinder_integration", e)

        @self.app.route("/api/v1/session", methods=["GET"])
        @self.limiter.limit("60 per minute")
        @require_api_key
        def get_session():
            """Describe the API key session of the caller (any valid key).

            Lets the console show "API key session · scopes" and hide actions
            the key cannot perform. Never returns the key or its hash.

            Returns:
                JSON ``{"key_type": "master" | "database", "key_name": str | null,
                "key_prefix": str | null, "scopes": [str], "rate_limit_storage":
                "shared" | "per-process"}``; ``scopes`` lists every usable scope
                (implied ones included; ``admin`` expands to all of them).
            """
            session = current_key_session()
            if session is None:  # pragma: no cover - require_api_key ran
                return internal_error("get_session")
            session["rate_limit_storage"] = self._rate_limit_storage_mode()
            response = jsonify(session)
            response.headers["Cache-Control"] = "no-store"
            return response, 200

        @self.app.route("/api/v1/stats", methods=["GET"])
        @self.limiter.limit("120 per minute")
        @require_api_key(scope="read")
        def get_stats():
            """Platform statistics for the console overview.

            ``reports_sent`` (kept for compatibility) counts sites flagged
            ``abuse_report_sent``, which the reporting pipeline also sets for
            sites whose only output was an analyst task. The real delivery
            state is in ``reports_by_status`` (``abuse_reports.status``: every
            pipeline status, 0 when absent, plus any other stored value; NULL
            statuses are not listed) and ``outbox_by_status``
            (``abuse_report_outbox.status``: pending, sending, sent, failed,
            pending_manual).

            Returns:
                JSON object of counters.
            """
            try:
                with self.db_manager.engine.begin() as conn:
                    stats = {
                        "total_reports": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites")
                        ).scalar(),
                        # An analyst-labelled benign site is not a threat, even
                        # while it stays up (it is monitored, not counted).
                        "active_sites": conn.execute(
                            text(
                                "SELECT COUNT(*) FROM phishing_sites "
                                "WHERE site_status = 'up' "
                                "AND COALESCE(label_verdict, '') <> 'benign'"
                            )
                        ).scalar(),
                        "taken_down": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE site_status = 'down'")
                        ).scalar(),
                        "reports_sent": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE abuse_report_sent = 1")
                        ).scalar(),
                        "manual_flags": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE manual_flag = 1")
                        ).scalar(),
                        "grinder_integration": {
                            "enabled": GRINDER_INTEGRATION_ENABLED,
                            "api_url": GRINDER0X_API_URL if GRINDER_INTEGRATION_ENABLED else None,
                        },
                    }

                    # Recent activity (last 7 days)
                    seven_days_ago = (
                        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    stats["recent_reports"] = conn.execute(
                        text("SELECT COUNT(*) FROM phishing_sites WHERE first_seen >= :date"),
                        {"date": seven_days_ago},
                    ).scalar()

                    # Threat level breakdown for active sites
                    rows = conn.execute(
                        text(
                            "SELECT multi_api_threat_level, COUNT(*) FROM phishing_sites "
                            "WHERE site_status = 'up' AND multi_api_threat_level IS NOT NULL "
                            "GROUP BY multi_api_threat_level"
                        )
                    ).fetchall()
                    stats["threat_breakdown"] = {r[0]: r[1] for r in rows}

                    # Delivery state of the reporting pipeline.
                    reports_by_status = {status.value: 0 for status in ReportStatus}
                    for status, count in conn.execute(
                        text(
                            "SELECT status, COUNT(*) FROM abuse_reports "
                            "WHERE status IS NOT NULL GROUP BY status"
                        )
                    ).fetchall():
                        reports_by_status[status] = int(count)
                    outbox_by_status = {status.value: 0 for status in OutboxStatus}
                    for status, count in conn.execute(
                        text("SELECT status, COUNT(*) FROM abuse_report_outbox GROUP BY status")
                    ).fetchall():
                        outbox_by_status[status] = int(count)
                    stats["reports_by_status"] = reports_by_status
                    stats["outbox_by_status"] = outbox_by_status

                    return jsonify(stats), 200

            except Exception as e:
                return internal_error("get_stats", e)

        @self.app.route("/api/v1/gsb/rescan", methods=["POST"])
        @self.limiter.limit("2 per minute")
        @require_api_key(scope="admin")
        def gsb_rescan():
            """
            Trigger Google Safe Browsing re-scan of existing sites.

            This re-checks sites against GSB to catch:
            - Sites that were later reported to Google
            - GSB classification changes

            Request body (optional):
            {
                "max_age_hours": 24,  // Re-scan sites not checked in X hours
                "batch_size": 50      // Number of sites to check
            }
            """
            try:
                data = request.get_json() or {}
                max_age_hours = data.get("max_age_hours", 24)
                batch_size = data.get("batch_size", 50)

                # Get or create the rescan job
                job = get_gsb_rescan_job(
                    db_manager=self.db_manager,
                    max_age_hours=max_age_hours,
                    batch_size=batch_size,
                )

                # Run a single rescan cycle
                result = job.run_once()

                return (
                    jsonify(
                        {
                            "status": "completed",
                            "sites_checked": result.get("sites_checked", 0),
                            "threats_found": result.get("threats_found", 0),
                            "status_changes": result.get("status_changes", []),
                            "errors": len(result.get("errors", [])),
                            "duration_seconds": result.get("duration_seconds", 0),
                        }
                    ),
                    200,
                )

            except Exception as e:
                return internal_error("gsb_rescan", e)

        @self.app.route("/api/v1/gsb/status", methods=["GET"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="read")
        def gsb_status():
            """Get GSB rescan job status and statistics."""
            try:
                job = get_gsb_rescan_job(db_manager=self.db_manager)
                stats = job.get_stats()

                # Get recent GSB status changes from DB
                recent_changes = self.db_manager.get_gsb_status_changes(since_hours=24)

                return (
                    jsonify(
                        {
                            "job_stats": stats,
                            "recent_threats": recent_changes,
                            "recent_threats_count": len(recent_changes),
                        }
                    ),
                    200,
                )

            except Exception as e:
                return internal_error("gsb_status", e)

        @self.app.route("/api/v1/gsb/check", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope="scan")
        def gsb_check_url():
            """
            Check a single URL against Google Safe Browsing.

            Request body:
            {
                "url": "https://example.com"
            }
            """
            try:
                data = request.get_json()
                if not data or "url" not in data:
                    return jsonify({"error": "Missing 'url' in request body"}), 400

                url = data["url"]
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                # Import GSB integration
                from src.intelligence.google_safe_browsing import GoogleSafeBrowsingIntegration

                gsb = GoogleSafeBrowsingIntegration()

                if not gsb.is_available():
                    return (
                        jsonify(
                            {
                                "error": "Google Safe Browsing API not configured",
                                "checked": False,
                            }
                        ),
                        503,
                    )

                result = gsb.check_url(url)

                return (
                    jsonify(
                        {
                            "url": url,
                            "checked": result.get("checked", False),
                            "safe": result.get("safe", True),
                            "threats_found": result.get("threats_found", []),
                            "threat_count": result.get("threat_count", 0),
                            "timestamp": result.get("timestamp"),
                            # The provider's error text can embed the request URL.
                            "error": "Safe Browsing lookup failed" if result.get("error") else None,
                        }
                    ),
                    200,
                )

            except Exception as e:
                return internal_error("gsb_check_url", e)

        @self.app.route("/api/v1/gsb/report", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="report_send")
        def gsb_report_url():
            """
            Report a phishing URL to Google Safe Browsing.

            Request body:
            {
                "url": "https://phishing-example.com",
                "screenshot_base64": "optional base64 encoded screenshot"
            }
            """
            try:
                data = request.get_json()
                if not data or "url" not in data:
                    return jsonify({"error": "Missing 'url' in request body"}), 400

                url = data["url"]
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                screenshot_base64 = data.get("screenshot_base64")

                # Import GSB reporter
                from src.intelligence.gsb_reporter import report_phishing_url

                result = report_phishing_url(
                    url=url,
                    screenshot_base64=screenshot_base64,
                )

                return jsonify(
                    {
                        "url": url,
                        "success": result.get("success", False),
                        "method": result.get("method"),
                        "message": result.get("message"),
                        "timestamp": result.get("timestamp"),
                    }
                ), (200 if result.get("success") else 500)

            except Exception as e:
                return internal_error("gsb_report_url", e)

        # ── GET /api/v1/alerts/google ──────────────────────────────────────────
        @self.app.route("/api/v1/alerts/google", methods=["GET"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="read")
        def google_alerts():
            """List Google Workspace Alert Center alerts."""
            try:
                sa_file = getattr(settings, "GOOGLE_SERVICE_ACCOUNT_FILE", None)
                admin_email = getattr(settings, "GOOGLE_ADMIN_EMAIL", None)
                domain = getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None)

                if not sa_file or not domain:
                    return jsonify({"error": "Google Workspace not configured"}), 503

                if not admin_email:
                    admin_email = f"admin@{domain}"

                from src.intelligence.alert_center_client import get_alert_center_client

                client = get_alert_center_client(sa_file, admin_email)

                alerts = client.list_alerts()

                # Strip raw data to keep response lean
                cleaned = []
                for a in alerts:
                    data = a.get("data", {})
                    if isinstance(data, dict):
                        data = {
                            k: v for k, v in data.items() if k not in ("rawData", "raw", "headers")
                        }
                    cleaned.append(
                        {
                            "alertId": a.get("alertId"),
                            "type": a.get("type"),
                            "source": a.get("source"),
                            "createTime": a.get("createTime"),
                            "updateTime": a.get("updateTime"),
                            "endTime": a.get("endTime"),
                            "deleted": a.get("deleted", False),
                            "severity": a.get("metadata", {}).get("severity"),
                            "status": a.get("metadata", {}).get("status"),
                            "data": data,
                        }
                    )

                return jsonify({"alerts": cleaned, "total": len(cleaned)}), 200

            except Exception as e:
                return internal_error("google_alerts", e)

        # ── GET /api/v1/alerts/google/<id> ─────────────────────────────────────
        @self.app.route("/api/v1/alerts/google/<alert_id>", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def google_alert_detail(alert_id: str):
            """Get a single Google Workspace Alert Center alert."""
            try:
                sa_file = getattr(settings, "GOOGLE_SERVICE_ACCOUNT_FILE", None)
                admin_email = getattr(settings, "GOOGLE_ADMIN_EMAIL", None)
                domain = getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None)

                if not sa_file or not domain:
                    return jsonify({"error": "Google Workspace not configured"}), 503

                if not admin_email:
                    admin_email = f"admin@{domain}"

                from src.intelligence.alert_center_client import get_alert_center_client

                client = get_alert_center_client(sa_file, admin_email)
                alert = client.get_alert(alert_id)
                feedback = client.list_feedback(alert_id)
                return jsonify({"alert": alert, "feedback": feedback}), 200

            except Exception as e:
                return internal_error("google_alert_detail", e)

        # ── POST /api/v1/scan/domain ───────────────────────────────────────────
        @self.app.route("/api/v1/scan/domain", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="scan")
        def scan_domain():
            """Scan a suspicious domain: DNS + WHOIS + threat classification."""
            try:
                body = request.get_json(silent=True) or {}
                domain = (body.get("domain") or "").strip().lower().removeprefix("www.")
                if not domain:
                    return jsonify({"error": "domain is required"}), 400

                from src.intelligence.domain_scanner import full_scan, is_valid_domain

                # domain goes into dig/whois argv and victim_domain is echoed back:
                # accept plain hostnames only
                if not is_valid_domain(domain):
                    return jsonify({"error": "invalid domain"}), 400

                victim = (body.get("victim_domain") or "").strip().lower()
                if victim and not is_valid_domain(victim):
                    return jsonify({"error": "invalid victim_domain"}), 400
                if not victim and settings.DOMAINS:
                    victim = settings.DOMAINS.split(",")[0].strip()

                result = full_scan(domain, victim_domain=victim or None)
                return jsonify(result), 200

            except Exception as e:
                return internal_error("scan_domain", e)

        # ── GET /api/v1/sites ──────────────────────────────────────────────────
        @self.app.route("/api/v1/sites", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_sites():
            """List phishing sites with optional filters and pagination.

            Unknown values are null rather than defaults: ``source``,
            ``priority`` and ``is_cloudflare`` when the column is NULL, and
            ``gsb_safe`` until Google Safe Browsing has checked the site
            (``gsb_last_check`` is NULL). ``first_seen``, ``last_seen`` and
            ``takedown_date`` are ISO-8601 with an explicit UTC offset.
            ``label_verdict`` is the latest analyst label (``phishing`` /
            ``benign``) or null; ``label`` filters on it (``unlabeled`` = no
            label yet).

            Returns:
                JSON ``{"items": [...], "total": int, "limit": int, "offset": int}``.
            """
            limit = int_arg(request.args, "limit", default=100, maximum=500)
            offset = _offset_arg()
            status_filter = enum_arg(request.args, "status", SITE_STATUSES)
            priority_filter = enum_arg(request.args, "priority", PRIORITIES)
            source_filter = str_arg(request.args, "source", max_length=64)
            label_filter = enum_arg(request.args, "label", SITE_LABEL_FILTERS)
            search = str_arg(request.args, "search") or ""
            try:

                where_clauses = []
                params: Dict[str, Any] = {"limit": limit, "offset": offset}

                if status_filter:
                    where_clauses.append("site_status = :status")
                    params["status"] = status_filter
                if priority_filter:
                    where_clauses.append("priority = :priority")
                    params["priority"] = priority_filter
                if source_filter:
                    where_clauses.append("source = :source")
                    params["source"] = source_filter
                if label_filter == "unlabeled":
                    where_clauses.append("label_verdict IS NULL")
                elif label_filter:
                    where_clauses.append("label_verdict = :label")
                    params["label"] = label_filter
                if search:
                    where_clauses.append("url ILIKE :search")
                    params["search"] = f"%{search}%"

                where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

                with self.db_manager.engine.begin() as conn:
                    total = conn.execute(
                        text(f"SELECT COUNT(*) FROM phishing_sites {where_sql}"), params
                    ).scalar()

                    rows = conn.execute(
                        text(f"""
                            SELECT id, url, site_status, priority, source,
                                   first_seen, last_seen, multi_api_threat_level,
                                   api_confidence_score, registrar_name, domain_age_days,
                                   abuse_report_sent, manual_flag, gsb_safe,
                                   resolved_ip, is_cloudflare, description, assigned_to,
                                   takedown_date, gsb_last_check, label_verdict, labeled_at
                            FROM phishing_sites {where_sql}
                            ORDER BY last_seen DESC NULLS LAST, id DESC
                            LIMIT :limit OFFSET :offset
                            """),
                        params,
                    ).fetchall()

                items = [
                    {
                        "id": r[0],
                        "url": r[1],
                        "site_status": r[2] or "unknown",
                        "priority": r[3],
                        "source": r[4],
                        "first_seen": iso_utc(r[5]),
                        "last_seen": iso_utc(r[6]),
                        "takedown_date": iso_utc(r[18]),
                        "multi_api_threat_level": r[7],
                        "api_confidence_score": r[8],
                        "registrar_name": r[9],
                        "domain_age_days": r[10],
                        "abuse_report_sent": bool(r[11]),
                        "manual_flag": bool(r[12]),
                        "gsb_safe": None if r[13] is None or r[19] is None else bool(r[13]),
                        "resolved_ip": r[14],
                        "is_cloudflare": None if r[15] is None else bool(r[15]),
                        "description": r[16],
                        "assigned_to": r[17],
                        "label_verdict": r[20],
                        "labeled_at": iso_utc(r[21]),
                    }
                    for r in rows
                ]

                return (
                    jsonify({"items": items, "total": total, "limit": limit, "offset": offset}),
                    200,
                )

            except Exception as e:
                return internal_error("get_sites", e)

        # ── GET /api/v1/sites/sources ──────────────────────────────────────────
        @self.app.route("/api/v1/sites/sources", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_site_sources():
            """Count phishing sites per detection source.

            A list (not a mapping) so that sites whose ``source`` is NULL are
            reported as ``{"source": null, ...}`` instead of under an invented
            name.

            Returns:
                JSON ``[{"source": str | null, "count": int}, ...]``, largest
                count first (NULL last on ties).
            """
            try:
                with self.db_manager.engine.begin() as conn:
                    rows = conn.execute(text("""
                        SELECT source, COUNT(*) AS n
                        FROM phishing_sites
                        GROUP BY source
                        ORDER BY n DESC, source NULLS LAST
                    """)).fetchall()
                return jsonify([{"source": r[0], "count": int(r[1])} for r in rows]), 200
            except Exception as e:
                return internal_error("get_site_sources", e)

        # ── POST /api/v1/sites/<id>/labels ─────────────────────────────────────
        @self.app.route("/api/v1/sites/<int:site_id>/labels", methods=["POST"])
        @self.limiter.limit("60 per minute")
        @require_api_key(scope=("write", "report_send"))
        def label_site(site_id: int):
            """Record an analyst decision about a site (the evaluation ground truth).

            Body: ``{"action": "confirm" | "dismiss" | "report", "brand"?: str,
            "kit"?: str, "note"?: str}`` (``brand``/``kit`` at most 100
            characters, ``note`` at most 1000).

            * ``confirm`` (scope ``write``): phishing; nothing is sent.
            * ``dismiss`` (scope ``write``): benign; the site leaves the reporting
              loop, its queued e-mails are cancelled and its analyst tasks closed.
            * ``report`` (scope ``report_send``): phishing; the site is flagged for
              the reporting pipeline, which also approves a submission waiting
              in ``GET /api/v1/reports/approvals``.

            Args:
                site_id: ``id`` of the site (``GET /api/v1/sites``).

            Returns:
                201 ``{"label": {...}, "site": {...}, "released_from_approval":
                bool, "cancelled_deliveries": int, "closed_tasks": int}``; 400 on
                an invalid body; 403 when the key lacks the action's scope; 404
                when no site has that id.
            """
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Request body must be a JSON object"}), 400
            raw_action = data.get("action")
            if raw_action not in LABEL_ACTIONS:
                return (
                    jsonify(
                        {
                            "error": "action must be one of: " + ", ".join(sorted(LABEL_ACTIONS)),
                            "parameter": "action",
                        }
                    ),
                    400,
                )
            for field, max_length in (
                ("brand", MAX_TAG_LENGTH),
                ("kit", MAX_TAG_LENGTH),
                ("note", MAX_NOTE_LENGTH),
            ):
                value = data.get(field)
                if value is not None and (not isinstance(value, str) or len(value) > max_length):
                    return (
                        jsonify(
                            {
                                "error": f"{field} must be a string of at most "
                                f"{max_length} characters",
                                "parameter": field,
                            }
                        ),
                        400,
                    )
            action = LabelAction(raw_action)
            required = "report_send" if action == LabelAction.REPORT else "write"
            if not has_scope(required):
                return jsonify({"error": f"Insufficient scope. Required: {required}"}), 403
            session = current_key_session() or {}
            try:
                outcome = LabelRepository(self.db_manager.engine).record(
                    site_id,
                    action,
                    brand=data.get("brand"),
                    kit=data.get("kit"),
                    note=data.get("note"),
                    labeled_by=session.get("key_name") or session.get("key_type"),
                )
            except SiteNotFoundError:
                return jsonify({"error": "Site not found"}), 404
            except Exception as e:
                return internal_error("label_site", e, extra={"site_id": site_id})
            logger.info(
                f"🏷️ Site {site_id} labelled {outcome.label.verdict} ({action.value}); "
                f"cancelled {outcome.cancelled_deliveries} e-mail(s), "
                f"closed {outcome.closed_tasks} task(s)"
            )
            return (
                jsonify(
                    {
                        "label": label_json(outcome.label),
                        "site": labeled_site_json(outcome.site),
                        "released_from_approval": outcome.released_from_approval,
                        "cancelled_deliveries": outcome.cancelled_deliveries,
                        "closed_tasks": outcome.closed_tasks,
                    }
                ),
                201,
            )

        # ── GET /api/v1/sites/<id>/labels ──────────────────────────────────────
        @self.app.route("/api/v1/sites/<int:site_id>/labels", methods=["GET"])
        @self.limiter.limit("60 per minute")
        @require_api_key(scope="read")
        def get_site_labels(site_id: int):
            """List every label of a site, newest first.

            Args:
                site_id: ``id`` of the site.

            Returns:
                JSON ``{"items": [...], "total": int}`` (empty for an unknown id).
            """
            try:
                labels = LabelRepository(self.db_manager.engine).history(site_id)
                return (
                    jsonify(
                        {"items": [label_json(label) for label in labels], "total": len(labels)}
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_site_labels", e, extra={"site_id": site_id})

        # ── GET /api/v1/sites/<id>/capture ─────────────────────────────────────
        @self.app.route("/api/v1/sites/<int:site_id>/capture", methods=["GET"])
        @self.limiter.limit("60 per minute")
        @require_api_key(scope="read")
        def get_site_capture(site_id: int):
            """The newest capture of a site: what the page served and what was read from it.

            Args:
                site_id: ``id`` of the site.

            Returns:
                JSON ``{"capture": {...} | null}`` (null until a scan captures the page),
                404 for an unknown site.
            """
            try:
                with self.db_manager.engine.connect() as conn:
                    site = conn.execute(
                        text("SELECT 1 FROM phishing_sites WHERE id = :s"), {"s": site_id}
                    ).first()
                    if site is None:
                        return jsonify({"error": "Site not found"}), 404
                    return jsonify({"capture": latest_capture(conn, site_id)}), 200
            except Exception as e:
                return internal_error("get_site_capture", e, extra={"site_id": site_id})

        # ── GET /api/v1/labels ─────────────────────────────────────────────────
        @self.app.route("/api/v1/labels", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_labels():
            """List analyst labels, newest first, optionally by verdict or action.

            Returns:
                JSON ``{"items": [...], "total": int, "limit": int, "offset": int}``.
            """
            limit = int_arg(request.args, "limit", default=50, minimum=1, maximum=200)
            offset = _offset_arg()
            verdict = enum_arg(request.args, "verdict", LABEL_VERDICTS)
            action = enum_arg(request.args, "action", LABEL_ACTIONS)
            try:
                labels, total = LabelRepository(self.db_manager.engine).list_labels(
                    verdict=verdict, action=action, limit=limit, offset=offset
                )
                return (
                    jsonify(
                        {
                            "items": [label_json(label) for label in labels],
                            "total": total,
                            "limit": limit,
                            "offset": offset,
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_labels", e)

        # ── Brand catalogue (/api/v1/brands) ──────────────────────────────────
        @self.app.route("/api/v1/brands", methods=["GET"])
        @self.limiter.limit("60 per minute")
        @require_api_key(scope="read")
        def list_brands():
            """List the brands added from the console, by priority then name.

            Query: ``search`` (slug, name, alias or domain), ``include_inactive``
            (``true``), ``limit`` (1-200), ``offset``.

            Returns:
                JSON ``{"items": [...], "total", "limit", "offset"}``; empty until a brand
                is added (the built-in detection list is not part of the catalogue).
            """
            limit = int_arg(request.args, "limit", default=50, minimum=1, maximum=200)
            offset = _offset_arg()
            search = str_arg(request.args, "search", max_length=100)
            include_inactive = request.args.get("include_inactive", "").lower() == "true"
            try:
                records, total = BrandRepository(self.db_manager.engine).list(
                    search=search, include_inactive=include_inactive, limit=limit, offset=offset
                )
            except Exception as e:
                return internal_error("list_brands", e)
            return (
                jsonify(
                    {
                        "items": [brand_json(r) for r in records],
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    }
                ),
                200,
            )

        @self.app.route("/api/v1/brands", methods=["POST"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def create_brand():
            """Add a brand to protect.

            Body: ``{"slug", "name", "category"?, "country"?, "priority"? (1-5),
            "aliases"?: [str], "domains"?: [str | {"domain", "kind", "login_url"?}],
            "lure_keywords"?: {"es": [str], "en": [str]}, "takedown_preferences"?: {}}``.

            Returns:
                201 with the brand; 400 on an invalid field; 409 when the slug or a
                domain is taken.
            """
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Request body must be a JSON object"}), 400
            try:
                record = BrandRepository(self.db_manager.engine).create(data)
            except (BrandValidationError, BrandConflictError) as e:
                return _brand_error(e)
            except Exception as e:
                return internal_error("create_brand", e)
            invalidate_brand_catalog()
            logger.info(f"🏷️ Brand {record.slug} added to the catalogue")
            return jsonify(brand_json(record)), 201

        @self.app.route("/api/v1/brands/<slug>", methods=["GET"])
        @self.limiter.limit("60 per minute")
        @require_api_key(scope="read")
        def get_brand(slug: str):
            """One brand with its domains and reference images.

            Args:
                slug: Brand slug.

            Returns:
                The brand, or 404.
            """
            try:
                return jsonify(brand_json(BrandRepository(self.db_manager.engine).get(slug))), 200
            except BrandNotFoundError as e:
                return _brand_error(e)
            except Exception as e:
                return internal_error("get_brand", e, extra={"slug": slug})

        @self.app.route("/api/v1/brands/<slug>", methods=["PATCH"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def update_brand(slug: str):
            """Change some fields of a brand (``domains`` replaces the list; ``active``
            re-enables or disables it).

            Args:
                slug: Brand slug.

            Returns:
                The brand; 400, 404 or 409 on errors.
            """
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Request body must be a JSON object"}), 400
            try:
                record = BrandRepository(self.db_manager.engine).update(slug, data)
            except (BrandValidationError, BrandNotFoundError, BrandConflictError) as e:
                return _brand_error(e)
            except Exception as e:
                return internal_error("update_brand", e, extra={"slug": slug})
            invalidate_brand_catalog()
            return jsonify(brand_json(record)), 200

        @self.app.route("/api/v1/brands/<slug>", methods=["DELETE"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def deactivate_brand(slug: str):
            """Stop using a brand for detection (kept, ``active: false``).

            Args:
                slug: Brand slug.

            Returns:
                The deactivated brand, or 404.
            """
            try:
                record = BrandRepository(self.db_manager.engine).deactivate(slug)
            except BrandNotFoundError as e:
                return _brand_error(e)
            except Exception as e:
                return internal_error("deactivate_brand", e, extra={"slug": slug})
            invalidate_brand_catalog()
            return jsonify(brand_json(record)), 200

        @self.app.route("/api/v1/brands/<slug>/assets", methods=["POST"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def add_brand_asset(slug: str):
            """Add a reference favicon or logo (multipart: ``file``, ``kind``,
            ``source_url``?). Only its hashes are stored.

            Args:
                slug: Brand slug.

            Returns:
                201 with the asset; 400 for a missing, oversized or undecodable image; 404;
                409 when the image is already a reference of the brand.
            """
            upload = request.files.get("file")
            if upload is None:
                return jsonify({"error": "file is required", "parameter": "file"}), 400
            data = upload.stream.read(MAX_ASSET_BYTES + 1)
            try:
                asset = BrandRepository(self.db_manager.engine).add_asset(
                    slug,
                    request.form.get("kind", ""),
                    data,
                    source_url=request.form.get("source_url") or None,
                )
            except (BrandValidationError, BrandNotFoundError, BrandConflictError) as e:
                return _brand_error(e)
            except Exception as e:
                return internal_error("add_brand_asset", e, extra={"slug": slug})
            invalidate_brand_catalog()
            return jsonify(brand_asset_json(asset)), 201

        @self.app.route("/api/v1/brands/<slug>/assets/<int:asset_id>", methods=["DELETE"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def delete_brand_asset(slug: str, asset_id: int):
            """Remove a reference image of a brand.

            Args:
                slug: Brand slug.
                asset_id: Asset id.

            Returns:
                204, or 404.
            """
            try:
                BrandRepository(self.db_manager.engine).delete_asset(slug, asset_id)
            except BrandNotFoundError as e:
                return _brand_error(e)
            except Exception as e:
                return internal_error("delete_brand_asset", e, extra={"slug": slug})
            invalidate_brand_catalog()
            return "", 204

        # ── GET /api/v1/reports ────────────────────────────────────────────────
        @self.app.route("/api/v1/reports", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_reports():
            """List abuse reports with threat context from phishing_sites."""
            limit = int_arg(request.args, "limit", default=100, maximum=500)
            offset = _offset_arg()
            status_filter = enum_arg(request.args, "status", REPORT_STATUSES)
            try:

                where_sql = "WHERE ar.status = :status" if status_filter else ""
                params: Dict[str, Any] = {"limit": limit, "offset": offset}
                if status_filter:
                    params["status"] = status_filter

                with self.db_manager.engine.begin() as conn:
                    total = conn.execute(
                        text(f"SELECT COUNT(*) FROM abuse_reports ar {where_sql}"), params
                    ).scalar()

                    rows = conn.execute(
                        text(f"""
                            SELECT ar.report_id, ar.site_url, ar.recipients, ar.status,
                                   ar.report_date, ar.sla_deadline, ar.response_received,
                                   ar.response_date, ar.icann_compliant, ar.screenshot_included,
                                   ar.follow_up_required,
                                   ps.multi_api_threat_level, ps.api_confidence_score
                            FROM abuse_reports ar
                            LEFT JOIN phishing_sites ps ON ps.url = ar.site_url
                            {where_sql}
                            ORDER BY ar.report_date DESC NULLS LAST
                            LIMIT :limit OFFSET :offset
                            """),
                        params,
                    ).fetchall()

                items = [
                    {
                        "report_id": r[0],
                        "site_url": r[1],
                        "recipients": parse_recipients(r[2]),
                        "status": r[3],
                        "report_date": iso_utc(r[4]),
                        "sla_deadline": iso_utc(r[5]),
                        "response_received": bool(r[6]),
                        "response_date": iso_utc(r[7]),
                        "icann_compliant": bool(r[8]),
                        "screenshot_included": bool(r[9]),
                        "follow_up_required": bool(r[10]),
                        "threat_level": r[11],
                        "confidence_score": r[12],
                    }
                    for r in rows
                ]

                return jsonify({"items": items, "total": total}), 200

            except Exception as e:
                return internal_error("get_reports", e)

        # ── PATCH /api/v1/reports/<report_id> ─────────────────────────────────
        @self.app.route("/api/v1/reports/<report_id>", methods=["PATCH"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="report")
        def update_report(report_id: str):
            """Update abuse report status."""
            try:
                data = request.get_json() or {}
                new_status = data.get("status")
                if not new_status or new_status not in REPORT_UPDATE_STATUSES:
                    return (
                        jsonify(
                            {
                                "error": "Invalid status. Must be one of: "
                                + ", ".join(sorted(REPORT_UPDATE_STATUSES))
                            }
                        ),
                        400,
                    )

                # abuse_reports.response_received is an INTEGER flag (0/1) in every
                # schema definition (alembic 001, report_tracker), so the CASE
                # branches must both be integers: mixing TRUE with the column makes
                # PostgreSQL reject the statement ("CASE types integer and boolean
                # cannot be matched").
                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text("""
                            UPDATE abuse_reports
                            SET status = :status,
                                response_date = CASE
                                    WHEN :status IN ('resolved', 'acknowledged') THEN NOW()
                                    ELSE response_date
                                END,
                                response_received = CASE
                                    WHEN :status IN ('resolved', 'acknowledged') THEN 1
                                    ELSE response_received
                                END
                            WHERE report_id = :report_id
                        """),
                        {"status": new_status, "report_id": report_id},
                    )
                    if result.rowcount == 0:
                        return jsonify({"error": "Report not found"}), 404

                return jsonify({"report_id": report_id, "status": new_status}), 200

            except Exception as e:
                return internal_error("update_report", e)

        # ── GET /api/v1/reports/tasks ──────────────────────────────────────────
        @self.app.route("/api/v1/reports/tasks", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_report_tasks():
            """List open analyst tasks of the reporting outbox, oldest first.

            A task is an outbox row an analyst must handle: a provider that only
            takes reports through a web form (``channel: "web_form"``, with its
            ``form_url``) or a site without any usable abuse contact
            (``channel: "manual_review"``). ``subject``/``text`` is the report
            to file.

            Returns:
                JSON ``{"items": [...], "total": int, "limit": int, "offset": int}``.
            """
            limit = int_arg(request.args, "limit", default=50, minimum=1, maximum=200)
            offset = _offset_arg()
            try:
                outbox = OutboxRepository(self.db_manager.engine)
                rows = outbox.pending_manual_tasks(limit=limit, offset=offset)
                total = outbox.count_pending_manual_tasks()
                return (
                    jsonify(
                        {
                            "items": [manual_task_json(row) for row in rows],
                            "total": total,
                            "limit": limit,
                            "offset": offset,
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_report_tasks", e)

        # ── POST /api/v1/reports/tasks/<id>/complete ──────────────────────────
        @self.app.route("/api/v1/reports/tasks/<int:task_id>/complete", methods=["POST"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="report")
        def complete_report_task(task_id: int):
            """Close an analyst task.

            Body: ``{"outcome": "submitted" | "not_applicable", "note"?: str}``
            (note at most 1000 characters). ``submitted`` marks the outbox row
            ``sent``; ``not_applicable`` marks it ``failed``. When a report had
            only analyst tasks and the last one is closed, the report leaves
            ``pending_manual``: ``sent`` if any task was submitted, else
            ``failed``.

            Args:
                task_id: Outbox row id (``id`` from GET /api/v1/reports/tasks).

            Returns:
                200 ``{"task": {...}, "report_status": str | null}``; 400 on an
                invalid body; 404 when no task has that id; 409 when it is
                already closed.
            """
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Request body must be a JSON object"}), 400
            raw_outcome = data.get("outcome")
            outcomes = sorted(o.value for o in ManualTaskOutcome)
            if raw_outcome not in outcomes:
                return (
                    jsonify(
                        {
                            "error": "outcome must be one of: " + ", ".join(outcomes),
                            "parameter": "outcome",
                        }
                    ),
                    400,
                )
            note = data.get("note")
            if note is not None and (
                not isinstance(note, str) or len(note) > REPORT_TASK_NOTE_MAX_LENGTH
            ):
                return (
                    jsonify(
                        {
                            "error": "note must be a string of at most "
                            f"{REPORT_TASK_NOTE_MAX_LENGTH} characters",
                            "parameter": "note",
                        }
                    ),
                    400,
                )
            session = current_key_session() or {}
            completed_by = session.get("key_name") or session.get("key_type")
            try:
                outbox = OutboxRepository(self.db_manager.engine)
                tracker = ReportTracker(self.db_manager.engine)
                with short_transaction(self.db_manager.engine) as conn:
                    row, changed = outbox.complete_manual_task(
                        conn,
                        task_id,
                        ManualTaskOutcome(raw_outcome),
                        note=(note or "").strip() or None,
                        completed_by=completed_by,
                    )
                    report_status = (
                        tracker.settle_manual_report(conn, row.report_id)
                        if row is not None and changed
                        else None
                    )
                if row is None:
                    return jsonify({"error": "Task not found"}), 404
                if not changed:
                    return (
                        jsonify({"error": "Task is already closed", "status": row.status}),
                        409,
                    )
                logger.info(f"🗂️ Analyst task {task_id} ({row.report_id}) closed as {raw_outcome}")
                return jsonify({"task": manual_task_json(row), "report_status": report_status}), 200
            except Exception as e:
                return internal_error("complete_report_task", e)

        # ── GET /api/v1/reports/approvals ──────────────────────────────────────
        @self.app.route("/api/v1/reports/approvals", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_report_approvals():
            """List submissions waiting for an analyst decision, oldest request first.

            A site is listed while a ``POST /api/v1/report`` from a key without
            ``report_send`` requested it, nobody flagged it for reporting and no
            label decided it. Approve with ``POST /api/v1/sites/<id>/labels``
            ``{"action": "report"}`` (``report_send``); reject with
            ``{"action": "dismiss"}`` (``write``).

            Returns:
                JSON ``{"items": [...], "total": int, "limit": int, "offset": int}``.
            """
            limit = int_arg(request.args, "limit", default=50, minimum=1, maximum=200)
            offset = _offset_arg()
            try:
                rows, total = LabelRepository(self.db_manager.engine).pending_approvals(
                    limit=limit, offset=offset
                )
                return (
                    jsonify(
                        {
                            "items": [approval_json(row) for row in rows],
                            "total": total,
                            "limit": limit,
                            "offset": offset,
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_report_approvals", e)

        # ── GET /api/v1/reports/stats ──────────────────────────────────────────
        @self.app.route("/api/v1/reports/stats", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_reports_stats():
            """Aggregate stats for the abuse reports pipeline."""
            try:
                with self.db_manager.engine.begin() as conn:
                    total = conn.execute(text("SELECT COUNT(*) FROM abuse_reports")).scalar() or 0

                    status_rows = conn.execute(
                        text("SELECT status, COUNT(*) FROM abuse_reports GROUP BY status")
                    ).fetchall()
                    status_breakdown = {(r[0] or "unknown"): r[1] for r in status_rows}

                    responded = (
                        conn.execute(
                            text("SELECT COUNT(*) FROM abuse_reports WHERE response_received = 1")
                        ).scalar()
                        or 0
                    )

                    overdue = (
                        conn.execute(
                            text(
                                "SELECT COUNT(*) FROM abuse_reports "
                                "WHERE response_received = 0 AND sla_deadline < NOW()"
                            )
                        ).scalar()
                        or 0
                    )

                    avg_row = conn.execute(
                        text(
                            "SELECT AVG(EXTRACT(EPOCH FROM (response_date - report_date)) / 3600) "
                            "FROM abuse_reports WHERE response_received = 1 AND response_date IS NOT NULL"
                        )
                    ).scalar()

                return (
                    jsonify(
                        {
                            "total_reports": total,
                            "status_breakdown": status_breakdown,
                            "response_rate": round(responded / total, 3) if total > 0 else None,
                            "overdue_reports": overdue,
                            "avg_response_time_hours": (
                                round(float(avg_row), 1) if avg_row else None
                            ),
                            "generated_at": iso_utc(datetime.datetime.now(datetime.timezone.utc)),
                        }
                    ),
                    200,
                )

            except Exception as e:
                return internal_error("get_reports_stats", e)

        # ── GET /api/v1/integrations ───────────────────────────────────────────
        @self.app.route("/api/v1/integrations", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_integrations():
            """Return health and circuit-breaker state of all external integrations.

            ``status`` is ``online``/``degraded``/``offline`` only when backed by
            circuit-breaker data of this API process (closed with at least one
            recorded call / half-open / open) and ``unknown`` otherwise: no
            breaker, or a breaker that has not made a call yet. SMTP has no
            breaker and the API does not send e-mail itself, so it is always
            ``unknown``; ``/api/v1/stats`` carries the real delivery state.

            Returns:
                JSON list of :func:`integration_health` entries.
            """
            try:
                mv = self.multi_api_validator
                integrations = [
                    # PhishTank's checkurl endpoint works unauthenticated (a key
                    # only raises the rate limit), so it's always "configured".
                    integration_health(
                        mv.virustotal, "virustotal", "VirusTotal", bool(mv.virustotal.api_key)
                    ),
                    integration_health(mv.urlvoid, "urlvoid", "URLVoid", bool(mv.urlvoid.api_key)),
                    integration_health(mv.phishtank, "phishtank", "PhishTank", True),
                    integration_health(
                        mv.google_safe_browsing,
                        "gsb",
                        "Google Safe Browsing",
                        bool(mv.google_safe_browsing.enabled),
                    ),
                    integration_health(
                        self.grinder_client,
                        "grinder",
                        "Grinder",
                        bool(self.grinder_client.enabled),
                    ),
                    integration_health(
                        None, "smtp", "SMTP (Abuse Reports)", bool(settings.SMTP_HOST)
                    ),
                ]
                return jsonify(integrations), 200

            except Exception as e:
                return internal_error("get_integrations", e)

        # ── GET /api/v1/activity ───────────────────────────────────────────────
        @self.app.route("/api/v1/activity", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_activity():
            """Recent platform activity: new detections, abuse reports and takedowns.

            Up to ``limit`` events of each kind are read (newest first, NULL
            timestamps last, ties by id), merged and trimmed to the ``limit``
            most recent. An event whose timestamp is not recorded keeps
            ``"timestamp": null`` and sorts after every dated event; it is never
            given the current time. ``severity`` of a detection is its stored
            threat level, null when the site has no verdict.

            Returns:
                JSON list of ``{"id", "type", "url", "timestamp", "detail",
                "severity"}``.
            """
            limit = int_arg(request.args, "limit", default=20, maximum=100)
            try:
                params = {"n": limit}
                with self.db_manager.engine.begin() as conn:
                    detections = conn.execute(
                        text(
                            "SELECT id, url, first_seen, multi_api_threat_level, priority "
                            "FROM phishing_sites ORDER BY first_seen DESC NULLS LAST, id DESC "
                            "LIMIT :n"
                        ),
                        params,
                    ).fetchall()
                    reports = conn.execute(
                        text(
                            "SELECT report_id, site_url, report_date, status "
                            "FROM abuse_reports ORDER BY report_date DESC NULLS LAST, id DESC "
                            "LIMIT :n"
                        ),
                        params,
                    ).fetchall()
                    takedowns = conn.execute(
                        text(
                            "SELECT id, url, takedown_date "
                            "FROM phishing_sites "
                            "WHERE site_status = 'down' AND takedown_date IS NOT NULL "
                            "ORDER BY takedown_date DESC, id DESC LIMIT :n"
                        ),
                        params,
                    ).fetchall()

                events: List[Tuple[Optional[datetime.datetime], Dict[str, Any]]] = []
                for r in detections:
                    events.append(
                        (
                            as_utc(r[2]),
                            {
                                "id": f"det-{r[0]}",
                                "type": "detection",
                                "url": r[1],
                                "detail": (
                                    "New phishing site detected — priority: " f"{r[4] or 'unknown'}"
                                ),
                                "severity": threat_level_or_none(r[3]),
                            },
                        )
                    )
                for r in reports:
                    events.append(
                        (
                            as_utc(r[2]),
                            {
                                "id": f"rpt-{r[0]}",
                                "type": "report",
                                "url": r[1],
                                "detail": f"Abuse report {r[0]} — status: {r[3] or 'unknown'}",
                                "severity": "info",
                            },
                        )
                    )
                for r in takedowns:
                    events.append(
                        (
                            as_utc(r[2]),
                            {
                                "id": f"td-{r[0]}",
                                "type": "takedown",
                                "url": r[1],
                                "detail": "Site confirmed offline / takedown successful",
                                "severity": "info",
                            },
                        )
                    )

                # Newest first, undated events last; ties keep id order (stable
                # sorts), so the order and what the limit cuts off are deterministic.
                events.sort(key=lambda e: e[1]["id"])
                dated: List[Tuple[datetime.datetime, Dict[str, Any]]] = [
                    (ts, item) for ts, item in events if ts is not None
                ]
                dated.sort(key=lambda e: e[0], reverse=True)
                activity = [{**item, "timestamp": iso_utc(ts)} for ts, item in dated]
                activity += [{**item, "timestamp": None} for ts, item in events if ts is None]
                activity = activity[:limit]
                return jsonify(activity), 200

            except Exception as e:
                return internal_error("get_activity", e)

        # ── GET /api/v1/nav/counts ─────────────────────────────────────────────
        @self.app.route("/api/v1/nav/counts", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_nav_counts():
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(text("""
                        SELECT
                            (SELECT COUNT(*) FROM phishing_sites
                             WHERE site_status = 'up'
                               AND COALESCE(label_verdict, '') <> 'benign') AS threats,
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'running') AS threads,
                            (SELECT COUNT(DISTINCT registrar_name) FROM phishing_sites
                             WHERE registrar_name IS NOT NULL AND site_status = 'up'
                               AND COALESCE(label_verdict, '') <> 'benign'
                               AND registrar_name IN (
                                 SELECT registrar_name FROM phishing_sites
                                 WHERE registrar_name IS NOT NULL
                                 GROUP BY registrar_name HAVING COUNT(*) >= 2
                             )) AS campaigns
                    """)).fetchone()
                return (
                    jsonify(
                        {
                            "threats": int(row[0] or 0),
                            "threads": int(row[1] or 0),
                            "campaigns": int(row[2] or 0),
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_nav_counts", e)

        # ── GET /api/v1/threads ────────────────────────────────────────────────
        @self.app.route("/api/v1/threads", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_threads():
            """List analysis threads with their result counters.

            ``results_count`` is the number of results the console shows for
            the thread right now (not discarded, not from a whitelisted sender,
            the own Workspace domain or Google) and always equals the ``total``
            of ``GET /api/v1/threads/<id>/results``. ``total_results`` is every
            result ever recorded for the thread, including discarded and
            filtered ones. ``last_execution_results`` is how many results the
            most recent completed execution recorded (``thread_executions.
            results_count``), null when the thread has no completed execution
            (CT and feed monitors do not record executions). Timestamps are
            ISO-8601 with an explicit UTC offset.

            Returns:
                JSON ``{"items": [...], "total": int}``.
            """
            try:
                with self.db_manager.engine.begin() as conn:
                    own_domain = (getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None) or "").lower()
                    rows = conn.execute(
                        text(f"""
                        SELECT t.id, t.thread_type, t.label, t.status, t.started_at,
                               t.completed_at, t.details, t.error_message,
                               t.search_interval_hours, t.last_searched_at,
                               (SELECT COUNT(*) {VISIBLE_THREAD_RESULTS_SQL}
                                AND tr.thread_id = t.id) AS visible_results,
                               (SELECT COUNT(*) FROM thread_results tr
                                WHERE tr.thread_id = t.id) AS recorded_results,
                               (SELECT te.results_count FROM thread_executions te
                                WHERE te.thread_id = t.id AND te.status = 'completed'
                                ORDER BY te.completed_at DESC NULLS LAST, te.id DESC
                                LIMIT 1) AS last_execution_results
                        FROM analysis_threads t
                        ORDER BY t.started_at DESC NULLS LAST, t.id DESC
                    """),
                        {"own_domain": own_domain},
                    ).fetchall()
                items = []
                for r in rows:
                    db_status = r[3]
                    if db_status == "error":
                        effective_status = "error"
                    elif db_status in ("idle", "completed", "paused"):
                        effective_status = db_status
                    else:
                        # active / running → always show as running (continuous monitor)
                        effective_status = "running"
                    items.append(
                        {
                            "id": r[0],
                            "thread_type": r[1],
                            "label": r[2],
                            "status": effective_status,
                            "started_at": iso_utc(r[4]),
                            "completed_at": iso_utc(r[5]),
                            "results_count": int(r[10] or 0),
                            "details": r[6],
                            "error_message": r[7],
                            "search_interval_hours": r[8],
                            "last_searched_at": iso_utc(r[9]),
                            "total_results": int(r[11] or 0),
                            "last_execution_results": None if r[12] is None else int(r[12]),
                        }
                    )
                return jsonify({"items": items, "total": len(items)}), 200
            except Exception as e:
                return internal_error("get_threads", e)

        # ── GET /api/v1/threads/stats ──────────────────────────────────────────
        @self.app.route("/api/v1/threads/stats", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_threads_stats():
            try:
                with self.db_manager.engine.begin() as conn:
                    own_domain = (getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None) or "").lower()
                    row = conn.execute(
                        text("""
                        SELECT
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'active'),
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'idle'),
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'error'),
                            (SELECT COUNT(*) FROM thread_results tr
                             LEFT JOIN email_sender_reputation esr
                                 ON tr.result_type = 'email_threat'
                                 AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                             WHERE tr.first_detected_at >= CURRENT_DATE
                             AND tr.status != 'discarded'
                             AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                             AND (:own_domain = '' OR tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                             AND (tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com'))),
                            (SELECT COUNT(*) FROM thread_results tr
                             LEFT JOIN email_sender_reputation esr
                                 ON tr.result_type = 'email_threat'
                                 AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                             WHERE (tr.status = 'threat' OR tr.result_type = 'email_threat')
                             AND tr.status != 'discarded'
                             AND tr.first_detected_at >= CURRENT_DATE
                             AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                             AND (:own_domain = '' OR tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                             AND (tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com')))
                    """),
                        {"own_domain": own_domain},
                    ).fetchone()
                return (
                    jsonify(
                        {
                            "running": int(row[0] or 0),
                            "idle": int(row[1] or 0),
                            "error": int(row[2] or 0),
                            "scanned_today": int(row[3] or 0),
                            "threats_today": int(row[4] or 0),
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_threads_stats", e)

        # ── GET /api/v1/threads/<id>/results ──────────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/results", methods=["GET"])
        @self.limiter.limit("30 per minute", key_func=thread_rate_limit_key)
        @self.limiter.limit("120 per minute")
        @require_api_key(scope="read")
        def get_thread_results(thread_id: int):
            """Page through the results the console shows for a thread.

            Same visibility rules as ``results_count`` of ``GET /api/v1/threads``
            (see ``VISIBLE_THREAD_RESULTS_SQL``); newest first, stable across
            pages. Timestamps are ISO-8601 with an explicit UTC offset.

            Args:
                thread_id: ``analysis_threads.id``.

            Returns:
                JSON ``{"items": [...], "total": int}``.
            """
            limit = int_arg(request.args, "limit", default=50, maximum=1000)
            offset = _offset_arg()
            try:
                own_domain = (getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None) or "").lower()
                params = {"tid": thread_id, "lim": limit, "off": offset, "own_domain": own_domain}
                with self.db_manager.engine.begin() as conn:
                    total = (
                        conn.execute(
                            text(
                                f"SELECT COUNT(*) {VISIBLE_THREAD_RESULTS_SQL} "
                                "AND tr.thread_id = :tid"
                            ),
                            params,
                        ).scalar()
                        or 0
                    )
                    rows = conn.execute(
                        text(f"""
                        SELECT tr.id, tr.result_type, tr.found_url, tr.title, tr.confidence,
                               tr.source, tr.first_detected_at, tr.last_detected_at,
                               tr.status, tr.details, tr.extra_data
                        {VISIBLE_THREAD_RESULTS_SQL}
                        AND tr.thread_id = :tid
                        ORDER BY tr.last_detected_at DESC, tr.id DESC LIMIT :lim OFFSET :off
                    """),
                        params,
                    ).fetchall()
                items = [
                    {
                        "id": r[0],
                        "result_type": r[1],
                        "found_url": r[2],
                        "title": r[3],
                        "confidence": r[4],
                        "source": r[5],
                        "first_detected_at": iso_utc(r[6]),
                        "last_detected_at": iso_utc(r[7]),
                        "status": r[8],
                        "details": r[9],
                        "extra_data": r[10],
                    }
                    for r in rows
                ]
                return jsonify({"items": items, "total": int(total)}), 200
            except Exception as e:
                return internal_error("get_thread_results", e)

        # ── PATCH /api/v1/threads/<id>/results/<result_id>/discard ────────────
        @self.app.route(
            "/api/v1/threads/<int:thread_id>/results/<int:result_id>/discard", methods=["PATCH"]
        )
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def discard_thread_result(thread_id: int, result_id: int):
            try:
                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text(
                            "UPDATE thread_results SET status = 'discarded' WHERE id = :rid AND thread_id = :tid"
                        ),
                        {"rid": result_id, "tid": thread_id},
                    )
                    if result.rowcount == 0:
                        return jsonify({"error": "Thread result not found"}), 404
                return jsonify({"discarded": result_id}), 200
            except Exception as e:
                return internal_error("discard_thread_result", e)

        # ── GET /api/v1/campaigns ──────────────────────────────────────────────
        @self.app.route("/api/v1/campaigns", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_campaigns():
            """Registrar-based campaign clusters with their most recent threats.

            A single aggregate query returns one page of clusters (registrars
            with at least two sites) together with each cluster's 20 most
            recent sites, the total number of clusters and the KPIs over all
            clusters, instead of one extra query per cluster.

            Query params: ``limit`` (1-500, default 100) and ``offset``.

            A cluster is ``active`` when it has live sites and activity in the
            last 24 hours, ``monitoring`` when it has live sites without recent
            activity, ``closed`` otherwise. ``confidence`` is the rounded mean
            stored ``api_confidence_score`` of its sites, null when none was
            scored. Timestamps are ISO-8601 with an explicit UTC offset.

            Returns:
                JSON ``{"items": [...], "total": int, "limit": int, "offset": int,
                "kpi": {...}}``; ``total`` and ``kpi`` cover every cluster, not
                just the page. Each item's ``id`` is stable across calls
                (derived from the registrar name).
            """
            limit = int_arg(request.args, "limit", default=100, minimum=1, maximum=500)
            offset = _offset_arg()
            # Same clock as before: naive UTC, compared with naive DB timestamps.
            stale_before = datetime.datetime.now(datetime.UTC).replace(
                tzinfo=None
            ) - datetime.timedelta(days=1)
            try:
                with self.db_manager.engine.begin() as conn:
                    rows = conn.execute(
                        text("""
                        WITH clusters AS (
                            SELECT registrar_name,
                                   COUNT(*) AS site_count,
                                   COUNT(*) FILTER (WHERE site_status = 'up') AS active_count,
                                   COUNT(*) FILTER (WHERE site_status = 'down') AS takedown_count,
                                   MIN(first_seen) AS first_seen,
                                   MAX(last_seen) AS last_activity,
                                   array_agg(DISTINCT resolved_ip)
                                       FILTER (WHERE resolved_ip IS NOT NULL) AS ips,
                                   AVG(api_confidence_score)
                                       FILTER (WHERE api_confidence_score IS NOT NULL)
                                       AS avg_confidence
                            FROM phishing_sites
                            WHERE registrar_name IS NOT NULL
                            GROUP BY registrar_name
                            HAVING COUNT(*) >= 2
                        ),
                        classified AS (
                            SELECT c.*,
                                   CASE
                                       WHEN c.active_count > 0
                                            AND c.last_activity >= :stale_before
                                           THEN 'active'
                                       WHEN c.active_count > 0 THEN 'monitoring'
                                       ELSE 'closed'
                                   END AS status
                            FROM clusters c
                        ),
                        totals AS (
                            SELECT COUNT(*) AS total,
                                   COUNT(*) FILTER (WHERE status = 'active') AS active,
                                   COUNT(*) FILTER (WHERE status = 'monitoring') AS monitoring,
                                   COUNT(*) FILTER (WHERE status = 'closed') AS closed,
                                   COALESCE(SUM(site_count), 0) AS total_sites,
                                   COALESCE(SUM(takedown_count), 0) AS total_takedowns
                            FROM classified
                        ),
                        page AS (
                            SELECT * FROM classified
                            ORDER BY active_count DESC, last_activity DESC NULLS LAST,
                                     registrar_name
                            LIMIT :lim OFFSET :off
                        ),
                        ranked AS (
                            SELECT ps.registrar_name, ps.url, ps.site_status,
                                   ps.first_seen, ps.multi_api_threat_level,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY ps.registrar_name
                                       ORDER BY ps.first_seen DESC NULLS LAST, ps.id DESC
                                   ) AS rn
                            FROM phishing_sites ps
                            JOIN page p ON p.registrar_name = ps.registrar_name
                        ),
                        recent AS (
                            SELECT registrar_name,
                                   json_agg(
                                       json_build_object(
                                           'url', url,
                                           'status', site_status,
                                           'first_seen', first_seen::text,
                                           'threat_level', multi_api_threat_level
                                       )
                                       ORDER BY rn
                                   ) AS threats
                            FROM ranked
                            WHERE rn <= 20
                            GROUP BY registrar_name
                        )
                        SELECT p.registrar_name, p.site_count, p.status,
                               p.takedown_count, p.first_seen, p.last_activity,
                               p.ips, p.avg_confidence,
                               COALESCE(r.threats, '[]'::json) AS threats,
                               t.total, t.active, t.monitoring, t.closed,
                               t.total_sites, t.total_takedowns
                        FROM totals t
                        LEFT JOIN page p ON TRUE
                        LEFT JOIN recent r ON r.registrar_name = p.registrar_name
                        ORDER BY p.active_count DESC, p.last_activity DESC NULLS LAST,
                                 p.registrar_name
                    """),
                        {"stale_before": stale_before, "lim": limit, "off": offset},
                    ).fetchall()

                items = []
                for row in rows:
                    if row[0] is None:  # no cluster on this page: totals only
                        continue
                    threats = row[8]
                    if isinstance(threats, str):
                        threats = json.loads(threats)
                    for threat in threats or []:
                        if isinstance(threat, dict) and "first_seen" in threat:
                            threat["first_seen"] = iso_utc(threat["first_seen"])
                    items.append(
                        {
                            "id": campaign_id("registrar", row[0]),
                            "name": f"{row[0]} cluster",
                            "registrar": row[0],
                            "status": row[2],
                            "sites": int(row[1] or 0),
                            "takedowns": int(row[3] or 0),
                            "first_seen": iso_utc(row[4]),
                            "last_activity": iso_utc(row[5]),
                            "confidence": round(float(row[7])) if row[7] is not None else None,
                            "resolved_ips": list(row[6]) if row[6] else [],
                            "threats": threats or [],
                        }
                    )

                first = rows[0] if rows else None
                kpi = {
                    "active": int(first[10] or 0) if first else 0,
                    "monitoring": int(first[11] or 0) if first else 0,
                    "closed": int(first[12] or 0) if first else 0,
                    "total_sites": int(first[13] or 0) if first else 0,
                    "total_takedowns": int(first[14] or 0) if first else 0,
                }
                total = int(first[9] or 0) if first else 0
                return (
                    jsonify(
                        {
                            "items": items,
                            "total": total,
                            "limit": limit,
                            "offset": offset,
                            "kpi": kpi,
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_campaigns", e)

        # ── GET /api/v1/intelligence/iocs ──────────────────────────────────────
        @self.app.route("/api/v1/intelligence/iocs", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_iocs():
            """List indicators of compromise derived from tracked phishing sites.

            Query params: ``type`` (domain | ip | email), ``limit``, ``offset``,
            ``search`` (case-insensitive substring of the value, at most 200
            characters) and ``threat`` (a stored threat level: critical, high,
            medium, low, clean or unknown).

            Domain items are one row per (host, stored threat level, source);
            their ``threat`` is that stored level. IP items aggregate every site
            resolving to the address; their ``threat`` is the severest stored
            level among those sites (``unknown`` only when nothing else is
            known, null when no site was analysed) and ``tags`` is
            ``["cloudflare"]``/``["direct"]`` from ``is_cloudflare``, or empty
            when that was never recorded. ``threat`` filters on the item's
            ``threat``. Registrar/hosting abuse-desk mailboxes are reporting
            contacts, not indicators, so ``type=email`` never exposes them.

            Returns:
                JSON ``{"items": [...], "total": int, "counts": {...}}``;
                ``total`` counts every item matching the filters (all pages),
                ``counts`` the distinct domains/IPs tracked (unfiltered).
            """
            ioc_type = enum_arg(request.args, "type", IOC_TYPES, default="domain")
            limit = int_arg(request.args, "limit", default=100, maximum=500)
            offset = _offset_arg()
            search = str_arg(request.args, "search", max_length=IOC_SEARCH_MAX_LENGTH)
            threat = enum_arg(request.args, "threat", STORED_THREAT_LEVELS)
            try:
                params: Dict[str, Any] = {"lim": limit, "off": offset}
                if search:
                    params["search"] = search.lower()
                if threat:
                    params["threat"] = threat
                items: List[Dict[str, Any]] = []
                total = 0
                with self.db_manager.engine.begin() as conn:
                    if ioc_type in ("ip", "domain"):
                        cte = _ioc_query(ioc_type, search=bool(search), threat=bool(threat))
                        rows = conn.execute(
                            text(f"""
                                {cte}
                                SELECT *, COUNT(*) OVER () AS total FROM iocs
                                ORDER BY {IOC_ORDER_BY[ioc_type]}
                                LIMIT :lim OFFSET :off
                            """),
                            params,
                        ).fetchall()
                        if rows:
                            total = int(rows[0][-1])
                        elif offset:
                            total = int(
                                conn.execute(
                                    text(f"{cte} SELECT COUNT(*) FROM iocs"), params
                                ).scalar()
                                or 0
                            )
                        items = [
                            _ioc_item(ioc_type, row, offset + i + 1) for i, row in enumerate(rows)
                        ]
                    # type=email: phishing_sites.all_abuse_emails holds the
                    # registrar/hosting abuse desks we report *to*; they are
                    # contacts, not indicators, and must never be shared as IOCs.
                    # No source of malicious e-mail indicators exists yet.

                    counts_row = conn.execute(text(f"""
                        SELECT COUNT(DISTINCT NULLIF({IOC_DOMAIN_SQL}, '')),
                               COUNT(DISTINCT NULLIF(resolved_ip, ''))
                        FROM phishing_sites
                    """)).fetchone()

                return (
                    jsonify(
                        {
                            "items": items,
                            "total": total,
                            "counts": {
                                "domain": int(counts_row[0] or 0),
                                "ip": int(counts_row[1] or 0),
                                "email": 0,
                            },
                        }
                    ),
                    200,
                )
            except Exception as e:
                return internal_error("get_iocs", e)

        # ── GET /api/v1/graph ──────────────────────────────────────────────────
        @self.app.route("/api/v1/graph", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_graph():
            """Relationship graph built from real phishing sites.

            Nodes: domain, ip, registrar, kit (derived from phishing_sites).
            Edges: domain --resolves_to--> ip, domain --registered_with--> registrar,
                   domain --detected_as--> kit.

            Query params:
              limit (<=500, default 200) — cap on source rows.
              focus  (optional) — "domain:foo.com" / "ip:1.2.3.4" /
                                  "registrar:Name" / "kit:evilginx" restricts
                                  to the 1-hop neighborhood of that node. Type
                                  and value match case-insensitively and the
                                  filter is applied in SQL before the limit;
                                  a malformed focus returns 400.

            A source row is one distinct (domain, IP, registrar, threat level,
            kit) combination of ``phishing_sites``. ``meta.total_rows`` is the
            number of such rows matching the query before ``LIMIT`` (same
            query, window count) and ``meta.limited`` is true when it exceeds
            the rows returned. See :func:`build_graph` for node and edge fields.

            Returns:
                JSON ``{"nodes": [...], "edges": [...], "meta": {...}}``.
            """
            limit = int_arg(request.args, "limit", default=200, minimum=1, maximum=500)
            try:
                focus = parse_graph_focus(request.args.get("focus"))
            except ValueError as exc:
                raise InvalidParameterError("focus", str(exc)) from None
            try:

                # The focus filter runs in SQL, before LIMIT, so a focused node
                # is found even when it is not among the most recent rows.
                params: Dict[str, Any] = {"lim": limit}
                focus_sql = ""
                if focus:
                    focus_sql = f"AND {GRAPH_FOCUS_SQL[focus[0]]} = :focus_value"
                    params["focus_value"] = focus[1]

                with self.db_manager.engine.begin() as conn:
                    rows = conn.execute(
                        text(f"""
                            SELECT
                                SPLIT_PART(SPLIT_PART(url, '://', 2), '/', 1) AS domain,
                                resolved_ip,
                                registrar_name,
                                multi_api_threat_level,
                                AVG(api_confidence_score) AS avg_conf,
                                bool_or(is_cloudflare = 1) AS cloudflare,
                                MIN(first_seen) AS first_seen,
                                MAX(last_seen) AS last_seen,
                                COUNT(*) AS hits,
                                detected_kit_type,
                                MAX(kit_confidence) AS kit_conf,
                                COUNT(*) OVER () AS total_rows
                            FROM phishing_sites
                            WHERE url IS NOT NULL
                              AND SPLIT_PART(SPLIT_PART(url, '://', 2), '/', 1) <> ''
                              {focus_sql}
                            GROUP BY domain, resolved_ip, registrar_name,
                                     multi_api_threat_level, detected_kit_type
                            ORDER BY MAX(last_seen) DESC NULLS LAST, domain,
                                     resolved_ip NULLS LAST, registrar_name NULLS LAST,
                                     multi_api_threat_level NULLS LAST,
                                     detected_kit_type NULLS LAST
                            LIMIT :lim
                        """),
                        params,
                    ).fetchall()

                graph = build_graph(rows, focus)
                total_rows = int(rows[0][11] or 0) if rows else 0
                graph["meta"].update(
                    {
                        "total_rows": total_rows,
                        "limit": limit,
                        "limited": total_rows > len(rows),
                    }
                )
                return jsonify(graph), 200
            except Exception as e:
                return internal_error("get_graph", e)

        # ── GET /api/v1/intelligence/brands ───────────────────────────────────
        @self.app.route("/api/v1/intelligence/brands", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_brands():
            try:
                keywords = [k.strip() for k in settings.KEYWORDS.split(",") if k.strip()]
                results = []
                with self.db_manager.engine.begin() as conn:
                    for kw in keywords:
                        pat = f"%{kw}%"
                        total = (
                            conn.execute(
                                text("SELECT COUNT(*) FROM phishing_sites WHERE url ILIKE :p"),
                                {"p": pat},
                            ).scalar()
                            or 0
                        )
                        if total == 0:
                            continue
                        active = (
                            conn.execute(
                                text(
                                    "SELECT COUNT(*) FROM phishing_sites "
                                    "WHERE url ILIKE :p AND site_status = 'up'"
                                ),
                                {"p": pat},
                            ).scalar()
                            or 0
                        )
                        results.append(
                            {
                                "name": kw.capitalize(),
                                "sites": int(total),
                                "active": int(active),
                            }
                        )
                results.sort(key=lambda x: x["sites"], reverse=True)
                return jsonify(results), 200
            except Exception as e:
                return internal_error("get_brands", e)

        # ── POST /api/v1/intelligence/stix/validate ───────────────────────────
        @self.app.route("/api/v1/intelligence/stix/validate", methods=["POST"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def validate_stix():
            from src.intelligence.stix_export import validate_stix_bundle

            data = request.get_json(silent=True) or {}
            bundle = data.get("bundle")
            if not bundle:
                return jsonify({"error": "bundle required"}), 400
            try:
                valid, errors = validate_stix_bundle(bundle)
                return jsonify({"valid": valid, "errors": errors}), 200
            except Exception as e:
                return internal_error("validate_stix", e)

        # ── POST /api/v2/stix/bundle ──────────────────────────────────────────
        @self.app.route("/api/v2/stix/bundle", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="read")
        def build_stix_bundle():
            """Build a STIX 2.1 indicator bundle marked with TLP 2.0.

            Body: ``{"indicators": [{"type", "value", "first_seen"?, "labels"?,
            "description"?}], "tlp"?, "confidence"?, "name"?}`` with ``type`` in
            domain | url | ipv4 | ipv6 | email-addr (max 5000), ``tlp`` in clear |
            green | amber | amber+strict | red (default amber) and ``confidence``
            0-100 (default 50).

            Returns:
                200 ``{"bundle": {...}}``; 400 ``{"error", "details": [{"index",
                "error"}]}`` on invalid input; 413 when the body is too large.
            """
            from src.intelligence.stix_export import (
                BundleRequestError,
                build_indicator_bundle,
                validate_bundle_request,
            )

            if (request.content_length or 0) > STIX_BUNDLE_MAX_BODY_BYTES:
                return jsonify({"error": "Request body too large"}), 413
            try:
                spec = validate_bundle_request(request.get_json(silent=True))
            except BundleRequestError as exc:
                body: Dict[str, Any] = {"error": stix_request_error_message(exc)}
                if exc.details:
                    body["details"] = exc.details[:STIX_BUNDLE_MAX_ERRORS]
                return jsonify(body), 400
            try:
                bundle = build_indicator_bundle(
                    spec["indicators"],
                    tlp=spec["tlp"],
                    confidence=spec["confidence"],
                    name=spec["name"],
                )
            except STIXError as e:
                return internal_error("build_stix_bundle", e)
            return jsonify({"bundle": bundle}), 200

        # ── POST /api/v1/intelligence/taxii/push ──────────────────────────────
        @self.app.route("/api/v1/intelligence/taxii/push", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="report")
        def push_taxii():
            if not getattr(settings, "TAXII_BASE_URL", None):
                return jsonify({"error": "TAXII not configured"}), 503

            from src.intelligence.stix_export import (
                TLP_MARKING_IDS,
                add_tlp_marking,
                validate_stix_bundle,
            )
            from src.intelligence.taxii_client import TAXIIClient

            data = request.get_json(silent=True) or {}
            bundle = data.get("bundle")
            if not bundle:
                return jsonify({"error": "bundle required"}), 400
            api_root = data.get("api_root") or getattr(settings, "TAXII_DEFAULT_API_ROOT", None)
            collection_id = data.get("collection_id") or getattr(
                settings, "TAXII_DEFAULT_COLLECTION_ID", None
            )
            if not api_root or not collection_id:
                return jsonify({"error": "api_root and collection_id required"}), 400

            tlp = data.get("tlp")
            if tlp is not None and str(tlp).lower() not in TLP_MARKING_IDS:
                return (
                    jsonify({"error": f"tlp must be one of: {', '.join(sorted(TLP_MARKING_IDS))}"}),
                    400,
                )
            try:
                if tlp:
                    bundle = add_tlp_marking(bundle, str(tlp))
                valid, errors = validate_stix_bundle(bundle)
                if not valid:
                    return jsonify({"error": "Invalid STIX bundle", "details": errors}), 400

                client = TAXIIClient()
                result = client.push_objects(api_root, collection_id, bundle["objects"])
                return jsonify(result), 200
            except Exception as e:
                return internal_error("push_taxii", e)

        # ── GET /api/v1/intelligence/taxii/pull ───────────────────────────────
        @self.app.route("/api/v1/intelligence/taxii/pull", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def pull_taxii():
            if not getattr(settings, "TAXII_BASE_URL", None):
                return jsonify({"error": "TAXII not configured"}), 503

            from src.intelligence.taxii_client import TAXIIClient

            api_root = request.args.get("api_root") or getattr(
                settings, "TAXII_DEFAULT_API_ROOT", None
            )
            collection_id = request.args.get("collection_id") or getattr(
                settings, "TAXII_DEFAULT_COLLECTION_ID", None
            )
            if not api_root or not collection_id:
                return jsonify({"error": "api_root and collection_id required"}), 400

            try:
                client = TAXIIClient()
                objects = client.pull_objects(api_root, collection_id)
                return jsonify({"objects": objects}), 200
            except Exception as e:
                return internal_error("pull_taxii", e)

        # ── POST /api/v1/intelligence/misp/push ───────────────────────────────
        @self.app.route("/api/v1/intelligence/misp/push", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="report")
        def push_misp():
            if not getattr(settings, "MISP_URL", None):
                return jsonify({"error": "MISP not configured"}), 503

            from src.intelligence.misp_client import MISPClient

            data = request.get_json(silent=True) or {}
            indicators = data.get("indicators")
            event_info = data.get("event_info")
            if not indicators or not event_info:
                return jsonify({"error": "indicators and event_info required"}), 400

            try:
                client = MISPClient()
                result = client.push_indicators(indicators, event_info)
                if result is None:
                    return jsonify({"error": "MISP push failed"}), 502
                return jsonify(result), 200
            except Exception as e:
                return internal_error("push_misp", e)

        # ── POST /api/v1/threads/image-tracking ───────────────────────────────
        @self.app.route("/api/v1/threads/image-tracking", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="write")
        def create_image_tracking_thread():
            data = request.get_json(silent=True) or {}
            label = data.get("label")
            s3_key = data.get("s3_key")
            search_interval_hours = data.get("search_interval_hours")
            if not s3_key:
                return jsonify({"error": "s3_key is required"}), 400
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads "
                            "(thread_type, label, status, image_s3_key, search_interval_hours) "
                            "VALUES ('image_tracking', :label, 'active', :s3_key, :interval) "
                            "RETURNING id"
                        ),
                        {"label": label, "s3_key": s3_key, "interval": search_interval_hours},
                    ).fetchone()
                    thread_id = row[0]
                if self.scheduler and self.scheduler.client:
                    threading.Thread(
                        target=self._trigger_image_search,
                        args=(thread_id, s3_key),
                        daemon=True,
                    ).start()
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                return internal_error("create_image_tracking_thread", e)

        # ── POST /api/v1/threads/google-ads ───────────────────────────────────
        @self.app.route("/api/v1/threads/google-ads", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="write")
        def create_google_ads_thread():
            data = request.get_json(silent=True) or {}
            label = data.get("label")
            keyword = data.get("keyword")
            location = data.get("location")
            if not keyword or not location:
                return jsonify({"error": "keyword and location are required"}), 400
            details = {
                "keyword": keyword,
                "location": location,
                "country_code": data.get("country_code", "us"),
                "language": data.get("language", "en"),
            }
            search_interval_hours = data.get("search_interval_hours")
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads "
                            "(thread_type, label, status, details, search_interval_hours) "
                            "VALUES ('google_ads', :label, 'active', :details::jsonb, :interval) "
                            "RETURNING id"
                        ),
                        {
                            "label": label,
                            "details": json.dumps(details),
                            "interval": search_interval_hours,
                        },
                    ).fetchone()
                    thread_id = row[0]
                if self.scheduler and self.scheduler.ads_client:
                    threading.Thread(
                        target=self._trigger_ads_search,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                return internal_error("create_google_ads_thread", e)

        # ── POST /api/v1/threads/ct-monitor ───────────────────────────────────
        @self.app.route("/api/v1/threads/ct-monitor", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="write")
        def create_ct_monitor_thread():
            # ct_monitor is a global singleton (one continuous CT-log stream,
            # not a per-user config like the other 3 thread types) -- this
            # route mostly exists for manual/API bootstrap convenience and UI
            # consistency with the other create-routes. In practice
            # CTMonitorJob.start() already bootstraps this row at server
            # startup when CT_MONITOR_ENABLED is set, so this usually just
            # confirms the existing row (idempotent, matching that bootstrap).
            data = request.get_json(silent=True) or {}
            label = data.get("label", "Certificate Transparency Monitor")
            try:
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text(
                            "SELECT id FROM analysis_threads WHERE thread_type = 'ct_monitor' LIMIT 1"
                        )
                    ).fetchone()
                    if existing:
                        return (
                            jsonify({"id": existing[0], "status": "active", "existing": True}),
                            200,
                        )
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads (thread_type, label, status) "
                            "VALUES ('ct_monitor', :label, 'active') RETURNING id"
                        ),
                        {"label": label},
                    ).fetchone()
                    thread_id = row[0]
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                return internal_error("create_ct_monitor_thread", e)

        # ── POST /api/v1/threads/<id>/search ──────────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/search", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope=("write", "email_admin"))
        def trigger_thread_search(thread_id: int):
            """Trigger an on-demand search/scan for a thread.

            E-mail monitor threads read a mailbox through domain-wide delegation,
            so they need the ``email_admin`` scope and an allowlisted mailbox;
            every other thread type needs ``write``.

            Args:
                thread_id: Thread to search for.

            Returns:
                202 when triggered; 403/404/400/503 otherwise.
            """
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "SELECT thread_type, image_s3_key, details FROM analysis_threads "
                            "WHERE id = :id"
                        ),
                        {"id": thread_id},
                    ).fetchone()
                if not row:
                    return jsonify({"error": "Thread not found"}), 404
                thread_type, s3_key, details = row[0], row[1], row[2]
                denied = _thread_access_denied(thread_type, details)
                if denied is not None:
                    return denied
                if thread_type == "image_tracking":
                    if not self.scheduler:
                        return (
                            jsonify(
                                {"error": "Scheduler not available (SERPAPI_KEY not configured)"}
                            ),
                            503,
                        )
                    if not self.scheduler.client:
                        return jsonify({"error": "Image search client not available"}), 503
                    threading.Thread(
                        target=self._trigger_image_search,
                        args=(thread_id, s3_key),
                        daemon=True,
                    ).start()
                elif thread_type == "google_ads":
                    if not self.scheduler:
                        return (
                            jsonify(
                                {"error": "Scheduler not available (SERPAPI_KEY not configured)"}
                            ),
                            503,
                        )
                    if not self.scheduler.ads_client:
                        return jsonify({"error": "Ads search client not available"}), 503
                    threading.Thread(
                        target=self._trigger_ads_search,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                elif thread_type == "email_monitor":
                    if not self.email_scheduler:
                        return jsonify({"error": "Email monitoring not configured"}), 503
                    threading.Thread(
                        target=self._trigger_email_scan,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                elif thread_type == "ct_monitor":
                    return (
                        jsonify(
                            {
                                "error": "ct_monitor is a continuous background stream; "
                                "there is no on-demand search trigger"
                            }
                        ),
                        400,
                    )
                else:
                    return (
                        jsonify(
                            {
                                "error": f"Manual search not supported for thread_type '{thread_type}'"
                            }
                        ),
                        400,
                    )
                return jsonify({"status": "search_triggered", "thread_id": thread_id}), 202
            except Exception as e:
                return internal_error("trigger_thread_search", e)

        # ── PATCH /api/v1/threads/<id> ─────────────────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope=("write", "email_admin"))
        def update_thread(thread_id: int):
            """Update a thread's label, status or search interval.

            E-mail monitor threads need ``email_admin`` (and an allowlisted
            mailbox); every other thread type needs ``write``.

            Args:
                thread_id: Thread to update.

            Returns:
                200 when updated; 400/403/404 otherwise.
            """
            data = request.get_json(silent=True) or {}
            allowed = {"label": str, "status": str, "search_interval_hours": int}
            updates: List[str] = []
            params: Dict[str, Any] = {"id": thread_id}
            for field, cast in allowed.items():
                if field in data:
                    updates.append(f"{field} = :{field}")
                    try:
                        params[field] = cast(data[field]) if data[field] is not None else None
                    except (TypeError, ValueError):
                        return jsonify({"error": f"'{field}' must be of type {cast.__name__}"}), 400
            if not updates:
                return jsonify({"error": "No valid fields to update"}), 400
            try:
                with self.db_manager.engine.begin() as conn:
                    thread = conn.execute(
                        text("SELECT thread_type, details FROM analysis_threads WHERE id = :id"),
                        {"id": thread_id},
                    ).fetchone()
                    if not thread:
                        return jsonify({"error": "Thread not found"}), 404
                    denied = _thread_access_denied(thread[0], thread[1])
                    if denied is not None:
                        return denied
                    result = conn.execute(
                        text(f"UPDATE analysis_threads SET {', '.join(updates)} WHERE id = :id"),
                        params,
                    )
                    if result.rowcount == 0:
                        return jsonify({"error": "Thread not found"}), 404
                return jsonify({"status": "updated"}), 200
            except Exception as e:
                return internal_error("update_thread", e)

        # ── PATCH /api/v1/threads/<id>/results/<rid> ──────────────────────────
        @self.app.route(
            "/api/v1/threads/<int:thread_id>/results/<int:result_id>", methods=["PATCH"]
        )
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def update_thread_result(thread_id: int, result_id: int):
            data = request.get_json(silent=True) or {}
            allowed = {"status": str, "assigned_to": str}
            updates: List[str] = []
            params: Dict[str, Any] = {"id": result_id, "tid": thread_id}
            for field, cast in allowed.items():
                if field in data:
                    updates.append(f"{field} = :{field}")
                    params[field] = cast(data[field]) if data[field] is not None else None
            if not updates:
                return jsonify({"error": "No valid fields to update"}), 400
            try:
                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text(
                            f"UPDATE thread_results SET {', '.join(updates)} "
                            "WHERE id = :id AND thread_id = :tid"
                        ),
                        params,
                    )
                    if result.rowcount == 0:
                        return jsonify({"error": "Thread result not found"}), 404
                return jsonify({"status": "updated"}), 200
            except Exception as e:
                return internal_error("update_thread_result", e)

        # ── GET /api/v1/threads/<id>/executions ───────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/executions", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_thread_executions(thread_id: int):
            limit = int_arg(request.args, "limit", default=20, maximum=100)
            offset = _offset_arg()
            try:
                with self.db_manager.engine.begin() as conn:
                    exists = conn.execute(
                        text("SELECT id FROM analysis_threads WHERE id = :id"),
                        {"id": thread_id},
                    ).fetchone()
                    if not exists:
                        return jsonify({"error": "Thread not found"}), 404
                    total = (
                        conn.execute(
                            text("SELECT COUNT(*) FROM thread_executions WHERE thread_id = :tid"),
                            {"tid": thread_id},
                        ).scalar()
                        or 0
                    )
                    rows = conn.execute(
                        text(
                            "SELECT id, execution_type, started_at, completed_at, status, "
                            "results_count, error_message, details "
                            "FROM thread_executions WHERE thread_id = :tid "
                            "ORDER BY started_at DESC NULLS LAST LIMIT :lim OFFSET :off"
                        ),
                        {"tid": thread_id, "lim": limit, "off": offset},
                    ).fetchall()
                items = [
                    {
                        "id": r[0],
                        "execution_type": r[1],
                        "started_at": str(r[2]) if r[2] else None,
                        "completed_at": str(r[3]) if r[3] else None,
                        "status": r[4],
                        "results_count": int(r[5] or 0),
                        "error_message": r[6],
                        "details": r[7],
                    }
                    for r in rows
                ]
                return jsonify({"items": items, "total": int(total)}), 200
            except Exception as e:
                return internal_error("get_thread_executions", e)

        # ── POST /api/v1/threads/email-monitor ───────────────────────────────
        @self.app.route("/api/v1/threads/email-monitor", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="email_admin")
        def create_email_monitor_thread():
            """Create an e-mail threat monitor for a mailbox or a whole domain.

            The monitor reads mail through a service account with domain-wide
            delegation, so it needs the ``email_admin`` scope and only accepts
            mailboxes/domains on the allowlist (see ``src.api.mailbox_policy``).

            Returns:
                201 with the thread ID; 400 on invalid input, 403 when the
                mailbox or domain is not allowlisted.
            """
            data = request.get_json(silent=True) or {}
            label = data.get("label")
            target_mailbox = data.get("target_mailbox")
            domain = data.get("domain")
            admin_email = data.get("admin_email")

            if not target_mailbox and not domain:
                return jsonify({"error": "Either target_mailbox or domain is required"}), 400

            if domain:
                if not isinstance(domain, str):
                    return jsonify({"error": "domain must be a string"}), 400
                domain = domain.strip().lower()
                if admin_email is not None and (
                    not isinstance(admin_email, str)
                    or not validators.email(admin_email)
                    or not admin_email.lower().endswith(f"@{domain}")
                ):
                    return (
                        jsonify(
                            {"error": "admin_email must be an address in the monitored domain"}
                        ),
                        400,
                    )
                if not is_domain_allowed(domain):
                    logger.warning(f"🛑 Refused domain-wide e-mail monitor for {domain}")
                    return (
                        jsonify({"error": "Domain is not on the e-mail monitoring allowlist"}),
                        403,
                    )
            else:
                if not isinstance(target_mailbox, str) or not validators.email(target_mailbox):
                    return jsonify({"error": "target_mailbox must be an e-mail address"}), 400
                target_mailbox = target_mailbox.strip()
                if not is_mailbox_allowed(target_mailbox):
                    logger.warning(f"🛑 Refused e-mail monitor for mailbox {target_mailbox}")
                    return (
                        jsonify({"error": "Mailbox is not on the e-mail monitoring allowlist"}),
                        403,
                    )

            search_interval_hours = data.get("search_interval_hours", 1)
            if (
                isinstance(search_interval_hours, bool)
                or not isinstance(search_interval_hours, int)
                or not 1 <= search_interval_hours <= 720
            ):
                return (
                    jsonify({"error": "search_interval_hours must be an integer from 1 to 720"}),
                    400,
                )

            if domain:
                details = {
                    "domain": domain,
                    "admin_email": admin_email,
                    "exclude_domains": data.get("exclude_domains", []),
                    "exclude_users": data.get("exclude_users", []),
                    "last_history_ids": {},
                }
            else:
                details = {
                    "target_mailbox": target_mailbox,
                    "exclude_domains": data.get("exclude_domains", []),
                    "last_history_id": None,
                }

            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads "
                            "(thread_type, label, status, details, search_interval_hours) "
                            "VALUES ('email_monitor', :label, 'active', CAST(:details AS JSONB), :interval) "
                            "RETURNING id"
                        ),
                        {
                            "label": label,
                            "details": json.dumps(details),
                            "interval": search_interval_hours,
                        },
                    ).fetchone()
                    thread_id = row[0]
                if self.email_scheduler:
                    threading.Thread(
                        target=self._trigger_email_scan,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                return internal_error("create_email_monitor_thread", e)

        # ── GET /api/v1/threads/<id>/email-inboxes ───────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/email-inboxes", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="email_admin")
        def get_thread_email_inboxes(thread_id: int):
            """Aggregate email scan results grouped by recipient inbox.

            Per-mailbox threat data needs the ``email_admin`` scope.

            Args:
                thread_id: E-mail monitor thread.

            Returns:
                JSON ``{"items": [...], "total": int}`` or 404.
            """
            try:
                with self.db_manager.engine.begin() as conn:
                    exists = conn.execute(
                        text("SELECT id FROM analysis_threads WHERE id = :id"),
                        {"id": thread_id},
                    ).fetchone()
                    if not exists:
                        return jsonify({"error": "Thread not found"}), 404

                    rows = conn.execute(
                        text("""
                            SELECT
                                extra_data->>'inbox' AS inbox,
                                COUNT(*) AS threat_count,
                                MAX((extra_data->>'threat_score')::int) AS max_score,
                                AVG((extra_data->>'threat_score')::float)::int AS avg_score,
                                MAX(first_detected_at) AS last_threat_at
                            FROM thread_results
                            WHERE thread_id = :tid
                              AND extra_data->>'inbox' IS NOT NULL
                            GROUP BY extra_data->>'inbox'
                            ORDER BY max_score DESC, threat_count DESC
                            """),
                        {"tid": thread_id},
                    ).fetchall()

                    items = [
                        {
                            "inbox": r[0],
                            "threat_count": r[1],
                            "max_score": r[2],
                            "avg_score": r[3],
                            "last_threat_at": str(r[4]) if r[4] else None,
                        }
                        for r in rows
                    ]
                    return jsonify({"items": items, "total": len(items)}), 200
            except Exception as e:
                return internal_error("get_thread_email_inboxes", e)

        # ── GET /api/v1/email/senders ─────────────────────────────────────────
        @self.app.route("/api/v1/email/senders", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def list_email_senders():
            from src.intelligence.email_reputation import SenderReputationTracker

            blocked_only = bool_arg(request.args, "blocked_only")
            whitelisted_only = bool_arg(request.args, "whitelisted_only")
            limit = int_arg(request.args, "limit", default=50, maximum=200)
            offset = _offset_arg()
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    items, total = tracker.list_senders(
                        conn,
                        blocked_only=blocked_only,
                        whitelisted_only=whitelisted_only,
                        limit=limit,
                        offset=offset,
                    )
                return jsonify({"items": items, "total": total}), 200
            except Exception as e:
                return internal_error("list_email_senders", e)

        # ── GET /api/v1/email/senders/<email>/reputation ──────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/reputation", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_sender_reputation(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    rep = tracker.get_reputation(conn, sender_email)
                if not rep:
                    return jsonify({"error": "Sender not found"}), 404
                return jsonify(rep), 200
            except Exception as e:
                return internal_error("get_sender_reputation", e)

        # ── PATCH /api/v1/email/senders/<email>/block ─────────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/block", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def block_sender(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            data = request.get_json(silent=True) or {}
            reason = data.get("reason", "Manual block by admin")
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM email_sender_reputation WHERE sender_email = :email"),
                        {"email": sender_email.lower()},
                    ).fetchone()
                    if not existing:
                        return jsonify({"error": "Sender not found"}), 404
                    tracker.mark_blocked(conn, sender_email, reason)
                return jsonify({"status": "blocked", "sender": sender_email}), 200
            except Exception as e:
                return internal_error("block_sender", e)

        # ── PATCH /api/v1/email/senders/<email>/unblock ───────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/unblock", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def unblock_sender(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM email_sender_reputation WHERE sender_email = :email"),
                        {"email": sender_email.lower()},
                    ).fetchone()
                    if not existing:
                        return jsonify({"error": "Sender not found"}), 404
                    tracker.mark_unblocked(conn, sender_email)
                return jsonify({"status": "unblocked", "sender": sender_email}), 200
            except Exception as e:
                return internal_error("unblock_sender", e)

        # ── PATCH /api/v1/email/senders/<email>/whitelist ─────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/whitelist", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def whitelist_sender(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            data = request.get_json(silent=True) or {}
            reason = data.get("reason", "Manual whitelist by admin")
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM email_sender_reputation WHERE sender_email = :email"),
                        {"email": sender_email.lower()},
                    ).fetchone()
                    if not existing:
                        # Auto-create a reputation record so we can whitelist unknown senders
                        conn.execute(
                            text(
                                "INSERT INTO email_sender_reputation "
                                "(sender_email, sender_domain, whitelisted, whitelisted_at, whitelist_reason) "
                                "VALUES (:email, :domain, TRUE, NOW(), :reason) "
                                "ON CONFLICT (sender_email) DO UPDATE SET "
                                "whitelisted = TRUE, whitelisted_at = NOW(), whitelist_reason = :reason, "
                                "blocked = FALSE, blocked_at = NULL, block_reason = NULL"
                            ),
                            {
                                "email": sender_email.lower(),
                                "domain": (
                                    sender_email.split("@")[-1].lower()
                                    if "@" in sender_email
                                    else sender_email.lower()
                                ),
                                "reason": reason,
                            },
                        )
                    else:
                        tracker.mark_whitelisted(conn, sender_email, reason)
                return jsonify({"status": "whitelisted", "sender": sender_email}), 200
            except Exception as e:
                return internal_error("whitelist_sender", e)

        # ── GET /api/v1/email/domains ─────────────────────────────────────────
        @self.app.route("/api/v1/email/domains", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def list_email_domains():
            from src.intelligence.email_reputation import SenderReputationTracker

            blocked_only = bool_arg(request.args, "blocked_only")
            limit = int_arg(request.args, "limit", default=50, maximum=200)
            offset = _offset_arg()
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    items, total = tracker.list_domains(
                        conn, blocked_only=blocked_only, limit=limit, offset=offset
                    )
                return jsonify({"items": items, "total": total}), 200
            except Exception as e:
                return internal_error("list_email_domains", e)

        # ── POST /api/v1/blocklist ────────────────────────────────────────────
        @self.app.route("/api/v1/blocklist", methods=["POST"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def add_blocklist_entry():
            data = request.get_json(silent=True) or {}
            entry = (data.get("entry") or "").lower().strip()
            entry_type = (data.get("type") or "").lower().strip()
            alert_id = data.get("alert_id")

            if not entry:
                return jsonify({"error": "entry is required"}), 400
            if entry_type not in ("email", "domain"):
                return jsonify({"error": "type must be 'email' or 'domain'"}), 400

            try:
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM blocklist WHERE entry = :entry"),
                        {"entry": entry},
                    ).fetchone()
                    if existing:
                        return jsonify({"status": "already_blocked", "entry": entry}), 200
                    conn.execute(
                        text(
                            "INSERT INTO blocklist (entry, entry_type, alert_id) VALUES (:entry, :entry_type, :alert_id)"
                        ),
                        {"entry": entry, "entry_type": entry_type, "alert_id": alert_id},
                    )
                logger.info(f"blocklist: added {entry} ({entry_type})")
                return jsonify({"status": "blocked", "entry": entry, "type": entry_type}), 201
            except Exception as e:
                return internal_error("add_blocklist_entry", e)

        # ── GET /api/v1/blocklist ─────────────────────────────────────────────
        @self.app.route("/api/v1/blocklist", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_blocklist():
            try:
                with self.db_manager.engine.connect() as conn:
                    rows = conn.execute(
                        text(
                            "SELECT entry, entry_type, alert_id, created_at FROM blocklist ORDER BY created_at DESC"
                        )
                    ).fetchall()
                items = [
                    {
                        "entry": r[0],
                        "type": r[1],
                        "alert_id": r[2],
                        "created_at": iso_utc(r[3]),
                    }
                    for r in rows
                ]
                return jsonify({"items": items, "total": len(items)}), 200
            except Exception as e:
                return internal_error("get_blocklist", e)

        # ── GET /api/v1/metrics/operational ────────────────────────────────────
        @self.app.route("/api/v1/metrics/operational", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope=("metrics", "read"))
        def get_operational_metrics():
            """Pipeline timings, queue depth and outcomes measured from the database.

            ``days`` (1-365, default 30) bounds the sites considered by their
            ``first_seen``. Durations are hours (count/median/p90/mean; null
            statistics when nothing was measured): time to detect (since domain
            registration), time to report (first delivered e-mail), time to the
            first and the last confirmed outage after that report, and the lead
            over public feeds. See ``src/observability/operational.py``.

            Returns:
                The metrics document.
            """
            days = int_arg(
                request.args,
                "days",
                default=DEFAULT_WINDOW_DAYS,
                minimum=1,
                maximum=MAX_WINDOW_DAYS,
            )
            try:
                return jsonify(compute_operational_metrics(self.db_manager.engine, days)), 200
            except Exception as e:
                return internal_error("get_operational_metrics", e)

        @self.app.route("/api/v1/health", methods=["GET"])
        @self.limiter.exempt
        def health_check():
            """Liveness/readiness probe (no authentication required).

            Pings the database through ``src.observability.health``. Only the
            aggregate and per-component statuses are returned, never messages
            (they can contain DSNs or exception text); details are logged.

            Returns:
                200 when healthy or degraded, 503 when unhealthy.
            """
            result = self._health_status()
            status = result["status"]
            return (
                jsonify(
                    {
                        "status": status,
                        "timestamp": iso_utc(datetime.datetime.now(datetime.timezone.utc)),
                        "version": APP_VERSION,
                        "grinder_integration": GRINDER_INTEGRATION_ENABLED,
                        "api_authentication": bool(self.api_key),
                        "checks": {
                            name: component.get("status", STATUS_UNHEALTHY)
                            for name, component in result["components"].items()
                        },
                    }
                ),
                503 if status == STATUS_UNHEALTHY else 200,
            )

        @self.app.route("/metrics", methods=["GET"])
        @self.limiter.limit("60 per minute")
        @require_metrics_access
        def prometheus_metrics():
            """Prometheus metrics in text exposition format.

            Requires ``Authorization: Bearer <METRICS_TOKEN>`` or an API key with
            the ``metrics`` or ``read`` scope; 401/403 otherwise.

            Returns:
                The Prometheus text payload.
            """
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

            return self.app.response_class(
                generate_latest(),
                mimetype=CONTENT_TYPE_LATEST,
            )

    def _rate_limit_storage_mode(self) -> str:
        """Tell whether rate-limit counters are shared by every API worker.

        Returns:
            ``"shared"`` when counters live in the configured external storage,
            ``"per-process"`` when they are kept in memory: no
            ``RATELIMIT_STORAGE_URL``, or the storage became unreachable and
            flask-limiter fell back to memory.
        """
        if self._rate_limit_storage_uri == MEMORY_STORAGE_URI:
            return "per-process"
        # flask-limiter has no public flag for its in-memory fallback.
        if getattr(self.limiter, "_storage_dead", False):
            return "per-process"
        return "shared"

    def _rate_limited(self, exc: RateLimitExceeded) -> Tuple[Response, int]:
        """Render a rate-limit breach as JSON with the seconds to wait.

        Args:
            exc: The breach raised by flask-limiter (its description names the
                limit, e.g. ``"5 per 1 minute"``).

        Returns:
            ``({"error": str, "retry_after": int}, 429)``; ``Retry-After`` is
            set to the same number of seconds (see :func:`_pin_retry_after`).
        """
        current = self.limiter.current_limit
        reset_at = current.reset_at if current is not None else time.time() + 60
        retry_after = max(1, math.ceil(reset_at - time.time()))
        g.rate_limit_retry_after = retry_after
        body = {
            "error": f"Rate limit exceeded ({exc.description}); retry in {retry_after} s",
            "retry_after": retry_after,
        }
        response = jsonify(body)
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    def _check_database(self) -> Dict[str, Any]:
        """Ping the database with a bounded wait.

        Returns:
            A health component dict (``status`` and a log-only ``message``).
        """
        try:
            return timeout(HEALTH_DB_TIMEOUT_SECONDS)(check_database)(self.db_manager.engine)
        except OperationTimeoutError:
            return {"status": STATUS_UNHEALTHY, "message": "Database ping timed out"}

    def _health_status(self) -> Dict[str, Any]:
        """Run the health checks, reusing a result younger than the cache TTL.

        The probe is unauthenticated and not rate limited, so caching bounds the
        number of database connections it can open.

        Returns:
            The aggregate result of ``HealthCheck.check_all()``.
        """
        with self._health_lock:
            cached = self._health_cache
            now = time.monotonic()
            if cached is not None and now - cached[0] < HEALTH_CACHE_SECONDS:
                return cached[1]
            result = self._health_checker.check_all()
            for name, component in result["components"].items():
                if component.get("status") != STATUS_HEALTHY:
                    logger.warning(
                        f"⚠️  Health check '{name}' is {component.get('status')}: "
                        f"{component.get('message')}"
                    )
            self._health_cache = (now, result)
            return result

    def _trigger_image_search(self, thread_id: int, s3_key: str):
        """Run an image tracking search in a fresh DB connection (for background threads)."""
        scheduler = self.scheduler
        if scheduler is None:
            return
        try:
            with self.db_manager.engine.begin() as conn:
                scheduler._run_image_tracking(conn, thread_id, s3_key)
        except Exception as e:
            logger.error(f"❌ _trigger_image_search thread {thread_id}: {e}")

    def _trigger_ads_search(self, thread_id: int, details):
        """Run a google_ads search in a fresh DB connection (for background threads)."""
        scheduler = self.scheduler
        if scheduler is None:
            return
        try:
            with self.db_manager.engine.begin() as conn:
                scheduler._run_google_ads(conn, thread_id, details)
        except Exception as e:
            logger.error(f"❌ _trigger_ads_search thread {thread_id}: {e}")

    def _trigger_email_scan(self, thread_id: int, details):
        """Run an email_monitor scan — manages its own transactions internally."""
        email_scheduler = self.email_scheduler
        if email_scheduler is None:
            return
        try:
            email_scheduler._run_email_monitor(thread_id, details)
        except Exception as e:
            logger.error(f"❌ _trigger_email_scan thread {thread_id}: {e}")

    def record_pending_submission(
        self,
        url: str,
        abuse_email: Optional[str],
        source: str,
        priority: str,
        description: str,
        requested_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Store a submission from a key without ``report_send`` for analyst review.

        The row is kept out of every automatic path: ``manual_flag`` stays 0 and
        ``auto_report_eligible`` 0 (the reporting loop needs one of them),
        ``requires_manual_review`` is set, and ``auto_analysis_status`` is
        ``awaiting_approval`` so the auto-analyzer (which could otherwise mark
        an ``external_api`` site auto-report-eligible) never selects it. An
        existing row only gets ``last_seen`` refreshed (and is flagged for
        review unless already approved or reported); analyst-curated fields
        are not overwritten. ``approval_requested_at``/``_by`` (first request
        wins) put the site in ``GET /api/v1/reports/approvals`` until a label
        decides it.

        Args:
            url: Submitted URL (already validated and SSRF-checked).
            abuse_email: Abuse contact suggested by the submitter, if any.
            source: Submitter-provided source label.
            priority: Submitter-provided priority.
            description: Free-text description.
            requested_by: Name (or type) of the submitting API key.

        Returns:
            The response body for the 202 answer.

        Raises:
            SQLAlchemyError: If the submission cannot be stored.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")  # legacy naive column: UTC (D16)
        with self.db_manager.engine.begin() as conn:
            existing = conn.execute(
                text("SELECT id FROM phishing_sites WHERE url = :url"), {"url": url}
            ).fetchone()
            if existing is None:
                conn.execute(
                    text("""
                        INSERT INTO phishing_sites
                        (url, manual_flag, first_seen, last_seen, abuse_email,
                         reported, abuse_report_sent, source, priority, description,
                         auto_report_eligible, requires_manual_review, auto_analysis_status,
                         approval_requested_at, approval_requested_by)
                        VALUES (:url, 0, :timestamp, :timestamp, :abuse_email,
                                0, 0, :source, :priority, :description,
                                0, 1, 'awaiting_approval', now(), :requested_by)
                    """),
                    {
                        "url": url,
                        "timestamp": timestamp,
                        "abuse_email": abuse_email,
                        "source": source,
                        "priority": priority,
                        "description": description,
                        "requested_by": requested_by,
                    },
                )
            else:
                conn.execute(
                    text("""
                        UPDATE phishing_sites
                        SET last_seen = :timestamp,
                            requires_manual_review = CASE
                                WHEN manual_flag = 1 OR abuse_report_sent = 1
                                    THEN requires_manual_review
                                ELSE 1
                            END,
                            approval_requested_at = CASE
                                WHEN manual_flag = 1 OR abuse_report_sent = 1
                                    THEN approval_requested_at
                                ELSE COALESCE(approval_requested_at, now())
                            END,
                            approval_requested_by = CASE
                                WHEN manual_flag = 1 OR abuse_report_sent = 1
                                    THEN approval_requested_by
                                ELSE COALESCE(approval_requested_by, :requested_by)
                            END
                        WHERE url = :url
                    """),
                    {"timestamp": timestamp, "url": url, "requested_by": requested_by},
                )
        logger.info(f"📝 Submission for {url} recorded; awaiting analyst approval")
        return {
            "status": "pending_approval",
            "message": "Submission recorded; an analyst must approve it before it is reported",
            "url": url,
            "timestamp": iso_utc(now_utc),
            "approval_required": True,
            "report_sent": False,
        }

    def process_phishing_report(
        self, url: str, abuse_email: Optional[str], source: str, priority: str, description: str
    ) -> Dict[str, Any]:
        """Persist a phishing report from the API and return right away.

        With a ``report_manager`` (the single-process ``--start-api`` mode),
        abuse-contact resolution (WHOIS) and the immediate abuse report can take
        well over 10 s for domains that don't resolve, so they run afterwards in
        a background thread (:meth:`_resolve_and_send_report`) registered with
        ``src.shutdown`` so a graceful shutdown waits for it. Without one (the
        gunicorn API role), nothing runs here: the scheduler role's reporting
        loop resolves the contacts and reports the site (``manual_flag = 1``,
        not yet reported). The same loop also picks the site up if this
        process stops before its thread finishes.

        Args:
            url: Submitted URL (already validated and SSRF-checked).
            abuse_email: Abuse contact suggested by the submitter, if any.
            source: Submitter-provided source label.
            priority: Submitter-provided priority.
            description: Free-text description.

        Returns:
            The response body; ``processing`` is ``queued`` (background work
            started here), ``scheduled`` (left to the scheduler role) or
            ``done`` (the site was already reported).
        """
        try:
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            timestamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")  # legacy naive column: UTC (D16)
            stored_emails: List[str] = []

            # Short transaction with no network I/O inside
            with self.db_manager.engine.begin() as conn:
                existing = conn.execute(
                    text(
                        "SELECT abuse_email, all_abuse_emails, "
                        "COALESCE(abuse_report_sent, 0) = 1 OR COALESCE(reported, 0) = 1 "
                        "FROM phishing_sites WHERE url = :url"
                    ),
                    {"url": url},
                ).fetchone()
                is_new = existing is None
                already_reported = bool(existing[2]) if existing is not None else False

                if is_new:
                    needs_resolution = not abuse_email
                    conn.execute(
                        text("""
                            INSERT INTO phishing_sites
                            (url, manual_flag, first_seen, last_seen, abuse_email, all_abuse_emails,
                             reported, abuse_report_sent, source, priority, description)
                            VALUES (:url, 1, :timestamp, :timestamp, :abuse_email, NULL,
                                    0, 0, :source, :priority, :description)
                        """),
                        {
                            "url": url,
                            "timestamp": timestamp,
                            "abuse_email": abuse_email,
                            "source": source,
                            "priority": priority,
                            "description": description,
                        },
                    )
                    logger.info(f"✅ Created new phishing report for {url}")
                else:
                    needs_resolution = (not abuse_email and not existing[0]) or not existing[1]
                    conn.execute(
                        text("""
                            UPDATE phishing_sites
                            SET manual_flag = 1, last_seen = :timestamp,
                                abuse_email = COALESCE(:abuse_email, abuse_email),
                                source = :source, priority = :priority, description = :description
                            WHERE url = :url
                        """),
                        {
                            "timestamp": timestamp,
                            "abuse_email": abuse_email,
                            "source": source,
                            "priority": priority,
                            "description": description,
                            "url": url,
                        },
                    )
                    logger.info(f"✅ Updated existing phishing report for {url}")
                    if existing[1]:
                        stored_emails = [e.strip() for e in existing[1].split(",") if e.strip()]
                    elif existing[0]:
                        stored_emails = [existing[0]]

            queued = self.report_manager is not None and (needs_resolution or bool(stored_emails))
            if queued:
                worker = threading.Thread(
                    target=self._resolve_and_send_report,
                    args=(url, needs_resolution, stored_emails),
                    daemon=True,
                    name="api-report",
                )
                worker.start()
                register_thread(worker)
                processing = "queued"
            elif self.report_manager is None and not already_reported:
                processing = "scheduled"
            else:
                processing = "done"

            result = {
                "status": "created" if is_new else "updated",
                "message": f"{'Created new' if is_new else 'Updated existing'} report for {url}",
                "url": url,
                "timestamp": iso_utc(now_utc),
                "abuse_emails_count": len(stored_emails),
                "report_sent": False,
                "report_recipients": [],
                "last_report_sent": None,
                "processing": processing,
            }
            if is_new:
                result["abuse_email"] = abuse_email
            else:
                result["abuse_email_resolved"] = bool(abuse_email or stored_emails)
            return result

        except Exception as e:
            logger.error(f"❌ Failed to process phishing report for {url}: {e}")
            return {"status": "error", "message": "Failed to process report", "url": url}

    def _resolve_and_send_report(
        self, url: str, needs_resolution: bool, stored_emails: List[str]
    ) -> None:
        """Background half of process_phishing_report: resolve contacts, then report.

        ``AbuseReportManager.send_abuse_report`` claims the site, marks it
        reported and queues the outbox e-mails in one transaction, so nothing
        is written here afterwards. A False return is not an error: the site
        may be claimed by another worker or inside the resend cool-down.

        Args:
            url: Reported URL.
            needs_resolution: Whether abuse contacts must be looked up (WHOIS).
            stored_emails: Contacts already stored for the site.
        """
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        whois_info = None
        abuse_emails: List[str] = []
        try:
            if needs_resolution:
                try:
                    whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
                    registrar = self.abuse_detector.extract_registrar(whois_info)
                    abuse_emails = (
                        self.abuse_detector.get_enhanced_abuse_email(domain, whois_info, registrar)
                        or []
                    )
                except Exception as e:
                    logger.warning(f"⚠️  Failed to auto-detect abuse email for {url}: {e}")

                if abuse_emails:
                    all_abuse_emails = ", ".join(abuse_emails)
                    with self.db_manager.engine.begin() as conn:
                        conn.execute(
                            text("""
                                UPDATE phishing_sites
                                SET abuse_email = COALESCE(:abuse_email, abuse_email),
                                    all_abuse_emails = COALESCE(:all_abuse_emails, all_abuse_emails)
                                WHERE url = :url
                                """),
                            {
                                "abuse_email": abuse_emails[0],
                                "all_abuse_emails": all_abuse_emails,
                                "url": url,
                            },
                        )
                    logger.info(
                        f"🔍 Resolved {len(abuse_emails)} abuse emails for {url}: {all_abuse_emails}"
                    )

            recipients = abuse_emails or stored_emails
            if self.report_manager and recipients:
                logger.info(
                    f"📧 Sending immediate abuse report for {url} to {len(recipients)} recipients"
                )
                if whois_info is None:
                    whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
                if self.report_manager.send_abuse_report(recipients, url, str(whois_info)):
                    logger.info(f"✅ Immediate abuse report accepted for {url}")
                else:
                    logger.info(
                        f"ℹ️  Immediate abuse report for {url} not sent now (claimed by another "
                        "worker, inside the resend cool-down, or no abuse desk accepted it)"
                    )
        except Exception as e:
            logger.error(f"❌ Failed to send immediate abuse report for {url}: {e}")

    def run(self, host: Optional[str] = None, port: int = 8091) -> None:
        """Serve the API with Flask's built-in server, for local development only.

        Production deployments serve ``src.api.wsgi`` with gunicorn. The Werkzeug
        interactive debugger is never enabled: it allows arbitrary code execution
        for anyone who can reach the port.

        Args:
            host: Interface to bind; defaults to ``settings.API_BIND_HOST``
                (``127.0.0.1``), so the dev server is not exposed by accident.
            port: TCP port to listen on.
        """
        host = host or settings.API_BIND_HOST
        auth_status = "with API key authentication" if self.api_key else "without authentication"
        grinder_status = (
            "with Grinder integration"
            if GRINDER_INTEGRATION_ENABLED
            else "without Grinder integration"
        )

        logger.info(f"🚀 Starting Enhanced Phishing API server on {host}:{port}")
        logger.warning("⚠️  Flask development server: use gunicorn with src.api.wsgi in production")
        logger.info(f"🔐 API Security: {auth_status}")
        logger.info(f"🔗 Threat Intelligence: {grinder_status}")

        if self.api_key:
            logger.info("🔑 API endpoints require Bearer token authentication")
        else:
            logger.warning(
                "⚠️  API running without authentication - not recommended for production"
            )

        self.app.run(host=host, port=port, debug=False, use_reloader=False)


# Global variable to store flask app for decorator access
flask_app = None

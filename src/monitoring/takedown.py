"""
Takedown Monitor for Anisakys Phishing Detection Engine.

Probes every reported site once per cycle and records what it saw. A site is
only confirmed ``down`` (and its open abuse reports resolved) after
``TAKEDOWN_CONSECUTIVE_FAILURES`` consecutive cycles in which every client
profile failed with ``nxdomain``, ``connection_error`` or HTTP 404/410. Bot
challenges never count as failures, parking pages lead to a separate
``parked`` status, and other HTTP errors or SSRF-blocked targets are
inconclusive. Every status transition, including a site coming back up, is
kept in ``site_status_events``.

Network I/O (probes, RDAP) never happens inside a database transaction: each
site is probed first, then written in its own short transaction. RDAP/IP
enrichment runs only when the resolved IP changes or once a day per site. A
cycle is skipped when this host itself is offline (connectivity canaries).
"""

from __future__ import annotations

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from ipwhois import IPWhois
from ipwhois.exceptions import BaseIpwhoisException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from src.config import settings
from src.database import DatabaseManager
from src.detection.liveness import (
    ProbeClass,
    ProbeResult,
    SiteProbe,
    network_is_healthy,
    probe_site,
)
from src.dns.network_utils import is_cloudflare_ip
from src.logger import logger
from src.shutdown import is_shutdown_requested, wait_for_shutdown

# Offset file path used by get_offset/save_offset (same source as src.main)
OFFSET_FILE = getattr(settings, "OFFSET_FILE")

STATUS_UP = "up"
STATUS_DOWN = "down"
STATUS_PARKED = "parked"

# RDAP/IP enrichment runs at most this often per site unless the IP changes.
IP_RECHECK_INTERVAL = datetime.timedelta(hours=24)

# Timeout for the connectivity canaries, independent of the probe timeout.
CANARY_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class SiteState:
    """Persisted takedown state of one site, as read at the start of a cycle."""

    id: int
    url: str
    status: Optional[str]
    takedown_date: Optional[datetime.datetime]
    consecutive_failures: int = 0
    consecutive_parked: int = 0
    resolved_ip: Optional[str] = None
    ip_checked_at: Optional[datetime.datetime] = None


@dataclass(frozen=True)
class Transition:
    """New takedown state computed from one cycle's probe."""

    status: str
    takedown_date: Optional[datetime.datetime]
    consecutive_failures: int
    consecutive_parked: int
    seen_alive: bool


def decide_transition(
    state: SiteState, result: ProbeResult, threshold: int, now: datetime.datetime
) -> Transition:
    """Apply the N-consecutive-failures rule to one cycle's observation.

    Args:
        state: Stored state before this cycle.
        result: Combined observation of the cycle (all client profiles).
        threshold: Consecutive failing (or parked) cycles needed to change
            the status to ``down`` (or ``parked``).
        now: Time of the observation.

    Returns:
        The new state. Alive sites become ``up`` immediately (resurrection);
        failures and parking pages change the status only once their counter
        reaches ``threshold``; inconclusive observations (other HTTP errors,
        SSRF-blocked targets) reset both counters and keep the status.
    """
    current = state.status or STATUS_UP

    if result.is_alive:
        return Transition(STATUS_UP, None, 0, 0, True)

    if result.classification == ProbeClass.PARKED:
        parked = state.consecutive_parked + 1
        if parked >= threshold and current != STATUS_PARKED:
            return Transition(STATUS_PARKED, None, 0, parked, False)
        return Transition(current, state.takedown_date, 0, parked, False)

    if result.is_failure:
        failures = state.consecutive_failures + 1
        if failures >= threshold:
            takedown = state.takedown_date if current == STATUS_DOWN else None
            return Transition(STATUS_DOWN, takedown or now, failures, 0, False)
        return Transition(current, state.takedown_date, failures, 0, False)

    return Transition(current, state.takedown_date, 0, 0, False)


def _rdap_network_name(ip: str) -> Optional[str]:
    """Look up the RDAP network name (hosting provider) of an IP.

    Args:
        ip: Public IP address.

    Returns:
        The network name, or ``None`` if RDAP has none.

    Raises:
        BaseIpwhoisException: On RDAP lookup failures.
    """
    result = IPWhois(ip).lookup_rdap(depth=1)
    return (result.get("network") or {}).get("name") or None


def _preferred_ip(ips: Sequence[str]) -> Optional[str]:
    """Pick the address to store: the first IPv4 address, else the first one.

    Args:
        ips: Resolved addresses.

    Returns:
        The chosen address, or ``None`` if there is none.
    """
    for ip in ips:
        if ":" not in ip:
            return ip
    return ips[0] if ips else None


class TakedownMonitor:
    """Confirm takedowns over consecutive probe cycles."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        timeout: int,
        check_interval: int = 3600,
        monitoring_event: Optional[threading.Event] = None,
        *,
        failure_threshold: Optional[int] = None,
        max_workers: Optional[int] = None,
        canary_urls: Optional[Sequence[str]] = None,
        prober: Optional[Callable[[str, int], SiteProbe]] = None,
        ip_lookup: Optional[Callable[[str], Optional[str]]] = None,
    ):
        """Create the monitor.

        Args:
            db_manager: Database access.
            timeout: Per-request probe timeout in seconds.
            check_interval: Seconds between cycles.
            monitoring_event: Set after the first cycle (gates reporting).
            failure_threshold: Consecutive failing cycles before ``down``;
                defaults to ``TAKEDOWN_CONSECUTIVE_FAILURES``.
            max_workers: Sites probed in parallel; defaults to
                ``TAKEDOWN_PROBE_WORKERS``.
            canary_urls: Connectivity canaries; defaults to
                ``TAKEDOWN_CANARY_URLS``.
            prober: ``(url, timeout) -> SiteProbe``; defaults to
                :func:`src.detection.liveness.probe_site`.
            ip_lookup: ``ip -> provider name`` RDAP lookup.
        """
        self.db_manager = db_manager
        self.timeout = timeout
        self.check_interval = check_interval
        self.monitoring_event = monitoring_event
        self.failure_threshold = max(
            1, failure_threshold or int(getattr(settings, "TAKEDOWN_CONSECUTIVE_FAILURES", 3))
        )
        self.max_workers = max(
            1, max_workers or int(getattr(settings, "TAKEDOWN_PROBE_WORKERS", 4))
        )
        if canary_urls is None:
            raw = getattr(settings, "TAKEDOWN_CANARY_URLS", "") or ""
            canary_urls = [u.strip() for u in raw.split(",") if u.strip()]
        self.canary_urls = list(canary_urls)
        self.prober = prober or probe_site
        self.ip_lookup = ip_lookup or _rdap_network_name

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main monitoring loop; returns once a shutdown is requested."""
        first_cycle_done = False

        while not is_shutdown_requested():
            try:
                self.run_cycle()
            except Exception as e:
                # Loop guard: a failed cycle must not kill the monitor thread;
                # the next cycle starts from the persisted state.
                logger.exception(f"❌ Error in takedown monitoring cycle: {e}")

            if not first_cycle_done:
                first_cycle_done = True
                if self.monitoring_event and not self.monitoring_event.is_set():
                    logger.info(
                        "✅ Takedown monitor initial cycle complete, setting monitoring event."
                    )
                    self.monitoring_event.set()

            wait_for_shutdown(self.check_interval)

    def run_cycle(self) -> Dict[str, int]:
        """Probe every site once and persist the outcome.

        Returns:
            Counters: ``sites``, ``checked``, ``transitions``, ``errors`` and
            ``skipped`` (1 when the cycle was skipped for lack of connectivity).
        """
        stats = {"sites": 0, "checked": 0, "transitions": 0, "errors": 0, "skipped": 0}
        if not network_is_healthy(self.canary_urls, CANARY_TIMEOUT_SECONDS):
            logger.warning(
                "⚠️ Connectivity canaries unreachable: skipping takedown cycle so a local "
                "outage is not counted as site failures"
            )
            stats["skipped"] = 1
            return stats

        sites = self._load_sites()
        stats["sites"] = len(sites)
        if not sites:
            return stats

        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(sites)), thread_name_prefix="takedown-probe"
        ) as pool:
            futures = [pool.submit(self._check_site_guarded, site) for site in sites]
            for future in as_completed(futures):
                outcome = future.result()
                if outcome in stats:
                    stats[outcome] += 1
                if outcome == "transitions":
                    stats["checked"] += 1

        logger.info(
            f"📡 Takedown cycle: {stats['checked']}/{stats['sites']} sites checked, "
            f"{stats['transitions']} status change(s), {stats['errors']} error(s)"
        )
        return stats

    # ------------------------------------------------------------------
    # Per-site work
    # ------------------------------------------------------------------

    def _load_sites(self) -> List[SiteState]:
        """Read the takedown state of every site in one short read.

        Returns:
            One :class:`SiteState` per row of ``phishing_sites``.
        """
        with self.db_manager.engine.connect() as conn:
            rows = conn.execute(text("""
                    SELECT id, url, site_status, takedown_date,
                           COALESCE(consecutive_failures, 0),
                           COALESCE(consecutive_parked, 0),
                           resolved_ip, ip_checked_at
                    FROM phishing_sites
                    WHERE url IS NOT NULL
                    ORDER BY id
                    """)).fetchall()
        return [
            SiteState(
                id=row[0],
                url=row[1],
                status=row[2],
                takedown_date=row[3],
                consecutive_failures=row[4],
                consecutive_parked=row[5],
                resolved_ip=row[6],
                ip_checked_at=row[7],
            )
            for row in rows
        ]

    def _check_site_guarded(self, state: SiteState) -> str:
        """Check one site, isolating database errors to that site.

        Args:
            state: Stored state of the site.

        Returns:
            ``"transitions"`` if the status changed, ``"checked"`` if it was
            recorded without a change, ``"errors"`` on a database error, or
            ``"skipped"`` during shutdown or after a concurrent change.
        """
        if is_shutdown_requested():
            return "skipped"
        try:
            return self.check_site(state)
        except SQLAlchemyError as e:
            logger.error(f"❌ Could not record takedown probe for {state.url}: {e}")
            return "errors"

    def check_site(self, state: SiteState, now: Optional[datetime.datetime] = None) -> str:
        """Probe one site, then persist the result in one short transaction.

        Args:
            state: Stored state of the site.
            now: Observation time (defaults to the current UTC time).

        Returns:
            ``"transitions"``, ``"checked"`` or ``"skipped"`` (see
            :meth:`_check_site_guarded`).

        Raises:
            SQLAlchemyError: If the update fails.
        """
        probe = self.prober(state.url, self.timeout)  # network I/O, no transaction open
        now = now or datetime.datetime.now(datetime.timezone.utc)
        ip_info = self._lookup_ip_info(state, probe, now)  # network I/O, no transaction open
        transition = decide_transition(state, probe.result, self.failure_threshold, now)
        if not self._apply(state, probe, transition, ip_info, now):
            return "skipped"
        return "transitions" if transition.status != (state.status or STATUS_UP) else "checked"

    def _lookup_ip_info(
        self, state: SiteState, probe: SiteProbe, now: datetime.datetime
    ) -> Optional[Dict[str, object]]:
        """Refresh IP/provider data when the IP changed or once a day.

        Args:
            state: Stored state of the site.
            probe: This cycle's probe.
            now: Observation time.

        Returns:
            Values to store (``resolved_ip``, ``asn_provider``,
            ``is_cloudflare``), or ``None`` when no refresh is due.
        """
        if probe.result.classification == ProbeClass.SSRF_BLOCKED:
            return None
        ip = _preferred_ip(probe.resolved_ips)
        if not ip:
            return None
        due = (
            ip != state.resolved_ip
            or state.ip_checked_at is None
            or now - state.ip_checked_at >= IP_RECHECK_INTERVAL
        )
        if not due:
            return None

        asn_provider: Optional[str] = None
        try:
            asn_provider = self.ip_lookup(ip)
        except (BaseIpwhoisException, OSError, ValueError) as e:
            # The attempt still counts for the daily limit; the stored
            # provider is kept (COALESCE in the update).
            logger.warning(f"⚠️ RDAP lookup failed for {ip} ({state.url}): {type(e).__name__}")
        return {
            "resolved_ip": ip,
            "asn_provider": asn_provider,
            "is_cloudflare": 1 if is_cloudflare_ip(ip) else 0,
        }

    def _apply(
        self,
        state: SiteState,
        probe: SiteProbe,
        transition: Transition,
        ip_info: Optional[Dict[str, object]],
        now: datetime.datetime,
    ) -> bool:
        """Persist one cycle's outcome for a site in a single short transaction.

        The update is conditional on the status read at the start of the
        cycle, so a concurrent change (operator, API) is never overwritten.

        Args:
            state: Stored state read at the start of the cycle.
            probe: This cycle's probe.
            transition: New state.
            ip_info: Refreshed IP data, if any.
            now: Observation time.

        Returns:
            ``False`` if the row changed (or vanished) since it was read.
        """
        old_status = state.status
        new_status = transition.status
        result = probe.result
        with self.db_manager.engine.begin() as conn:
            updated = conn.execute(
                text("""
                    UPDATE phishing_sites
                    SET site_status = :status,
                        takedown_date = :takedown,
                        consecutive_failures = :failures,
                        consecutive_parked = :parked,
                        last_probe_class = :probe_class,
                        last_probe_at = :now,
                        last_seen = CASE WHEN :alive THEN :now ELSE last_seen END,
                        resolved_ip = CASE WHEN :ip_checked THEN :resolved_ip
                                           ELSE resolved_ip END,
                        asn_provider = CASE WHEN :ip_checked
                                            THEN COALESCE(:asn_provider, asn_provider)
                                            ELSE asn_provider END,
                        is_cloudflare = CASE WHEN :ip_checked THEN :is_cloudflare
                                             ELSE is_cloudflare END,
                        ip_checked_at = CASE WHEN :ip_checked THEN :now ELSE ip_checked_at END
                    WHERE id = :id AND site_status IS NOT DISTINCT FROM :old_status
                    """),
                {
                    "status": new_status,
                    "takedown": transition.takedown_date,
                    "failures": transition.consecutive_failures,
                    "parked": transition.consecutive_parked,
                    "probe_class": result.classification.value,
                    "now": now,
                    "alive": transition.seen_alive,
                    "ip_checked": ip_info is not None,
                    "resolved_ip": (ip_info or {}).get("resolved_ip"),
                    "asn_provider": (ip_info or {}).get("asn_provider"),
                    "is_cloudflare": (ip_info or {}).get("is_cloudflare"),
                    "id": state.id,
                    "old_status": old_status,
                },
            )
            if updated.rowcount == 0:
                logger.info(f"⏭️ {state.url} changed during the cycle; probe not recorded")
                return False

            if new_status == (old_status or STATUS_UP):
                return True

            conn.execute(
                text("""
                    INSERT INTO site_status_events
                        (site_id, site_url, old_status, new_status, probe_class,
                         status_code, detail, created_at)
                    VALUES (:id, :url, :old, :new, :probe_class, :code, :detail, :now)
                    """),
                {
                    "id": state.id,
                    "url": state.url,
                    "old": old_status,
                    "new": new_status,
                    "probe_class": result.classification.value,
                    "code": result.status_code,
                    "detail": result.detail[:500] if result.detail else None,
                    "now": now,
                },
            )

            if new_status == STATUS_DOWN:
                resolved = conn.execute(
                    text("""
                        UPDATE abuse_reports
                        SET status = 'resolved', response_date = NOW()
                        WHERE site_url = :url
                        AND status NOT IN ('resolved', 'rejected')
                        """),
                    {"url": state.url},
                )
                logger.info(
                    f"✅ Takedown confirmed for {state.url} after "
                    f"{transition.consecutive_failures} failing cycle(s) "
                    f"({result.classification.value}); resolved {resolved.rowcount} report(s)"
                )
            elif new_status == STATUS_UP and old_status in (STATUS_DOWN, STATUS_PARKED):
                logger.warning(f"🧟 {state.url} is back up (was {old_status})")
            else:
                logger.info(f"🔄 {state.url}: site_status '{old_status}' -> '{new_status}'")
        return True


def save_offset(offset: int):
    """Save current offset to file."""
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))
    logger.debug(f"💾 Offset saved as: {offset}")


def get_offset() -> int:
    """Get the current offset from a file."""
    try:
        with open(OFFSET_FILE, "r") as f:
            offset_str = f.read().strip()
            offset = int(float(offset_str))
            logger.debug(f"📖 Retrieved offset: {offset}")
            return offset
    except Exception as ex:
        logger.error(f"❌ Error getting offset from {OFFSET_FILE}: {ex}")
        return 0

"""ASN enrichment of a capture's server IP (phase 2, WS3).

RDAP/WHOIS lookups are network calls, so this lives in the backend (never in
the capture worker, which has no business talking to WHOIS servers) and is
memoised: phishing kits cluster on the same few hosting networks, so one
lookup usually serves many captures.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 4


@lru_cache(maxsize=1024)
def asn_of(server_ip: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """The ASN and organisation announcing an IP, by RDAP.

    Args:
        server_ip: The capture's server IP.

    Returns:
        ``(asn, asn_org)`` (numbers as strings, as the database stores them),
        or ``(None, None)`` when the IP is missing or nobody answers in time.
    """
    if not server_ip:
        return (None, None)
    try:
        from ipwhois import IPWhois

        response = IPWhois(server_ip, timeout=_TIMEOUT_SECONDS).lookup_rdap(depth=1)
        asn = response.get("asn")
        network = response.get("network") or {}
        asn_org = response.get("asn_description") or network.get("name")
        return ((str(asn) if asn else None), (str(asn_org) if asn_org else None))
    except Exception as exc:  # unannounced/private IP, rate limit, timeout: absent, not a failure
        logger.debug(f"ASN lookup failed for {server_ip}: {exc}")
        return (None, None)

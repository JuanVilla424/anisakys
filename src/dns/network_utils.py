"""
Network Utilities Module

DNS and IP resolution utilities for phishing detection.

EPIC-006: Main.py Modularization
"""

import logging
import socket
import ipaddress
from typing import Tuple, Optional
from urllib.parse import urlparse

from ipwhois import IPWhois

from src.config import CLOUDFLARE_IP_RANGES

logger = logging.getLogger(__name__)

# Schemes we are ever willing to fetch/render server-side.
SAFE_URL_SCHEMES = frozenset({"http", "https"})


def _ip_is_public(ip: str) -> bool:
    """True only for globally-routable addresses.

    Rejects loopback, RFC1918/ULA private, link-local (incl. the
    169.254.169.254 cloud-metadata address), multicast, reserved and the
    unspecified address, for both IPv4 and IPv6.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def assess_url_target(url: str) -> str:
    """Classify a URL's fetch destination for SSRF safety.

    Returns one of:
      "invalid"    — not http/https or no host.
      "blocked"    — host resolves to at least one non-public address.
      "unresolved" — host could not be resolved (safe to hand to external
                     threat-intel APIs, but nothing internal was reached).
      "public"     — every resolved address is globally routable.

    Callers must refuse any direct server-side fetch/render (screenshots,
    redirects) unless the verdict is "public"; "blocked" must never be
    fetched, even indirectly.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return "invalid"
    if parsed.scheme.lower() not in SAFE_URL_SCHEMES or not parsed.hostname:
        return "invalid"

    host = parsed.hostname
    # A literal IP host is classified directly — no DNS needed.
    try:
        ipaddress.ip_address(host)
        return "public" if _ip_is_public(host) else "blocked"
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError):
        return "unresolved"

    resolved = {str(info[4][0]) for info in infos}
    if not resolved:
        return "unresolved"
    if any(not _ip_is_public(ip) for ip in resolved):
        logger.warning(f"🛑 SSRF guard blocked {host} — resolves to non-public address")
        return "blocked"
    return "public"


def get_ip_info(domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Get IP address and ASN provider information for a domain."""
    try:
        resolved_ip = socket.gethostbyname(domain)
        obj = IPWhois(resolved_ip)
        res = obj.lookup_rdap(depth=1)
        asn_provider = res.get("network", {}).get("name", "")
        return resolved_ip, asn_provider
    except Exception as e:
        logger.error(f"Failed to get IP info for {domain}: {e}")
        return None, None


def is_cloudflare_ip(ip: str) -> bool:
    """Check if an IP address belongs to Cloudflare."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in net:
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking Cloudflare IP: {e}")
        return False

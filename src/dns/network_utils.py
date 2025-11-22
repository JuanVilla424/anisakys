"""
Network Utilities Module

DNS and IP resolution utilities for phishing detection.

EPIC-006: Main.py Modularization
"""

import logging
import socket
import ipaddress
from typing import Tuple, Optional

from ipwhois import IPWhois

from src.config import CLOUDFLARE_IP_RANGES

logger = logging.getLogger(__name__)


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

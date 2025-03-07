#!/usr/bin/env python3
"""
populate_provider_email.py

This script updates the "provider_abuse_email" field in the phishing_sites table by
resolving each site's IP and ASN/provider. If the site is not behind Cloudflare, it
automatically generates a provider abuse email in the format:
    abuse@{normalized_asn}.com
where the ASN string is normalized by removing non-alphanumeric characters.
"""

import sqlite3
import socket
import re
import ipaddress
from typing import Optional
from ipwhois import IPWhois
from src.config import CLOUDFLARE_IP_RANGES


def get_ip_info(domain: str):
    """Resolve the domain and look up its ASN/provider using IPWhois."""
    try:
        resolved_ip = socket.gethostbyname(domain)
        obj = IPWhois(resolved_ip)
        res = obj.lookup_rdap(depth=1)
        asn_provider = res.get("network", {}).get("name", "")
        return resolved_ip, asn_provider
    except Exception as e:
        print(f"Error retrieving IP info for {domain}: {e}")
        return None, None


def is_cloudflare_ip(ip: str) -> bool:
    """Return True if the IP address falls within a known Cloudflare range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in net:
                return True
        return False
    except Exception as e:
        print(f"Error checking Cloudflare for IP {ip}: {e}")
        return False


def get_provider_abuse_email(asn_provider: str) -> Optional[str]:
    """
    Automatically generate a provider abuse email from the ASN/provider string.
    The provider string is normalized by removing non-alphanumeric characters and converting to lowercase,
    then an email is constructed as abuse@{normalized_asn}.com.
    """
    if not asn_provider:
        return None
    normalized = re.sub(r"[^a-z0-9]", "", asn_provider.lower())
    if normalized:
        email = f"abuse@{normalized}.com"
        return email
    return None


def populate_provider_email(db_file: str = "scan_results.db"):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT url FROM phishing_sites")
    rows = cursor.fetchall()
    for (url,) in rows:
        # Remove protocol and trailing path to get the domain
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        resolved_ip, asn_provider = get_ip_info(domain)
        if not resolved_ip:
            print(f"Skipping {url}: could not resolve IP.")
            continue
        if is_cloudflare_ip(resolved_ip):
            print(f"Skipping {url}: Cloudflare detected.")
            continue
        provider_email = get_provider_abuse_email(asn_provider)
        if provider_email:
            print(f"Updating {url} with provider abuse email: {provider_email}")
            cursor.execute(
                "UPDATE phishing_sites SET provider_abuse_email = ? WHERE url = ?",
                (provider_email, url),
            )
        else:
            print(f"No ASN/provider info for {url}; cannot generate provider abuse email.")
    conn.commit()
    conn.close()
    print("Provider abuse email population complete.")


if __name__ == "__main__":
    populate_provider_email()

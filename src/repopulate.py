#!/usr/bin/env python3
import sqlite3
import socket
import re
import ipaddress
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


def repopulate_asn_and_cloudflare(db_file: str = "scan_results.db"):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT url FROM phishing_sites WHERE site_status = 'up'")
    rows = cursor.fetchall()
    for (url,) in rows:
        # Extract domain from URL (remove http/https and any trailing paths)
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        resolved_ip, asn_provider = get_ip_info(domain)
        cloudflare_flag = 1 if resolved_ip and is_cloudflare_ip(resolved_ip) else 0
        print(f"Updating {url}: IP={resolved_ip}, ASN={asn_provider}, Cloudflare={cloudflare_flag}")
        cursor.execute(
            """
            UPDATE phishing_sites
            SET resolved_ip = ?, asn_provider = ?, is_cloudflare = ?
            WHERE url = ?
            """,
            (resolved_ip, asn_provider, cloudflare_flag, url),
        )
    conn.commit()
    conn.close()
    print("Re-population complete.")


if __name__ == "__main__":
    repopulate_asn_and_cloudflare()

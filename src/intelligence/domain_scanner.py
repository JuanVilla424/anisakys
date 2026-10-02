"""
Domain Scanner — DNS + WHOIS + threat classification.

Used by:
  - POST /api/v1/scan/domain  (phishing_api.py)
  - src/scripts/send_abuse_report.py
"""

import re
import subprocess
from datetime import datetime, timezone
from typing import Optional


# ── DNS ───────────────────────────────────────────────────────────────────────


def _dig(domain: str, record_type: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["dig", "+short", record_type, domain],
            stderr=subprocess.DEVNULL,
            timeout=10,
            text=True,
        )
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def resolve_dns(domain: str) -> dict:
    """Resolve A, MX, NS, TXT, CNAME, www records for a domain."""
    return {
        "A": _dig(domain, "A"),
        "MX": _dig(domain, "MX"),
        "NS": _dig(domain, "NS"),
        "TXT": _dig(domain, "TXT"),
        "CNAME": _dig(domain, "CNAME"),
        "www_A": _dig(f"www.{domain}", "A"),
        "www_CNAME": _dig(f"www.{domain}", "CNAME"),
    }


# ── WHOIS ─────────────────────────────────────────────────────────────────────


def get_whois_data(domain: str) -> dict:
    """Run whois and extract key fields."""
    result = {
        "registrar": "",
        "abuse_email": "",
        "creation_date": "",
        "updated_date": "",
        "registrant_org": "",
        "name_servers": [],
        "raw": "",
    }
    try:
        raw = subprocess.check_output(
            ["whois", domain],
            stderr=subprocess.DEVNULL,
            timeout=15,
            text=True,
            errors="replace",
        )
        result["raw"] = raw

        patterns = {
            "registrar": r"(?:Registrar|registrar):\s*(.+)",
            "abuse_email": r"(?:Registrar Abuse Contact Email|abuse-mailbox|Abuse Email):\s*([\w.+\-]+@[\w.\-]+)",
            "creation_date": r"(?:Creation Date|Created On|created):\s*(.+)",
            "updated_date": r"(?:Updated Date|Last Modified|last-modified):\s*(.+)",
            "registrant_org": r"(?:Registrant Organization|org):\s*(.+)",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, raw, re.IGNORECASE)
            if m:
                result[key] = m.group(1).strip()

        if not result["abuse_email"]:
            m = re.search(r"abuse[^\n]*?([\w.+\-]+@[\w.\-]+)", raw, re.IGNORECASE)
            if m:
                result["abuse_email"] = m.group(1).strip()

        ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
        result["name_servers"] = [ns.strip().lower() for ns in ns_matches]

    except Exception:
        pass

    return result


# ── Threat classification ─────────────────────────────────────────────────────


def classify_threat(suspect_domain: str, dns: dict) -> dict:
    """
    Classify threat type and severity from DNS fingerprint.

    Returns:
        {
            "type": str,        # BEC | PHISHING_WEB | CREDENTIAL_HARVESTING | LOOKALIKE
            "severity": str,    # CRITICAL | HIGH | MEDIUM | LOW
            "indicators": list[str]
        }
    """
    indicators = []
    threat_type = "LOOKALIKE"
    severity = "MEDIUM"

    has_mx = bool(dns.get("MX"))
    has_web_a = bool(dns.get("A") or dns.get("www_A") or dns.get("www_CNAME"))
    has_ns = bool(dns.get("NS"))

    if has_mx and not has_web_a:
        threat_type = "BEC"
        severity = "CRITICAL"
        indicators.append(
            "Active MX records with no web presence — BEC email impersonation profile"
        )
        for mx in dns.get("MX", []):
            indicators.append(f"MX: {mx}")

    elif has_web_a and not has_mx:
        threat_type = "PHISHING_WEB"
        severity = "HIGH"
        indicators.append("Active web presence with no MX records — phishing page profile")
        for a in dns.get("A", []) + dns.get("www_A", []):
            indicators.append(f"A: {a}")

    elif has_mx and has_web_a:
        threat_type = "CREDENTIAL_HARVESTING"
        severity = "HIGH"
        indicators.append("Active MX and web records — fully operational fraudulent infrastructure")
        for mx in dns.get("MX", []):
            indicators.append(f"MX: {mx}")
        for a in dns.get("A", []):
            indicators.append(f"A: {a}")

    elif has_ns and not has_mx and not has_web_a:
        threat_type = "LOOKALIKE"
        severity = "LOW"
        indicators.append("Domain registered but no active email or web — pre-staged lookalike")

    for txt in dns.get("TXT", []):
        if "v=spf1" in txt.lower():
            indicators.append(f"SPF record: {txt[:80]}")
        if "v=dmarc1" in txt.lower():
            indicators.append(f"DMARC record: {txt[:80]}")
        if "google-site-verification" in txt.lower():
            indicators.append("Google Workspace verification — active email setup")
            if threat_type in ("BEC", "LOOKALIKE"):
                severity = "CRITICAL"

    return {"type": threat_type, "severity": severity, "indicators": indicators}


# ── Full scan ─────────────────────────────────────────────────────────────────


def full_scan(domain: str, victim_domain: Optional[str] = None) -> dict:
    """
    Run a complete domain scan: DNS + WHOIS + threat classification.

    Returns:
        {
            "domain": str,
            "victim_domain": str | None,
            "scanned_at": str (ISO),
            "dns": dict,
            "whois": dict (raw excluded),
            "threat": { type, severity, indicators },
        }
    """
    dns = resolve_dns(domain)
    whois = get_whois_data(domain)
    threat = classify_threat(domain, dns)
    whois_clean = {k: v for k, v in whois.items() if k != "raw"}

    return {
        "domain": domain,
        "victim_domain": victim_domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "dns": dns,
        "whois": whois_clean,
        "threat": threat,
    }

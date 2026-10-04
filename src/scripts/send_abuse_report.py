"""
Dynamic abuse report sender for suspicious lookalike / BEC domains.

Usage:
    cd /opt/anisakys
    python -m src.scripts.send_abuse_report <suspect_domain> [victim_domain] [options]

Arguments:
    suspect_domain   Domain being reported (required)
    victim_domain    Legitimate domain being impersonated (optional, auto-inferred from settings)

Options:
    --to EMAIL       Override abuse contact (auto-detected from WHOIS if omitted)
    --dry-run        Print report without sending
    --escalate N     CC escalation level 1, 2, or 3 (default: 1)
    --subject TEXT   Override email subject
"""

import argparse
import html
import re
import subprocess
import sys
import os
import types
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

# ── Bootstrap package stubs to avoid circular imports ────────────────────────
_base = os.path.join(os.path.dirname(__file__), "..", "..")
_src = os.path.normpath(os.path.join(_base, "src"))
for _pkg, _subdir in [
    ("src.intelligence", "intelligence"),
    ("src.detection", "detection"),
    ("src.reporting", "reporting"),
]:
    if _pkg not in sys.modules:
        _mod = types.ModuleType(_pkg)
        _mod.__path__ = [os.path.join(_src, _subdir)]
        _mod.__package__ = _pkg
        sys.modules[_pkg] = _mod

from src.config import settings  # noqa: E402

# ── DNS helpers ───────────────────────────────────────────────────────────────


def _dig(domain: str, record_type: str) -> list[str]:
    """Run dig and return answer lines (value only)."""
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
    """Resolve A, MX, NS, TXT, CNAME records for a domain."""
    return {
        "A": _dig(domain, "A"),
        "MX": _dig(domain, "MX"),
        "NS": _dig(domain, "NS"),
        "TXT": _dig(domain, "TXT"),
        "CNAME": _dig(domain, "CNAME"),
        "www_A": _dig(f"www.{domain}", "A"),
        "www_CNAME": _dig(f"www.{domain}", "CNAME"),
    }


# ── WHOIS helpers ─────────────────────────────────────────────────────────────


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

        # Also scan for any email-looking string after "abuse"
        if not result["abuse_email"]:
            m = re.search(r"abuse[^\n]*?([\w.+\-]+@[\w.\-]+)", raw, re.IGNORECASE)
            if m:
                result["abuse_email"] = m.group(1).strip()

        ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
        result["name_servers"] = [ns.strip().lower() for ns in ns_matches]

    except Exception as exc:
        print(f"[warn] whois failed for {domain}: {exc}", file=sys.stderr)

    return result


# ── Threat classification ─────────────────────────────────────────────────────


def classify_threat(suspect_domain: str, dns: dict) -> dict:
    """
    Classify threat type and severity from DNS fingerprint.

    Returns:
        {
            "type": str,           # BEC | PHISHING_WEB | CREDENTIAL_HARVESTING | LOOKALIKE | UNKNOWN
            "severity": str,       # CRITICAL | HIGH | MEDIUM | LOW
            "indicators": list[str]
        }
    """
    indicators = []
    threat_type = "LOOKALIKE"
    severity = "MEDIUM"

    has_mx = bool(dns["MX"])
    has_web_a = bool(dns["A"] or dns["www_A"] or dns["www_CNAME"])
    bool(dns["TXT"])
    bool(dns["CNAME"])
    has_ns = bool(dns["NS"])

    # BEC profile: active MX + parked/no web
    if has_mx and not has_web_a:
        threat_type = "BEC"
        severity = "CRITICAL"
        indicators.append(
            "Active MX records with no web presence — BEC email impersonation profile"
        )
        for mx in dns["MX"]:
            indicators.append(f"MX: {mx}")

    # Phishing web: has web but no MX
    elif has_web_a and not has_mx:
        threat_type = "PHISHING_WEB"
        severity = "HIGH"
        indicators.append(
            "Active web presence with no MX records — credential harvesting / phishing page profile"
        )
        for a in dns["A"] + dns["www_A"]:
            indicators.append(f"A record: {a}")

    # Both web and email active
    elif has_mx and has_web_a:
        threat_type = "CREDENTIAL_HARVESTING"
        severity = "HIGH"
        indicators.append("Active MX and web records — fully operational fraudulent infrastructure")
        for mx in dns["MX"]:
            indicators.append(f"MX: {mx}")
        for a in dns["A"]:
            indicators.append(f"A: {a}")

    # Registered with NS but nothing active yet
    elif has_ns and not has_mx and not has_web_a:
        threat_type = "LOOKALIKE"
        severity = "LOW"
        indicators.append("Domain registered but no active email or web — pre-staged lookalike")

    # SPF / DMARC policy indicators
    for txt in dns["TXT"]:
        if "v=spf1" in txt.lower():
            indicators.append(f"SPF record present: {txt[:80]}")
        if "v=dmarc1" in txt.lower():
            indicators.append(f"DMARC record present: {txt[:80]}")
        if "google-site-verification" in txt.lower():
            indicators.append("Google Workspace verification — active email setup via Google")
            if threat_type in ("BEC", "LOOKALIKE"):
                severity = "CRITICAL"

    return {"type": threat_type, "severity": severity, "indicators": indicators}


# ── Report builder ────────────────────────────────────────────────────────────

_SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f39c12",
    "LOW": "#27ae60",
}


def build_html_report(
    suspect_domain: str,
    victim_domain: str,
    dns: dict,
    whois: dict,
    threat: dict,
    sender: str,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_color = _SEVERITY_COLOR.get(threat["severity"], "#7f8c8d")
    esc = html.escape
    # DNS answers, WHOIS fields and domains are attacker-controlled: escape all.
    suspect_domain, victim_domain, sender = esc(suspect_domain), esc(victim_domain), esc(sender)

    def dns_row(label: str, values: list) -> str:
        if not values:
            return ""
        val_html = "<br>".join(f"<code>{esc(str(v))}</code>" for v in values)
        return f"<tr><td style='padding:6px 12px;font-weight:bold;color:#555;white-space:nowrap'>{label}</td><td style='padding:6px 12px'>{val_html}</td></tr>"

    dns_rows = "".join(
        filter(
            None,
            [
                dns_row("A", dns["A"]),
                dns_row("www A", dns["www_A"]),
                dns_row("www CNAME", dns["www_CNAME"]),
                dns_row("MX", dns["MX"]),
                dns_row("NS", dns["NS"]),
                dns_row("TXT", dns["TXT"][:5]),  # limit to first 5
            ],
        )
    )

    indicators_html = "".join(
        f"<li style='margin:4px 0'>{esc(str(ind))}</li>" for ind in threat["indicators"]
    )

    whois_rows = ""
    for label, key in [
        ("Registrar", "registrar"),
        ("Creation Date", "creation_date"),
        ("Updated Date", "updated_date"),
        ("Registrant Org", "registrant_org"),
    ]:
        if whois.get(key):
            whois_rows += f"<tr><td style='padding:4px 12px;font-weight:bold;color:#555'>{label}</td><td style='padding:4px 12px'>{esc(str(whois[key]))}</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;font-size:14px;color:#222;max-width:700px;margin:0 auto;padding:20px">

  <h2 style="color:#c0392b;border-bottom:2px solid #c0392b;padding-bottom:8px">
    Abuse Report: Fraudulent Domain Impersonating {victim_domain}
  </h2>

  <p>
    We are writing to report a domain that is impersonating our organization,
    <strong>{victim_domain}</strong>. We request immediate investigation and
    suspension of the domain <strong>{suspect_domain}</strong>.
  </p>

  <h3>Threat Classification</h3>
  <table style="border-collapse:collapse;width:100%">
    <tr>
      <td style="padding:6px 12px;font-weight:bold;color:#555">Type</td>
      <td style="padding:6px 12px"><strong>{esc(threat['type'].replace('_', ' '))}</strong></td>
    </tr>
    <tr>
      <td style="padding:6px 12px;font-weight:bold;color:#555">Severity</td>
      <td style="padding:6px 12px">
        <span style="background:{sev_color};color:#fff;padding:2px 10px;border-radius:4px;font-weight:bold">
          {esc(threat['severity'])}
        </span>
      </td>
    </tr>
    <tr>
      <td style="padding:6px 12px;font-weight:bold;color:#555">Suspect Domain</td>
      <td style="padding:6px 12px"><code>{suspect_domain}</code></td>
    </tr>
    <tr>
      <td style="padding:6px 12px;font-weight:bold;color:#555">Legitimate Domain</td>
      <td style="padding:6px 12px"><code>{victim_domain}</code></td>
    </tr>
    <tr>
      <td style="padding:6px 12px;font-weight:bold;color:#555">Report Date</td>
      <td style="padding:6px 12px">{ts}</td>
    </tr>
  </table>

  <h3>Threat Indicators</h3>
  <ul style="margin:8px 0;padding-left:20px">{indicators_html}</ul>

  <h3>DNS Evidence</h3>
  <table style="border-collapse:collapse;width:100%;background:#f9f9f9;border:1px solid #ddd">
    {dns_rows}
  </table>

  <h3>WHOIS Registration Data</h3>
  <table style="border-collapse:collapse;width:100%">
    {whois_rows}
  </table>

  <h3>Requested Actions</h3>
  <ol style="margin:8px 0;padding-left:20px">
    <li>Immediately suspend the domain <strong>{suspect_domain}</strong></li>
    <li>Disable any active MX / email services associated with this domain</li>
    <li>Preserve logs for potential law enforcement referral</li>
    <li>Notify us at <a href="mailto:{sender}">{sender}</a> once the domain is suspended</li>
  </ol>

  <p style="margin-top:24px">
    We reserve the right to escalate this report to ICANN, relevant national CERTs,
    and law enforcement if no action is taken within 48 hours.
  </p>

  <hr style="margin:24px 0;border:none;border-top:1px solid #ddd">
  <p style="font-size:12px;color:#888">
    This report was generated automatically by the Anisakys threat intelligence platform.<br>
    Contact: <a href="mailto:{sender}">{sender}</a>
  </p>

</body>
</html>"""


# ── SMTP sender ───────────────────────────────────────────────────────────────


def send_report(
    to_email: str,
    cc_emails: list[str],
    subject: str,
    html_body: str,
    dry_run: bool = False,
) -> None:
    """Send the report through the shared mailer, under the global SMTP cap.

    Uses the same relay policy as the pipeline (``SMTP_SECURITY``: credentials
    are never sent without TLS) and consumes a slot of the database-backed
    rate limit shared by every Anisakys process.

    Args:
        to_email: Abuse contact.
        cc_emails: Copy recipients.
        subject: Message subject.
        html_body: Escaped HTML report.
        dry_run: Print instead of sending.

    Raises:
        SystemExit: When the shared SMTP rate limit is exhausted.
    """
    if dry_run:
        print("\n" + "=" * 70)
        print(f"[DRY RUN] To:      {to_email}")
        print(f"[DRY RUN] CC:      {', '.join(cc_emails)}")
        print(f"[DRY RUN] From:    {settings.ABUSE_EMAIL_SENDER}")
        print(f"[DRY RUN] Subject: {subject}")
        print("=" * 70)
        print(html_body[:2000])
        print("=" * 70)
        return

    from sqlalchemy import create_engine

    from src.reporting.mailer import SmtpMailer
    from src.reporting.smtp_rate_limiter import DatabaseSmtpRateLimiter

    if not settings.DATABASE_URL:
        print("ERROR: DATABASE_URL is required for the shared SMTP rate limit.", file=sys.stderr)
        sys.exit(1)
    engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
    try:
        limiter = DatabaseSmtpRateLimiter(engine, max_per_hour=settings.SMTP_RATE_LIMIT_PER_HOUR)
        if not limiter.acquire():
            print("ERROR: shared SMTP rate limit reached; try again later.", file=sys.stderr)
            sys.exit(1)
    finally:
        engine.dispose()

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.ABUSE_EMAIL_SENDER
    msg["To"] = to_email
    if cc_emails:
        msg["Cc"] = ", ".join(cc_emails)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=settings.ABUSE_EMAIL_SENDER.rpartition("@")[2] or None)
    msg.set_content(
        "This abuse report is best read as HTML; the HTML part contains the full evidence."
    )
    msg.add_alternative(html_body, subtype="html")

    SmtpMailer().send(msg, [to_email] + cc_emails)
    print(f"[ok] Report sent to {to_email} (CC: {', '.join(cc_emails) or 'none'})")


# ── CLI entry point ───────────────────────────────────────────────────────────


def normalize_domain(raw: str) -> str:
    """Lower-case a domain argument and drop a leading ``www.`` label.

    ``str.removeprefix`` is used on purpose: ``lstrip("www.")`` strips any of
    those characters, which turned ``web.com`` into ``eb.com``.

    Args:
        raw: Domain as typed on the command line.

    Returns:
        The normalised domain.
    """
    return raw.strip().lower().rstrip("/").removeprefix("www.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send an abuse report for a suspicious domain")
    parser.add_argument("suspect_domain", help="Domain being reported")
    parser.add_argument(
        "victim_domain",
        nargs="?",
        default=None,
        help="Legitimate domain being impersonated (default: first domain in settings.DOMAINS)",
    )
    parser.add_argument(
        "--to", dest="to_email", help="Abuse contact email (auto-detected if omitted)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print report without sending")
    parser.add_argument(
        "--escalate",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="CC escalation level (1=DEFAULT_CC_EMAILS, 2=LEVEL2, 3=LEVEL3)",
    )
    parser.add_argument("--subject", help="Override email subject")
    parser.add_argument("--cc", dest="extra_cc", help="Override CC email(s), comma-separated")
    return parser.parse_args()


def _cc_for_level(level: int) -> list[str]:
    """Return CC list for the requested escalation level (cumulative)."""
    cc: list[str] = []
    for raw in [
        settings.DEFAULT_CC_EMAILS,
        settings.DEFAULT_CC_EMAILS_ESCALATION_LEVEL2 if level >= 2 else None,
        settings.DEFAULT_CC_EMAILS_ESCALATION_LEVEL3 if level >= 3 else None,
    ]:
        if raw:
            cc.extend(e.strip() for e in raw.split(",") if e.strip())
    return list(dict.fromkeys(cc))  # deduplicate, preserve order


def run() -> None:
    args = parse_args()

    suspect = normalize_domain(args.suspect_domain)
    victim = (args.victim_domain or "").strip().lower()

    # Infer victim domain from settings if not provided
    if not victim and settings.DOMAINS:
        victim = settings.DOMAINS.split(",")[0].strip()
    if not victim:
        print("ERROR: victim_domain not provided and settings.DOMAINS is not set", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Suspect domain : {suspect}")
    print(f"[*] Victim domain  : {victim}")
    print("[*] Resolving DNS  ...")

    dns = resolve_dns(suspect)
    print(f"    A={dns['A']}, MX={len(dns['MX'])} records, NS={dns['NS'][:2]}")

    print("[*] Running WHOIS  ...")
    whois = get_whois_data(suspect)
    print(f"    Registrar: {whois['registrar'] or '(unknown)'}")
    print(f"    Abuse:     {whois['abuse_email'] or '(not found)'}")
    print(f"    Created:   {whois['creation_date'] or '(unknown)'}")

    print("[*] Classifying threat ...")
    threat = classify_threat(suspect, dns)
    print(f"    Type: {threat['type']}  Severity: {threat['severity']}")
    for ind in threat["indicators"]:
        print(f"      - {ind}")

    # Determine recipient
    to_email = args.to_email or whois["abuse_email"]
    if not to_email:
        print("\nERROR: Could not auto-detect abuse contact from WHOIS.", file=sys.stderr)
        print("Use --to EMAIL to specify the abuse contact manually.", file=sys.stderr)
        sys.exit(1)

    # Build CC list
    cc_emails = (
        [e.strip() for e in args.extra_cc.split(",") if e.strip()]
        if args.extra_cc
        else _cc_for_level(args.escalate)
    )

    # Build subject
    subject = args.subject or (
        f"{settings.ABUSE_EMAIL_SUBJECT} — {suspect} impersonating {victim}"
        if settings.ABUSE_EMAIL_SUBJECT
        else f"Abuse Report: {suspect} — fraudulent domain impersonating {victim}"
    )

    # Build report
    html_body = build_html_report(
        suspect_domain=suspect,
        victim_domain=victim,
        dns=dns,
        whois=whois,
        threat=threat,
        sender=settings.ABUSE_EMAIL_SENDER,
    )

    # Send
    print(f"\n[*] {'[DRY RUN] ' if args.dry_run else ''}Sending to: {to_email}")
    send_report(
        to_email=to_email,
        cc_emails=cc_emails,
        subject=subject,
        html_body=html_body,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    run()

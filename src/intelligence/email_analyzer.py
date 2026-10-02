"""
Email threat heuristics analyzer.

Scores an email 0-100 based on indicators of phishing/spam/APT:
  - Authentication failures (SPF, DKIM, DMARC)
  - Sender header anomalies (display name mismatch, Reply-To divergence)
  - Urgency keywords (bilingual es/en)
  - Suspicious attachment extensions
  - Risky URL patterns (short URLs, IP-based URLs)
  - Domain age (young domains are APT indicator)
"""

import re
from typing import Optional

from src.logger import logger

# ── Static lists ─────────────────────────────────────────────────────────────

URGENCY_KEYWORDS_ES = [
    "urgente",
    "verificar",
    "verificación",
    "cuenta suspendida",
    "acción inmediata",
    "confirme",
    "confirmar",
    "restringido",
    "bloqueo preventivo",
    "actualice sus datos",
    "acceso bloqueado",
    "alerta de seguridad",
    "contraseña expirada",
    "haga clic aquí",
    "tiempo limitado",
    "actúe ahora",
    "su cuenta será cerrada",
    "ingrese sus datos",
]

URGENCY_KEYWORDS_EN = [
    "urgent",
    "verify",
    "verification",
    "account suspended",
    "immediate action",
    "confirm",
    "restricted",
    "click here",
    "limited time",
    "act now",
    "your account will be closed",
    "enter your credentials",
    "security alert",
    "password expired",
    "unusual activity",
    "login attempt",
    "validate your account",
]

ALL_URGENCY_KEYWORDS = [k.lower() for k in URGENCY_KEYWORDS_ES + URGENCY_KEYWORDS_EN]

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".jar",
    ".scr",
    ".lnk",
    ".msi",
    ".hta",
    ".iso",
    ".img",
    ".com",
    ".pif",
    ".wsf",
    ".reg",
    ".dll",
    ".cpl",
    ".msc",
}

SHORT_URL_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "short.link",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "x.co",
    "shorte.st",
    "bc.vc",
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
    "gmx.com",
}

# Regex for URL extraction from email body
URL_PATTERN = re.compile(r"https?://[^\s\"'<>\]\[(){}]+", re.IGNORECASE)

IP_URL_PATTERN = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE)


class EmailAnalyzer:
    def __init__(self):
        pass

    def analyze(self, parsed_email: dict) -> dict:
        """
        Analyze a parsed email dict (from GmailClient.get_message) and return
        a threat assessment dict:
        {
          "threat_score": int (0-100),
          "risk_factors": list[str],
          "auth_results": dict,
          "sender_analysis": dict,
          "content_analysis": dict,
          "attachment_analysis": dict,
          "urls_extracted": list[str],
          "domain_age_days": int | None,
        }
        """
        score = 0
        risk_factors = []

        auth = self._check_auth_results(parsed_email)
        sender = self._check_sender(parsed_email)
        content = self._check_content(parsed_email.get("body_text", ""))
        attachments = self._check_attachments(parsed_email.get("attachments", []))
        domain_age_days = self._check_domain_age(parsed_email.get("from_email", ""))

        # --- Auth scoring ---
        if auth.get("spf") == "fail":
            score += 25
            risk_factors.append("spf_fail")
        elif auth.get("spf") == "softfail":
            score += 10
            risk_factors.append("spf_softfail")

        if auth.get("dmarc") == "fail":
            score += 20
            risk_factors.append("dmarc_fail")

        if auth.get("dkim") == "fail":
            score += 10
            risk_factors.append("dkim_fail")

        # --- Sender scoring ---
        if sender.get("reply_to_mismatch"):
            score += 15
            risk_factors.append("reply_to_mismatch")

        if sender.get("display_name_domain_mismatch"):
            score += 15
            risk_factors.append("display_name_mismatch")

        if sender.get("free_provider_official_claim"):
            score += 10
            risk_factors.append("free_provider_official_claim")

        # --- Content scoring ---
        kw_count = content.get("urgency_keywords_count", 0)
        if kw_count > 0:
            kw_score = min(kw_count * 5, 25)
            score += kw_score
            risk_factors.append(f"urgency_keywords:{kw_count}")

        if content.get("ip_urls_count", 0) > 0:
            score += 15
            risk_factors.append(f"ip_based_url:{content['ip_urls_count']}")

        short_count = content.get("short_urls_count", 0)
        if short_count > 0:
            score += min(short_count * 10, 20)
            risk_factors.append(f"short_url:{short_count}")

        if content.get("password_zip_pattern"):
            score += 15
            risk_factors.append("password_protected_zip")

        # --- Attachment scoring ---
        sus_exts = attachments.get("suspicious_extensions", [])
        if sus_exts:
            score += min(len(sus_exts) * 20, 40)
            risk_factors.append(f"suspicious_attachment:{','.join(sus_exts)}")

        # --- Domain age scoring (APT indicator) ---
        if domain_age_days is not None:
            if domain_age_days < 30:
                score += 30
                risk_factors.append(f"domain_age_days:{domain_age_days}")
            elif domain_age_days < 90:
                score += 15
                risk_factors.append(f"domain_age_days:{domain_age_days}")
            elif domain_age_days < 180:
                score += 5
                risk_factors.append(f"domain_age_days:{domain_age_days}")

        return {
            "threat_score": min(score, 100),
            "risk_factors": risk_factors,
            "auth_results": auth,
            "sender_analysis": sender,
            "content_analysis": content,
            "attachment_analysis": attachments,
            "urls_extracted": content.get("urls", []),
            "domain_age_days": domain_age_days,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _check_auth_results(self, parsed_email: dict) -> dict:
        """Parse Authentication-Results and Received-SPF headers."""
        auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
        raw = parsed_email.get("authentication_results", "") or ""
        raw += " " + (parsed_email.get("received_spf", "") or "")
        raw = raw.lower()

        for key in ("spf", "dkim", "dmarc"):
            for result in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
                if f"{key}={result}" in raw:
                    auth[key] = result
                    break

        return auth

    def _check_sender(self, parsed_email: dict) -> dict:
        """Detect anomalies in sender headers."""
        from_email = parsed_email.get("from_email", "").lower()
        from_name = parsed_email.get("from_name", "").lower()
        reply_to_raw = parsed_email.get("reply_to") or ""
        to = parsed_email.get("to", "").lower()

        from_domain = from_email.split("@")[-1] if "@" in from_email else ""

        # Reply-To ≠ From domain
        reply_to_domain = ""
        if reply_to_raw:
            rt_match = re.search(r"@([\w.\-]+)", reply_to_raw.lower())
            if rt_match:
                reply_to_domain = rt_match.group(1)
        reply_to_mismatch = bool(reply_to_domain and from_domain and reply_to_domain != from_domain)

        # Display name mentions a known domain but email is from different domain
        display_name_domain_mismatch = False
        if from_name:
            # Look for domain-like patterns in display name
            name_domains = re.findall(r"[\w]+\.(?:com|org|net|co|bank|gov|edu)", from_name)
            for nd in name_domains:
                if nd not in from_domain:
                    display_name_domain_mismatch = True
                    break

        # Free email provider claiming official-sounding name
        free_provider_official_claim = False
        if from_domain in FREE_EMAIL_PROVIDERS:
            official_indicators = [
                "bank",
                "banco",
                "soporte",
                "support",
                "seguridad",
                "security",
                "noreply",
                "no-reply",
                "admin",
                "service",
                "servicio",
                "oficial",
                "official",
                "alert",
                "alerta",
                "notification",
                "verificacion",
            ]
            if any(ind in from_name for ind in official_indicators):
                free_provider_official_claim = True

        return {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "reply_to_mismatch": reply_to_mismatch,
            "display_name_domain_mismatch": display_name_domain_mismatch,
            "free_provider_official_claim": free_provider_official_claim,
        }

    def _check_content(self, body_text: str) -> dict:
        """Scan body text for urgency keywords, suspicious URLs, and patterns."""
        body_lower = body_text.lower()

        # Urgency keywords
        matched_keywords = [kw for kw in ALL_URGENCY_KEYWORDS if kw in body_lower]

        # URL extraction
        urls = URL_PATTERN.findall(body_text)
        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        # IP-based URLs
        ip_urls = [u for u in unique_urls if IP_URL_PATTERN.match(u)]

        # Short URLs
        short_urls = []
        for u in unique_urls:
            try:
                host = re.match(r"https?://([^/]+)", u)
                if host and host.group(1).lower().rstrip(".") in SHORT_URL_DOMAINS:
                    short_urls.append(u)
            except Exception:
                pass

        # Password-protected ZIP pattern
        password_zip = bool(
            re.search(r"\.(zip|rar|7z)", body_lower)
            and re.search(r"(password|contraseña|clave|pass)[\s:]*[\w!@#$%^&*]+", body_lower)
        )

        return {
            "urgency_keywords_count": len(matched_keywords),
            "urgency_keywords_matched": matched_keywords[:10],
            "urls": unique_urls[:50],
            "total_urls": len(unique_urls),
            "ip_urls_count": len(ip_urls),
            "short_urls_count": len(short_urls),
            "password_zip_pattern": password_zip,
        }

    def _check_attachments(self, attachments: list) -> dict:
        """Flag attachments with dangerous extensions."""
        suspicious = []
        for att in attachments:
            filename = att.get("filename", "")
            if not filename:
                continue
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in SUSPICIOUS_EXTENSIONS:
                suspicious.append(filename)

        return {
            "total_attachments": len(attachments),
            "suspicious_extensions": suspicious,
        }

    def _check_domain_age(self, from_email: str) -> Optional[int]:
        """
        Return age in days of the sender's domain, or None if unavailable.
        Young domains (< 180 days) are a common APT indicator.
        """
        if not from_email or "@" not in from_email:
            return None
        domain = from_email.split("@")[-1]
        if domain in FREE_EMAIL_PROVIDERS:
            return None  # Free providers are old — skip WHOIS
        try:
            import whois
            from datetime import datetime, timezone

            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation is None:
                return None
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - creation).days
            return max(age, 0)
        except Exception:
            return None

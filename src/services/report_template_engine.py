"""Report Template Engine for ICANN-compliant abuse reports."""

import logging
from datetime import datetime
from typing import Dict, Optional, List
from jinja2 import Template

logger = logging.getLogger(__name__)


class ReportTemplateEngine:
    """Engine for generating professional ICANN-compliant abuse reports.

    Features:
    - Professional email templates
    - Evidence formatting
    - WHOIS data integration
    - Screenshot references
    - Multi-API threat intelligence summary
    - ICANN compliance language

    Example:
        ```python
        engine = ReportTemplateEngine()

        report = engine.generate_phishing_report(
            url="https://evil-bank.com",
            virustotal_positives=35,
            urlvoid_blacklists=8,
            screenshot_url="screenshots/evidence.png",
            whois_data={"registrar": "Evil Registrar", "creation_date": "2026-01-01"}
        )

        print(report["subject"])
        print(report["body"])
        ```
    """

    def __init__(self):
        """Initialize report template engine."""
        pass

    def generate_phishing_report(
        self,
        url: str,
        reporter_name: str = "Security Team",
        reporter_org: str = "Anisakys Security",
        reporter_email: str = "security@company.com",
        virustotal_positives: Optional[int] = None,
        virustotal_total: Optional[int] = None,
        urlvoid_blacklists: Optional[int] = None,
        urlvoid_engines: Optional[int] = None,
        phishtank_verified: Optional[bool] = None,
        confidence_score: Optional[float] = None,
        threat_level: Optional[str] = None,
        screenshot_url: Optional[str] = None,
        whois_data: Optional[Dict] = None,
        additional_notes: Optional[str] = None,
    ) -> Dict[str, str]:
        """Generate professional phishing report email.

        Args:
            url: URL being reported
            reporter_name: Name of reporter
            reporter_org: Reporter's organization
            reporter_email: Reporter's contact email
            virustotal_positives: Number of VT engines detecting threat
            virustotal_total: Total VT engines
            urlvoid_blacklists: Number of URLVoid blacklists
            urlvoid_engines: Total URLVoid engines
            phishtank_verified: PhishTank verification status
            confidence_score: Overall confidence score (0-100)
            threat_level: Threat level classification
            screenshot_url: Path to screenshot evidence
            whois_data: WHOIS lookup results
            additional_notes: Optional additional information

        Returns:
            Dict with "subject", "body", and "html_body" keys

        Example:
            ```python
            report = engine.generate_phishing_report(
                url="https://fake-paypal-secure.com",
                reporter_name="John Doe",
                reporter_org="Example Corp SOC",
                reporter_email="soc@example.com",
                virustotal_positives=42,
                virustotal_total=70,
                urlvoid_blacklists=15,
                confidence_score=92.5,
                threat_level="high",
                whois_data={"registrar": "Suspicious Registrar"}
            )
            ```
        """
        # Generate subject
        subject = self._generate_subject(url, threat_level)

        # Generate body
        body = self._generate_phishing_body(
            url=url,
            reporter_name=reporter_name,
            reporter_org=reporter_org,
            reporter_email=reporter_email,
            virustotal_positives=virustotal_positives,
            virustotal_total=virustotal_total,
            urlvoid_blacklists=urlvoid_blacklists,
            urlvoid_engines=urlvoid_engines,
            phishtank_verified=phishtank_verified,
            confidence_score=confidence_score,
            threat_level=threat_level,
            screenshot_url=screenshot_url,
            whois_data=whois_data,
            additional_notes=additional_notes,
        )

        # Generate HTML version
        html_body = self._generate_html_body(body)

        return {
            "subject": subject,
            "body": body,
            "html_body": html_body,
        }

    def generate_malware_report(
        self,
        url: str,
        reporter_name: str = "Security Team",
        reporter_org: str = "Anisakys Security",
        reporter_email: str = "security@company.com",
        virustotal_positives: Optional[int] = None,
        virustotal_total: Optional[int] = None,
        malware_type: Optional[str] = None,
        additional_notes: Optional[str] = None,
    ) -> Dict[str, str]:
        """Generate professional malware distribution report.

        Args:
            url: URL hosting malware
            reporter_name: Name of reporter
            reporter_org: Reporter's organization
            reporter_email: Reporter's contact email
            virustotal_positives: Number of AV engines detecting malware
            virustotal_total: Total AV engines
            malware_type: Type of malware detected
            additional_notes: Optional additional information

        Returns:
            Dict with "subject", "body", and "html_body" keys

        Example:
            ```python
            report = engine.generate_malware_report(
                url="https://evil-site.com/payload.exe",
                virustotal_positives=58,
                virustotal_total=70,
                malware_type="Trojan.Generic"
            )
            ```
        """
        subject = f"[URGENT] Malware Distribution Site Report - {self._extract_domain(url)}"

        body_template = """
Dear Abuse Team,

We are writing to report a website under your management that is actively distributing malware.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Malicious URL: {{ url }}
Report Date: {{ report_date }}
Threat Type: Malware Distribution
{% if malware_type %}Malware Type: {{ malware_type }}{% endif %}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{% if virustotal_positives %}VirusTotal Detection: {{ virustotal_positives }}/{{ virustotal_total }} antivirus engines detected malware
{% endif %}
This indicates confirmed malware distribution and presents an active threat to internet users.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUESTED ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

We respectfully request that you:
1. Immediately suspend or take down this malicious website
2. Investigate the account holder for Terms of Service violations
3. Provide confirmation of action taken
4. Consider implementing preventive measures for future abuse

ICANN requires registrars to respond to abuse complaints within 48 hours.

{% if additional_notes %}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ADDITIONAL INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{ additional_notes }}
{% endif %}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORTER INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Organization: {{ reporter_org }}
Reporter: {{ reporter_name }}
Contact: {{ reporter_email }}

Please respond to this email with confirmation of action taken.

Thank you for your prompt attention to this critical security matter.

Sincerely,
{{ reporter_name }}
{{ reporter_org }}

---
This report was generated by Anisakys ICANN Compliance System
Report ID: {{ report_id }}
"""

        template = Template(body_template)
        body = template.render(
            url=url,
            report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            malware_type=malware_type,
            virustotal_positives=virustotal_positives,
            virustotal_total=virustotal_total,
            reporter_name=reporter_name,
            reporter_org=reporter_org,
            reporter_email=reporter_email,
            additional_notes=additional_notes,
            report_id=datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        )

        return {
            "subject": subject,
            "body": body,
            "html_body": self._generate_html_body(body),
        }

    def _generate_subject(self, url: str, threat_level: Optional[str] = None) -> str:
        """Generate email subject line.

        Args:
            url: URL being reported
            threat_level: Optional threat level

        Returns:
            Subject line string
        """
        domain = self._extract_domain(url)
        urgency = "[URGENT]" if threat_level in ["high", "critical"] else ""

        return f"{urgency} Phishing Site Report - {domain}".strip()

    def _generate_phishing_body(
        self,
        url: str,
        reporter_name: str,
        reporter_org: str,
        reporter_email: str,
        virustotal_positives: Optional[int],
        virustotal_total: Optional[int],
        urlvoid_blacklists: Optional[int],
        urlvoid_engines: Optional[int],
        phishtank_verified: Optional[bool],
        confidence_score: Optional[float],
        threat_level: Optional[str],
        screenshot_url: Optional[str],
        whois_data: Optional[Dict],
        additional_notes: Optional[str],
    ) -> str:
        """Generate phishing report email body.

        Args:
            Various report parameters

        Returns:
            Formatted email body
        """
        body_template = """
Dear Abuse Team,

We are writing to report a phishing website operating under your management. This site is actively attempting to deceive users and steal sensitive information.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHISHING SITE DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Malicious URL: {{ url }}
Detection Date: {{ report_date }}
Threat Type: Phishing
{% if threat_level %}Threat Level: {{ threat_level|upper }}{% endif %}
{% if confidence_score %}Confidence Score: {{ confidence_score }}%{% endif %}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE VERIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{% if virustotal_positives %}✓ VirusTotal: {{ virustotal_positives }}/{{ virustotal_total }} security vendors flagged this URL as malicious
{% endif %}{% if urlvoid_blacklists %}✓ URLVoid: Listed in {{ urlvoid_blacklists }}/{{ urlvoid_engines }} reputation blacklists
{% endif %}{% if phishtank_verified %}✓ PhishTank: Verified as active phishing site in community database
{% endif %}
Our multi-source threat intelligence analysis confirms this is an active phishing threat.

{% if whois_data %}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DOMAIN REGISTRATION INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{% if whois_data.registrar %}Registrar: {{ whois_data.registrar }}
{% endif %}{% if whois_data.creation_date %}Registration Date: {{ whois_data.creation_date }}
{% endif %}{% if whois_data.abuse_email %}Abuse Contact: {{ whois_data.abuse_email }}
{% endif %}{% endif %}

{% if screenshot_url %}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EVIDENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Screenshot evidence is attached to this email showing the fraudulent website.
Screenshot: {{ screenshot_url }}
{% endif %}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUESTED ACTION (ICANN COMPLIANCE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

We respectfully request that you take immediate action:

1. SUSPEND or TAKE DOWN the reported phishing website
2. INVESTIGATE the domain registrant for Terms of Service violations
3. PROVIDE confirmation of action taken within 48 hours (ICANN requirement)
4. IMPLEMENT preventive measures to prevent future abuse

Per ICANN requirements, registrars must respond to abuse complaints within 48 hours of receipt.

{% if additional_notes %}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ADDITIONAL INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{ additional_notes }}
{% endif %}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORTER CONTACT INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Organization: {{ reporter_org }}
Security Team: {{ reporter_name }}
Email: {{ reporter_email }}

Please respond to this email confirming receipt and providing an estimated timeline for resolution.

Thank you for your prompt attention to this critical security matter. Your cooperation helps protect internet users from fraud.

Best regards,
{{ reporter_name }}
{{ reporter_org }}

---
This report was automatically generated by Anisakys ICANN Compliance System
Report ID: {{ report_id }}
Generated: {{ report_date }}
"""

        template = Template(body_template)
        body = template.render(
            url=url,
            report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            threat_level=threat_level,
            confidence_score=confidence_score,
            virustotal_positives=virustotal_positives,
            virustotal_total=virustotal_total,
            urlvoid_blacklists=urlvoid_blacklists,
            urlvoid_engines=urlvoid_engines,
            phishtank_verified=phishtank_verified,
            screenshot_url=screenshot_url,
            whois_data=whois_data,
            reporter_name=reporter_name,
            reporter_org=reporter_org,
            reporter_email=reporter_email,
            additional_notes=additional_notes,
            report_id=datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        )

        return body

    def _generate_html_body(self, plain_text_body: str) -> str:
        """Generate HTML version of email body.

        Args:
            plain_text_body: Plain text email body

        Returns:
            HTML formatted body
        """
        # Simple HTML wrapper with basic formatting
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #dc3545; color: white; padding: 15px; text-align: center; }}
        .content {{ background-color: #f8f9fa; padding: 20px; }}
        .section {{ margin-bottom: 20px; padding: 15px; background-color: white; border-left: 4px solid #dc3545; }}
        .footer {{ text-align: center; color: #6c757d; font-size: 12px; padding: 15px; }}
        pre {{ background-color: #f1f1f1; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>⚠️ ICANN Abuse Report</h2>
        </div>
        <div class="content">
            <pre>{plain_text_body}</pre>
        </div>
        <div class="footer">
            <p>This is an automated report from Anisakys ICANN Compliance System</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL.

        Args:
            url: Full URL

        Returns:
            Domain name
        """
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except:
            return url

"""
Registrar/Hosting abuse web form URL database.

Maps registrar/hosting name patterns to their abuse web form URLs and reporting method.
Only includes providers that have dedicated web forms.
Providers NOT in this DB accept email — covered by WHOIS all_abuse_emails.

Methods:
- form_only: Email reports are ignored/rejected. Web form is the ONLY way.
- form_and_email: Both web form and email work. Form is usually faster.
"""

from typing import Dict, List, Optional


# Each entry: patterns (lowercase substrings to match against registrar_name),
# form_url, and method
REGISTRAR_FORM_DB: List[Dict] = [
    # === FORM ONLY (email does NOT work) ===
    {
        "patterns": ["godaddy"],
        "name": "GoDaddy",
        "form_url": "https://supportcenter.godaddy.com/abusereport/phishing",
        "method": "form_only",
    },
    {
        "patterns": ["cloudflare, inc", "cloudflare registrar"],
        "name": "Cloudflare Registrar",
        "form_url": "https://abuse.cloudflare.com/phishing",
        "method": "form_only",
    },
    {
        "patterns": ["porkbun"],
        "name": "Porkbun",
        "form_url": "https://porkbun.com/abuse",
        "method": "form_only",
    },
    {
        "patterns": ["ovh", "ovhcloud"],
        "name": "OVHcloud",
        "form_url": "https://www.ovhcloud.com/en/abuse/",
        "method": "form_only",
    },
    {
        "patterns": ["google llc", "google domains"],
        "name": "Google Cloud",
        "form_url": "https://support.google.com/code/contact/cloud_platform_report",
        "method": "form_only",
    },
    {
        "patterns": ["microsoft"],
        "name": "Microsoft Azure",
        "form_url": "https://msrc.microsoft.com/report/abuse",
        "method": "form_only",
    },
    # === FORM AND EMAIL (both work, form is faster) ===
    {
        "patterns": ["tucows", "enom"],
        "name": "Tucows / Enom",
        "form_url": "https://tucowsdomains.com/abuse-form/phishing/",
        "method": "form_and_email",
    },
    {
        "patterns": ["squarespace"],
        "name": "Squarespace",
        "form_url": "https://support.squarespace.com/hc/en-us/requests/new?ticket_form_id=23532118441357",
        "method": "form_and_email",
    },
    {
        "patterns": ["name.com"],
        "name": "Name.com",
        "form_url": "https://www.name.com/abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["dynadot"],
        "name": "Dynadot",
        "form_url": "https://www.dynadot.com/report-abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["gandi"],
        "name": "Gandi",
        "form_url": "https://help.gandi.net/en/abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["hostinger"],
        "name": "Hostinger",
        "form_url": "https://www.hostinger.com/report-abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["namesilo"],
        "name": "NameSilo",
        "form_url": "https://www.namesilo.com/phishing-report",
        "method": "form_and_email",
    },
    {
        "patterns": ["ionos", "1&1"],
        "name": "IONOS",
        "form_url": "https://registrar.ionos.info/domains_raa/complaints",
        "method": "form_and_email",
    },
    {
        "patterns": [
            "newfold",
            "network solutions",
            "register.com",
            "bluehost",
            "web.com",
            "hostgator",
        ],
        "name": "Newfold Digital",
        "form_url": "https://www.newfold.com/abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["publicdomainregistry", "pdr ltd", "pdr"],
        "name": "PublicDomainRegistry",
        "form_url": "https://publicdomainregistry.com/phishing/",
        "method": "form_and_email",
    },
    {
        "patterns": ["reg.ru"],
        "name": "REG.RU",
        "form_url": "https://www.reg.ru/legal/abuse/",
        "method": "form_and_email",
    },
    {
        "patterns": ["amazon", "aws"],
        "name": "Amazon / AWS",
        "form_url": "https://support.aws.amazon.com/#/contacts/report-abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["digitalocean"],
        "name": "DigitalOcean",
        "form_url": "https://www.digitalocean.com/company/contact/abuse",
        "method": "form_and_email",
    },
    {
        "patterns": ["hetzner"],
        "name": "Hetzner",
        "form_url": "https://abuse.hetzner.com/en",
        "method": "form_and_email",
    },
    {
        "patterns": ["contabo"],
        "name": "Contabo",
        "form_url": "https://contabo.com/en/abuse/",
        "method": "form_and_email",
    },
    {
        "patterns": ["linode", "akamai"],
        "name": "Linode / Akamai",
        "form_url": "https://www.linode.com/legal-abuse/",
        "method": "form_and_email",
    },
    {
        "patterns": ["alibaba", "hichina", "aliyun"],
        "name": "Alibaba Cloud",
        "form_url": "https://www.alibabacloud.com/report",
        "method": "form_and_email",
    },
    {
        "patterns": ["fastly"],
        "name": "Fastly CDN",
        "form_url": "https://abuse.fastly.com/",
        "method": "form_and_email",
    },
    {
        "patterns": ["sucuri"],
        "name": "Sucuri",
        "form_url": "https://abuse.sucuri.net/",
        "method": "form_and_email",
    },
]


def lookup_registrar_form(registrar_name: Optional[str]) -> Optional[Dict]:
    """
    Look up a registrar's abuse web form URL and reporting method.

    Args:
        registrar_name: Registrar name from WHOIS (e.g. "GoDaddy.com, LLC")

    Returns:
        Dict with form_url, method, name if matched. None if no form found.
        None means email works fine (covered by WHOIS all_abuse_emails).
    """
    if not registrar_name:
        return None

    lower = registrar_name.lower()
    for entry in REGISTRAR_FORM_DB:
        if any(p in lower for p in entry["patterns"]):
            return {
                "name": entry["name"],
                "form_url": entry["form_url"],
                "method": entry["method"],
            }

    return None

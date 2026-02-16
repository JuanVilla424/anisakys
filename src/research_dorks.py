"""
Google Dorks Generator for Phishing Research
"""
import requests
from typing import Dict, List, Any
import datetime


def generate_dorks(target_domain: str, target_brand: str = None) -> Dict[str, Any]:
    """
    Generate Google Dorks for phishing detection research.

    Args:
        target_domain: The legitimate domain to protect (e.g., facebook.com)
        target_brand: Brand name (e.g., facebook). If None, derived from domain.

    Returns:
        Dictionary with generated dorks organized by category
    """
    # Use domain as brand if brand not provided
    if not target_brand:
        target_brand = target_domain.replace('.com', '').replace('.net', '').replace('.org', '').replace('www.', '')

    # Generate Google Dorks for phishing detection
    dorks = [
        {
            "category": "Login Page Impersonation",
            "description": "Find fake login pages mimicking the target brand",
            "dorks": [
                f'intitle:"{target_brand}" intitle:"login" -site:{target_domain}',
                f'intitle:"{target_brand}" "sign in" -site:{target_domain}',
                f'intitle:"{target_brand}" "password" -site:{target_domain}',
                f'"{target_brand} login" -site:{target_domain}',
            ]
        },
        {
            "category": "Domain Typosquatting",
            "description": "Detect domains similar to the target trying to confuse users",
            "dorks": [
                f'inurl:{target_brand} -site:{target_domain}',
                f'site:*{target_brand}*.com -site:{target_domain}',
                f'site:*{target_brand}*.net -site:{target_domain}',
                f'"{target_brand}" inurl:verify -site:{target_domain}',
            ]
        },
        {
            "category": "Credential Harvesting",
            "description": "Identify phishing attempts trying to steal credentials",
            "dorks": [
                f'"{target_brand}" "confirm your account" -site:{target_domain}',
                f'"{target_brand}" "verify your identity" -site:{target_domain}',
                f'"{target_brand}" "suspended account" -site:{target_domain}',
                f'"{target_brand}" "unusual activity" -site:{target_domain}',
                f'"{target_brand}" "security alert" -site:{target_domain}',
            ]
        },
        {
            "category": "Fake Support Pages",
            "description": "Find fake support/help pages",
            "dorks": [
                f'"{target_brand} support" -site:{target_domain}',
                f'"{target_brand} help" inurl:login -site:{target_domain}',
                f'"{target_brand} customer service" -site:{target_domain}',
                f'"{target_brand} contact" inurl:verify -site:{target_domain}',
            ]
        },
        {
            "category": "Suspicious File Types",
            "description": "HTML/PHP files potentially containing phishing forms",
            "dorks": [
                f'"{target_brand}" filetype:html "password" -site:{target_domain}',
                f'"{target_brand}" filetype:php "login" -site:{target_domain}',
                f'"{target_brand}" filetype:html "submit" -site:{target_domain}',
            ]
        },
        {
            "category": "Mobile App Scams",
            "description": "Fake mobile apps or app download pages",
            "dorks": [
                f'"{target_brand} app" "download" -site:{target_domain} -site:play.google.com -site:apple.com',
                f'"{target_brand} mobile" "apk" -site:{target_domain}',
                f'"{target_brand}" "install app" -site:{target_domain} -site:play.google.com',
            ]
        }
    ]

    # Generate search URLs for each dork
    for category in dorks:
        enhanced_dorks = []
        for dork in category["dorks"]:
            enhanced_dorks.append({
                "query": dork,
                "google_url": f"https://www.google.com/search?q={requests.utils.quote(dork)}",
                "duckduckgo_url": f"https://duckduckgo.com/?q={requests.utils.quote(dork)}",
                "bing_url": f"https://www.bing.com/search?q={requests.utils.quote(dork)}"
            })
        category["dorks"] = enhanced_dorks

    result = {
        "target_domain": target_domain,
        "target_brand": target_brand,
        "total_dorks": sum(len(cat["dorks"]) for cat in dorks),
        "categories": dorks,
        "timestamp": datetime.datetime.now().isoformat(),
        "recommendations": [
            "⚠️ Review results manually - expect false positives",
            "🔍 Check domain registration dates (new domains are more suspicious)",
            "🔒 Verify SSL certificates on suspected sites",
            "🛡️ Use VirusTotal to scan suspicious URLs before visiting",
            "📧 Report confirmed phishing sites to hosting providers",
            "⏰ Set up monitoring - phishing sites change rapidly"
        ]
    }

    return result

"""
Data module for Anisakys Phishing Detection Engine.

Contains static databases for abuse contacts, WHOIS servers, and registrar information.
"""

from src.data.asn_abuse_db import ASN_ABUSE_EMAIL_DB
from src.data.provider_abuse_db import PROVIDER_ABUSE_EMAIL_DB
from src.data.registrar_abuse_db import ENHANCED_REGISTRAR_ABUSE_DB
from src.data.whois_servers import TLD_WHOIS_SERVERS

__all__ = [
    "ASN_ABUSE_EMAIL_DB",
    "PROVIDER_ABUSE_EMAIL_DB",
    "ENHANCED_REGISTRAR_ABUSE_DB",
    "TLD_WHOIS_SERVERS",
]

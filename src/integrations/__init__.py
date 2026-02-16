"""External API integrations for threat validation."""

from src.integrations.virustotal import VirusTotalClient
from src.integrations.urlvoid import URLVoidClient
from src.integrations.phishtank import PhishTankClient

__all__ = [
    "VirusTotalClient",
    "URLVoidClient",
    "PhishTankClient",
]

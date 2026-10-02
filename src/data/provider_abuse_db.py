"""
Provider name to abuse email mapping database.

Fallback database when ASN lookup fails, uses provider name matching.
EPIC-005: Normalized to lists for multi-contact handling.
"""

# Provider name to abuse email mapping (fallback when ASN lookup fails)
PROVIDER_ABUSE_EMAIL_DB = {
    # Major Cloud & Hosting Providers (Case-insensitive matching)
    "HOSTINGER": ["abuse@hostinger.com"],
    "HOSTINGER-HOSTING": ["abuse@hostinger.com"],
    "DIGITALOCEAN": ["abuse@digitalocean.com"],
    "AMAZON": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
    "AWS": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
    "MICROSOFT": ["abuse@microsoft.com", "msrc@microsoft.com"],
    "AZURE": ["abuse@microsoft.com", "msrc@microsoft.com"],
    "GOOGLE": ["abuse@google.com"],
    "GOOGLE-CLOUD": ["abuse@google.com"],
    "CLOUDFLARE": ["abuse@cloudflare.com", "trust-safety@cloudflare.com"],
    "AKAMAI": ["abuse@akamai.com"],
    "OVH": ["abuse@ovh.com"],
    "HETZNER": ["abuse@hetzner.de"],
    "HETZNER-ONLINE": ["abuse@hetzner.de"],
    "LINODE": ["abuse@linode.com"],
    "VULTR": ["abuse@vultr.com"],
    "GODADDY": ["abuse@godaddy.com"],
    "CONTABO": ["abuse@contabo.com"],
    "IONOS": ["abuse@oneandone.net"],
    "1&1": ["abuse@oneandone.net"],
    # Additional Major Providers
    "NAMECHEAP": ["abuse@namecheap.com"],
    "DREAMHOST": ["abuse@dreamhost.com"],
    "BLUEHOST": ["abuse@unified-layer.com"],
    "HOSTGATOR": ["abuse@unified-layer.com"],
    "UNIFIED-LAYER": ["abuse@unified-layer.com"],
    "LIQUIDWEB": ["abuse@liquidweb.com"],
    "LIQUID-WEB": ["abuse@liquidweb.com"],
    # European Providers
    "LEASEWEB": ["abuse@leaseweb.com"],
    "SERVERIUS": ["abuse@serverius.net"],
    "WORLDSTREAM": ["abuse@worldstream.nl"],
    "UKFAST": ["abuse@ukfast.co.uk"],
    "MYLOC": ["abuse@myloc.de"],
    "CORE-BACKBONE": ["abuse@core-backbone.com"],
    # US/Canadian Providers
    "PSYCHZ": ["abuse@psychz.net"],
    "PSYCHZ-NETWORKS": ["abuse@psychz.net"],
    "HOSTWINDS": ["abuse@hostwinds.com"],
    "HIVELOCITY": ["abuse@hivelocity.net"],
    "DEDIPATH": ["abuse@dedipath.com"],
    "NETACTUATE": ["abuse@netactivity.us"],
    "PACKET": ["abuse@packet.com"],
    "EQUINIX": ["abuse@packet.com"],
    # Asian Providers
    "GCORE": ["abuse@gcorelabs.com"],
    "G-CORE": ["abuse@gcorelabs.com"],
    "GCORELABS": ["abuse@gcorelabs.com"],
    "NTT": ["abuse@ntt.com", "security@ntt.com"],
    "SOFTBANK": ["abuse@softbank.jp"],
    "VIRTUOZZO": ["abuse@virtuozzo.com"],
    # Registrars and Domains
    "ENOM": ["abuse@enom.com"],
    "NETWORK-SOLUTIONS": ["abuse@networksolutions.com"],
    "TUCOWS": ["abuse@tucows.com"],
    "GANDI": ["abuse@gandi.net"],
    # Telecom Providers
    "COMCAST": ["abuse@comcast.net"],
    "CHARTER": ["abuse@charter.com"],
    "SPECTRUM": ["abuse@charter.com"],
    "VERIZON": ["abuse@verizon.net"],
    "AT&T": ["abuse@att.net"],
    "COX": ["abuse@cox.net"],
    # International Providers
    "TELEFONICA": ["abuse@telefonica.es"],
    "ORANGE": ["abuse@orange.com"],
    "PROXIMUS": ["abuse@proximus.be"],
    "TELSTRA": ["abuse@telstra.com.au"],
    "TPG": ["abuse@tpg.com.au"],
    # Common Partial Matches
    "NET-": ["abuse@"],  # Will be handled by partial matching
    "AS-": ["abuse@"],  # Will be handled by partial matching
    "HOSTING": ["abuse@"],  # Generic hosting fallback
    "CLOUD": ["abuse@"],  # Generic cloud fallback
}

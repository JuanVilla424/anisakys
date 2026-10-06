"""
URL lexical analysis for phishing detection.

Brand impersonation (typosquatting, combo-squatting, look-alike characters, a brand in a
subdomain) comes from the brand catalogue, matched on token boundaries with official
domains first (src/detection/normalize.py, src/brands/catalog.py): a brand's own domains
never impersonate it, a short brand name only matches a whole token, and look-alike
characters are compared through UTS-39 skeletons. Keywords and TLDs are simple lists.
"""

import logging
import unicodedata
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.detection.normalize import BrandCatalog, BrandMatch, Host, normalize_host, skeleton

logger = logging.getLogger(__name__)

# Known brands/targets for typosquatting detection
KNOWN_BRANDS = {
    # Banks - Colombia
    "bancolombia": ["bancolombia.com", "bancolombia.com.co"],
    "davivienda": ["davivienda.com", "davivienda.com.co"],
    "bbva": ["bbva.com", "bbva.com.co", "bbvanet.com.co"],
    "bancodebogota": ["bancodebogota.com", "bancodebogota.com.co"],
    "bancopopular": ["bancopopular.com.co"],
    "colpatria": ["colpatria.com", "scotiabankcolpatria.com"],
    "avvillas": ["avvillas.com.co"],
    "nequi": ["nequi.com", "nequi.com.co"],
    "daviplata": ["daviplata.com"],
    # Banks - International
    "paypal": ["paypal.com", "paypal.me"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "hsbc": ["hsbc.com"],
    "santander": ["santander.com", "santander.com.co"],
    # Tech Companies
    "google": ["google.com", "gmail.com", "googleapis.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "hotmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "spotify": ["spotify.com"],
    "dropbox": ["dropbox.com"],
    "zoom": ["zoom.us"],
    # E-commerce
    "mercadolibre": ["mercadolibre.com", "mercadolibre.com.co", "mercadopago.com"],
    "rappi": ["rappi.com", "rappi.com.co"],
    "ebay": ["ebay.com"],
    "aliexpress": ["aliexpress.com"],
    # Government - Colombia
    "dian": ["dian.gov.co"],
    "govco": ["gov.co"],
    "registraduria": ["registraduria.gov.co"],
    "mintransporte": ["mintransporte.gov.co"],
    # Crypto
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "blockchain": ["blockchain.com"],
}

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    # Authentication
    "login",
    "signin",
    "sign-in",
    "log-in",
    "logon",
    "password",
    "passwd",
    "pwd",
    "authenticate",
    "auth",
    "verify",
    "verification",
    "verificar",
    "confirm",
    "confirmar",
    "confirmacion",
    "validate",
    "validar",
    "validacion",
    # Account actions
    "account",
    "cuenta",
    "mi-cuenta",
    "update",
    "actualizar",
    "actualizacion",
    "unlock",
    "desbloquear",
    "bloqueo",
    "suspend",
    "suspended",
    "suspendido",
    "reactivate",
    "reactivar",
    "recover",
    "recovery",
    "recuperar",
    "reset",
    "restablecer",
    # Security
    "secure",
    "security",
    "seguro",
    "seguridad",
    "alert",
    "alerta",
    "warning",
    "unusual",
    "suspicious",
    "compromised",
    "comprometido",
    # Urgency
    "urgent",
    "urgente",
    "immediately",
    "inmediato",
    "expire",
    "expir",
    "vence",
    "vencimiento",
    "limit",
    "limited",
    "limite",
    "limitado",
    "action-required",
    "accion-requerida",
    # Financial
    "bank",
    "banco",
    "banking",
    "payment",
    "pago",
    "pagos",
    "invoice",
    "factura",
    "transaction",
    "transaccion",
    "transfer",
    "transferencia",
    "transferir",
    "credit",
    "credito",
    "tarjeta",
    "refund",
    "reembolso",
    "bonus",
    "premio",
    "reward",
    # Personal info
    "ssn",
    "social-security",
    "cedula",
    "documento",
    "identity",
    "identidad",
    # Support/Service
    "support",
    "soporte",
    "help",
    "ayuda",
    "customer",
    "cliente",
    "service",
    "servicio",
]

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    # Freenom - Free TLDs (80-88% malicious)
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    # Extremely high abuse (90%+ malicious)
    ".buzz",
    ".wang",
    ".host",
    ".icu",
    ".live",
    # Very high abuse (70-90% malicious)
    ".xin",
    ".top",
    ".qpon",
    ".info",
    # High abuse (50-70% malicious)
    ".xyz",
    ".online",
    ".locker",
    ".lgbt",
    ".cc",
    # Country codes with high abuse
    ".cn",
    ".us",
    ".ru",
    ".su",
    ".li",
    ".ws",
    ".pw",
    # Phishing kits / cheap registration
    ".sbs",
    ".cfd",
    ".shop",
    # Common phishing TLDs
    ".bid",
    ".loan",
    ".win",
    ".click",
    ".link",
    ".work",
    ".date",
    ".review",
    ".stream",
    ".download",
    ".racing",
    ".cricket",
    ".science",
    ".site",
    ".party",
    ".trade",
    ".webcam",
    # High abuse misc
    ".town",
    ".pizza",
    ".pictures",
    ".poker",
    ".biz",
    # Confusing TLDs (look like file extensions)
    ".zip",
    ".mov",
]


class URLAnalyzer:
    """Analyzes URLs for phishing indicators"""

    def __init__(self, catalog: Optional[BrandCatalog] = None):
        """Create an analyzer.

        Args:
            catalog: Brand catalogue (default: the current detection catalogue, built-in
                brands plus the ones added from the console).
        """
        self.brands = KNOWN_BRANDS
        self.suspicious_keywords = SUSPICIOUS_KEYWORDS
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self._catalog = catalog

    def catalog(self) -> BrandCatalog:
        """The brand catalogue used for matching.

        Returns:
            The fixed catalogue given at construction, else the current one.
        """
        if self._catalog is not None:
            return self._catalog
        from src.brands.catalog import current_catalog

        return current_catalog()

    def analyze(self, url: str) -> Dict:
        """
        Perform comprehensive URL analysis

        Returns:
            Dict with analysis results and risk indicators
        """
        try:
            host = normalize_host(url)
            domain = host.ascii if host else ""
            catalog = self.catalog()
            matches = catalog.match(host)

            results = {
                "url": url,
                "domain": domain,
                "official_brand": catalog.official_brand(host),
                "typosquatting": self._typosquatting(matches, catalog),
                "homoglyphs": self._homoglyphs(host, matches),
                "suspicious_keywords": self._detect_keywords(url),
                "suspicious_tld": self._check_tld(domain),
                "combo_squatting": self._combo_squatting(host, matches),
                "tld_swap": self._tld_swap(host, matches),
                "excessive_subdomains": self._subdomains(host, matches),
                "risk_score": 0,
                "risk_factors": [],
            }

            # Calculate risk score
            results["risk_score"], results["risk_factors"] = self._calculate_risk(results)

            return results

        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            return {
                "url": url,
                "error": str(e),
                "risk_score": 0,
                "risk_factors": [],
            }

    @staticmethod
    def _typosquatting(matches: Sequence[BrandMatch], catalog: BrandCatalog) -> Dict[str, Any]:
        """A brand spelled with edits or ASCII look-alikes (``paypall``, ``rnicrosoft``)."""
        for match in matches:
            ascii_look_alike = match.kind == "homoglyph" and match.token.isascii()
            if match.kind == "typo" or ascii_look_alike:
                return {
                    "detected": True,
                    "target_brand": match.brand,
                    "similarity": match.score,
                    "techniques": [
                        "look_alike_characters" if ascii_look_alike else "edit_distance"
                    ],
                    "legitimate_domains": catalog.official_domains(match.brand),
                }
        return {"detected": False, "target_brand": None, "similarity": 0.0, "techniques": []}

    @staticmethod
    def _homoglyphs(host: Optional[Host], matches: Sequence[BrandMatch]) -> Dict[str, Any]:
        """Non-ASCII characters that look like Latin letters (IDN homograph attacks)."""
        result: Dict[str, Any] = {
            "detected": False,
            "homoglyphs_found": [],
            "normalized_domain": host.ascii if host else "",
            "target_brand": None,
        }
        if host is None or not host.is_idn:
            return result
        found: List[Dict[str, str]] = []
        for char in host.unicode:
            if ord(char) < 128:
                continue
            prototype = skeleton(char)
            if prototype.isascii() and prototype.strip():
                found.append(
                    {
                        "original": char,
                        "looks_like": prototype,
                        "unicode_name": unicodedata.name(char, "UNKNOWN"),
                    }
                )
        if found:
            result["detected"] = True
            result["homoglyphs_found"] = found
            result["normalized_domain"] = skeleton(host.unicode)
            for match in matches:
                if match.kind == "homoglyph" and not match.token.isascii():
                    result["target_brand"] = match.brand
                    break
        return result

    @staticmethod
    def _combo_squatting(host: Optional[Host], matches: Sequence[BrandMatch]) -> Dict[str, Any]:
        """A brand plus other words in a domain that is not the brand's."""
        for match in matches:
            if match.kind != "combo" or host is None:
                continue
            if match.alias and match.alias in host.label:
                pattern = host.label.replace(match.alias, "[BRAND]", 1)
            else:
                pattern = match.token.replace(match.alias, "[BRAND]", 1)
            return {"detected": True, "target_brand": match.brand, "combo_pattern": pattern}
        return {"detected": False, "target_brand": None, "combo_pattern": None}

    @staticmethod
    def _tld_swap(host: Optional[Host], matches: Sequence[BrandMatch]) -> Dict[str, Any]:
        """The brand's exact name under a suffix the catalogue does not list as its own.

        Ambiguous on its own: global brands hold their name under many country and
        generic suffixes (``google.com.pe``, ``amazon.fr``), and attackers register it
        under others (``bancolombia.co``). The scan weighs it with the domain's age.
        """
        for match in matches:
            if match.kind == "brand_label" and host is not None:
                return {"detected": True, "target_brand": match.brand, "suffix": host.suffix}
        return {"detected": False, "target_brand": None, "suffix": None}

    @staticmethod
    def _subdomains(host: Optional[Host], matches: Sequence[BrandMatch]) -> Dict[str, Any]:
        """Excessive subdomains, and brands hidden in a subdomain."""
        result: Dict[str, Any] = {"detected": False, "subdomain_count": 0, "subdomains": []}
        if host is None or host.is_ip or not host.subdomain:
            return result
        subdomains = [s for s in host.subdomain.split(".") if s]
        result["subdomain_count"] = len(subdomains)
        result["subdomains"] = subdomains
        if len(subdomains) > 2:
            result["detected"] = True
        sub_segments = {p for s in subdomains for p in s.replace("_", "-").split("-") if p}
        for match in matches:
            if match.token in sub_segments:
                result["detected"] = True
                result["brand_in_subdomain"] = match.brand
                break
        return result

    def _detect_keywords(self, url: str) -> Dict:
        """Detect suspicious keywords in URL"""
        result = {
            "detected": False,
            "keywords_found": [],
            "count": 0,
        }

        url_lower = url.lower()
        found = []

        for keyword in self.suspicious_keywords:
            # Check for keyword in URL path, params, or subdomain
            if keyword in url_lower:
                found.append(keyword)

        if found:
            result["detected"] = True
            result["keywords_found"] = list(set(found))  # Remove duplicates
            result["count"] = len(result["keywords_found"])

        return result

    def _check_tld(self, domain: str) -> Dict:
        """Check if domain uses a suspicious TLD"""
        result = {
            "detected": False,
            "tld": None,
        }

        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                result["detected"] = True
                result["tld"] = tld
                break

        return result

    def _calculate_risk(self, analysis: Dict) -> Tuple[int, List[str]]:
        """Calculate overall risk score and list factors"""
        score = 0
        factors = []

        # Typosquatting (high risk)
        if analysis["typosquatting"]["detected"]:
            score += 40
            brand = analysis["typosquatting"]["target_brand"]
            techniques = ", ".join(analysis["typosquatting"]["techniques"])
            factors.append(f"Typosquatting detected targeting '{brand}' ({techniques})")

        # Homoglyphs (very high risk)
        if analysis["homoglyphs"]["detected"]:
            score += 50
            chars = [h["original"] for h in analysis["homoglyphs"]["homoglyphs_found"]]
            factors.append(f"Homoglyph/IDN attack detected: {chars}")

        # Suspicious keywords
        if analysis["suspicious_keywords"]["detected"]:
            keyword_count = analysis["suspicious_keywords"]["count"]
            score += min(keyword_count * 5, 25)  # Max 25 points
            keywords = analysis["suspicious_keywords"]["keywords_found"][:5]
            factors.append(f"Suspicious keywords: {', '.join(keywords)}")

        # Suspicious TLD
        if analysis["suspicious_tld"]["detected"]:
            score += 15
            factors.append(f"Suspicious TLD: {analysis['suspicious_tld']['tld']}")

        # Combo-squatting
        if analysis["combo_squatting"]["detected"]:
            score += 30
            brand = analysis["combo_squatting"]["target_brand"]
            factors.append(f"Combo-squatting detected targeting '{brand}'")

        # The brand's exact name under another suffix (weighed with the domain age later)
        tld_swap = analysis.get("tld_swap") or {}
        if tld_swap.get("detected"):
            score += 20
            factors.append(
                f"Brand name '{tld_swap['target_brand']}' under another suffix (.{tld_swap['suffix']})"
            )

        # Excessive subdomains
        if analysis["excessive_subdomains"]["detected"]:
            score += 10
            count = analysis["excessive_subdomains"]["subdomain_count"]
            factors.append(f"Excessive subdomains: {count} levels")

            if analysis["excessive_subdomains"].get("brand_in_subdomain"):
                score += 20
                brand = analysis["excessive_subdomains"]["brand_in_subdomain"]
                factors.append(f"Brand name '{brand}' hidden in subdomain")

        return min(score, 100), factors


# Singleton instance
url_analyzer = URLAnalyzer()

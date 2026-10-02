"""
URL Analyzer for Phishing Detection
Implements typosquatting, homograph, and keyword detection
"""

import re
import logging
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse
import unicodedata

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

# Homoglyph mappings (characters that look similar)
HOMOGLYPHS = {
    "a": ["а", "ɑ", "α", "а", "@", "4"],  # Cyrillic а, Latin alpha
    "b": ["Ь", "ь", "β", "6", "8"],
    "c": ["с", "ϲ", "ς", "("],  # Cyrillic с
    "d": ["ԁ", "ɗ"],
    "e": ["е", "ё", "є", "ε", "3"],  # Cyrillic е
    "g": ["ɡ", "ց", "9", "q"],
    "h": ["һ", "հ"],  # Cyrillic һ
    "i": ["і", "і", "ι", "1", "l", "!", "|"],  # Cyrillic і
    "j": ["ј", "ʝ"],  # Cyrillic ј
    "k": ["κ", "к"],  # Cyrillic к
    "l": ["1", "i", "|", "ӏ", "I"],
    "m": ["м", "rn"],  # Cyrillic м, rn combo
    "n": ["п", "ո"],
    "o": ["о", "ο", "σ", "0", "ө"],  # Cyrillic о, Greek omicron
    "p": ["р", "ρ"],  # Cyrillic р
    "q": ["զ", "գ"],
    "r": ["г", "ř"],
    "s": ["ѕ", "$", "5"],  # Cyrillic ѕ
    "t": ["т", "+", "7"],
    "u": ["υ", "ս", "μ"],
    "v": ["ν", "ѵ"],  # Greek nu
    "w": ["ω", "ѡ", "vv"],
    "x": ["х", "χ", "×"],  # Cyrillic х
    "y": ["у", "γ", "ү"],  # Cyrillic у
    "z": ["ζ", "2"],
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

    def __init__(self):
        self.brands = KNOWN_BRANDS
        self.homoglyphs = HOMOGLYPHS
        self.suspicious_keywords = SUSPICIOUS_KEYWORDS
        self.suspicious_tlds = SUSPICIOUS_TLDS

        # Build reverse mapping for faster lookups
        self._brand_domains = {}
        for brand, domains in self.brands.items():
            for domain in domains:
                self._brand_domains[domain.lower()] = brand

    def analyze(self, url: str) -> Dict:
        """
        Perform comprehensive URL analysis

        Returns:
            Dict with analysis results and risk indicators
        """
        try:
            parsed = urlparse(url.lower())
            domain = parsed.netloc or parsed.path.split("/")[0]

            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]

            results = {
                "url": url,
                "domain": domain,
                "typosquatting": self._detect_typosquatting(domain),
                "homoglyphs": self._detect_homoglyphs(domain),
                "suspicious_keywords": self._detect_keywords(url),
                "suspicious_tld": self._check_tld(domain),
                "combo_squatting": self._detect_combo_squatting(domain),
                "excessive_subdomains": self._check_subdomains(domain),
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

    def _detect_typosquatting(self, domain: str) -> Dict:
        """Detect typosquatting attempts against known brands"""
        result = {
            "detected": False,
            "target_brand": None,
            "similarity": 0.0,
            "techniques": [],
        }

        # Extract base domain (without TLD)
        parts = domain.split(".")
        if len(parts) < 2:
            return result

        # Check main domain and subdomains
        domains_to_check = [parts[-2]]  # Main domain
        if len(parts) > 2:
            domains_to_check.extend(parts[:-2])  # Subdomains

        for check_domain in domains_to_check:
            # Normalize l33t speak substitutions
            normalized = self._normalize_leet(check_domain)

            for brand, legitimate_domains in self.brands.items():
                # Skip if it's the legitimate domain
                if domain in legitimate_domains:
                    return result

                # Check both original and normalized versions
                for variant in [check_domain, normalized]:
                    similarity = self._calculate_similarity(variant, brand)

                    # Direct match after normalization
                    if normalized == brand and check_domain != brand:
                        result["detected"] = True
                        result["target_brand"] = brand
                        result["similarity"] = 1.0
                        result["techniques"] = ["leet_speak_substitution"]
                        result["legitimate_domains"] = legitimate_domains
                        return result

                    if similarity >= 0.65 and similarity < 1.0:
                        techniques = self._identify_typo_techniques(variant, brand)
                        if techniques or similarity >= 0.8:
                            result["detected"] = True
                            result["target_brand"] = brand
                            result["similarity"] = similarity
                            result["techniques"] = (
                                techniques if techniques else ["similar_spelling"]
                            )
                            result["legitimate_domains"] = legitimate_domains
                            return result

        return result

    def _normalize_leet(self, text: str) -> str:
        """Normalize l33t speak substitutions to standard letters"""
        leet_map = {
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "6": "g",
            "7": "t",
            "8": "b",
            "9": "g",
            "@": "a",
            "$": "s",
            "!": "i",
            "|": "l",
        }
        result = ""
        for char in text.lower():
            result += leet_map.get(char, char)
        return result

    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate Levenshtein-based similarity ratio"""
        if not s1 or not s2:
            return 0.0

        # Levenshtein distance
        len1, len2 = len(s1), len(s2)
        if len1 == 0:
            return 0.0 if len2 > 0 else 1.0
        if len2 == 0:
            return 0.0

        # Create distance matrix
        distances = [[0 for _ in range(len2 + 1)] for _ in range(len1 + 1)]

        for i in range(len1 + 1):
            distances[i][0] = i
        for j in range(len2 + 1):
            distances[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                distances[i][j] = min(
                    distances[i - 1][j] + 1,  # deletion
                    distances[i][j - 1] + 1,  # insertion
                    distances[i - 1][j - 1] + cost,  # substitution
                )

        distance = distances[len1][len2]
        max_len = max(len1, len2)
        return 1.0 - (distance / max_len)

    def _identify_typo_techniques(self, typo: str, brand: str) -> List[str]:
        """Identify specific typosquatting techniques used"""
        techniques = []

        # Character substitution (e.g., 0 for o)
        if self._has_char_substitution(typo, brand):
            techniques.append("character_substitution")

        # Character omission (e.g., gogle instead of google)
        if len(typo) == len(brand) - 1:
            for i in range(len(brand)):
                if brand[:i] + brand[i + 1 :] == typo:
                    techniques.append("character_omission")
                    break

        # Character addition (e.g., googgle)
        if len(typo) == len(brand) + 1:
            for i in range(len(typo)):
                if typo[:i] + typo[i + 1 :] == brand:
                    techniques.append("character_addition")
                    break

        # Character transposition (e.g., googel)
        if len(typo) == len(brand):
            for i in range(len(brand) - 1):
                swapped = brand[:i] + brand[i + 1] + brand[i] + brand[i + 2 :]
                if swapped == typo:
                    techniques.append("character_transposition")
                    break

        # Adjacent key substitution (keyboard proximity)
        if self._has_adjacent_key_typo(typo, brand):
            techniques.append("adjacent_key")

        return techniques

    def _has_char_substitution(self, typo: str, brand: str) -> bool:
        """Check for common character substitutions"""
        substitutions = {
            "o": "0",
            "0": "o",
            "l": "1",
            "1": "l",
            "i": "1",
            "1": "i",
            "e": "3",
            "3": "e",
            "a": "4",
            "4": "a",
            "s": "5",
            "5": "s",
            "g": "9",
            "9": "g",
        }

        if len(typo) != len(brand):
            return False

        for i, (t, b) in enumerate(zip(typo, brand)):
            if t != b and substitutions.get(b) == t:
                return True
        return False

    def _has_adjacent_key_typo(self, typo: str, brand: str) -> bool:
        """Check for adjacent keyboard key typos"""
        keyboard_adjacency = {
            "q": "wa",
            "w": "qeas",
            "e": "wrds",
            "r": "etfd",
            "t": "rygf",
            "y": "tuhg",
            "u": "yijh",
            "i": "uokj",
            "o": "iplk",
            "p": "ol",
            "a": "qwsz",
            "s": "awedxz",
            "d": "serfcx",
            "f": "drtgvc",
            "g": "ftyhbv",
            "h": "gyujnb",
            "j": "huikmn",
            "k": "jiolm",
            "l": "kop",
            "z": "asx",
            "x": "zsdc",
            "c": "xdfv",
            "v": "cfgb",
            "b": "vghn",
            "n": "bhjm",
            "m": "njk",
        }

        if len(typo) != len(brand):
            return False

        for t, b in zip(typo, brand):
            if t != b and t in keyboard_adjacency.get(b, ""):
                return True
        return False

    def _detect_homoglyphs(self, domain: str) -> Dict:
        """Detect homoglyph/IDN attacks"""
        result = {
            "detected": False,
            "homoglyphs_found": [],
            "normalized_domain": domain,
            "target_brand": None,
        }

        # Check for non-ASCII characters
        try:
            domain.encode("ascii")
            # Pure ASCII, no homoglyphs
            return result
        except UnicodeEncodeError:
            pass

        # Found non-ASCII characters
        homoglyphs_found = []
        normalized = ""

        for char in domain:
            char_lower = char.lower()
            found_replacement = False

            for latin, lookalikes in self.homoglyphs.items():
                if char_lower in lookalikes:
                    homoglyphs_found.append(
                        {
                            "original": char,
                            "looks_like": latin,
                            "unicode_name": unicodedata.name(char, "UNKNOWN"),
                        }
                    )
                    normalized += latin
                    found_replacement = True
                    break

            if not found_replacement:
                normalized += char

        if homoglyphs_found:
            result["detected"] = True
            result["homoglyphs_found"] = homoglyphs_found
            result["normalized_domain"] = normalized

            # Check if normalized domain matches a known brand
            for brand, domains in self.brands.items():
                for legit_domain in domains:
                    if normalized in legit_domain or legit_domain.split(".")[0] in normalized:
                        result["target_brand"] = brand
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

    def _detect_combo_squatting(self, domain: str) -> Dict:
        """Detect combo-squatting (brand + extra words)"""
        result = {
            "detected": False,
            "target_brand": None,
            "combo_pattern": None,
        }

        # Common combo patterns
        combo_patterns = [
            "-login",
            "-secure",
            "-verify",
            "-update",
            "-account",
            "-support",
            "-help",
            "-service",
            "-online",
            "-web",
            "login-",
            "secure-",
            "verify-",
            "update-",
            "account-",
            "my-",
            "my",
            "-my",
            "online-",
            "web-",
            "e-",
            "i-",
        ]

        domain_parts = domain.split(".")
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]

        for brand in self.brands.keys():
            if brand in main_domain and brand != main_domain:
                # Brand is part of domain but not the whole domain
                for pattern in combo_patterns:
                    if pattern in main_domain:
                        result["detected"] = True
                        result["target_brand"] = brand
                        result["combo_pattern"] = pattern
                        return result

                # Generic combo (brand + something else)
                if len(main_domain) > len(brand) + 2:
                    result["detected"] = True
                    result["target_brand"] = brand
                    result["combo_pattern"] = main_domain.replace(brand, "[BRAND]")

        return result

    def _check_subdomains(self, domain: str) -> Dict:
        """Check for excessive subdomains (often used in phishing)"""
        result = {
            "detected": False,
            "subdomain_count": 0,
            "subdomains": [],
        }

        parts = domain.split(".")

        # Exclude TLD and main domain
        if len(parts) > 2:
            subdomains = parts[:-2]
            result["subdomain_count"] = len(subdomains)
            result["subdomains"] = subdomains

            # More than 2 subdomains is suspicious
            if len(subdomains) > 2:
                result["detected"] = True

            # Check for brand names in subdomains
            for subdomain in subdomains:
                for brand in self.brands.keys():
                    if brand in subdomain:
                        result["detected"] = True
                        result["brand_in_subdomain"] = brand
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

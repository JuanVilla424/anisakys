"""
Typosquatting Detection and Analysis for Phishing Research
"""
import socket
import dns.resolver
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urlparse
import logging
import difflib
import whois
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class TyposquattingGenerator:
    """Generate typosquatting domain variations for phishing detection."""

    # EXPANDED character substitutions
    SUBSTITUTIONS = {
        'a': ['@', '4', 'а', 'α'],  # Latin, Cyrillic, Greek
        'e': ['3', 'е', 'ε'],
        'i': ['1', 'l', '!', 'і', 'ι'],
        'o': ['0', 'о', 'ο'],
        's': ['5', '$', 'ѕ'],
        'l': ['1', 'i', '|'],
        'g': ['9', 'q'],
        'b': ['8', 'ь'],
        'c': ['с', '('],
        'd': ['cl', 'ԁ'],
        'h': ['һ', 'н'],
        'n': ['п', 'η'],
        'p': ['р'],
        'q': ['9', 'g'],
        'r': ['г'],
        't': ['7', 'т'],
        'u': ['v', 'υ'],
        'v': ['u', 'ν'],
        'w': ['vv', 'ω'],
        'x': ['х', '×'],
        'y': ['у', 'γ'],
        'z': ['2'],
    }

    # MASSIVELY EXPANDED TLD list
    COMMON_TLDS = [
        # Popular
        'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'app',
        'online', 'site', 'xyz', 'top', 'club', 'live', 'me',
        # New gTLDs
        'tech', 'store', 'shop', 'web', 'digital', 'cloud',
        'ai', 'dev', 'cc', 'tv', 'fm', 'ws', 'tk',
        # Country codes often used for phishing
        'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq',
        'pw', 'to', 'icu', 'vip', 'in', 'pro',
        # Finance-related (for paypal, banks, etc)
        'finance', 'money', 'cash', 'pay', 'bank',
        # Security-related
        'secure', 'safe', 'verify', 'account', 'login',
        # Others
        'services', 'support', 'help', 'center', 'systems'
    ]

    # Common subdomains used in phishing
    COMMON_SUBDOMAINS = [
        'www', 'secure', 'login', 'account', 'verify', 'update',
        'security', 'support', 'help', 'service', 'auth',
        'my', 'portal', 'member', 'user', 'signin', 'signup',
        'mail', 'webmail', 'outlook', 'office'
    ]

    # Common words to append/prepend
    COMMON_WORDS = [
        'secure', 'verify', 'account', 'login', 'auth',
        'support', 'help', 'service', 'portal', 'official',
        'mail', 'web', 'online', 'mobile', 'app',
        'update', 'confirm', 'check', 'new'
    ]

    def __init__(self, max_variants: int = 500):
        """
        Initialize typosquatting generator.

        Args:
            max_variants: Maximum number of variants to generate per technique
        """
        self.max_variants = max_variants
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 2
        self.dns_resolver.lifetime = 2

    def extract_domain_parts(self, domain: str) -> Dict[str, str]:
        """Extract domain name and TLD from full domain."""
        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(domain).netloc

        # Remove www prefix
        domain = domain.replace('www.', '')

        # Split domain and TLD
        parts = domain.rsplit('.', 1)
        if len(parts) == 2:
            return {'name': parts[0], 'tld': parts[1]}
        return {'name': domain, 'tld': 'com'}

    def generate_omission_variants(self, domain_name: str) -> List[str]:
        """Generate variants by omitting characters."""
        variants = []
        for i in range(len(domain_name)):
            variant = domain_name[:i] + domain_name[i+1:]
            if len(variant) > 2:  # Keep reasonable length
                variants.append(variant)
        return variants[:self.max_variants]

    def generate_repetition_variants(self, domain_name: str) -> List[str]:
        """Generate variants by repeating characters."""
        variants = []
        for i in range(len(domain_name)):
            variant = domain_name[:i] + domain_name[i] + domain_name[i:]
            variants.append(variant)
        return variants[:self.max_variants]

    def generate_substitution_variants(self, domain_name: str) -> List[str]:
        """Generate variants by substituting similar characters."""
        variants = []
        for i, char in enumerate(domain_name):
            if char.lower() in self.SUBSTITUTIONS:
                for replacement in self.SUBSTITUTIONS[char.lower()]:
                    variant = domain_name[:i] + replacement + domain_name[i+1:]
                    variants.append(variant)
        return variants[:self.max_variants]

    def generate_insertion_variants(self, domain_name: str) -> List[str]:
        """Generate variants by inserting common characters."""
        variants = []
        common_chars = ['-', '_', '0', '1']
        for i in range(len(domain_name) + 1):
            for char in common_chars:
                variant = domain_name[:i] + char + domain_name[i:]
                variants.append(variant)
        return variants[:self.max_variants]

    def generate_tld_variants(self, domain_name: str, original_tld: str) -> List[str]:
        """Generate variants with different TLDs."""
        variants = []
        for tld in self.COMMON_TLDS:
            if tld != original_tld:
                variants.append(f"{domain_name}.{tld}")
        return variants

    def generate_hyphenation_variants(self, domain_name: str) -> List[str]:
        """Generate variants by adding hyphens between words."""
        variants = []
        if len(domain_name) > 3:
            for i in range(1, len(domain_name)):
                variant = domain_name[:i] + '-' + domain_name[i:]
                variants.append(variant)
        return variants[:self.max_variants]

    def generate_prefix_suffix_variants(self, domain_name: str) -> List[str]:
        """Generate variants with common words prepended/appended."""
        variants = []
        for word in self.COMMON_WORDS[:15]:  # Limit to avoid explosion
            variants.append(f"{word}-{domain_name}")
            variants.append(f"{word}{domain_name}")
            variants.append(f"{domain_name}-{word}")
            variants.append(f"{domain_name}{word}")
        return variants

    def generate_double_extension_variants(self, domain_name: str, original_tld: str) -> List[str]:
        """Generate variants with double extensions like paypal.com.phishing.tk"""
        variants = []
        # Only generate a few to avoid explosion
        dangerous_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top']
        for tld in dangerous_tlds:
            variants.append(f"{domain_name}.{original_tld}.{tld}")
        return variants

    def generate_bitsquatting_variants(self, domain_name: str) -> List[str]:
        """Generate bitsquatting variants (bit flip)."""
        variants = []
        # Only do ASCII bitsquatting for first few characters
        for i in range(min(len(domain_name), 5)):
            char = domain_name[i]
            if char.isalpha():
                # Flip one bit
                char_code = ord(char)
                for bit in range(8):
                    flipped = char_code ^ (1 << bit)
                    if 97 <= flipped <= 122 or 65 <= flipped <= 90:  # valid letter
                        new_char = chr(flipped)
                        variant = domain_name[:i] + new_char + domain_name[i+1:]
                        variants.append(variant)
        return variants[:self.max_variants]

    def generate_homoglyph_variants(self, domain_name: str) -> List[str]:
        """Generate advanced homoglyph variants using lookalike characters."""
        homoglyphs = {
            'a': ['а', 'ɑ'],  # Cyrillic a, Latin small letter alpha
            'e': ['е', 'ҽ'],  # Cyrillic e
            'o': ['о', 'ο', '૦'],  # Cyrillic o, Greek omicron
            'p': ['р', 'ρ'],  # Cyrillic p, Greek rho
            'c': ['с', 'ϲ'],  # Cyrillic c
            'x': ['х', 'ⅹ'],  # Cyrillic x
        }

        variants = []
        # Replace each character that has homoglyphs
        for i, char in enumerate(domain_name):
            if char in homoglyphs:
                for replacement in homoglyphs[char]:
                    variant = domain_name[:i] + replacement + domain_name[i+1:]
                    variants.append(variant)
        return variants[:self.max_variants]

    def generate_transposition_variants(self, domain_name: str) -> List[str]:
        """Generate variants by swapping adjacent characters."""
        variants = []
        for i in range(len(domain_name) - 1):
            variant = (domain_name[:i] +
                      domain_name[i+1] +
                      domain_name[i] +
                      domain_name[i+2:])
            variants.append(variant)
        return variants

    def get_domain_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get WHOIS information for a domain.

        Returns:
            Dict with creation_date, registrar, age_days, is_new
        """
        try:
            w = whois.whois(domain)

            creation_date = None
            if w.creation_date:
                # Handle both single date and list of dates
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date

            if creation_date:
                # Make both datetimes timezone-naive for comparison
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)

                now = datetime.now()
                age_days = (now - creation_date).days
                is_new = age_days < 365  # Less than 1 year = new/suspicious

                return {
                    'creation_date': creation_date.isoformat() if isinstance(creation_date, datetime) else str(creation_date),
                    'registrar': w.registrar if hasattr(w, 'registrar') else None,
                    'age_days': age_days,
                    'is_new': is_new,
                    'error': None
                }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return {
                'creation_date': None,
                'registrar': None,
                'age_days': None,
                'is_new': False,
                'error': str(e)
            }

        return None

    def check_domain_exists(self, domain: str) -> Dict[str, Any]:
        """
        Check if a domain is registered and active.

        Returns:
            Dict with 'exists', 'has_dns', 'ip' keys
        """
        result = {
            'domain': domain,
            'exists': False,
            'has_dns': False,
            'ip': None,
            'error': None
        }

        try:
            # Try DNS resolution
            answers = self.dns_resolver.resolve(domain, 'A')
            if answers:
                result['exists'] = True
                result['has_dns'] = True
                result['ip'] = str(answers[0])
                return result
        except dns.resolver.NXDOMAIN:
            result['error'] = 'Domain does not exist'
        except dns.resolver.NoAnswer:
            result['error'] = 'No DNS records'
        except dns.resolver.Timeout:
            result['error'] = 'DNS timeout'
        except Exception as e:
            result['error'] = f'DNS error: {str(e)}'

        return result

    def generate_all_variants(self, domain: str) -> Dict[str, Any]:
        """
        Generate all typosquatting variants for a domain.

        Args:
            domain: Target domain (e.g., 'facebook.com')

        Returns:
            Dict with variants organized by technique
        """
        parts = self.extract_domain_parts(domain)
        domain_name = parts['name']
        tld = parts['tld']

        # Generate variants using ALL techniques (original + new advanced ones)
        all_variants = {
            'omission': self.generate_omission_variants(domain_name),
            'repetition': self.generate_repetition_variants(domain_name),
            'substitution': self.generate_substitution_variants(domain_name),
            'insertion': self.generate_insertion_variants(domain_name),
            'hyphenation': self.generate_hyphenation_variants(domain_name),
            'prefix_suffix': self.generate_prefix_suffix_variants(domain_name),
            'double_extension': self.generate_double_extension_variants(domain_name, tld),
            'bitsquatting': self.generate_bitsquatting_variants(domain_name),
            'homoglyph': self.generate_homoglyph_variants(domain_name),
            'transposition': self.generate_transposition_variants(domain_name),
        }

        # Combine all variants and add original TLD
        combined_variants = set()
        for technique, variants in all_variants.items():
            # double_extension already includes TLD
            if technique == 'double_extension':
                combined_variants.update(variants)
            else:
                for variant in variants:
                    # Add with original TLD
                    combined_variants.add(f"{variant}.{tld}")

        # Add TLD variations for the original domain name
        tld_variants = self.generate_tld_variants(domain_name, tld)
        combined_variants.update(tld_variants)

        # Remove the original domain
        original_full = f"{domain_name}.{tld}"
        combined_variants.discard(original_full)

        return {
            'original_domain': original_full,
            'domain_name': domain_name,
            'tld': tld,
            'total_variants': len(combined_variants),
            'variants': sorted(list(combined_variants)),
            'techniques': {
                'omission': len(all_variants['omission']),
                'repetition': len(all_variants['repetition']),
                'substitution': len(all_variants['substitution']),
                'insertion': len(all_variants['insertion']),
                'hyphenation': len(all_variants['hyphenation']),
                'tld_variation': len(tld_variants),
                'prefix_suffix': len(all_variants['prefix_suffix']),
                'double_extension': len(all_variants['double_extension']),
                'bitsquatting': len(all_variants['bitsquatting']),
                'homoglyph': len(all_variants['homoglyph']),
                'transposition': len(all_variants['transposition']),
            }
        }

    def calculate_similarity_score(self, original: str, variant: str) -> float:
        """
        Calculate similarity score between original domain and variant.
        Higher score = more similar = higher phishing risk.

        Args:
            original: Original domain
            variant: Variant domain

        Returns:
            Similarity score (0-100)
        """
        # Extract domain names without TLD for comparison
        orig_parts = self.extract_domain_parts(original)
        var_parts = self.extract_domain_parts(variant)

        # Use difflib to calculate similarity
        similarity = difflib.SequenceMatcher(None, orig_parts['name'], var_parts['name']).ratio()

        # Boost score if TLD is the same
        if orig_parts['tld'] == var_parts['tld']:
            similarity = min(1.0, similarity + 0.1)

        return round(similarity * 100, 2)

    def check_all_variants(self, original_domain: str, variants: List[str], max_check: int = 300) -> List[Dict[str, Any]]:
        """
        Check ALL variants and return their status (active or inactive) with WHOIS data.

        Args:
            original_domain: Original target domain
            variants: List of domain variants to check
            max_check: Maximum number of domains to check

        Returns:
            List of all domains with DNS, WHOIS information and similarity scores
        """
        all_results = []
        checked = 0

        for variant in variants[:max_check]:
            checked += 1
            result = self.check_domain_exists(variant)

            # Calculate similarity score
            similarity = self.calculate_similarity_score(original_domain, variant)

            # Get WHOIS data for active domains
            whois_data = None
            if result['exists'] and result['has_dns']:
                whois_data = self.get_domain_whois(variant)

            # Calculate initial phishing score based on similarity, DNS status, and age
            phishing_score = 0
            if result['exists'] and result['has_dns']:
                # Base score from similarity
                phishing_score = int(similarity * 0.3)  # 30% from similarity

                # Add points if domain is new (registered recently)
                if whois_data and whois_data.get('is_new'):
                    phishing_score += 30  # New domains are very suspicious
                    logger.info(f"⚠️  NEW domain detected: {variant} ({whois_data.get('age_days')} days old)")

                logger.info(f"✓ Found active variant: {variant} -> {result['ip']} (similarity: {similarity}%, initial score: {phishing_score})")

            result['similarity_score'] = similarity
            result['phishing_score'] = phishing_score
            result['is_active'] = result['exists'] and result['has_dns']
            result['whois'] = whois_data
            all_results.append(result)

            # Log progress every 10 domains
            if checked % 10 == 0:
                active_count = sum(1 for r in all_results if r['is_active'])
                logger.info(f"Checked {checked}/{min(len(variants), max_check)} variants, found {active_count} active")

        return all_results


def analyze_typosquatting(domain: str, max_variants_check: int = 100) -> Dict[str, Any]:
    """
    Analyze a domain for typosquatting variants.

    Args:
        domain: Target domain to analyze
        max_variants_check: Maximum number of variants to check for DNS

    Returns:
        Dict with generated variants and ALL checked domains (active and inactive)
    """
    generator = TyposquattingGenerator()

    # Generate all variants
    logger.info(f"🔍 Generating typosquatting variants for {domain}")
    variant_data = generator.generate_all_variants(domain)

    # Check ALL variants (active and inactive)
    logger.info(f"🌐 Checking {min(len(variant_data['variants']), max_variants_check)} variants...")
    all_checked = generator.check_all_variants(
        variant_data['original_domain'],
        variant_data['variants'],
        max_check=max_variants_check
    )

    # Separate active and inactive
    active_domains = [d for d in all_checked if d['is_active']]
    inactive_domains = [d for d in all_checked if not d['is_active']]

    return {
        'target_domain': variant_data['original_domain'],
        'total_variants_generated': variant_data['total_variants'],
        'variants_checked': len(all_checked),
        'active_domains_found': len(active_domains),
        'inactive_domains_found': len(inactive_domains),
        'all_domains': all_checked,  # ALL domains checked
        'active_domains': active_domains,  # Just active ones
        'inactive_domains': inactive_domains,  # Just inactive ones
        'generation_techniques': variant_data['techniques'],
    }

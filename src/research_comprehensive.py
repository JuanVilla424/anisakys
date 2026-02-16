"""
Comprehensive Phishing Research Module
Integrates typosquatting + Google Dorks + search engine detection
"""
import logging
from typing import Dict, Any, List
from src.research_typosquatting import analyze_typosquatting
from src.research_dorks import generate_dorks

logger = logging.getLogger(__name__)


def comprehensive_research(domain: str, brand: str = None, max_variants: int = 50) -> Dict[str, Any]:
    """
    Perform comprehensive phishing research combining multiple techniques.

    Args:
        domain: Target domain to protect (e.g., 'paypal.com')
        brand: Optional brand name (e.g., 'paypal')
        max_variants: Maximum typosquatting variants to check

    Returns:
        Comprehensive research results with:
        - Typosquatting variants (active/inactive)
        - Google Dorks for search engine detection
        - Unified threat assessment
    """
    logger.info(f"🔬 Starting comprehensive research for {domain}")

    # 1. Typosquatting Analysis
    logger.info(f"📊 Phase 1: Typosquatting variant generation")
    typosquatting_results = analyze_typosquatting(domain, max_variants_check=max_variants)

    # 2. Google Dorks Generation
    logger.info(f"🔍 Phase 2: Search engine dorks generation")
    dorks_results = generate_dorks(domain, brand)

    # 3. Combine results
    active_typosquatting = typosquatting_results.get('active_domains_found', 0)
    total_dorks = dorks_results.get('total_dorks', 0)

    # Calculate unified threat score
    threat_score = min(100, (active_typosquatting * 10) + (total_dorks // 2))

    threat_level = 'critical' if threat_score >= 80 else \
                   'high' if threat_score >= 60 else \
                   'medium' if threat_score >= 40 else 'low'

    logger.info(f"✅ Research complete: {active_typosquatting} active variants, {total_dorks} dorks, threat={threat_level}")

    return {
        'target_domain': domain,
        'target_brand': brand or domain.replace('.com', '').replace('.net', '').replace('.org', ''),
        'timestamp': dorks_results.get('generated_at'),

        # Typosquatting results
        'typosquatting': {
            'total_variants_generated': typosquatting_results.get('total_variants_generated', 0),
            'variants_checked': typosquatting_results.get('variants_checked', 0),
            'active_domains_found': typosquatting_results.get('active_domains_found', 0),
            'inactive_domains_found': typosquatting_results.get('inactive_domains_found', 0),
            'all_domains': typosquatting_results.get('all_domains', []),
            'active_domains': typosquatting_results.get('active_domains', []),
            'techniques': typosquatting_results.get('generation_techniques', {}),
        },

        # Search engine dorks
        'dorks': {
            'total_dorks': total_dorks,
            'categories': dorks_results.get('categories', []),
        },

        # Unified threat assessment
        'threat_assessment': {
            'score': threat_score,
            'level': threat_level,
            'active_typosquatting_count': active_typosquatting,
            'search_dorks_count': total_dorks,
            'recommendation': _get_recommendation(threat_level, active_typosquatting, total_dorks)
        }
    }


def _get_recommendation(threat_level: str, active_variants: int, dork_count: int) -> str:
    """Generate threat-appropriate recommendation."""
    if threat_level == 'critical':
        return f"CRITICAL: {active_variants} active typosquatting domains detected. Immediate action required. Execute all {dork_count} search dorks to identify additional phishing campaigns in search engines and ads."
    elif threat_level == 'high':
        return f"HIGH RISK: {active_variants} active variants found. Search {dork_count} dorks to identify phishing in search results and monitor closely."
    elif threat_level == 'medium':
        return f"MODERATE: {active_variants} active variants. Use {dork_count} dorks for ongoing monitoring of search engines."
    else:
        return f"LOW: {active_variants} variants detected. Use {dork_count} dorks for periodic monitoring."

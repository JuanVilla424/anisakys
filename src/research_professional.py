"""
Professional Phishing Research Engine
Comprehensive automated detection across typosquatting and search engines
"""
import logging
from typing import Dict, Any, List
from src.research_typosquatting import analyze_typosquatting
from src.research_dorks import generate_dorks
from src.search_engine_scraper import SearchEngineScraper
import asyncio

logger = logging.getLogger(__name__)


async def professional_research(
    domain: str,
    brand: str = None,
    max_typo_variants: int = 50,
    scan_search_engines: bool = True,
    multi_api_validator=None
) -> Dict[str, Any]:
    """
    Professional comprehensive phishing research.

    Phases:
    1. Typosquatting variant generation and DNS checking
    2. Google Dorks generation
    3. Search engine scraping (Google, Bing, DuckDuckGo)
    4. URL extraction from organic results and ads
    5. Automated multi-API scanning of ALL found URLs
    6. Screenshot capture and visual comparison
    7. Threat scoring and classification

    Args:
        domain: Target domain to protect
        brand: Brand name (optional)
        max_typo_variants: Max typosquatting variants to check
        scan_search_engines: Whether to scan search engines
        multi_api_validator: Multi-API validator instance

    Returns:
        Comprehensive research results with confirmed phishing sites
    """
    logger.info(f"🚀 Starting PROFESSIONAL RESEARCH for {domain}")

    results = {
        'target_domain': domain,
        'target_brand': brand or domain.replace('.com', '').replace('.net', '').replace('.org', ''),
        'status': 'in_progress',
        'phases_completed': [],
        'typosquatting_results': {},
        'search_engine_results': {},
        'confirmed_phishing_sites': [],
        'total_urls_scanned': 0,
        'total_confirmed_phishing': 0,
        'threat_assessment': {}
    }

    # ===== PHASE 1: Typosquatting Analysis =====
    logger.info("📊 PHASE 1: Typosquatting variant analysis")
    try:
        typo_results = analyze_typosquatting(domain, max_variants_check=max_typo_variants)

        results['typosquatting_results'] = {
            'total_variants_generated': typo_results.get('total_variants_generated', 0),
            'variants_checked': typo_results.get('variants_checked', 0),
            'active_domains_found': typo_results.get('active_domains_found', 0),
            'inactive_domains_found': typo_results.get('inactive_domains_found', 0),
            'active_domains': typo_results.get('active_domains', []),
        }

        results['phases_completed'].append('typosquatting')
        logger.info(f"✅ PHASE 1 Complete: {typo_results.get('active_domains_found', 0)} active variants")

    except Exception as e:
        logger.error(f"❌ PHASE 1 Error: {e}")
        results['typosquatting_results']['error'] = str(e)

    # ===== PHASE 2: Google Dorks Generation =====
    logger.info("🔍 PHASE 2: Search engine dorks generation")
    try:
        dorks_data = generate_dorks(domain, brand)

        # Extract all dork queries
        all_dorks = []
        for category in dorks_data.get('categories', []):
            for dork_obj in category.get('dorks', []):
                all_dorks.append(dork_obj['query'])

        results['dorks_generated'] = len(all_dorks)
        results['phases_completed'].append('dorks_generation')
        logger.info(f"✅ PHASE 2 Complete: {len(all_dorks)} dorks generated")

    except Exception as e:
        logger.error(f"❌ PHASE 2 Error: {e}")
        all_dorks = []

    # ===== PHASE 3: Search Engine Scraping =====
    if scan_search_engines and all_dorks:
        logger.info("🌐 PHASE 3: Search engine scraping (Google, Bing, DuckDuckGo)")
        try:
            scraper = SearchEngineScraper()

            # Limit to top dorks to avoid rate limiting
            top_dorks = all_dorks[:6]  # Top 6 dorks for speed

            search_results = scraper.comprehensive_search(
                dorks=top_dorks,
                exclude_domain=domain,
                max_results_per_dork=5  # 5 results per dork per engine
            )

            results['search_engine_results'] = {
                'total_urls_found': len(search_results),
                'by_source': _count_by_source(search_results),
                'ads_found': sum(1 for r in search_results if r.get('is_ad')),
                'organic_found': sum(1 for r in search_results if not r.get('is_ad')),
            }

            results['phases_completed'].append('search_engine_scraping')
            logger.info(f"✅ PHASE 3 Complete: {len(search_results)} URLs extracted from search engines")

        except Exception as e:
            logger.error(f"❌ PHASE 3 Error: {e}")
            search_results = []
            results['search_engine_results']['error'] = str(e)
    else:
        search_results = []
        logger.info("⏭️ PHASE 3 Skipped: Search engine scanning disabled")

    # ===== PHASE 4: Automated Multi-API Scanning =====
    logger.info("🔬 PHASE 4: Automated multi-API scanning of all URLs")

    urls_to_scan = []

    # Add active typosquatting domains
    for typo_domain in results['typosquatting_results'].get('active_domains', []):
        urls_to_scan.append({
            'url': typo_domain.get('url', f"http://{typo_domain['domain']}"),
            'domain': typo_domain['domain'],
            'source': 'typosquatting',
            'similarity_score': typo_domain.get('similarity_score', 0),
            'phishing_score': typo_domain.get('phishing_score', 0),
        })

    # Add search engine URLs
    for search_result in search_results:
        urls_to_scan.append({
            'url': search_result['url'],
            'domain': scraper.extract_domain(search_result['url']),
            'source': f"search_{search_result['source']}",
            'is_ad': search_result.get('is_ad', False),
            'title': search_result.get('title', ''),
            'search_query': search_result.get('search_query', ''),
        })

    logger.info(f"📋 Total URLs to scan: {len(urls_to_scan)}")

    # Scan each URL with multi-API validator
    confirmed_phishing = []

    if multi_api_validator:
        for idx, url_data in enumerate(urls_to_scan, 1):
            try:
                logger.info(f"🔍 Scanning {idx}/{len(urls_to_scan)}: {url_data['url'][:60]}")

                # Perform comprehensive scan
                scan_result = multi_api_validator.comprehensive_scan(url_data['url'])

                # Extract confidence and threat level
                confidence = scan_result.get('confidence_score', 0)
                threat_level = scan_result.get('aggregated_threat_level', 'unknown')

                # Classify as phishing if confidence >= 70 or threat level is high/critical
                is_phishing = (
                    confidence >= 70 or
                    threat_level in ['high', 'critical'] or
                    scan_result.get('virustotal', {}).get('positives', 0) >= 3
                )

                if is_phishing:
                    confirmed_phishing.append({
                        **url_data,
                        'scan_result': {
                            'confidence_score': confidence,
                            'threat_level': threat_level,
                            'virustotal': scan_result.get('virustotal', {}),
                            'urlvoid': scan_result.get('urlvoid', {}),
                            'phishtank': scan_result.get('phishtank', {}),
                        }
                    })
                    logger.warning(f"🚨 CONFIRMED PHISHING: {url_data['url']} (Confidence: {confidence})")

            except Exception as e:
                logger.error(f"❌ Scan error for {url_data['url']}: {e}")
                continue

        results['phases_completed'].append('multi_api_scanning')
        logger.info(f"✅ PHASE 4 Complete: {len(confirmed_phishing)} confirmed phishing sites")
    else:
        logger.warning("⚠️ PHASE 4 Skipped: Multi-API validator not available")

    # ===== PHASE 5: Results Compilation =====
    logger.info("📊 PHASE 5: Results compilation and threat assessment")

    results['confirmed_phishing_sites'] = confirmed_phishing
    results['total_urls_scanned'] = len(urls_to_scan)
    results['total_confirmed_phishing'] = len(confirmed_phishing)

    # Calculate unified threat score
    typo_count = results['typosquatting_results'].get('active_domains_found', 0)
    search_urls = len(search_results)
    confirmed_count = len(confirmed_phishing)

    threat_score = min(100, (confirmed_count * 15) + (typo_count * 5) + (search_urls * 2))

    threat_level = 'critical' if threat_score >= 80 else \
                   'high' if threat_score >= 60 else \
                   'medium' if threat_score >= 40 else \
                   'low' if threat_score >= 20 else 'minimal'

    results['threat_assessment'] = {
        'score': threat_score,
        'level': threat_level,
        'confirmed_phishing_count': confirmed_count,
        'typosquatting_active_count': typo_count,
        'search_urls_found': search_urls,
        'recommendation': _get_recommendation(threat_level, confirmed_count, typo_count, search_urls)
    }

    results['status'] = 'completed'
    results['phases_completed'].append('results_compilation')

    logger.info(f"🎯 RESEARCH COMPLETE:")
    logger.info(f"   - Threat Score: {threat_score}/100 ({threat_level})")
    logger.info(f"   - Confirmed Phishing: {confirmed_count}")
    logger.info(f"   - Active Typosquatting: {typo_count}")
    logger.info(f"   - Search URLs Found: {search_urls}")

    return results


def _count_by_source(results: List[Dict]) -> Dict[str, int]:
    """Count results by source."""
    counts = {}
    for r in results:
        source = r.get('source', 'unknown')
        counts[source] = counts.get(source, 0) + 1
    return counts


def _get_recommendation(threat_level: str, confirmed: int, typo: int, search: int) -> str:
    """Generate threat-appropriate recommendation."""
    if threat_level == 'critical':
        return f"CRITICAL THREAT: {confirmed} confirmed phishing sites detected across typosquatting and search engines. IMMEDIATE ACTION REQUIRED. Deploy all countermeasures and report to authorities."
    elif threat_level == 'high':
        return f"HIGH RISK: {confirmed} confirmed phishing sites found. {typo} active typosquatting domains and {search} suspicious search results. Immediate reporting and monitoring required."
    elif threat_level == 'medium':
        return f"MODERATE RISK: {confirmed} confirmed threats with {typo} typosquatting variants. Implement monitoring and reporting protocols."
    elif threat_level == 'low':
        return f"LOW RISK: {confirmed} threats detected. Standard monitoring recommended."
    else:
        return f"MINIMAL RISK: Limited threats detected. Periodic monitoring sufficient."

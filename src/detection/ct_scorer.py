"""
Certificate Transparency (CT) candidate scorer.

Combines the existing lexical url_analyzer.analyze() score with two
CT-specific signals: dnstwist permutation-set membership and
confusable_homoglyphs Unicode-confusable detection. Deliberately does NOT
modify url_analyzer.py itself -- it's already relied on by
multi_api_validator.py and email_scheduler.py, and changing its weights
risks regressing both.

Two-stage filter (performance): the CT firehose observes millions of
domains/day. Running the full Levenshtein-based url_analyzer.analyze()
against every one of them is wasteful. quick_prefilter() is a cheap O(1)
set-membership + substring check that must run first; only domains that
pass it should reach score_ct_candidate().
"""

import logging
from typing import Dict, List, Optional

import dnstwist
from confusable_homoglyphs import confusables

from src.detection.url_analyzer import url_analyzer

logger = logging.getLogger(__name__)

# Any composite score at or above this is worth a human's attention.
# url_analyzer alone reaches this only via multiple corroborating signals
# (e.g. suspicious TLD [15] + several keywords [25] + combo-squat [30] = 70),
# not a single weak hit -- keeps noise out of thread_results.
DEFAULT_MIN_SCORE = 55

# Composite-only bonuses, additive on top of url_analyzer's 0-100 score,
# re-capped at 100 afterwards. Kept modest since url_analyzer's own
# homoglyph check (+50) already covers the ASCII-lookalike table; these
# cover signals url_analyzer structurally cannot see (full Unicode
# confusables, membership in a brand's precomputed permutation set).
PERMUTATION_MATCH_BONUS = 35
CONFUSABLE_BONUS = 25


def build_permutation_set(
    known_brands: Dict[str, List[str]], extra_keywords: Optional[List[str]] = None
) -> Dict[str, str]:
    """Precompute a permuted-domain -> brand map via dnstwist, passive/offline
    only (format='list' + output=devnull -- no DNS resolution, no network
    calls). Safe to call once at job startup; safe to refresh periodically.

    dnstwist needs a domain-shaped string (with a TLD) to fuzz meaningfully,
    not a bare brand name -- confirmed empirically (dnstwist.run(domain=
    "nequi.com", ...) yields ~1800 realistic permutations; a bare "nequi"
    would not). known_brands (e.g. url_analyzer.KNOWN_BRANDS) already maps
    brand -> legitimate domains; extra_keywords (e.g. settings.KEYWORDS
    tokens not already covered by known_brands) get a synthesized ".com"
    suffix purely to give dnstwist a domain shape -- the synthesized domain
    is never treated as a real, resolvable one, and format='list' performs
    no registration/DNS check regardless.
    """
    seed_domains: Dict[str, str] = {}
    for brand, domains in known_brands.items():
        seed_domains[brand] = domains[0] if domains else f"{brand}.com"
    for keyword in extra_keywords or []:
        keyword = keyword.strip().lower()
        if not keyword or keyword in seed_domains:
            continue
        seed_domains[keyword] = f"{keyword}.com"

    permutation_to_brand: Dict[str, str] = {}
    for brand, seed_domain in seed_domains.items():
        try:
            results = dnstwist.run(domain=seed_domain, format="list", output=dnstwist.devnull)
        except Exception as exc:
            logger.warning(f"dnstwist permutation generation failed for '{seed_domain}': {exc}")
            continue
        for entry in results or []:
            candidate = entry.get("domain") if isinstance(entry, dict) else None
            if candidate:
                permutation_to_brand[str(candidate).lower()] = brand

    logger.info(
        f"🔭 CT permutation set built: {len(seed_domains)} brand seeds -> "
        f"{len(permutation_to_brand)} permutations"
    )
    return permutation_to_brand


def quick_prefilter(domain: str, brand_seeds: List[str], permutation_map: Dict[str, str]) -> bool:
    """Cheap first-pass filter: O(1) set membership + substring check. Only
    domains passing this should reach the heavier score_ct_candidate()."""
    domain_lower = domain.lower()
    if domain_lower in permutation_map:
        return True
    return any(seed in domain_lower for seed in brand_seeds)


def score_ct_candidate(domain: str, permutation_map: Dict[str, str]) -> Dict:
    """Score one CT-observed domain for brand-impersonation risk.

    Returns {domain, score, matched_brand, permutation_hit, confusable_hit,
    risk_factors}. `score` (0-100) is what callers compare against a minimum
    threshold before recording a thread_results candidate.
    """
    base = url_analyzer.analyze(f"https://{domain}")
    score = base.get("risk_score", 0)
    factors = list(base.get("risk_factors", []))
    matched_brand = (
        base.get("typosquatting", {}).get("target_brand")
        or base.get("combo_squatting", {}).get("target_brand")
        or base.get("homoglyphs", {}).get("target_brand")
    )

    permutation_hit = permutation_map.get(domain.lower())
    if permutation_hit:
        score += PERMUTATION_MATCH_BONUS
        matched_brand = matched_brand or permutation_hit
        factors.append(f"Matches precomputed permutation of '{permutation_hit}'")

    confusable_hit = False
    try:
        confusable_hit = bool(confusables.is_dangerous(domain))
    except Exception as exc:
        logger.debug(f"confusable_homoglyphs check failed for {domain}: {exc}")
    if confusable_hit:
        score += CONFUSABLE_BONUS
        factors.append("Unicode-confusable (mixed-script/IDN) domain")

    return {
        "domain": domain,
        "score": min(score, 100),
        "matched_brand": matched_brand,
        "permutation_hit": permutation_hit,
        "confusable_hit": confusable_hit,
        "risk_factors": factors,
    }

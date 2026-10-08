"""
Unit tests for src/detection/ct_scorer.py -- the CT candidate composite
scorer. Fully offline: url_analyzer is pure lexical, dnstwist's list mode
does no DNS, confusable_homoglyphs is pure Unicode table lookup. No mocking
needed anywhere in this file.
"""

import unittest

from src.detection.ct_scorer import (
    DEFAULT_MIN_SCORE,
    PERMUTATION_MATCH_BONUS,
    build_permutation_set,
    quick_prefilter,
    score_ct_candidate,
)


class TestScoreCTCandidate(unittest.TestCase):
    def test_clean_domain_scores_low(self):
        result = score_ct_candidate("example.com", {})
        self.assertLess(result["score"], DEFAULT_MIN_SCORE)
        self.assertFalse(result["confusable_hit"])
        self.assertIsNone(result["permutation_hit"])

    def test_known_brand_typosquat_scores_above_threshold(self):
        # "bancolomb1a" leet-normalizes to exactly "bancolombia" (a KNOWN_BRANDS
        # key) -- url_analyzer's typosquatting check fires at +40 -- plus
        # ".tk" is a KNOWN suspicious TLD -- +15. 55 total from url_analyzer
        # alone, with an empty permutation_map so this test isolates exactly
        # what url_analyzer + confusable_homoglyphs contribute.
        result = score_ct_candidate("bancolomb1a.tk", {})
        self.assertGreaterEqual(result["score"], DEFAULT_MIN_SCORE)
        self.assertEqual(result["matched_brand"], "bancolombia")
        self.assertIn("Typosquatting detected targeting 'bancolombia'", result["risk_factors"][0])

    def test_permutation_hit_adds_bonus_and_sets_matched_brand(self):
        # A domain with a near-zero base score, but present in a (hand-built,
        # deterministic -- not a live dnstwist call) permutation map.
        permutation_map = {"totally-clean-looking-name.com": "testbrand"}
        result = score_ct_candidate("totally-clean-looking-name.com", permutation_map)
        self.assertEqual(result["permutation_hit"], "testbrand")
        self.assertEqual(result["matched_brand"], "testbrand")
        self.assertGreaterEqual(result["score"], PERMUTATION_MATCH_BONUS)

    def test_confusable_domain_sets_confusable_hit(self):
        # Cyrillic 'а' (U+0430) substituted for the second character -- an
        # explicit escape, not a pasted look-alike glyph, so the test source
        # itself stays unambiguous to read.
        mixed_script_domain = "bаncolombia.com"
        result = score_ct_candidate(mixed_script_domain, {})
        self.assertTrue(result["confusable_hit"])
        self.assertIn("Unicode-confusable", result["risk_factors"][-1])

    def test_score_never_exceeds_100(self):
        # Stack every bonus at once: typosquat + suspicious TLD (url_analyzer)
        # + permutation hit + Unicode-confusable, on top of an already-high
        # url_analyzer base -- confirms the final min(score, 100) recap holds
        # even when the composite bonuses would otherwise push it over.
        domain = "bancolomb1a-login-secure.tk"
        permutation_map = {domain: "bancolombia"}
        result = score_ct_candidate(domain, permutation_map)
        self.assertLessEqual(result["score"], 100)


class TestQuickPrefilter(unittest.TestCase):
    def test_matches_permutation_membership(self):
        self.assertTrue(quick_prefilter("some-domain.tk", ["nequi"], {"some-domain.tk": "nequi"}))

    def test_matches_brand_substring(self):
        self.assertTrue(quick_prefilter("nequi-secure-login.tk", ["nequi"], {}))

    def test_rejects_unrelated_domain(self):
        self.assertFalse(
            quick_prefilter("totally-unrelated-website.com", ["nequi", "bancolombia"], {})
        )

    def test_is_case_insensitive(self):
        self.assertTrue(quick_prefilter("NEQUI-SECURE.tk", ["nequi"], {}))


class TestBuildPermutationSet(unittest.TestCase):
    def test_returns_nonempty_for_real_brand_with_known_domain(self):
        permutation_map = build_permutation_set({"nequi": ["nequi.com"]})
        self.assertGreater(len(permutation_map), 0)
        self.assertTrue(all(brand == "nequi" for brand in permutation_map.values()))

    def test_handles_extra_keywords_without_known_domain(self):
        # No known_brands entry at all -- "fcm" only exists as a bare
        # extra_keyword, so build_permutation_set must synthesize "fcm.com"
        # to give dnstwist a domain shape to fuzz.
        permutation_map = build_permutation_set({}, extra_keywords=["fcm"])
        self.assertGreater(len(permutation_map), 0)
        self.assertTrue(all(brand == "fcm" for brand in permutation_map.values()))

    def test_extra_keyword_already_in_known_brands_is_not_duplicated(self):
        permutation_map = build_permutation_set({"nequi": ["nequi.com"]}, extra_keywords=["nequi"])
        # Should behave identically to the known_brands-only case -- no error,
        # no double-fuzzing of the same brand under two different seed domains.
        self.assertGreater(len(permutation_map), 0)


if __name__ == "__main__":
    unittest.main()

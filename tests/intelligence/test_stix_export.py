"""
Unit tests for src/intelligence/stix_export.py -- validate_stix_bundle and
add_tlp_marking. Uses the real stix2 library (not mocked) since validation
correctness IS what's under test here.
"""

import unittest

from src.intelligence.stix_export import TLP_MARKING_IDS, add_tlp_marking, validate_stix_bundle


def _valid_bundle():
    return {
        "type": "bundle",
        "id": "bundle--e9e0b1a4-6a1e-4d1a-9e5b-2c8b2c2b2c2b",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--c1b3b3b3-1111-4222-8333-444444444444",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "pattern": "[domain-name:value = 'evil.example.com']",
                "pattern_type": "stix",
                "labels": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00.000Z",
            }
        ],
    }


class TestValidateStixBundle(unittest.TestCase):
    def test_valid_bundle_passes(self):
        valid, errors = validate_stix_bundle(_valid_bundle())
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_malformed_bundle_fails_with_error_message(self):
        bad_bundle = {"type": "bundle", "id": "bundle--x", "objects": [{"type": "indicator"}]}
        valid, errors = validate_stix_bundle(bad_bundle)
        self.assertFalse(valid)
        self.assertTrue(len(errors) >= 1)
        self.assertIsInstance(errors[0], str)

    def test_not_a_bundle_at_all_fails(self):
        valid, errors = validate_stix_bundle({"not": "stix"})
        self.assertFalse(valid)


class TestAddTlpMarking(unittest.TestCase):
    def test_adds_correct_marking_definition_id_per_level(self):
        for level, expected_id in TLP_MARKING_IDS.items():
            result = add_tlp_marking(_valid_bundle(), level)
            marking_objs = [o for o in result["objects"] if o["type"] == "marking-definition"]
            self.assertEqual(len(marking_objs), 1)
            self.assertEqual(marking_objs[0]["id"], expected_id)

    def test_sets_object_marking_refs_on_non_marking_objects(self):
        result = add_tlp_marking(_valid_bundle(), "amber")
        indicator = next(o for o in result["objects"] if o["type"] == "indicator")
        self.assertEqual(indicator["object_marking_refs"], [TLP_MARKING_IDS["amber"]])

    def test_marking_definition_not_marked_with_itself(self):
        result = add_tlp_marking(_valid_bundle(), "red")
        marking_obj = next(o for o in result["objects"] if o["type"] == "marking-definition")
        self.assertNotIn("object_marking_refs", marking_obj)

    def test_does_not_duplicate_marking_definition_on_repeat_calls(self):
        once = add_tlp_marking(_valid_bundle(), "green")
        twice = add_tlp_marking(once, "green")
        marking_objs = [o for o in twice["objects"] if o["type"] == "marking-definition"]
        self.assertEqual(len(marking_objs), 1)

    def test_unknown_tlp_level_raises_value_error(self):
        with self.assertRaises(ValueError):
            add_tlp_marking(_valid_bundle(), "purple")

    def test_original_bundle_is_not_mutated(self):
        original = _valid_bundle()
        add_tlp_marking(original, "red")
        self.assertNotIn("object_marking_refs", original["objects"][0])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the TLP 2.0 indicator bundle builder in src/intelligence/stix_export.py.

Uses the real stix2 library: the built objects are validated by it.
"""

from datetime import datetime, timezone

import pytest
import stix2

from src.intelligence.stix_export import (
    ANISAKYS_IDENTITY_ID,
    MAX_BUNDLE_INDICATORS,
    TLP2_EXTENSION_DEFINITION_ID,
    TLP2_MARKING_IDS,
    BundleRequestError,
    build_indicator_bundle,
    escape_pattern_value,
    indicator_pattern,
    validate_bundle_request,
    validate_stix_bundle,
)

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _bundle(payload):
    spec = validate_bundle_request(payload)
    return build_indicator_bundle(
        spec["indicators"],
        tlp=spec["tlp"],
        confidence=spec["confidence"],
        name=spec["name"],
        now=NOW,
    )


def _objects(bundle, stix_type):
    return [o for o in bundle["objects"] if o["type"] == stix_type]


class TestPatterns:
    def test_backslash_and_single_quote_are_escaped(self):
        assert escape_pattern_value("a'b\\c") == "a\\'b\\\\c"
        assert escape_pattern_value("\\'") == "\\\\\\'"

    @pytest.mark.parametrize(
        "ioc_type, value, expected",
        [
            ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
            ("url", "http://x.example/a", "[url:value = 'http://x.example/a']"),
            ("ipv4", "203.0.113.5", "[ipv4-addr:value = '203.0.113.5']"),
            ("ipv6", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
            ("email-addr", "a@b.example", "[email-addr:value = 'a@b.example']"),
        ],
    )
    def test_pattern_per_type(self, ioc_type, value, expected):
        assert indicator_pattern(ioc_type, value) == expected

    def test_hostile_value_yields_a_valid_pattern(self):
        value = "http://evil.example/?q=' OR 1=1]\\"
        bundle = _bundle({"indicators": [{"type": "url", "value": value}]})

        indicator = _objects(bundle, "indicator")[0]
        assert indicator["pattern"] == "[url:value = 'http://evil.example/?q=\\' OR 1=1]\\\\']"
        assert validate_stix_bundle(bundle) == (True, [])


class TestBundleContents:
    def test_defaults_tlp_amber_confidence_50_and_valid_from_now(self):
        bundle = _bundle({"indicators": [{"type": "domain", "value": "evil.example"}]})

        indicator = _objects(bundle, "indicator")[0]
        assert indicator["confidence"] == 50
        assert indicator["valid_from"] == "2026-10-01T12:00:00Z"
        assert indicator["indicator_types"] == ["malicious-activity"]
        assert indicator["object_marking_refs"] == [TLP2_MARKING_IDS["amber"]]

    def test_tlp2_marking_definition_is_included_and_referenced(self):
        bundle = _bundle(
            {"indicators": [{"type": "domain", "value": "evil.example"}], "tlp": "amber+strict"}
        )

        markings = _objects(bundle, "marking-definition")
        assert len(markings) == 1
        marking = markings[0]
        assert marking["id"] == "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
        assert marking["name"] == "TLP:AMBER+STRICT"
        assert marking["extensions"][TLP2_EXTENSION_DEFINITION_ID] == {
            "extension_type": "property-extension",
            "tlp_2_0": "amber+strict",
        }
        for obj in bundle["objects"]:
            if obj["type"] != "marking-definition":
                assert obj["object_marking_refs"] == [marking["id"]]

    @pytest.mark.parametrize("level", sorted(TLP2_MARKING_IDS))
    def test_every_tlp2_level(self, level):
        bundle = _bundle({"indicators": [{"type": "domain", "value": "x.example"}], "tlp": level})

        assert _objects(bundle, "marking-definition")[0]["id"] == TLP2_MARKING_IDS[level]

    def test_identity_labels_description_first_seen_and_confidence(self):
        bundle = _bundle(
            {
                "indicators": [
                    {
                        "type": "ipv4",
                        "value": "203.0.113.5",
                        "first_seen": "2026-01-02T03:04:05Z",
                        "labels": ["phishing", "evilginx"],
                        "description": "AiTM proxy",
                    }
                ],
                "confidence": 90,
            }
        )

        (identity,) = _objects(bundle, "identity")
        assert identity["id"] == ANISAKYS_IDENTITY_ID
        assert identity["name"] == "Anisakys"
        indicator = _objects(bundle, "indicator")[0]
        assert indicator["created_by_ref"] == ANISAKYS_IDENTITY_ID
        assert indicator["valid_from"] == "2026-01-02T03:04:05Z"
        assert indicator["labels"] == ["phishing", "evilginx"]
        assert indicator["description"] == "AiTM proxy"
        assert indicator["confidence"] == 90

    def test_naive_first_seen_is_utc(self):
        bundle = _bundle(
            {"indicators": [{"type": "domain", "value": "x.example", "first_seen": "2026-01-02"}]}
        )

        assert _objects(bundle, "indicator")[0]["valid_from"] == "2026-01-02T00:00:00Z"

    def test_name_adds_a_report_referencing_every_indicator(self):
        bundle = _bundle(
            {
                "indicators": [
                    {"type": "domain", "value": "a.example"},
                    {"type": "url", "value": "https://b.example/x"},
                ],
                "name": "Campaign 42",
            }
        )

        (report,) = _objects(bundle, "report")
        assert report["name"] == "Campaign 42"
        assert set(report["object_refs"]) == {i["id"] for i in _objects(bundle, "indicator")}

    def test_no_report_without_name(self):
        bundle = _bundle({"indicators": [{"type": "domain", "value": "a.example"}]})

        assert _objects(bundle, "report") == []

    def test_bundle_parses_with_stix2(self):
        bundle = _bundle({"indicators": [{"type": "email-addr", "value": "x@evil.example"}]})

        parsed = stix2.parse(bundle)
        assert isinstance(parsed, stix2.Bundle)


class TestValidation:
    def test_offending_indexes_are_listed(self):
        with pytest.raises(BundleRequestError) as exc:
            validate_bundle_request(
                {
                    "indicators": [
                        {"type": "domain", "value": "ok.example"},
                        {"type": "sha256", "value": "abc"},
                        {"type": "url", "value": "   "},
                        {"type": "ipv4", "value": "999.1.1.1"},
                        {"type": "ipv6", "value": "203.0.113.5"},
                        {"type": "email-addr", "value": "no-at-sign"},
                        "not-an-object",
                        {"type": "domain", "value": "x.example", "first_seen": "yesterday"},
                        {"type": "domain", "value": "x.example", "labels": "phishing"},
                    ]
                }
            )

        assert [d["index"] for d in exc.value.details] == [1, 2, 3, 4, 5, 6, 7, 8]
        assert "sha256" in exc.value.details[0]["error"]

    @pytest.mark.parametrize(
        "payload, message",
        [
            (None, "JSON object"),
            ({}, "non-empty list"),
            ({"indicators": []}, "non-empty list"),
            ({"indicators": [{"type": "domain", "value": "x"}], "tlp": "white"}, "tlp"),
            ({"indicators": [{"type": "domain", "value": "x"}], "confidence": 101}, "confidence"),
            ({"indicators": [{"type": "domain", "value": "x"}], "confidence": True}, "confidence"),
            ({"indicators": [{"type": "domain", "value": "x"}], "confidence": "50"}, "confidence"),
            ({"indicators": [{"type": "domain", "value": "x"}], "name": ""}, "name"),
        ],
    )
    def test_top_level_errors(self, payload, message):
        with pytest.raises(BundleRequestError) as exc:
            validate_bundle_request(payload)

        assert message in exc.value.message

    def test_more_than_5000_indicators_are_rejected(self):
        payload = {"indicators": [{"type": "domain", "value": "x.example"}] * 5001}

        with pytest.raises(BundleRequestError) as exc:
            validate_bundle_request(payload)

        assert str(MAX_BUNDLE_INDICATORS) in exc.value.message

    def test_tlp_is_case_insensitive(self):
        spec = validate_bundle_request(
            {"indicators": [{"type": "domain", "value": "x.example"}], "tlp": "CLEAR"}
        )

        assert spec["tlp"] == "clear"

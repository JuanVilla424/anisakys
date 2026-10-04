"""Unit tests for src.api.serializers (timestamp and threat-level formatting)."""

import datetime

import pytest

from src.api.serializers import (
    STORED_THREAT_LEVELS,
    as_utc,
    iso_utc,
    severest_threat_level,
    threat_level_or_none,
)


class TestIsoUtc:
    def test_naive_database_values_are_taken_as_utc(self):
        assert iso_utc(datetime.datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05+00:00"

    def test_aware_values_are_converted_to_utc(self):
        bogota = datetime.timezone(datetime.timedelta(hours=-5))
        value = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=bogota)

        assert iso_utc(value) == "2026-01-02T08:04:05+00:00"

    def test_naive_in_process_values_can_be_read_as_local_time(self):
        local = datetime.datetime(2026, 1, 2, 3, 4, 5)

        expected = local.astimezone(datetime.UTC).isoformat()
        assert iso_utc(local, naive_is_local=True) == expected

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("2026-01-02 03:04:05", "2026-01-02T03:04:05+00:00"),
            ("2026-01-02", "2026-01-02T00:00:00+00:00"),
            ("2026-01-02T03:04:05.250000", "2026-01-02T03:04:05.250000+00:00"),
        ],
    )
    def test_text_casts_are_parsed(self, raw, expected):
        assert iso_utc(raw) == expected

    def test_dates_become_midnight_utc(self):
        assert iso_utc(datetime.date(2026, 1, 2)) == "2026-01-02T00:00:00+00:00"

    @pytest.mark.parametrize("value", [None, "", "not a date", 12345])
    def test_unknown_values_are_none(self, value):
        assert iso_utc(value) is None


class TestAsUtc:
    def test_mixed_naive_and_aware_values_become_comparable(self):
        naive = as_utc(datetime.datetime(2026, 1, 1, 12, 0))
        aware = as_utc(
            datetime.datetime(
                2026, 1, 1, 8, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))
            )
        )

        assert naive is not None and aware is not None
        assert aware > naive
        assert naive.tzinfo is datetime.UTC

    def test_unknown_values_are_none(self):
        assert as_utc(None) is None
        assert as_utc("garbage") is None


class TestThreatLevels:
    def test_stored_levels_include_unknown(self):
        assert STORED_THREAT_LEVELS == {"clean", "low", "medium", "high", "critical", "unknown"}

    @pytest.mark.parametrize("value", [None, "unknown", "", "bogus", 3])
    def test_values_without_a_verdict_are_none(self, value):
        assert threat_level_or_none(value) is None

    def test_levels_are_normalised(self):
        assert threat_level_or_none(" HIGH ") == "high"

    def test_severest_level_wins_and_unknown_is_ignored(self):
        assert severest_threat_level(["low", "unknown", None, "high", "medium"]) == "high"
        assert severest_threat_level(["clean"]) == "clean"
        assert severest_threat_level([None, "unknown"]) is None

"""
Values placed in dig/whois argv must be validated hostnames, so input like
"-f/etc/passwd" can never be parsed as a command-line option.
"""

import pytest

# src.detection must load before src.intelligence (package-level import cycle, as in src.main)
import src.detection  # noqa: F401  # pylint: disable=unused-import
from src.intelligence import domain_scanner


@pytest.mark.parametrize(
    "value", ["-f/etc/passwd", "-h evil.example", "a b.com", "", "example.com;id"]
)
def test_invalid_domains_never_reach_subprocess(monkeypatch, value):
    def fail(*_args, **_kwargs):
        raise AssertionError("subprocess must not run for an invalid domain")

    monkeypatch.setattr(domain_scanner.subprocess, "check_output", fail)

    assert domain_scanner.is_valid_domain(value) is False
    with pytest.raises(ValueError):
        domain_scanner._dig(value, "A")  # pylint: disable=protected-access
    with pytest.raises(ValueError):
        domain_scanner.get_whois_data(value)


def test_whois_ends_options_before_the_domain(monkeypatch):
    seen = {}

    def fake_check_output(argv, **_kwargs):
        seen["argv"] = argv
        return ""

    monkeypatch.setattr(domain_scanner.subprocess, "check_output", fake_check_output)

    domain_scanner.get_whois_data("example.com")

    assert seen["argv"] == ["whois", "--", "example.com"]

"""Tests for the manual abuse-report CLI (src/scripts/send_abuse_report.py)."""

from unittest.mock import MagicMock, patch

import pytest

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
import src.scripts.send_abuse_report as script

THREAT = {"type": "lookalike_domain", "severity": "HIGH", "indicators": ["<b>x</b>"]}
DNS = {"A": ["<img src=x>"], "www_A": [], "www_CNAME": [], "MX": [], "NS": [], "TXT": []}


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("web.com", "web.com"),  # lstrip("www.") used to produce "eb.com"
            ("www.example.com", "example.com"),
            ("  WWW.Example.COM/ ", "example.com"),
            ("wwwexample.com", "wwwexample.com"),
        ],
    )
    def test_only_a_leading_www_label_is_removed(self, raw, expected):
        assert script.normalize_domain(raw) == expected


class TestHtmlReport:
    def test_attacker_controlled_values_are_escaped(self):
        body = script.build_html_report(
            suspect_domain="evil.example",
            victim_domain="bank.example",
            dns=DNS,
            whois={"registrar": "<script>alert(1)</script>"},
            threat=THREAT,
            sender="soc@bank.example",
        )

        assert "<script>" not in body
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
        assert "<img src=x>" not in body
        assert "<b>x</b>" not in body


class TestSendReport:
    def test_sends_through_the_shared_mailer_under_the_global_cap(self):
        limiter = MagicMock()
        limiter.acquire.return_value = True
        mailer = MagicMock()
        with (
            patch("sqlalchemy.create_engine"),
            patch("src.reporting.smtp_rate_limiter.DatabaseSmtpRateLimiter", return_value=limiter),
            patch("src.reporting.mailer.SmtpMailer", return_value=mailer),
        ):
            script.send_report("abuse@registrar.example", ["cc@bank.example"], "S", "<p>r</p>")

        message, recipients = mailer.send.call_args.args
        assert recipients == ["abuse@registrar.example", "cc@bank.example"]
        assert message.get_content_type() == "multipart/alternative"

    def test_refuses_to_send_when_the_shared_cap_is_reached(self):
        limiter = MagicMock()
        limiter.acquire.return_value = False
        mailer = MagicMock()
        with (
            patch("sqlalchemy.create_engine"),
            patch("src.reporting.smtp_rate_limiter.DatabaseSmtpRateLimiter", return_value=limiter),
            patch("src.reporting.mailer.SmtpMailer", return_value=mailer),
            pytest.raises(SystemExit),
        ):
            script.send_report("abuse@registrar.example", [], "S", "<p>r</p>")

        mailer.send.assert_not_called()

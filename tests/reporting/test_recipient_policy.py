"""Recipient safety: who may receive an abuse report (offline, no DNS/WHOIS)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.reporting import recipient_policy
from src.reporting.email_detector import EnhancedAbuseEmailDetector
from src.reporting.recipient_policy import (
    ContactCandidate,
    ContactTier,
    order_by_trust,
    recipient_rejection_reason,
    registrable_domain,
)


@pytest.fixture
def detector():
    with (
        patch("src.reporting.email_detector.AbuseContactResolver"),
        patch("src.reporting.email_detector.dns.resolver.Resolver"),
    ):
        det = EnhancedAbuseEmailDetector(db_manager=MagicMock())
    det.dns_resolver = MagicMock()
    det.abuse_resolver = MagicMock()
    det.abuse_resolver.resolve.return_value = []
    return det


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("https://login.evil.com.co/path", "evil.com.co"),
            ("a.b.example.co.uk", "example.co.uk"),
            ("www.example.com", "example.com"),
            ("EXAMPLE.COM.", "example.com"),
            ("https://192.0.2.10/x", "192.0.2.10"),
        ],
    )
    def test_uses_the_public_suffix_list(self, value, expected):
        assert registrable_domain(value) == expected

    def test_never_fetches_the_suffix_list(self):
        """The extractor must run on the bundled snapshot only."""
        assert recipient_policy._PSL.suffix_list_urls == ()


class TestRecipientRejection:
    """validate_abuse_email_domain() only rejected exact and sub-domain matches,
    so abuse@evil.com.co passed for login.evil.com.co (sibling host, same
    registrable domain controlled by the attacker)."""

    @pytest.mark.parametrize(
        "email, site",
        [
            ("abuse@evil.com.co", "https://login.evil.com.co/verify"),
            ("security@mail.evil.co.uk", "https://pay.evil.co.uk"),
            ("abuse@evil.com", "https://www.evil.com"),
        ],
    )
    def test_same_registrable_domain_is_rejected(self, email, site):
        assert recipient_rejection_reason(email, site) is not None
        assert EnhancedAbuseEmailDetector.validate_abuse_email_domain(email, site) is False

    def test_address_published_by_the_site_is_rejected(self):
        content = "<footer>Support: helpdesk@victim-support.example</footer>"

        assert (
            EnhancedAbuseEmailDetector.validate_abuse_email_domain(
                "helpdesk@victim-support.example", "https://phish.example", site_content=content
            )
            is False
        )

    def test_unrelated_abuse_desk_is_accepted(self):
        assert recipient_rejection_reason("abuse@registrar.example", "https://phish.co") is None


class TestWhoisExtraction:
    """extract_emails_from_whois() fell back to every address in the WHOIS
    text, including registrant addresses, so reports could go to the attacker."""

    def test_registrant_only_whois_yields_nothing(self, detector):
        whois_text = (
            "Domain Name: EVIL.EXAMPLE\n"
            "Registrant Email: crook@gmail.com\n"
            "Admin Email: crook@gmail.com\n"
            "Tech Email: noc-team@evil-hosting.example\n"
        )

        assert detector.extract_emails_from_whois(whois_text) == []

    def test_python_whois_object_keeps_only_the_abuse_role(self, detector):
        record = MagicMock()
        record.emails = ["crook@gmail.com", "abuse@registrar.example", "admin@registrar.example"]
        record.text = (
            "Registrant Email: crook@gmail.com\n"
            "Registrar Abuse Contact Email: abuse@registrar.example\n"
        )

        assert detector.extract_emails_from_whois(record) == ["abuse@registrar.example"]

    def test_abuse_like_registrant_address_is_still_excluded(self, detector):
        whois_text = "Registrant Email: abuse-me@evil-owner.example\n"

        assert detector.extract_emails_from_whois(whois_text) == []

    def test_rdap_abuse_entity_is_trusted_whatever_its_local_part(self, detector):
        rdap = {"registrar": "MarkMonitor", "abuse_contacts": ["complaints@markmonitor.com"]}

        assert detector.extract_emails_from_whois(rdap) == ["complaints@markmonitor.com"]


class TestCloudflareOrigin:
    """get_real_ip_behind_cloudflare() took the IP of the MX host as the site's
    real host, so complaints went to Google/Microsoft for sites they don't host."""

    def test_mx_records_are_never_consulted(self, detector):
        with patch(
            "src.reporting.email_detector.socket.gethostbyname",
            side_effect=OSError("no origin sub-domain"),
        ):
            assert detector.get_real_ip_behind_cloudflare("evil.example") is None

        queried = [call.args[1] for call in detector.dns_resolver.resolve.call_args_list]
        assert "MX" not in queried


class TestTrustOrdering:
    """AbuseContactResolver merges sources through a set and truncates the
    result, so the order (and which contacts survive) was arbitrary."""

    def test_order_by_trust_is_stable(self):
        candidates = [
            ContactCandidate("abuse@asn.example", ContactTier.ASN_ABUSE, "asn"),
            ContactCandidate("abuse@curated.example", ContactTier.CURATED, "db"),
            ContactCandidate("abuse@rdap.example", ContactTier.RDAP_ABUSE, "rdap"),
            ContactCandidate("ABUSE@rdap.example", ContactTier.CURATED, "dup"),
        ]

        assert order_by_trust(candidates) == [
            "abuse@rdap.example",
            "abuse@curated.example",
            "abuse@asn.example",
        ]

    def test_resolve_abuse_contacts_orders_rdap_then_curated_then_asn(self, detector):
        def resolve(asn=None, provider_name=None, whois_data=None, target_domain=None):
            if whois_data is not None:
                return ["abuse@network-rdap.example"]
            if provider_name:
                return ["abuse@provider-db.example"]
            if asn:
                return ["noc@asn-db.example", "abuse@asn-db.example"]
            return []

        detector.abuse_resolver.resolve.side_effect = resolve
        network = MagicMock(provider_name="Some Hosting", asn="AS64500", rdap={"objects": {}})
        with (
            patch.object(
                detector, "get_abuse_email_by_registrar", return_value="abuse@reg-db.example"
            ),
            patch.object(detector, "_lookup_network", return_value=network),
            patch("src.reporting.email_detector.socket.gethostbyname", return_value="192.0.2.7"),
        ):
            resolution = detector.resolve_abuse_contacts(
                "phish.example",
                {"abuse_contacts": ["abuse@registrar-rdap.example"]},
                registrar="Some Registrar",
            )

        assert resolution.emails == [
            "abuse@registrar-rdap.example",
            "abuse@network-rdap.example",
            "abuse@reg-db.example",
            "abuse@provider-db.example",
            "abuse@asn-db.example",
            "noc@asn-db.example",
        ]
        assert resolution.hosting_provider == "Some Hosting"
        assert resolution.asn == "AS64500"

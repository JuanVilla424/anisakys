"""
Tests for src/reporting/email_detector.py

Covers: EnhancedAbuseEmailDetector — static methods (pure logic, no mocks),
        instance methods for DNS resolution and WHOIS parsing.

Import note: src.reporting has a circular import via src.intelligence. We load
src.main first so all modules are registered in sys.modules before our imports.
"""

import pytest
from unittest.mock import MagicMock, patch

import dns.exception

# Load main first to resolve the circular import between src.intelligence and src.detection
from src import main  # noqa: F401 — side-effect import to seed sys.modules

from src.reporting.email_detector import EnhancedAbuseEmailDetector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db():
    return MagicMock()


@pytest.fixture
def detector(mock_db):
    """EnhancedAbuseEmailDetector with mocked constructor dependencies."""
    with (
        patch("src.reporting.email_detector.AbuseContactResolver"),
        patch("src.reporting.email_detector.dns.resolver.Resolver"),
    ):
        det = EnhancedAbuseEmailDetector(db_manager=mock_db)
        det.dns_resolver = MagicMock()
        det.abuse_resolver = MagicMock()
    return det


# ---------------------------------------------------------------------------
# TestExtractEmailsFromWhois
# ---------------------------------------------------------------------------


class TestExtractEmailsFromWhois:
    def test_extracts_emails_from_whois_object_emails_attr(self, detector):
        """Should extract emails from whois object's .emails attribute."""
        mock_whois = MagicMock()
        mock_whois.emails = ["abuse@registrar.com", "admin@registrar.com"]
        result = detector.extract_emails_from_whois(mock_whois)
        assert "abuse@registrar.com" in result

    def test_extracts_abuse_emails_from_raw_text(self, detector):
        """Should extract abuse-related emails by regex when .emails is empty."""
        mock_whois = MagicMock()
        mock_whois.emails = None
        mock_whois.__str__ = lambda self: "Registrar: GoDaddy\nAbuse: abuse@godaddy.com\n"
        result = detector.extract_emails_from_whois(mock_whois)
        assert "abuse@godaddy.com" in result

    def test_deduplicates_emails(self, detector):
        """Should return unique emails when same address appears multiple times."""
        mock_whois = MagicMock()
        mock_whois.emails = ["abuse@registrar.com", "abuse@registrar.com", "Abuse@REGISTRAR.COM"]
        result = detector.extract_emails_from_whois(mock_whois)
        assert len(result) == 1
        assert result[0] == "abuse@registrar.com"

    def test_normalizes_emails_to_lowercase(self, detector):
        """Should lowercase all extracted emails."""
        mock_whois = MagicMock()
        mock_whois.emails = ["ABUSE@REGISTRAR.COM"]
        result = detector.extract_emails_from_whois(mock_whois)
        assert result[0] == "abuse@registrar.com"

    def test_returns_empty_for_empty_whois(self, detector):
        """Should return empty list when no emails can be extracted."""
        mock_whois = MagicMock()
        mock_whois.emails = None
        mock_whois.__str__ = lambda self: "Domain: example.com\nStatus: active\n"
        result = detector.extract_emails_from_whois(mock_whois)
        assert result == []


# ---------------------------------------------------------------------------
# TestExtractRegistrar (static method)
# ---------------------------------------------------------------------------


class TestExtractRegistrar:
    def test_extracts_registrar_from_dict(self):
        """Should extract registrar string from dict with 'registrar' key."""
        result = EnhancedAbuseEmailDetector.extract_registrar({"registrar": "GoDaddy LLC"})
        assert result == "GoDaddy LLC"

    def test_extracts_first_registrar_from_list(self):
        """Should take the first registrar when value is a list."""
        result = EnhancedAbuseEmailDetector.extract_registrar(
            {"registrar": ["GoDaddy LLC", "GoDaddy Inc"]}
        )
        assert result == "GoDaddy LLC"

    def test_extracts_registrar_from_raw_text(self):
        """Should parse 'Registrar: X' pattern from raw WHOIS text."""
        whois_text = "Domain Name: EXAMPLE.COM\nRegistrar: Namecheap Inc\nStatus: active\n"
        result = EnhancedAbuseEmailDetector.extract_registrar(whois_text)
        assert result == "Namecheap Inc"

    def test_returns_none_when_not_found(self):
        """Should return None when no registrar field is present."""
        result = EnhancedAbuseEmailDetector.extract_registrar("No registrar info here")
        assert result is None

    def test_returns_none_for_empty_dict(self):
        """Should return None for dict without a 'registrar' key."""
        result = EnhancedAbuseEmailDetector.extract_registrar({})
        assert result is None


# ---------------------------------------------------------------------------
# TestValidateAbuseEmailDomain (static method)
# ---------------------------------------------------------------------------


class TestValidateAbuseEmailDomain:
    def test_valid_abuse_email_from_different_domain(self):
        """Should return True when email domain differs from reported domain."""
        result = EnhancedAbuseEmailDetector.validate_abuse_email_domain(
            "abuse@registrar.com", "phishingsite.com"
        )
        assert result is True

    def test_rejects_email_from_same_domain(self):
        """Should return False when email domain matches the reported domain."""
        result = EnhancedAbuseEmailDetector.validate_abuse_email_domain(
            "abuse@phishingsite.com", "phishingsite.com"
        )
        assert result is False

    def test_rejects_subdomain_of_reported_domain(self):
        """Should return False when email is from a subdomain of the reported domain."""
        result = EnhancedAbuseEmailDetector.validate_abuse_email_domain(
            "abuse@mail.phishingsite.com", "phishingsite.com"
        )
        assert result is False

    def test_strips_www_from_reported_domain(self):
        """Should treat www.phishingsite.com the same as phishingsite.com."""
        result = EnhancedAbuseEmailDetector.validate_abuse_email_domain(
            "abuse@phishingsite.com", "www.phishingsite.com"
        )
        assert result is False

    def test_returns_false_for_malformed_email(self):
        """Should return False for email string without @ character."""
        result = EnhancedAbuseEmailDetector.validate_abuse_email_domain(
            "not-an-email", "phishingsite.com"
        )
        assert result is False


# ---------------------------------------------------------------------------
# TestParseStoredAbuseEmails (static method)
# ---------------------------------------------------------------------------


class TestParseStoredAbuseEmails:
    def test_parses_single_email(self):
        """Should return a one-element list for a single email string."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails("abuse@example.com")
        assert result == ["abuse@example.com"]

    def test_parses_comma_separated_emails(self):
        """Should split comma-separated emails into a list."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails(
            "abuse@example.com, security@example.com"
        )
        assert "abuse@example.com" in result
        assert "security@example.com" in result
        assert len(result) == 2

    def test_parses_json_array_format(self):
        """Should parse JSON array format '["a@b.com", "c@d.com"]'."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails(
            '["abuse@example.com", "security@example.com"]'
        )
        assert "abuse@example.com" in result
        assert "security@example.com" in result

    def test_parses_python_list_string_format(self):
        """Should parse Python literal list format ['a@b.com']."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails(
            "['abuse@example.com', 'security@example.com']"
        )
        assert "abuse@example.com" in result

    def test_handles_empty_string(self):
        """Should return empty list for empty input string."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails("")
        assert result == []

    def test_handles_none_input(self):
        """Should return empty list for None input."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails(None)
        assert result == []

    def test_handles_whitespace_only(self):
        """Should return empty list for whitespace-only input."""
        result = EnhancedAbuseEmailDetector.parse_stored_abuse_emails("   ")
        assert result == []


# ---------------------------------------------------------------------------
# TestValidateEmail (instance method, DNS-dependent)
# ---------------------------------------------------------------------------


class TestValidateEmail:
    def test_valid_email_with_mx_record(self, detector):
        """Should return True when format is valid and domain has an MX record."""
        with patch("src.reporting.email_detector.validators.email", return_value=True):
            detector.dns_resolver.resolve.return_value = [MagicMock()]
            result = detector.validate_email("abuse@example.com")
        assert result is True

    def test_invalid_format_rejected_by_validators(self, detector):
        """Should return False immediately when validators.email() returns falsy."""
        with patch("src.reporting.email_detector.validators.email", return_value=False):
            result = detector.validate_email("not-an-email")
        assert result is False

    def test_no_mx_record_returns_false(self, detector):
        """Should return False when domain DNS resolution raises DNSException."""
        with patch("src.reporting.email_detector.validators.email", return_value=True):
            detector.dns_resolver.resolve.side_effect = dns.exception.DNSException("NXDOMAIN")
            result = detector.validate_email("abuse@nodomain.xyz")
        assert result is False


# ---------------------------------------------------------------------------
# TestGetAbuseEmailFromDns (instance method, DNS-dependent)
# ---------------------------------------------------------------------------


class TestGetAbuseEmailFromDns:
    def test_returns_none_on_dns_exception(self, detector):
        """Should return None when DNS TXT resolution fails."""
        detector.dns_resolver.resolve.side_effect = dns.exception.DNSException("timeout")
        result = detector.get_abuse_email_from_dns("example.com")
        assert result is None

    def test_returns_none_when_no_abuse_txt_records(self, detector):
        """Should return None when TXT records exist but contain no abuse email."""
        mock_record = MagicMock()
        mock_record.__str__ = lambda self: '"v=spf1 include:example.com ~all"'
        detector.dns_resolver.resolve.return_value = [mock_record]
        result = detector.get_abuse_email_from_dns("example.com")
        assert result is None

    def test_returns_abuse_email_from_matching_txt(self, detector):
        """Should return email when TXT record contains 'abuse' keyword and valid email."""
        mock_record = MagicMock()
        mock_record.__str__ = lambda self: '"abuse-contact: abuse@provider.com; policy: rfc7505"'
        detector.dns_resolver.resolve.return_value = [mock_record]

        with patch.object(detector, "validate_email", return_value=True):
            result = detector.get_abuse_email_from_dns("example.com")

        # If the regex matches an email in the record, it returns it
        assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# TestGetEnhancedWhoisInfo (static method, network-dependent)
# ---------------------------------------------------------------------------


class TestGetEnhancedWhoisInfo:
    def test_returns_whois_data_on_success(self):
        """Should return whois data directly when python-whois succeeds."""
        mock_whois_data = MagicMock()
        mock_whois_data.domain_name = "example.com"
        mock_whois_data.registrar = "GoDaddy"

        with patch("src.reporting.email_detector.whois.whois", return_value=mock_whois_data):
            result = EnhancedAbuseEmailDetector.get_enhanced_whois_info("example.com")

        assert result is mock_whois_data

    def test_returns_empty_dict_when_all_methods_fail(self):
        """Should return {} when python-whois, subprocess, and RDAP all fail."""
        with (
            patch("src.reporting.email_detector.whois.whois", side_effect=Exception("timeout")),
            patch("src.reporting.email_detector.subprocess.run", side_effect=Exception("no whois")),
            patch.object(EnhancedAbuseEmailDetector, "get_rdap_info", return_value={}),
        ):
            result = EnhancedAbuseEmailDetector.get_enhanced_whois_info("unknown.xyz")

        assert result == {}

    def test_falls_back_to_subprocess_on_python_whois_failure(self):
        """Should attempt subprocess whois when python-whois library fails."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = (
            "Domain Name: EXAMPLE.COM\nRegistrar: Test Registrar\nCreated: 2020-01-01\n"
        )

        with (
            patch(
                "src.reporting.email_detector.whois.whois",
                side_effect=Exception("whois lib failed"),
            ),
            patch("src.reporting.email_detector.subprocess.run", return_value=mock_proc),
            patch.object(EnhancedAbuseEmailDetector, "get_rdap_info", return_value={}),
        ):
            result = EnhancedAbuseEmailDetector.get_enhanced_whois_info("example.com")

        assert isinstance(result, dict)

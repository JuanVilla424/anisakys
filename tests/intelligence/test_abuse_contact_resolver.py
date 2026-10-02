"""
Unit tests for AbuseContactResolver class.

Tests cover:
- ASN database resolution
- Provider database resolution
- WHOIS/RDAP data parsing
- Email validation and filtering
- Deduplication
- Multi-source resolution
"""

import unittest
from unittest.mock import Mock
from src.intelligence.abuse_contact_resolver import AbuseContactResolver


class TestAbuseContactResolverBasic(unittest.TestCase):
    """Test basic AbuseContactResolver functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.asn_db = {
            "16509": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
            "8075": ["abuse@microsoft.com"],
            "15169": ["network-abuse@google.com"],
        }

        self.provider_db = {
            "AMAZON": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
            "MICROSOFT": ["abuse@microsoft.com"],
            "GOOGLE": ["network-abuse@google.com"],
            "HOSTINGER": ["abuse@hostinger.com"],
        }

        self.resolver = AbuseContactResolver(
            asn_db=self.asn_db,
            provider_db=self.provider_db,
        )

    def test_init_default_values(self):
        """Test resolver initializes with correct defaults."""
        resolver = AbuseContactResolver(asn_db={}, provider_db={})
        self.assertTrue(resolver.validate_domains)
        self.assertEqual(resolver.max_contacts, 10)

    def test_init_custom_values(self):
        """Test resolver initializes with custom values."""
        resolver = AbuseContactResolver(
            asn_db={}, provider_db={}, validate_domains=False, max_contacts=5
        )
        self.assertFalse(resolver.validate_domains)
        self.assertEqual(resolver.max_contacts, 5)


class TestASNResolution(unittest.TestCase):
    """Test ASN database resolution."""

    def setUp(self):
        """Set up test fixtures."""
        self.asn_db = {
            "16509": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
            "8075": ["abuse@microsoft.com"],
            "AS15169": ["network-abuse@google.com"],  # With AS prefix
        }
        self.resolver = AbuseContactResolver(
            asn_db=self.asn_db, provider_db={}, validate_domains=False
        )

    def test_resolve_asn_without_prefix(self):
        """Test ASN resolution without AS prefix."""
        result = self.resolver.resolve(asn="16509")
        self.assertEqual(len(result), 2)
        self.assertIn("abuse@amazon.com", result)
        self.assertIn("ec2-abuse@amazon.com", result)

    def test_resolve_asn_with_prefix(self):
        """Test ASN resolution with AS prefix."""
        result = self.resolver.resolve(asn="AS16509")
        self.assertEqual(len(result), 2)
        self.assertIn("abuse@amazon.com", result)

    def test_resolve_asn_stored_with_prefix(self):
        """Test ASN resolution when database has AS prefix."""
        result = self.resolver.resolve(asn="15169")
        self.assertEqual(len(result), 1)
        self.assertIn("network-abuse@google.com", result)

    def test_resolve_nonexistent_asn(self):
        """Test resolution of non-existent ASN."""
        result = self.resolver.resolve(asn="99999")
        self.assertEqual(len(result), 0)

    def test_resolve_empty_asn(self):
        """Test resolution with empty ASN."""
        result = self.resolver.resolve(asn="")
        self.assertEqual(len(result), 0)


class TestProviderResolution(unittest.TestCase):
    """Test provider database resolution."""

    def setUp(self):
        """Set up test fixtures."""
        self.provider_db = {
            "AMAZON": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
            "HOSTINGER": ["abuse@hostinger.com"],
            "HOSTINGER-HOSTING": ["abuse@hostinger.com"],
            "INVALID-PROVIDER": ["abuse@", "invalid", ""],  # Invalid emails
        }
        self.resolver = AbuseContactResolver(
            asn_db={}, provider_db=self.provider_db, validate_domains=False
        )

    def test_resolve_provider_exact_match(self):
        """Test provider resolution with exact match."""
        result = self.resolver.resolve(provider_name="AMAZON")
        self.assertEqual(len(result), 2)
        self.assertIn("abuse@amazon.com", result)

    def test_resolve_provider_case_insensitive(self):
        """Test provider resolution is case insensitive."""
        result = self.resolver.resolve(provider_name="amazon")
        self.assertEqual(len(result), 2)
        self.assertIn("abuse@amazon.com", result)

    def test_resolve_provider_partial_match(self):
        """Test provider resolution with partial match."""
        result = self.resolver.resolve(provider_name="HOSTINGER")
        self.assertEqual(len(result), 1)
        self.assertIn("abuse@hostinger.com", result)

    def test_resolve_provider_filters_invalid_emails(self):
        """Test that invalid emails are filtered out."""
        result = self.resolver.resolve(provider_name="INVALID-PROVIDER")
        self.assertEqual(len(result), 0)

    def test_resolve_nonexistent_provider(self):
        """Test resolution of non-existent provider."""
        result = self.resolver.resolve(provider_name="NONEXISTENT")
        self.assertEqual(len(result), 0)


class TestWhoisResolution(unittest.TestCase):
    """Test WHOIS/RDAP data parsing."""

    def setUp(self):
        """Set up test fixtures."""
        self.resolver = AbuseContactResolver(asn_db={}, provider_db={}, validate_domains=False)

    def test_resolve_whois_with_rdap_objects(self):
        """Test WHOIS resolution with RDAP objects."""
        whois_data = {
            "objects": {
                "abuse-contact": {
                    "contact": {
                        "role": "abuse",
                        "email": "abuse@example.com",
                    }
                }
            }
        }
        result = self.resolver.resolve(whois_data=whois_data)
        self.assertEqual(len(result), 1)
        self.assertIn("abuse@example.com", result)

    def test_resolve_whois_with_email_list(self):
        """Test WHOIS resolution with email list in RDAP."""
        whois_data = {
            "objects": {
                "abuse-contact": {
                    "contact": {
                        "role": "abuse",
                        "email": ["abuse1@example.com", "abuse2@example.com"],
                    }
                }
            }
        }
        result = self.resolver.resolve(whois_data=whois_data)
        self.assertEqual(len(result), 2)
        self.assertIn("abuse1@example.com", result)
        self.assertIn("abuse2@example.com", result)

    def test_resolve_whois_with_abuse_contacts_field(self):
        """Test WHOIS resolution with direct abuse_contacts field."""
        whois_data = {"abuse_contacts": "abuse@example.com"}
        result = self.resolver.resolve(whois_data=whois_data)
        self.assertEqual(len(result), 1)
        self.assertIn("abuse@example.com", result)

    def test_resolve_whois_with_raw_text(self):
        """Test WHOIS resolution by parsing raw text."""
        whois_data = {
            "raw_whois": """
            Domain Name: example.com
            Registrar: Example Registrar
            Abuse Contact: abuse@example.com
            Abuse-Mailbox: security@example.com
            """
        }
        result = self.resolver.resolve(whois_data=whois_data)
        self.assertGreaterEqual(len(result), 1)
        # Should find at least one abuse email in the raw text

    def test_resolve_empty_whois(self):
        """Test resolution with empty WHOIS data."""
        result = self.resolver.resolve(whois_data={})
        self.assertEqual(len(result), 0)


class TestEmailValidation(unittest.TestCase):
    """Test email validation and filtering."""

    def setUp(self):
        """Set up test fixtures."""
        self.asn_db = {
            "12345": [
                "abuse@hosting.com",
                "abuse@phishing-site.com",  # Same domain
                "invalid@",  # Invalid format
                "",  # Empty
                "notanemail",  # No @
            ]
        }
        self.resolver = AbuseContactResolver(
            asn_db=self.asn_db, provider_db={}, validate_domains=True
        )

    def test_filters_same_domain_emails(self):
        """Test that emails from same domain are filtered."""
        result = self.resolver.resolve(asn="12345", target_domain="phishing-site.com")
        self.assertEqual(len(result), 1)
        self.assertIn("abuse@hosting.com", result)
        self.assertNotIn("abuse@phishing-site.com", result)

    def test_filters_invalid_email_formats(self):
        """Test that invalid email formats are filtered."""
        result = self.resolver.resolve(asn="12345")
        # Should only have valid emails
        for email in result:
            self.assertIn("@", email)
            self.assertFalse(email.endswith("@"))

    def test_allows_valid_emails_when_validation_disabled(self):
        """Test that validation can be disabled."""
        resolver = AbuseContactResolver(asn_db=self.asn_db, provider_db={}, validate_domains=False)
        result = resolver.resolve(asn="12345", target_domain="phishing-site.com")
        # Should include same-domain email when validation is disabled
        self.assertIn("abuse@phishing-site.com", result)

    def test_validates_email_format_correctly(self):
        """Test email format validation."""
        valid_emails = [
            "abuse@example.com",
            "security+alerts@example.co.uk",
            "admin_abuse@example-site.com",
        ]
        for email in valid_emails:
            self.assertTrue(
                self.resolver._is_valid_email_format(email),
                f"Should validate {email} as valid",
            )

        invalid_emails = [
            "abuse@",
            "@example.com",
            "not-an-email",
            "",
            None,
        ]
        for email in invalid_emails:
            self.assertFalse(
                self.resolver._is_valid_email_format(email),
                f"Should validate {email} as invalid",
            )


class TestDeduplication(unittest.TestCase):
    """Test email deduplication across multiple sources."""

    def setUp(self):
        """Set up test fixtures."""
        self.asn_db = {
            "16509": ["abuse@amazon.com", "ec2-abuse@amazon.com"],
        }
        self.provider_db = {
            "AMAZON": ["abuse@amazon.com", "aws-abuse@amazon.com"],  # Duplicate + new
        }
        self.resolver = AbuseContactResolver(
            asn_db=self.asn_db, provider_db=self.provider_db, validate_domains=False
        )

    def test_deduplicates_across_sources(self):
        """Test that emails are deduplicated across ASN and provider sources."""
        result = self.resolver.resolve(asn="16509", provider_name="AMAZON")
        # Should have unique emails only: abuse@amazon.com, ec2-abuse@amazon.com, aws-abuse@amazon.com
        self.assertEqual(len(result), 3)
        self.assertIn("abuse@amazon.com", result)
        self.assertIn("ec2-abuse@amazon.com", result)
        self.assertIn("aws-abuse@amazon.com", result)

    def test_respects_max_contacts_limit(self):
        """Test that max_contacts limit is respected."""
        # Create resolver with max 2 contacts
        resolver = AbuseContactResolver(
            asn_db=self.asn_db,
            provider_db=self.provider_db,
            validate_domains=False,
            max_contacts=2,
        )
        result = resolver.resolve(asn="16509", provider_name="AMAZON")
        self.assertEqual(len(result), 2)


class TestMultiSourceResolution(unittest.TestCase):
    """Test resolution from multiple sources simultaneously."""

    def setUp(self):
        """Set up test fixtures."""
        self.asn_db = {"16509": ["asn-abuse@amazon.com"]}
        self.provider_db = {"AMAZON": ["provider-abuse@amazon.com"]}
        self.resolver = AbuseContactResolver(
            asn_db=self.asn_db, provider_db=self.provider_db, validate_domains=False
        )

    def test_combines_asn_and_provider(self):
        """Test combining ASN and provider sources."""
        result = self.resolver.resolve(asn="16509", provider_name="AMAZON")
        self.assertEqual(len(result), 2)
        self.assertIn("asn-abuse@amazon.com", result)
        self.assertIn("provider-abuse@amazon.com", result)

    def test_combines_all_three_sources(self):
        """Test combining ASN, provider, and WHOIS sources."""
        whois_data = {"abuse_contacts": "whois-abuse@amazon.com"}
        result = self.resolver.resolve(asn="16509", provider_name="AMAZON", whois_data=whois_data)
        self.assertEqual(len(result), 3)
        self.assertIn("asn-abuse@amazon.com", result)
        self.assertIn("provider-abuse@amazon.com", result)
        self.assertIn("whois-abuse@amazon.com", result)

    def test_fallback_to_provider_when_asn_missing(self):
        """Test fallback to provider when ASN has no results."""
        result = self.resolver.resolve(asn="99999", provider_name="AMAZON")
        self.assertEqual(len(result), 1)
        self.assertIn("provider-abuse@amazon.com", result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.resolver = AbuseContactResolver(asn_db={}, provider_db={})

    def test_resolve_with_no_parameters(self):
        """Test resolution with no parameters provided."""
        result = self.resolver.resolve()
        self.assertEqual(len(result), 0)

    def test_resolve_with_none_values(self):
        """Test resolution with None values."""
        result = self.resolver.resolve(
            asn=None, provider_name=None, whois_data=None, target_domain=None
        )
        self.assertEqual(len(result), 0)

    def test_resolve_with_empty_strings(self):
        """Test resolution with empty strings."""
        result = self.resolver.resolve(asn="", provider_name="", target_domain="")
        self.assertEqual(len(result), 0)

    def test_handles_malformed_whois_data(self):
        """Test handling of malformed WHOIS data."""
        malformed_whois = {
            "objects": "not-a-dict",  # Should be dict
            "abuse_contacts": 123,  # Should be string or list
        }
        # Should not crash
        result = self.resolver.resolve(whois_data=malformed_whois)
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()

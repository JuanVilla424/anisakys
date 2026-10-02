"""
Abuse contact validator for ICANN compliance
Validates abuse email addresses before sending reports
"""

import re
import socket
import smtplib
import dns.resolver
import dns.exception
from typing import Optional, Dict, List, Tuple
import requests
import logging
from urllib.parse import urlparse
import validators

logger = logging.getLogger(__name__)


class AbuseContactValidator:
    """Validates abuse contact emails for ICANN compliance"""

    def __init__(self, timeout: int = 10):
        """
        Inicializar validador

        Args:
            timeout: Network timeout in seconds
        """
        self.timeout = timeout
        self.cache = {}  # Simple cache for repeated validations

    def validate_email_format(self, email: str) -> bool:
        """
        Validate email format using regex

        Args:
            email: Email address to validate

        Returns:
            True if format is valid
        """
        if not email or not isinstance(email, str):
            return False

        # Basic email regex that complies with RFC 5322
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        if not re.match(email_pattern, email.strip()):
            return False

        # Additional verifications
        if len(email) > 254:  # RFC 5321 limit
            return False

        local, domain = email.rsplit("@", 1)
        if len(local) > 64:  # RFC 5321 limit for local part
            return False

        return True

    def validate_domain_mx(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate that domain has MX records

        Args:
            domain: Domain to check

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            mx_records = dns.resolver.resolve(domain, "MX", lifetime=self.timeout)
            if mx_records:
                logger.debug(f"Domain {domain} has {len(mx_records)} MX records")
                return True, None
            else:
                return False, "No MX records found"

        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist"
        except dns.resolver.NoAnswer:
            return False, "No MX records found"
        except dns.exception.Timeout:
            return False, "DNS timeout"
        except Exception as e:
            return False, f"DNS error: {str(e)}"

    def validate_smtp_connectivity(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Test SMTP connectivity to email domain

        Args:
            email: Email address to test

        Returns:
            Tuple of (is_valid, error_message)
        """
        domain = email.split("@")[1]

        try:
            # Get MX records first
            mx_records = dns.resolver.resolve(domain, "MX", lifetime=self.timeout)
            mx_host = str(mx_records[0].exchange).rstrip(".")

            # Test SMTP connection
            with smtplib.SMTP(timeout=self.timeout) as smtp:
                smtp.connect(mx_host, 25)
                response = smtp.helo()

                if response[0] == 250:
                    logger.debug(f"SMTP connectivity verified for {domain}")
                    return True, None
                else:
                    return False, f"SMTP HELO failed: {response[1]}"

        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist"
        except dns.resolver.NoAnswer:
            return False, "No MX records found"
        except smtplib.SMTPConnectError as e:
            return False, f"SMTP connection failed: {str(e)}"
        except smtplib.SMTPServerDisconnected:
            return False, "SMTP server disconnected"
        except socket.timeout:
            return False, "SMTP connection timeout"
        except Exception as e:
            return False, f"SMTP error: {str(e)}"

    def check_abuse_email_standards(self, email: str, domain: str) -> Tuple[bool, List[str]]:
        """
        Check if email follows abuse contact standards

        Args:
            email: Email address to check
            domain: Domain being reported

        Returns:
            Tuple of (is_compliant, warnings)
        """
        warnings = []
        is_compliant = True

        email_local = email.split("@")[0].lower()
        email_domain = email.split("@")[1].lower()

        # Check if it's a proper abuse email
        if not any(
            keyword in email_local for keyword in ["abuse", "security", "admin", "hostmaster"]
        ):
            warnings.append(
                "Email doesn't appear to be an abuse contact (missing abuse/security/admin)"
            )
            is_compliant = False

        # Check if email domain matches the site domain being reported
        site_domain = urlparse(f"http://{domain}").netloc.lower()
        if email_domain == site_domain:
            warnings.append("Abuse email domain matches site domain - may not be responsive")
            is_compliant = False

        # Check for common non-abuse addresses
        non_abuse_locals = [
            "info",
            "contact",
            "support",
            "sales",
            "marketing",
            "noreply",
            "no-reply",
        ]
        if email_local in non_abuse_locals:
            warnings.append(
                f"Email uses generic address '{email_local}' - may not handle abuse reports"
            )

        return is_compliant, warnings

    def validate_registrar_abuse_contact(
        self, email: str, registrar: str = None, target_domain: str = None
    ) -> Dict[str, any]:
        """
        Validate registrar abuse contact specifically

        Args:
            email: Registrar abuse email
            registrar: Registrar name (optional)
            target_domain: The domain being reported (to check for same-domain issues)

        Returns:
            Dict with validation results
        """
        cache_key = f"registrar_{email}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        result = {
            "email": email,
            "registrar": registrar,
            "valid": False,
            "format_valid": False,
            "domain_valid": False,
            "smtp_valid": False,
            "standards_compliant": False,
            "warnings": [],
            "errors": [],
        }

        # Format validation
        result["format_valid"] = self.validate_email_format(email)
        if not result["format_valid"]:
            result["errors"].append("Invalid email format")
            self.cache[cache_key] = result
            return result

        domain = email.split("@")[1]

        # Domain MX validation
        result["domain_valid"], domain_error = self.validate_domain_mx(domain)
        if not result["domain_valid"]:
            result["errors"].append(f"Domain validation failed: {domain_error}")

        # SMTP connectivity (optional - may be blocked by firewalls)
        result["smtp_valid"], smtp_error = self.validate_smtp_connectivity(email)
        if not result["smtp_valid"]:
            result["warnings"].append(f"SMTP connectivity issue: {smtp_error}")

        # Standards compliance (use target_domain if provided, otherwise skip same-domain check)
        result["standards_compliant"], standards_warnings = self.check_abuse_email_standards(
            email, target_domain or "unknown-domain.example"
        )
        result["warnings"].extend(standards_warnings)

        # Overall validity (format + domain required, SMTP optional)
        result["valid"] = result["format_valid"] and result["domain_valid"]

        self.cache[cache_key] = result
        return result

    def validate_hosting_abuse_contact(
        self, email: str, hosting_provider: str = None, site_domain: str = None
    ) -> Dict[str, any]:
        """
        Validate hosting provider abuse contact

        Args:
            email: Hosting provider abuse email
            hosting_provider: Provider name (optional)
            site_domain: Site domain being reported (optional)

        Returns:
            Dict with validation results
        """
        cache_key = f"hosting_{email}_{site_domain}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        result = {
            "email": email,
            "hosting_provider": hosting_provider,
            "site_domain": site_domain,
            "valid": False,
            "format_valid": False,
            "domain_valid": False,
            "smtp_valid": False,
            "standards_compliant": False,
            "warnings": [],
            "errors": [],
        }

        # Format validation
        result["format_valid"] = self.validate_email_format(email)
        if not result["format_valid"]:
            result["errors"].append("Invalid email format")
            self.cache[cache_key] = result
            return result

        domain = email.split("@")[1]

        # Domain MX validation
        result["domain_valid"], domain_error = self.validate_domain_mx(domain)
        if not result["domain_valid"]:
            result["errors"].append(f"Domain validation failed: {domain_error}")

        # SMTP connectivity
        result["smtp_valid"], smtp_error = self.validate_smtp_connectivity(email)
        if not result["smtp_valid"]:
            result["warnings"].append(f"SMTP connectivity issue: {smtp_error}")

        # Standards compliance (use site domain if provided)
        check_domain = site_domain if site_domain else domain
        result["standards_compliant"], standards_warnings = self.check_abuse_email_standards(
            email, check_domain
        )
        result["warnings"].extend(standards_warnings)

        # Overall validity
        result["valid"] = result["format_valid"] and result["domain_valid"]

        self.cache[cache_key] = result
        return result

    def validate_multiple_contacts(
        self, emails: List[str], context: str = "general"
    ) -> Dict[str, any]:
        """
        Validate multiple abuse contacts

        Args:
            emails: List of email addresses
            context: Context for validation (registrar, hosting, etc.)

        Returns:
            Dict with validation results for all emails
        """
        results = {
            "context": context,
            "total_emails": len(emails),
            "valid_emails": 0,
            "invalid_emails": 0,
            "results": {},
        }

        for email in emails:
            if context == "registrar":
                result = self.validate_registrar_abuse_contact(email)
            elif context == "hosting":
                result = self.validate_hosting_abuse_contact(email)
            else:
                # Generic validation
                result = self.validate_registrar_abuse_contact(email)

            results["results"][email] = result

            if result["valid"]:
                results["valid_emails"] += 1
            else:
                results["invalid_emails"] += 1

        return results

    def get_validation_summary(self, validation_result: Dict[str, any]) -> str:
        """
        Get human-readable summary of validation results

        Args:
            validation_result: Result from validation methods

        Returns:
            Summary string
        """
        if validation_result.get("total_emails"):
            # Multiple email results
            valid = validation_result["valid_emails"]
            total = validation_result["total_emails"]
            return f"Validated {total} emails: {valid} valid, {total-valid} invalid"
        else:
            # Single email result
            email = validation_result["email"]
            if validation_result["valid"]:
                warnings_count = len(validation_result.get("warnings", []))
                if warnings_count > 0:
                    return f"✅ {email} is valid (with {warnings_count} warnings)"
                else:
                    return f"✅ {email} is valid"
            else:
                errors_count = len(validation_result.get("errors", []))
                return f"❌ {email} is invalid ({errors_count} errors)"


# Convenience functions
def validate_abuse_email(email: str, timeout: int = 10) -> Dict[str, any]:
    """
    Quick validation of a single abuse email

    Args:
        email: Email to validate
        timeout: Network timeout

    Returns:
        Validation result dict
    """
    validator = AbuseContactValidator(timeout)
    return validator.validate_registrar_abuse_contact(email)


def validate_abuse_emails(
    emails: List[str], context: str = "general", timeout: int = 10
) -> Dict[str, any]:
    """
    Quick validation of multiple abuse emails

    Args:
        emails: List of emails to validate
        context: Validation context
        timeout: Network timeout

    Returns:
        Validation results dict
    """
    validator = AbuseContactValidator(timeout)
    return validator.validate_multiple_contacts(emails, context)


if __name__ == "__main__":
    # Test the validator
    import sys

    if len(sys.argv) < 2:
        print("Usage: python abuse_contact_validator.py <email1> [email2] ...")
        sys.exit(1)

    emails = sys.argv[1:]

    validator = AbuseContactValidator()

    for email in emails:
        print(f"\nValidating: {email}")
        result = validator.validate_registrar_abuse_contact(email)
        print(validator.get_validation_summary(result))

        if result["errors"]:
            print("❌ Errors:")
            for error in result["errors"]:
                print(f"   - {error}")

        if result["warnings"]:
            print("⚠️  Warnings:")
            for warning in result["warnings"]:
                print(f"   - {warning}")

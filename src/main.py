#!/usr/bin/env python3
"""
Enhanced Anisakys Phishing Detection Engine

This script scans and processes phishing sites with improved abuse email detection
and REST API capabilities for external reporting.

Usage examples:
  ./anisakys.py --timeout 30 --log-level DEBUG
  ./anisakys.py --report https://site.domain.com --abuse-email abuse@domain.com
  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"
  ./anisakys.py --threads-only --log-level DEBUG
  ./anisakys.py --regen-queries
  ./anisakys.py --test-report --abuse-email your-test@example.com
  ./anisakys.py --start-api --api-port 8080  # Start REST API server
"""

import gc
import os
import re
import time
import argparse
import requests
from itertools import permutations, islice
import datetime
from typing import List, Optional, Tuple, Dict, Any
import threading
import smtplib
import psutil
import json
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from jinja2 import Environment, FileSystemLoader, select_autoescape
import whois
import socket
import ipaddress
import dns.resolver
import dns.exception
from ipwhois import IPWhois
import validators
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy import create_engine, text
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging as flask_logging

from src.config import settings, CLOUDFLARE_IP_RANGES
from src.logger import logger

# Database and file configuration
DATABASE_URL = getattr(settings, "DATABASE_URL", None)
if not DATABASE_URL:
    raise Exception("DATABASE_URL must be set in your .env file")

QUERIES_FILE = getattr(settings, "QUERIES_FILE", "queries_test.txt")
if not QUERIES_FILE:
    raise Exception("QUERIES_FILE must be set in your .env file")

OFFSET_FILE = getattr(settings, "OFFSET_FILE", "offset_test.txt")

# Constants
ALLOWED_HEAD_STATUS = {200, 201, 202, 203, 204, 205, 206, 301, 302, 403, 405, 503, 504}
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/115.0 Safari/537.36"
)
DNS_ERROR_KEY_PHRASES = {
    "Name or service not known",
    "getaddrinfo failed",
    "Failed to resolve",
    "Max retries exceeded",
}

# Enhanced abuse email patterns
ABUSE_EMAIL_PATTERNS = [
    r"abuse@[\w\.-]+\.\w+",
    r"security@[\w\.-]+\.\w+",
    r"admin@[\w\.-]+\.\w+",
    r"postmaster@[\w\.-]+\.\w+",
    r"hostmaster@[\w\.-]+\.\w+",
    r"webmaster@[\w\.-]+\.\w+",
    r"support@[\w\.-]+\.\w+",
    r"noc@[\w\.-]+\.\w+",
    r"legal@[\w\.-]+\.\w+",
    r"compliance@[\w\.-]+\.\w+",
]

# Enhanced ASN to abuse email mapping
ASN_ABUSE_EMAIL_DB = {
    # Major Cloud Providers
    "16509": "abuse@amazon.com",  # Amazon AWS
    "14618": "abuse@amazon.com",  # Amazon AWS
    "8075": "abuse@microsoft.com",  # Microsoft Azure
    "15169": "abuse@google.com",  # Google Cloud
    "13335": "abuse@cloudflare.com",  # Cloudflare
    "20940": "abuse@akamai.com",  # Akamai
    # Major Hosting Providers
    "14061": "abuse@digitalocean.com",  # DigitalOcean
    "16276": "abuse@ovh.com",  # OVH
    "24940": "abuse@hetzner.de",  # Hetzner
    "63949": "abuse@linode.com",  # Linode
    "62240": "abuse@vultr.com",  # Vultr
    "36351": "abuse@godaddy.com",  # GoDaddy
    "26496": "abuse@godaddy.com",  # GoDaddy
    "46606": "abuse@unified-layer.com",  # Unified Layer (Bluehost, HostGator)
    "46562": "abuse@totaluptime.com",  # Total Uptime
    "19318": "abuse@interserver.net",  # Interserver
    "55286": "abuse@server.lu",  # Server.lu
    "49505": "abuse@selectel.ru",  # Selectel
    "39561": "abuse@contabo.com",  # Contabo
    "51167": "abuse@contabo.com",  # Contabo
    "8560": "abuse@oneandone.net",  # IONOS (1&1)
    "8075": "abuse@microsoft.com",  # Microsoft
    "29066": "abuse@velianet.com",  # Velia.net
    # European Providers
    "12876": "abuse@online.net",  # Online.net (Scaleway)
    "12322": "abuse@proxad.net",  # Free/Proxad
    "3215": "abuse@orange.com",  # Orange
    "5432": "abuse@proximus.be",  # Proximus
    "6830": "abuse@upc.ch",  # UPC
    "6739": "abuse@ono.com",  # ONO
    "3352": "abuse@telefonica.es",  # Telefonica
    # US Providers
    "7922": "abuse@comcast.net",  # Comcast
    "20115": "abuse@charter.com",  # Charter/Spectrum
    "22773": "abuse@cox.net",  # Cox
    "11427": "abuse@twc.com",  # Time Warner
    "7018": "abuse@att.net",  # AT&T
    "701": "abuse@verizon.net",  # Verizon
    # Latin American Providers
    "27699": "abuse@telecom.com.ar",  # Telecom Argentina
    "7738": "abuse@telecom.com.br",  # Telecom Brasil
    "28573": "abuse@claro.com.co",  # Claro Colombia
    "19429": "abuse@emcali.net.co",  # Emcali Colombia
    "14080": "abuse@une.net.co",  # UNE Colombia
    # Asian Providers
    "9808": "abuse@guangdong.chinamobile.com",  # China Mobile
    "4134": "abuse@chinatelecom.cn",  # China Telecom
    "4837": "abuse@chinaunicom.cn",  # China Unicom
    "9583": "abuse@sify.com",  # Sify (India)
    "45609": "abuse@bharti.in",  # Bharti Airtel
    # Other Notable Providers
    "200019": "abuse@alexhost.com",  # Alexhost
    "49981": "abuse@worldstream.nl",  # WorldStream
    "60068": "abuse@cdn77.com",  # CDN77
    "13414": "abuse@twitter.com",  # Twitter
    "32934": "abuse@facebook.com",  # Meta/Facebook
    "714": "abuse@apple.com",  # Apple
    "36459": "abuse@github.com",  # GitHub
}

# TLD to WHOIS server mapping for better WHOIS lookups
TLD_WHOIS_SERVERS = {
    # Generic TLDs
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.nic.biz",
    "name": "whois.nic.name",
    "mobi": "whois.dotmobiregistry.net",
    "tel": "whois.nic.tel",
    "travel": "whois.nic.travel",
    "museum": "whois.museum",
    "coop": "whois.nic.coop",
    "aero": "whois.information.aero",
    "asia": "whois.nic.asia",
    "cat": "whois.nic.cat",
    "jobs": "whois.nic.jobs",
    "pro": "whois.registrypro.pro",
    # New gTLDs
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "website": "whois.nic.website",
    "space": "whois.nic.space",
    "tech": "whois.nic.tech",
    "store": "whois.nic.store",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "page": "whois.nic.google",
    "cloud": "whois.nic.cloud",
    "blog": "whois.nic.blog",
    "news": "whois.nic.news",
    "media": "whois.nic.media",
    "agency": "whois.nic.agency",
    "company": "whois.nic.company",
    "email": "whois.nic.email",
    "services": "whois.nic.services",
    "solutions": "whois.nic.solutions",
    "support": "whois.nic.support",
    "systems": "whois.nic.systems",
    "network": "whois.nic.network",
    "center": "whois.nic.center",
    "international": "whois.nic.international",
    "global": "whois.nic.global",
    "world": "whois.nic.world",
    # Country TLDs
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "co.uk": "whois.nic.uk",
    "ca": "whois.cira.ca",
    "au": "whois.auda.org.au",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "it": "whois.nic.it",
    "es": "whois.nic.es",
    "nl": "whois.domain-registry.nl",
    "be": "whois.dns.be",
    "ch": "whois.nic.ch",
    "at": "whois.nic.at",
    "pl": "whois.dns.pl",
    "cz": "whois.nic.cz",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "kr": "whois.kr",
    "in": "whois.inregistry.net",
    "br": "whois.registro.br",
    "mx": "whois.mx",
    "ar": "whois.nic.ar",
    "cl": "whois.nic.cl",
    "co": "whois.nic.co",
    "pe": "whois.nic.pe",
    "ve": "whois.nic.ve",
    "za": "whois.registry.net.za",
    "sg": "whois.sgnic.sg",
    "my": "whois.mynic.my",
    "th": "whois.thnic.co.th",
    "id": "whois.id",
    "ph": "whois.nic.ph",
    "vn": "whois.nic.vn",
    "tw": "whois.twnic.net.tw",
    "hk": "whois.hkirc.hk",
}

# Enhanced registrar abuse database
ENHANCED_REGISTRAR_ABUSE_DB = {
    "godaddy": "abuse@godaddy.com",
    "namecheap": "abuse@namecheap.com",
    "enom": "abuse@enom.com",
    "network solutions": "abuse@web.com",
    "gandi": "abuse@gandi.net",
    "1&1": "abuse@1und1.de",
    "hover": "abuse@hover.com",
    "dynadot": "abuse@dynadot.com",
    "name.com": "abuse@name.com",
    "porkbun": "abuse@porkbun.com",
    "cloudflare": "abuse@cloudflare.com",
    "tucows": "domainabuse@tucows.com",
    "psi-usa": "abuse@psi-usa.com",
    "key-systems": "abuse@key-systems.net",
    "reg.ru": "abuse@reg.ru",
    "regru": "abuse@reg.ru",
    "hosting.ua": "abuse@hosting.ua",
    "regtime": "abuse@regtime.net",
    "webnames": "abuse@webnames.ru",
    "r01": "abuse@r01.ru",
    "domeneshop": "abuse@domeneshop.no",
    "one.com": "abuse@one.com",
    "ovh": "abuse@ovh.com",
    "ionos": "abuse@ionos.com",
    "registrar.eu": "abuse@registrar.eu",
    "openprovider": "abuse@openprovider.com",
    "epik": "abuse@epik.com",
    "njalla": "abuse@njalla.com",
    "directnic": "abuse@directnic.com",
    "fabulous": "abuse@fabulous.com",
    "markmonitor": "abusecomplaints@markmonitor.com",
    "cscglobal": "domainabuse@cscglobal.com",
    "corporatedomains": "abuse@corporatedomains.com",
    "google": "registrar-abuse@google.com",
    "squarespace": "abuse@squarespace.com",
    "amazon": "abuse@amazonaws.com",
    "microsoft": "abuse@microsoft.com",
    "verisign": "abuse@verisign.com",
    "neustar": "abuse@neustar.biz",
    "donuts": "abuse@donuts.email",
    "registry": "abuse@registry.pro",
    "afilias": "abuse@afilias.info",
    "centralnic": "abuse@centralnic.com",
    "radix": "abuse@radix.website",
    "minds + machines": "abuse@mmx.co",
    "rightside": "abuse@rightside.co",
    "uniregistry": "abuse@uniregistry.com",
    "identity digital": "abuse@identity.digital",
    "public interest registry": "abuse@pir.org",
    "icann": "abuse@icann.org",
}

# Global engine for database operations
db_engine = create_engine(DATABASE_URL, pool_pre_ping=True, echo=False)


class DynamicBatchConfig:
    """Configuration for dynamic batch sizing based on system resources."""

    @staticmethod
    def get_batch_size() -> int:
        """Calculate optimal batch size based on available system resources."""
        try:
            cpus = os.cpu_count() or 1
            return 1000 * cpus
        except Exception as e:
            logger.debug(f"Can't get batch size: {e}")
            mem = psutil.virtual_memory()
            batch = int(mem.available / (10 * 1024 * 1024))
            return max(100, batch)


class AttachmentConfig:
    """Configuration for email attachments."""

    @staticmethod
    def get_attachment() -> Optional[str]:
        """Get default attachment path from settings."""
        path = getattr(settings, "DEFAULT_ATTACHMENT", None)
        if path and os.path.exists(path):
            abs_path = os.path.abspath(path)
            logger.info(f"Using default attachment from settings: {abs_path}")
            return path
        else:
            if path:
                logger.error(f"DEFAULT_ATTACHMENT file '{path}' does not exist.")
        return None

    @staticmethod
    def get_attachments_from_folder() -> List[str]:
        """
        Get all attachment files from the attachments folder.

        Returns:
            List[str]: List of file paths to attach
        """
        attachments = []

        # Check for attachments folder setting
        attachments_folder = getattr(settings, "ATTACHMENTS_FOLDER", None)
        if (
            attachments_folder
            and os.path.exists(attachments_folder)
            and os.path.isdir(attachments_folder)
        ):
            logger.info(f"Using attachments folder: {attachments_folder}")

            # Get all files from the folder
            for filename in os.listdir(attachments_folder):
                file_path = os.path.join(attachments_folder, filename)
                if os.path.isfile(file_path):
                    # Filter by allowed extensions (optional)
                    allowed_extensions = getattr(
                        settings,
                        "ALLOWED_ATTACHMENT_EXTENSIONS",
                        [".pdf", ".txt", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".zip"],
                    )

                    if any(file_path.lower().endswith(ext) for ext in allowed_extensions):
                        attachments.append(file_path)
                        logger.debug(f"Added attachment: {file_path}")
                    else:
                        logger.debug(f"Skipped file (not allowed extension): {file_path}")

            if attachments:
                logger.info(f"Found {len(attachments)} attachment(s) in folder")
            else:
                logger.warning(f"No valid attachments found in folder: {attachments_folder}")

        return attachments

    @staticmethod
    def get_all_attachments() -> List[str]:
        """
        Get all attachments (both single file and folder-based).

        Returns:
            List[str]: List of all attachment file paths
        """
        attachments = []

        # First, try to get attachments from folder
        folder_attachments = AttachmentConfig.get_attachments_from_folder()
        if folder_attachments:
            attachments.extend(folder_attachments)

        # If no folder attachments, try single file attachment
        if not attachments:
            single_attachment = AttachmentConfig.get_attachment()
            if single_attachment:
                attachments.append(single_attachment)

        return attachments


class EngineMode:
    """Determines the operational mode of the engine."""

    def __init__(self, args):
        self.report_mode = args.report is not None
        self.process_reports_mode = args.process_reports
        self.threads_only_mode = args.threads_only
        self.api_mode = getattr(args, "start_api", False)
        self.scanning_mode = not (
            self.report_mode
            or self.process_reports_mode
            or self.threads_only_mode
            or args.test_report
            or self.api_mode
        )


class EnhancedAbuseEmailDetector:
    """Enhanced abuse email detection with multiple sources and validation."""

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10

    def validate_email(self, email: str) -> bool:
        """Validate email address format and domain."""
        if not validators.email(email):
            return False

        # Additional validation for domain existence
        try:
            domain = email.split("@")[1]
            self.dns_resolver.resolve(domain, "MX")
            return True
        except (dns.exception.DNSException, IndexError):
            logger.debug(f"Domain validation failed for email: {email}")
            return False

    def extract_emails_from_whois(self, whois_data: Any) -> List[str]:
        """Extract email addresses from WHOIS data using enhanced patterns."""
        emails = []
        whois_str = str(whois_data).lower()

        # Use multiple patterns to find emails
        for pattern in ABUSE_EMAIL_PATTERNS:
            found_emails = re.findall(pattern, whois_str, re.IGNORECASE)
            emails.extend(found_emails)

        # General email pattern as fallback
        general_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        all_emails = re.findall(general_pattern, whois_str)

        # Filter for abuse-related emails
        abuse_keywords = ["abuse", "security", "admin", "postmaster", "hostmaster", "webmaster"]
        abuse_emails = [
            email
            for email in all_emails
            if any(keyword in email.lower() for keyword in abuse_keywords)
        ]

        emails.extend(abuse_emails)

        # Remove duplicates and validate
        unique_emails = list(set(emails))
        validated_emails = [email for email in unique_emails if self.validate_email(email)]

        return validated_emails

    def get_abuse_email_from_dns(self, domain: str) -> Optional[str]:
        """Try to get abuse email from DNS TXT records."""
        try:
            txt_records = self.dns_resolver.resolve(domain, "TXT")
            for record in txt_records:
                record_str = str(record).lower()
                if "abuse" in record_str:
                    email_match = re.search(
                        r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", record_str
                    )
                    if email_match and self.validate_email(email_match.group(1)):
                        logger.info(
                            f"Found abuse email in DNS TXT for {domain}: {email_match.group(1)}"
                        )
                        return email_match.group(1)
        except dns.exception.DNSException:
            logger.debug(f"DNS TXT query failed for {domain}")
        return None

    def get_abuse_email_from_whois_servers(self, domain: str) -> Optional[str]:
        """Query multiple WHOIS servers for abuse information."""
        whois_servers = [
            f"whois.{domain.split('.')[-1]}",
            "whois.internic.net",
            "whois.arin.net",
            "whois.ripe.net",
            "whois.apnic.net",
            "whois.lacnic.net",
            "whois.afrinic.net",
        ]

        for server in whois_servers:
            try:
                result = subprocess.run(
                    ["whois", "-h", server, domain], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    emails = self.extract_emails_from_whois(result.stdout)
                    if emails:
                        logger.info(f"Found abuse email from WHOIS server {server}: {emails[0]}")
                        return emails[0]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def get_abuse_email_by_registrar(self, registrar: str) -> Optional[str]:
        """Get abuse email from registrar database (cached + enhanced)."""
        # Check database cache first
        with self.db_manager.engine.begin() as conn:
            result = conn.execute(
                text("SELECT abuse_email FROM registrar_abuse WHERE LOWER(registrar) LIKE :param"),
                {"param": "%" + registrar.lower() + "%"},
            ).fetchone()
            if result:
                logger.info(f"Found cached abuse email for registrar '{registrar}': {result[0]}")
                return result[0]

        # Check enhanced static database
        for reg_name, email in ENHANCED_REGISTRAR_ABUSE_DB.items():
            if reg_name.lower() in registrar.lower():
                # Cache the result (PostgreSQL compatible)
                try:
                    with self.db_manager.engine.begin() as conn:
                        conn.execute(
                            text(
                                "INSERT INTO registrar_abuse (registrar, abuse_email) VALUES (:registrar, :email) ON CONFLICT (registrar) DO NOTHING"
                            ),
                            {"registrar": registrar, "email": email},
                        )
                except Exception as e:
                    # If ON CONFLICT is not supported, handle duplicate key error
                    logger.debug(f"Failed to cache registrar abuse email (likely duplicate): {e}")
                logger.info(f"Found enhanced abuse email for registrar '{registrar}': {email}")
                return email

        return None

    def get_enhanced_abuse_email(
        self, domain: str, whois_data: Any = None, registrar: str = None
    ) -> List[str]:
        """Get abuse email using multiple enhanced detection methods."""
        abuse_emails = []

        # 1. Check cached registrar database
        if registrar:
            registrar_email = self.get_abuse_email_by_registrar(registrar)
            if registrar_email and self.validate_abuse_email_domain(registrar_email, domain):
                abuse_emails.append(registrar_email)

        # 2. Extract from WHOIS data (exclude same domain)
        if whois_data:
            whois_emails = self.extract_emails_from_whois(whois_data)
            for email in whois_emails:
                if self.validate_abuse_email_domain(email, domain):
                    abuse_emails.append(email)

        # 3. Try DNS TXT records
        dns_email = self.get_abuse_email_from_dns(domain)
        if dns_email and self.validate_abuse_email_domain(dns_email, domain):
            abuse_emails.append(dns_email)

        # 4. Try alternative WHOIS servers
        if not abuse_emails:
            whois_server_email = self.get_abuse_email_from_whois_servers(domain)
            if whois_server_email and self.validate_abuse_email_domain(whois_server_email, domain):
                abuse_emails.append(whois_server_email)

        # 5. Check if domain is behind Cloudflare and get hosting provider
        try:
            domain_ip = socket.gethostbyname(domain)
            if is_cloudflare_ip(domain_ip):
                logger.info(f"Domain {domain} is behind Cloudflare, investigating real hosting...")

                # Try to find real IP behind Cloudflare
                real_ip = self.get_real_ip_behind_cloudflare(domain)
                if real_ip:
                    provider_name, provider_abuse = self.get_hosting_provider_info(real_ip)
                    if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                        abuse_emails.append(provider_abuse)
                        logger.info(
                            f"Found hosting provider abuse email: {provider_abuse} (Provider: {provider_name})"
                        )

                # Always add Cloudflare as secondary option
                cloudflare_email = "abuse@cloudflare.com"
                if cloudflare_email not in abuse_emails:
                    abuse_emails.append(cloudflare_email)
                    logger.info(f"Added Cloudflare abuse email as secondary option")
            else:
                # Not behind Cloudflare, check hosting provider directly
                provider_name, provider_abuse = self.get_hosting_provider_info(domain_ip)
                if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                    abuse_emails.append(provider_abuse)
                    logger.info(
                        f"Found hosting provider abuse email: {provider_abuse} (Provider: {provider_name})"
                    )
        except Exception as e:
            logger.debug(f"Failed to get IP/hosting info for {domain}: {e}")

        # 6. Generate common abuse email patterns (exclude same domain)
        if not abuse_emails:
            # Try parent domain or known hosting providers
            try:
                # Get hosting info from IP WHOIS
                domain_ip = socket.gethostbyname(domain)
                provider_name, provider_abuse = self.get_hosting_provider_info(domain_ip)
                if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                    abuse_emails.append(provider_abuse)
            except:
                pass

        # Remove duplicates while preserving order
        unique_emails = []
        seen = set()
        for email in abuse_emails:
            if email not in seen:
                unique_emails.append(email)
                seen.add(email)

        # Log the final result
        if unique_emails:
            logger.info(
                f"Found {len(unique_emails)} valid abuse email(s) for {domain}: {unique_emails}"
            )
        else:
            logger.warning(f"No valid abuse emails found for {domain}")

        return unique_emails

    @staticmethod
    def extract_registrar(whois_data) -> Optional[str]:
        """Extract registrar from WHOIS data."""
        if isinstance(whois_data, dict):
            registrar = whois_data.get("registrar")
            if registrar:
                if isinstance(registrar, list):
                    return registrar[0].strip()
                else:
                    return str(registrar).strip()
        whois_str = str(whois_data)
        match = re.search(r"Registrar:\s*(.+)", whois_str, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def validate_abuse_email_domain(self, email: str, reported_domain: str) -> bool:
        """
        Validate that abuse email is not from the same domain being reported.

        Args:
            email (str): Abuse email to validate
            reported_domain (str): Domain being reported for phishing

        Returns:
            bool: True if email is valid for reporting, False if same domain
        """
        try:
            email_domain = email.split("@")[1].lower()
            reported_domain_clean = reported_domain.lower().replace("www.", "")

            # Check if it's the same domain
            if email_domain == reported_domain_clean:
                logger.warning(
                    f"Cannot send abuse report to same domain: {email} for {reported_domain}"
                )
                return False

            # Check if it's a subdomain of the reported domain
            if email_domain.endswith("." + reported_domain_clean):
                logger.warning(
                    f"Cannot send abuse report to subdomain: {email} for {reported_domain}"
                )
                return False

            return True
        except IndexError:
            return False

    def get_real_ip_behind_cloudflare(self, domain: str) -> Optional[str]:
        """
        Try to get the real IP behind Cloudflare using various methods.

        Args:
            domain (str): Domain to investigate

        Returns:
            Optional[str]: Real IP if found, None otherwise
        """
        real_ips = []

        # Method 1: Check common subdomains that might not be behind Cloudflare
        common_subdomains = ["direct", "origin", "real", "server", "host", "main", "www-origin"]

        for subdomain in common_subdomains:
            try:
                test_domain = f"{subdomain}.{domain}"
                ip = socket.gethostbyname(test_domain)
                if not is_cloudflare_ip(ip):
                    real_ips.append(ip)
                    logger.info(f"Found potential real IP via subdomain {test_domain}: {ip}")
            except:
                continue

        # Method 2: Check MX records (mail servers often reveal real hosting)
        try:
            mx_records = self.dns_resolver.resolve(domain, "MX")
            for mx in mx_records:
                mx_domain = str(mx.exchange).rstrip(".")
                try:
                    ip = socket.gethostbyname(mx_domain)
                    if not is_cloudflare_ip(ip):
                        real_ips.append(ip)
                        logger.info(f"Found potential real IP via MX record {mx_domain}: {ip}")
                except:
                    continue
        except:
            pass

        # Method 3: Historical DNS queries (simplified version)
        # In production, you might want to use services like SecurityTrails API

        return real_ips[0] if real_ips else None

    def get_abuse_email_by_asn(self, asn: str) -> Optional[str]:
        """
        Get abuse email from ASN database.

        Args:
            asn (str): ASN number (with or without 'AS' prefix)

        Returns:
            Optional[str]: Abuse email if found, None otherwise
        """
        # Normalize ASN (remove AS prefix if present)
        asn_clean = asn.replace("AS", "").strip()

        abuse_email = ASN_ABUSE_EMAIL_DB.get(asn_clean)
        if abuse_email:
            logger.info(f"Found ASN abuse email for AS{asn_clean}: {abuse_email}")
            return abuse_email

        return None

    def get_enhanced_whois_data(self, domain: str) -> dict:
        """
        Get WHOIS data using appropriate server based on TLD.

        Args:
            domain (str): Domain to query

        Returns:
            dict: WHOIS data
        """
        try:
            # First try with python-whois library
            data = whois.whois(domain)
            if data and (data.domain_name or data.registrar):
                logger.debug(f"Got WHOIS data for {domain} using python-whois")
                return data
        except Exception as e:
            logger.debug(f"Python-whois failed for {domain}: {e}")

        # If that fails, try with specific WHOIS server for TLD
        try:
            tld = domain.split(".")[-1].lower()
            whois_server = TLD_WHOIS_SERVERS.get(tld)

            if whois_server:
                logger.debug(f"Trying WHOIS server {whois_server} for {domain}")
                result = subprocess.run(
                    ["whois", "-h", whois_server, domain],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if result.returncode == 0 and result.stdout:
                    # Convert raw whois to dict-like structure
                    whois_text = result.stdout
                    whois_dict = {"raw_whois": whois_text}

                    # Extract key information
                    registrar_match = re.search(r"Registrar:\s*(.+)", whois_text, re.IGNORECASE)
                    if registrar_match:
                        whois_dict["registrar"] = registrar_match.group(1).strip()

                    domain_match = re.search(r"Domain Name:\s*(.+)", whois_text, re.IGNORECASE)
                    if domain_match:
                        whois_dict["domain_name"] = domain_match.group(1).strip()

                    logger.info(f"Got WHOIS data for {domain} using {whois_server}")
                    return whois_dict
        except Exception as e:
            logger.debug(f"Direct WHOIS query failed for {domain}: {e}")

        # Final fallback - try generic whois command
        try:
            logger.debug(f"Trying generic whois command for {domain}")
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                whois_text = result.stdout
                whois_dict = {"raw_whois": whois_text}

                registrar_match = re.search(r"Registrar:\s*(.+)", whois_text, re.IGNORECASE)
                if registrar_match:
                    whois_dict["registrar"] = registrar_match.group(1).strip()

                logger.info(f"Got WHOIS data for {domain} using generic whois")
                return whois_dict
        except Exception as e:
            logger.debug(f"Generic whois failed for {domain}: {e}")

        logger.warning(f"All WHOIS methods failed for {domain}")
        return {}

    def get_hosting_provider_info(
        self, ip: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Get hosting provider information from IP address with enhanced ASN support.

        Args:
            ip (str): IP address to investigate

        Returns:
            Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
            (provider_name, provider_abuse_email, asn, asn_abuse_email)
        """
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)

            # Get provider name - handle None values
            provider_name = None
            network_info = res.get("network", {})
            if network_info:
                provider_name = network_info.get("name", "")
                if not provider_name:
                    provider_name = res.get("asn_description", "")

            # Ensure provider_name is string
            if provider_name is None:
                provider_name = ""

            # Get ASN information
            asn = res.get("asn", "")
            if asn and not str(asn).startswith("AS"):
                asn = f"AS{asn}"

            # Get ASN abuse email
            asn_abuse_email = None
            if asn:
                asn_abuse_email = self.get_abuse_email_by_asn(str(asn))

            # Look for provider abuse emails in the WHOIS data
            provider_abuse_emails = []

            # Check abuse contacts
            objects = res.get("objects", {})
            if objects:
                for contact_id, contact_data in objects.items():
                    if isinstance(contact_data, dict):
                        contact_info = contact_data.get("contact", {})
                        if contact_info and contact_info.get("role", "").lower() == "abuse":
                            email = contact_info.get("email")
                            if email:
                                if isinstance(email, list):
                                    provider_abuse_emails.extend(email)
                                else:
                                    provider_abuse_emails.append(email)

            # Look for abuse emails in remarks or other fields
            if network_info:
                remarks = network_info.get("remarks", [])
                if remarks:
                    for remark in remarks:
                        if isinstance(remark, dict):
                            title = remark.get("title", "")
                            description = remark.get("description", [])
                            if title and "abuse" in title.lower():
                                for desc in description:
                                    if desc:
                                        emails = re.findall(
                                            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                                            str(desc),
                                        )
                                        provider_abuse_emails.extend(emails)

            # Filter and validate provider emails
            valid_provider_emails = []
            for email in provider_abuse_emails:
                if email and self.validate_email(email):
                    valid_provider_emails.append(email)

            provider_abuse_email = valid_provider_emails[0] if valid_provider_emails else None

            logger.debug(
                f"IP {ip} info: Provider={provider_name}, ASN={asn}, "
                f"Provider abuse={provider_abuse_email}, ASN abuse={asn_abuse_email}"
            )

            return provider_name, provider_abuse_email, asn, asn_abuse_email

        except Exception as e:
            logger.error(f"Failed to get hosting provider info for IP {ip}: {e}")
            return None, None, None, None


class PhishingAPI:
    """REST API for external phishing reports."""

    def __init__(self, db_manager, abuse_detector):
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.app = Flask(__name__)
        self.app.config["JSON_SORT_KEYS"] = False

        # Configure Flask logging to be less verbose
        flask_logging.getLogger("werkzeug").setLevel(flask_logging.WARNING)

        # Rate limiting
        self.limiter = Limiter(
            app=self.app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour", "10 per minute"],
        )

        self.setup_routes()

    def setup_routes(self):
        """Setup API routes."""

        @self.app.route("/api/v1/report", methods=["POST"])
        @self.limiter.limit("5 per minute")
        def report_phishing():
            """Report a phishing site via API."""
            try:
                data = request.get_json()

                if not data:
                    return jsonify({"error": "No JSON data provided"}), 400

                url = data.get("url")
                if not url:
                    return jsonify({"error": "URL is required"}), 400

                # Validate URL
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                abuse_email = data.get("abuse_email")
                source = data.get("source", "api")
                priority = data.get("priority", "medium")
                description = data.get("description", "")

                # Validate abuse_email if provided
                if abuse_email and not self.abuse_detector.validate_email(abuse_email):
                    return jsonify({"error": "Invalid abuse email format"}), 400

                # Process the report
                result = self.process_phishing_report(
                    url, abuse_email, source, priority, description
                )

                return jsonify(result), 200

            except Exception as e:
                logger.error(f"API error in report_phishing: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/status/<path:url>", methods=["GET"])
        @self.limiter.limit("10 per minute")
        def get_report_status(url):
            """Get the status of a reported URL."""
            try:
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text(
                            """
                            SELECT url, manual_flag, first_seen, last_seen,
                                   reported, abuse_report_sent, site_status,
                                   takedown_date, abuse_email, source, priority
                            FROM phishing_sites
                            WHERE url = :url
                        """
                        ),
                        {"url": url},
                    ).fetchone()

                    if not result:
                        return jsonify({"error": "URL not found"}), 404

                    return (
                        jsonify(
                            {
                                "url": result[0],
                                "flagged": bool(result[1]),
                                "first_seen": result[2],
                                "last_seen": result[3],
                                "reported": bool(result[4]),
                                "abuse_report_sent": bool(result[5]),
                                "site_status": result[6],
                                "takedown_date": result[7],
                                "abuse_email": result[8],
                                "source": result[9] if len(result) > 9 else None,
                                "priority": result[10] if len(result) > 10 else None,
                            }
                        ),
                        200,
                    )

            except Exception as e:
                logger.error(f"API error in get_report_status: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/stats", methods=["GET"])
        @self.limiter.limit("20 per minute")
        def get_stats():
            """Get statistics about phishing reports."""
            try:
                with self.db_manager.engine.begin() as conn:
                    stats = {
                        "total_reports": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites")
                        ).scalar(),
                        "active_sites": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE site_status = 'up'")
                        ).scalar(),
                        "taken_down": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE site_status = 'down'")
                        ).scalar(),
                        "reports_sent": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE abuse_report_sent = 1")
                        ).scalar(),
                        "manual_flags": conn.execute(
                            text("SELECT COUNT(*) FROM phishing_sites WHERE manual_flag = 1")
                        ).scalar(),
                    }

                    # Recent activity (last 7 days)
                    seven_days_ago = (
                        datetime.datetime.now() - datetime.timedelta(days=7)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    stats["recent_reports"] = conn.execute(
                        text("SELECT COUNT(*) FROM phishing_sites WHERE first_seen >= :date"),
                        {"date": seven_days_ago},
                    ).scalar()

                    return jsonify(stats), 200

            except Exception as e:
                logger.error(f"API error in get_stats: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/health", methods=["GET"])
        def health_check():
            """Health check endpoint."""
            return (
                jsonify({"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}),
                200,
            )

    def process_phishing_report(
        self, url: str, abuse_email: Optional[str], source: str, priority: str, description: str
    ) -> Dict[str, Any]:
        """Process a phishing report from the API."""
        try:
            with self.db_manager.engine.begin() as conn:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Check if URL already exists
                existing = conn.execute(
                    text("SELECT id, manual_flag FROM phishing_sites WHERE url = :url"),
                    {"url": url},
                ).fetchone()

                if existing:
                    # Update existing record
                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET manual_flag = 1, last_seen = :timestamp,
                                abuse_email = COALESCE(:abuse_email, abuse_email),
                                source = :source, priority = :priority, description = :description
                            WHERE url = :url
                        """
                        ),
                        {
                            "timestamp": timestamp,
                            "abuse_email": abuse_email,
                            "source": source,
                            "priority": priority,
                            "description": description,
                            "url": url,
                        },
                    )
                    logger.info(f"Updated existing phishing report for {url}")
                    return {
                        "status": "updated",
                        "message": f"Updated existing report for {url}",
                        "url": url,
                        "timestamp": timestamp,
                    }
                else:
                    # If no abuse email provided, try to find one
                    if not abuse_email:
                        try:
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            whois_data = basic_whois_lookup(url)
                            registrar = self.abuse_detector.extract_registrar(whois_data)
                            abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                                domain, whois_data, registrar
                            )
                            abuse_email = abuse_emails[0] if abuse_emails else None
                        except Exception as e:
                            logger.warning(f"Failed to auto-detect abuse email for {url}: {e}")

                    # Create new record
                    conn.execute(
                        text(
                            """
                            INSERT INTO phishing_sites
                            (url, manual_flag, first_seen, last_seen, abuse_email,
                             reported, abuse_report_sent, source, priority, description)
                            VALUES (:url, 1, :timestamp, :timestamp, :abuse_email,
                                    0, 0, :source, :priority, :description)
                        """
                        ),
                        {
                            "url": url,
                            "timestamp": timestamp,
                            "abuse_email": abuse_email,
                            "source": source,
                            "priority": priority,
                            "description": description,
                        },
                    )
                    logger.info(f"Created new phishing report for {url}")
                    return {
                        "status": "created",
                        "message": f"Created new report for {url}",
                        "url": url,
                        "abuse_email": abuse_email,
                        "timestamp": timestamp,
                    }

        except Exception as e:
            logger.error(f"Failed to process phishing report for {url}: {e}")
            return {"status": "error", "message": f"Failed to process report: {str(e)}", "url": url}

    def run(self, host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
        """Run the API server."""
        logger.info(f"Starting Phishing API server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)


BATCH_SIZE = DynamicBatchConfig.get_batch_size()


def generate_queries_file(keywords: List[str], domains: List[str]) -> None:
    """Generate queries file with all keyword/domain combinations."""
    total = 0
    with open(QUERIES_FILE, "w") as f:
        for i in range(1, len(keywords) + 1):
            for p in permutations(keywords, i):
                for q in ["-".join(p), "".join(p)]:
                    for d in domains:
                        f.write(f"{q}{d}\n")
                        total += 1
    logger.info(f"Generated full query list with {total} lines.")


def get_ip_info(domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Get IP address and ASN provider information for a domain."""
    try:
        resolved_ip = socket.gethostbyname(domain)
        obj = IPWhois(resolved_ip)
        res = obj.lookup_rdap(depth=1)
        asn_provider = res.get("network", {}).get("name", "")
        return resolved_ip, asn_provider
    except Exception as e:
        logger.error(f"Failed to get IP info for {domain}: {e}")
        return None, None


def is_cloudflare_ip(ip: str) -> bool:
    """Check if an IP address belongs to Cloudflare."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in net:
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking Cloudflare IP: {e}")
        return False


class PhishingUtils:
    """Utility functions for phishing detection and processing."""

    @staticmethod
    def store_scan_result(
        url: str, response_code: int, found_keywords: List[str], db_file: str = DATABASE_URL
    ) -> None:
        """Store scan result in database."""
        engine = create_engine(db_file, pool_pre_ping=True, echo=False)
        with engine.begin() as conn:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            keywords_str = ", ".join(found_keywords) if found_keywords else ""

            result = conn.execute(
                text("SELECT id, first_seen, count FROM scan_results WHERE url=:url"), {"url": url}
            ).fetchone()

            if result:
                new_count = result[2] + 1
                conn.execute(
                    text(
                        """
                        UPDATE scan_results
                        SET last_seen=:timestamp, response_code=:response_code,
                            found_keywords=:keywords_str, count=:new_count
                        WHERE url=:url
                    """
                    ),
                    {
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "keywords_str": keywords_str,
                        "new_count": new_count,
                        "url": url,
                    },
                )
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO scan_results
                        (url, first_seen, last_seen, response_code, found_keywords, count)
                        VALUES (:url, :timestamp, :timestamp, :response_code, :keywords_str, 1)
                    """
                    ),
                    {
                        "url": url,
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "keywords_str": keywords_str,
                    },
                )
            logger.info(f"Stored scan result for {url}")
        engine.dispose()

    @staticmethod
    def update_scan_result_response_code(url: str, response_code: int) -> None:
        """Update response code for existing scan result."""
        with db_engine.begin() as conn:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = conn.execute(
                text("SELECT id, count FROM scan_results WHERE url=:url"), {"url": url}
            ).fetchone()

            if result:
                new_count = result[1] + 1
                conn.execute(
                    text(
                        """
                        UPDATE scan_results
                        SET last_seen=:timestamp, response_code=:response_code, count=:new_count
                        WHERE url=:url
                    """
                    ),
                    {
                        "timestamp": timestamp,
                        "response_code": response_code,
                        "new_count": new_count,
                        "url": url,
                    },
                )
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO scan_results
                        (url, first_seen, last_seen, response_code, found_keywords, count)
                        VALUES (:url, :timestamp, :timestamp, :response_code, '', 1)
                    """
                    ),
                    {"url": url, "timestamp": timestamp, "response_code": response_code},
                )
            logger.info(f"Updated scan result response code for {url}")

    @staticmethod
    def log_positive_result(url: str, found_keywords: List[str]) -> None:
        """Log positive phishing detection result."""
        log_file = "positive_report.txt"
        entry = (
            f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {url}: {', '.join(found_keywords)}\n"
        )

        try:
            with open(log_file, "r+") as f:
                if url in f.read():
                    logger.debug(f"Duplicate entry skipped: {url}")
                    return
                f.write(entry)
        except FileNotFoundError:
            with open(log_file, "w") as f:
                f.write(entry)

        logger.info(f"Logged phishing match: {url}")

    @staticmethod
    def determine_site_status(
        url: str,
        resolved_ip: Optional[str],
        current_status: str,
        current_takedown: Optional[str],
        timestamp: str,
        timeout: int,
    ) -> Tuple[str, Optional[str]]:
        """Determine the site's status ("up" or "down") and takedown date."""
        if not resolved_ip:
            new_status = "down"
            new_takedown = current_takedown if current_status == "down" else timestamp
        else:
            try:
                response = requests.get(
                    url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT}
                )
                if response.status_code == 200:
                    if "suspended" in response.text.lower():
                        new_status = "down"
                        new_takedown = current_takedown if current_status == "down" else timestamp
                    else:
                        new_status = "up"
                        new_takedown = None
                else:
                    new_status = "down"
                    new_takedown = current_takedown if current_status == "down" else timestamp
            except Exception as e:
                logger.error(f"GET request failed for {url}: {e}")
                new_status = "down"
                new_takedown = current_takedown if current_status == "down" else timestamp

        return new_status, new_takedown


def upgrade_phishing_db():
    """Upgrade phishing database schema with new ASN fields."""
    with db_engine.begin() as conn:
        # Add new columns for API functionality
        try:
            conn.execute(text("ALTER TABLE phishing_sites ADD COLUMN source TEXT DEFAULT 'manual'"))
        except:
            pass
        try:
            conn.execute(
                text("ALTER TABLE phishing_sites ADD COLUMN priority TEXT DEFAULT 'medium'")
            )
        except:
            pass
        try:
            conn.execute(text("ALTER TABLE phishing_sites ADD COLUMN description TEXT"))
        except:
            pass

        # Add new ASN-related columns
        try:
            conn.execute(text("ALTER TABLE phishing_sites ADD COLUMN asn TEXT"))
        except:
            pass
        try:
            conn.execute(text("ALTER TABLE phishing_sites ADD COLUMN asn_abuse_email TEXT"))
        except:
            pass
        try:
            conn.execute(text("ALTER TABLE phishing_sites ADD COLUMN hosting_provider TEXT"))
        except:
            pass
        try:
            conn.execute(text("ALTER TABLE phishing_sites ADD COLUMN all_abuse_emails TEXT"))
        except:
            pass

    logger.info("Upgraded phishing_sites table with ASN support if necessary.")


class DatabaseManager:
    """Database operations manager."""

    def __init__(self, db_url: str = DATABASE_URL):
        self.db_url = db_url
        self.engine = db_engine

    def init_db(self):
        """Initialize scan results table."""
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id SERIAL PRIMARY KEY,
                        url TEXT UNIQUE,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        response_code INTEGER,
                        found_keywords TEXT,
                        count INTEGER
                    )
                """
                )
            )
            logger.info("Initialized scan_results table.")

    def init_phishing_db(self):
        """Initialize phishing sites table with enhanced ASN support."""
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS phishing_sites (
                        id SERIAL PRIMARY KEY,
                        url TEXT UNIQUE,
                        manual_flag INTEGER DEFAULT 0,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        whois_info TEXT,
                        abuse_email TEXT,
                        reported INTEGER DEFAULT 0,
                        abuse_report_sent INTEGER DEFAULT 0,
                        site_status TEXT DEFAULT 'up',
                        takedown_date TIMESTAMP,
                        last_report_sent TIMESTAMP,
                        resolved_ip TEXT,
                        asn_provider TEXT,
                        is_cloudflare INTEGER,
                        provider_abuse_email TEXT,
                        source TEXT DEFAULT 'manual',
                        priority TEXT DEFAULT 'medium',
                        description TEXT,
                        asn TEXT,
                        asn_abuse_email TEXT,
                        hosting_provider TEXT,
                        all_abuse_emails TEXT
                    )
                """
                )
            )
            logger.info("Initialized phishing_sites table with enhanced ASN support.")

    def init_registrar_abuse_db(self):
        """Initialize registrar abuse table."""
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS registrar_abuse (
                        registrar TEXT PRIMARY KEY,
                        abuse_email TEXT
                    )
                """
                )
            )
            logger.info("Initialized registrar_abuse table.")


def basic_whois_lookup(url: str) -> dict:
    """
    Perform enhanced WHOIS lookup for a URL using TLD-specific servers.

    Args:
        url (str): URL to lookup

    Returns:
        dict: WHOIS data
    """
    try:
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        logger.debug(f"Performing enhanced WHOIS lookup for: {domain}")

        # Use a dummy detector to access the enhanced WHOIS method
        # In production, you might want to refactor this
        from sqlalchemy import create_engine

        dummy_db_manager = type("DummyDBManager", (), {"engine": create_engine(DATABASE_URL)})()
        detector = EnhancedAbuseEmailDetector(dummy_db_manager)
        data = detector.get_enhanced_whois_data(domain)

        return data
    except Exception as e:
        logger.error(f"Enhanced WHOIS lookup failed for {url}: {e}")
        return {}


class AbuseReportManager:
    """Enhanced abuse report manager with improved email detection."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        abuse_detector: EnhancedAbuseEmailDetector,
        cc_emails: Optional[List[str]],
        timeout: int,
        monitoring_event: threading.Event = None,
    ):
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        if cc_emails is None:
            default_cc = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL2", "")
            self.cc_emails = (
                [email.strip() for email in default_cc.split(",")] if default_cc else []
            )
        else:
            self.cc_emails = cc_emails
        self.timeout = timeout
        self.monitoring_event = monitoring_event

    def get_enhanced_abuse_emails(self, whois_data, domain: str) -> List[str]:
        """Get abuse emails using enhanced detection methods."""
        registrar = self.abuse_detector.extract_registrar(whois_data) or ""

        # Use the enhanced method from abuse_detector
        abuse_emails = self.abuse_detector.get_enhanced_abuse_email(domain, whois_data, registrar)

        # If no emails found, try fallback methods with domain validation
        if not abuse_emails:
            whois_str = str(whois_data)
            emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", whois_str)
            for email in emails:
                if "abuse" in email.lower() and self.abuse_detector.validate_abuse_email_domain(
                    email, domain
                ):
                    abuse_emails.append(email)

        return abuse_emails

    def send_abuse_report(
        self,
        abuse_emails: List[str],
        site_url: str,
        whois_str: str,
        attachment_paths: Optional[List[str]] = None,
        test_mode: bool = False,
    ) -> bool:
        """
        Send abuse report with enhanced error handling and multiple attachments support.

        Args:
            abuse_emails (List[str]): List of abuse email addresses
            site_url (str): URL of the phishing site
            whois_str (str): WHOIS information
            attachment_paths (Optional[List[str]]): List of attachment file paths
            test_mode (bool): Whether this is a test report

        Returns:
            bool: True if report was sent successfully, False otherwise
        """
        # Get attachments - prioritize parameter, then get all configured attachments
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()

        smtp_host = getattr(settings, "SMTP_HOST")
        smtp_port = getattr(settings, "SMTP_PORT")
        smtp_user = getattr(settings, "SMTP_USER", "")
        smtp_pass = getattr(settings, "SMTP_PASS", "")
        sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")
        subject = f"{getattr(settings, 'ABUSE_EMAIL_SUBJECT')} for {site_url}"

        # Prepare attachment filenames for template
        attachment_filenames = (
            [os.path.basename(path) for path in attachment_paths] if attachment_paths else []
        )

        # Prepare CC list
        final_cc = [] if test_mode else (self.cc_emails[:] if self.cc_emails else [])
        if not test_mode and sender_email not in final_cc:
            final_cc.insert(0, sender_email)

        if not test_mode and not self.cc_emails:
            escalation2 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL2", "")
            escalation3 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL3", "")
            for var in [escalation2, escalation3]:
                if var:
                    for email in var.split(","):
                        email = email.strip()
                        if email and email not in final_cc:
                            final_cc.append(email)

        # Render email template
        try:
            env_jinja = Environment(
                loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"])
            )
            html_content = env_jinja.get_template("abuse_report.html").render(
                site_url=site_url,
                whois_info=whois_str,
                attachment_filenames=attachment_filenames,  # Updated to support multiple files
                attachment_count=len(attachment_filenames),
                cc_emails=final_cc,
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            logger.debug("Rendered email content (first 300 chars): " + html_content[:300])
        except Exception as render_err:
            logger.error(f"Template rendering failed: {render_err}")
            return False

        # Filter out non-primary abuse emails
        primary_candidates = [
            email for email in abuse_emails if "abuse-tracker" not in email.lower()
        ]
        if primary_candidates:
            abuse_emails = primary_candidates

        success_count = 0
        site_domain = (
            re.sub(r"^https?://", "", site_url).strip().split("/")[0].lower().replace("www.", "")
        )

        for primary in abuse_emails:
            try:
                # Validate email format
                if not self.abuse_detector.validate_email(primary):
                    logger.warning(f"Invalid email format, skipping: {primary}")
                    continue

                # Validate email is not from same domain being reported
                if not self.abuse_detector.validate_abuse_email_domain(primary, site_domain):
                    logger.warning(
                        f"Skipping abuse email from same domain being reported: {primary} for {site_url}"
                    )
                    continue

                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = primary

                if not test_mode and final_cc:
                    msg["Cc"] = ", ".join(final_cc)
                    recipients = [primary] + final_cc
                else:
                    recipients = [primary]

                msg.attach(MIMEText(html_content, "html"))

                # Attach multiple files if provided
                attached_files = []
                if attachment_paths:
                    for attachment_path in attachment_paths:
                        try:
                            if os.path.exists(attachment_path) and os.path.isfile(attachment_path):
                                with open(attachment_path, "rb") as f:
                                    file_data = f.read()

                                # Check file size (limit to 25MB per file)
                                max_size = (
                                    getattr(settings, "MAX_ATTACHMENT_SIZE_MB", 25) * 1024 * 1024
                                )
                                if len(file_data) > max_size:
                                    logger.warning(
                                        f"Skipping large attachment: {attachment_path} "
                                        f"({len(file_data) / 1024 / 1024:.1f}MB > {max_size / 1024 / 1024}MB)"
                                    )
                                    continue

                                filename = os.path.basename(attachment_path)
                                part = MIMEApplication(file_data, Name=filename)
                                part["Content-Disposition"] = f'attachment; filename="{filename}"'
                                msg.attach(part)
                                attached_files.append(filename)
                                logger.debug(f"Attached file: {filename} ({len(file_data)} bytes)")
                            else:
                                logger.warning(
                                    f"Attachment file not found or not a file: {attachment_path}"
                                )
                        except Exception as e:
                            logger.error(f"Failed to attach file {attachment_path}: {e}")
                            continue

                # Check total email size
                total_size = len(msg.as_string())
                max_email_size = getattr(settings, "MAX_EMAIL_SIZE_MB", 25) * 1024 * 1024
                if total_size > max_email_size:
                    logger.error(
                        f"Email too large ({total_size / 1024 / 1024:.1f}MB), skipping send to {primary}"
                    )
                    continue

                # Send email
                attachment_info = ""
                if attached_files:
                    if len(attached_files) == 1:
                        attachment_info = f" with attachment {attached_files[0]}"
                    else:
                        attachment_info = (
                            f" with {len(attached_files)} attachments: {', '.join(attached_files)}"
                        )

                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    if smtp_user and smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.sendmail(sender_email, recipients, msg.as_string())

                logger.info(
                    f"✅ Abuse report sent to {primary} for site {site_url}{attachment_info}; "
                    f"CC: {final_cc if final_cc else 'None'}"
                )
                success_count += 1

            except Exception as e:
                logger.error(f"Failed to send abuse report to {primary}: {e}")
                continue

        # Log final summary
        if success_count > 0:
            logger.info(
                f"🎯 SUMMARY: Successfully sent abuse reports to {success_count}/{len(abuse_emails)} recipients for {site_url}"
            )
        else:
            logger.error(
                f"❌ SUMMARY: Failed to send abuse reports to any recipients for {site_url}"
            )

        return success_count > 0

    def report_phishing_sites(self):
        """Main loop for reporting phishing sites."""
        if self.monitoring_event:
            logger.info(
                "Waiting for monitoring thread to complete initial cycle before sending abuse reports..."
            )
            self.monitoring_event.wait()
            logger.info("Monitoring thread initial cycle complete. Starting abuse reporting.")

        while True:
            try:
                with self.db_manager.engine.begin() as conn:
                    sites = conn.execute(
                        text(
                            """
                            SELECT url, abuse_email, last_report_sent, site_status, takedown_date, priority
                            FROM phishing_sites
                            WHERE manual_flag = 1 AND site_status = 'up'
                            ORDER BY
                                CASE priority
                                    WHEN 'high' THEN 1
                                    WHEN 'medium' THEN 2
                                    WHEN 'low' THEN 3
                                    ELSE 2
                                END,
                                first_seen ASC
                        """
                        )
                    ).fetchall()

                    for row in sites:
                        url, stored_abuse, last_report_sent, current_status, current_takedown = row[
                            :5
                        ]

                        try:
                            current_time = datetime.datetime.now()
                            if last_report_sent:
                                if isinstance(last_report_sent, datetime.datetime):
                                    last_report_time = last_report_sent
                                elif isinstance(last_report_sent, str):
                                    last_report_time = datetime.datetime.strptime(
                                        last_report_sent, "%Y-%m-%d %H:%M:%S"
                                    )
                            else:
                                last_report_time = None

                            if (
                                last_report_time
                                and (current_time - last_report_time).total_seconds() < 172800
                            ):
                                continue

                            whois_data = basic_whois_lookup(url)
                            whois_str = str(whois_data)
                            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            resolved_ip, asn_provider = get_ip_info(domain)

                            # Use the refactored function to determine site status
                            new_status, new_takedown = PhishingUtils.determine_site_status(
                                url,
                                resolved_ip,
                                current_status,
                                current_takedown,
                                timestamp,
                                self.timeout,
                            )

                            # Check for Cloudflare
                            cloudflare_detected = resolved_ip and is_cloudflare_ip(resolved_ip)

                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET whois_info=:whois_str, last_seen=:timestamp, reported=1, last_report_sent=:timestamp,
                                        resolved_ip=:resolved_ip, asn_provider=:asn_provider, is_cloudflare=:is_cloudflare,
                                        site_status=:new_status, takedown_date=:new_takedown
                                    WHERE url=:url
                                """
                                ),
                                {
                                    "whois_str": whois_str,
                                    "timestamp": timestamp,
                                    "resolved_ip": resolved_ip,
                                    "asn_provider": asn_provider,
                                    "is_cloudflare": 1 if cloudflare_detected else 0,
                                    "new_status": new_status,
                                    "new_takedown": new_takedown,
                                    "url": url,
                                },
                            )
                            logger.info(f"WHOIS data enriched for {url}")

                            # Get abuse emails using enhanced detection
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            registrar = self.abuse_detector.extract_registrar(whois_data)
                            abuse_list = self.abuse_detector.get_enhanced_abuse_email(
                                domain, whois_data, registrar
                            )

                            # Additional check: if Cloudflare detected but no other emails found, only use Cloudflare
                            if cloudflare_detected and not abuse_list:
                                logger.info(
                                    f"Cloudflare detected for {url}, no hosting provider found. Using abuse@cloudflare.com only"
                                )
                                abuse_list = ["abuse@cloudflare.com"]
                            elif cloudflare_detected and abuse_list:
                                # Ensure Cloudflare is in the list but not first priority unless no hosting found
                                cloudflare_email = "abuse@cloudflare.com"
                                if cloudflare_email not in abuse_list:
                                    abuse_list.append(cloudflare_email)
                                logger.info(
                                    f"Cloudflare detected for {url}. Will report to hosting provider first, then Cloudflare: {abuse_list}"
                                )
                            elif cloudflare_detected:
                                # Pure Cloudflare case
                                logger.info(
                                    f"Cloudflare detected for {url}, using Cloudflare abuse only"
                                )
                                abuse_list = ["abuse@cloudflare.com"]

                            # Fall back to stored abuse email if no enhanced detection result and not same domain
                            if not abuse_list and stored_abuse:
                                if self.abuse_detector.validate_abuse_email_domain(
                                    stored_abuse, domain
                                ):
                                    abuse_list = [stored_abuse]
                                else:
                                    logger.warning(
                                        f"Stored abuse email {stored_abuse} is same domain as reported site {url}, skipping"
                                    )

                            if abuse_list:
                                attachment_paths = AttachmentConfig.get_all_attachments()
                                if self.send_abuse_report(
                                    abuse_list, url, whois_str, attachment_paths=attachment_paths
                                ):
                                    conn.execute(
                                        text(
                                            """
                                            UPDATE phishing_sites
                                            SET abuse_report_sent=1, abuse_email=:abuse_email, last_report_sent=:timestamp
                                            WHERE url=:url
                                        """
                                        ),
                                        {
                                            "abuse_email": abuse_list[0],
                                            "timestamp": timestamp,
                                            "url": url,
                                        },
                                    )
                            else:
                                logger.warning(
                                    f"No valid abuse emails found for {url} - all emails were same domain or invalid"
                                )

                        except Exception as e:
                            logger.error(f"WHOIS query failed for {url}: {e}")

            except Exception as e:
                logger.error(f"Error in abuse reporting loop: {e}")

            time.sleep(settings.REPORT_INTERVAL)

    def process_manual_reports(self, attachment_paths: Optional[List[str]] = None):
        """Process manual reports that haven't been processed yet."""
        # If no specific attachments provided, get all configured attachments
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()

        with self.db_manager.engine.begin() as conn:
            sites = conn.execute(
                text(
                    """
                    SELECT url, reported, abuse_report_sent, abuse_email, priority
                    FROM phishing_sites
                    WHERE manual_flag = 1 AND reported = 0
                    ORDER BY
                        CASE priority
                            WHEN 'high' THEN 1
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 3
                            ELSE 2
                        END,
                        first_seen ASC
                """
                )
            ).fetchall()

            for row in sites:
                url, reported, abuse_report_sent, stored_abuse = row[:4]

                try:
                    whois_data = basic_whois_lookup(url)
                    whois_str = str(whois_data)
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    resolved_ip, asn_provider = get_ip_info(domain)
                    cloudflare_detected = resolved_ip and is_cloudflare_ip(resolved_ip)

                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET whois_info=:whois_str, last_seen=:timestamp, reported=1,
                                resolved_ip=:resolved_ip, asn_provider=:asn_provider, is_cloudflare=:is_cloudflare
                            WHERE url=:url
                        """
                        ),
                        {
                            "whois_str": whois_str,
                            "timestamp": timestamp,
                            "resolved_ip": resolved_ip,
                            "asn_provider": asn_provider,
                            "is_cloudflare": 1 if cloudflare_detected else 0,
                            "url": url,
                        },
                    )
                    logger.info(f"Manually processed WHOIS data for {url}")

                    # Get abuse emails using enhanced detection
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    registrar = self.abuse_detector.extract_registrar(whois_data)
                    abuse_list = self.abuse_detector.get_enhanced_abuse_email(
                        domain, whois_data, registrar
                    )

                    # Additional check: if Cloudflare detected, enhance the logic
                    if cloudflare_detected and not abuse_list:
                        logger.info(
                            f"Cloudflare detected for {url}, no hosting provider found. Using abuse@cloudflare.com only"
                        )
                        abuse_list = ["abuse@cloudflare.com"]
                    elif cloudflare_detected and abuse_list:
                        # Ensure Cloudflare is in the list but as secondary option
                        cloudflare_email = "abuse@cloudflare.com"
                        if cloudflare_email not in abuse_list:
                            abuse_list.append(cloudflare_email)
                        logger.info(
                            f"Cloudflare detected for {url}. Will report to hosting provider first, then Cloudflare: {abuse_list}"
                        )
                    elif cloudflare_detected:
                        # Pure Cloudflare case
                        logger.info(f"Cloudflare detected for {url}, using Cloudflare abuse only")
                        abuse_list = ["abuse@cloudflare.com"]

                    # Fall back to stored abuse email if no enhanced detection result and not same domain
                    if not abuse_list and stored_abuse:
                        if self.abuse_detector.validate_abuse_email_domain(stored_abuse, domain):
                            abuse_list = [stored_abuse]
                        else:
                            logger.warning(
                                f"Stored abuse email {stored_abuse} is same domain as reported site {url}, skipping"
                            )

                    if abuse_list and abuse_report_sent == 0:
                        if self.send_abuse_report(
                            abuse_list, url, whois_str, attachment_paths=attachment_paths
                        ):
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET abuse_report_sent=1, abuse_email=:abuse_email, last_report_sent=:timestamp
                                    WHERE url=:url
                                """
                                ),
                                {"abuse_email": abuse_list[0], "timestamp": timestamp, "url": url},
                            )
                    elif not abuse_list:
                        logger.warning(
                            f"No valid abuse emails found for {url} - all emails were same domain or invalid"
                        )

                except Exception as e:
                    logger.error(f"WHOIS query failed for {url}: {e}")

        logger.info("Completed manual reports processing.")

    def send_test_report(self, test_email: str, attachment_paths: Optional[List[str]] = None):
        """Send a test abuse report."""
        test_whois_str = "This is a test WHOIS information for a test phishing site."
        test_site_url = "https://test.phishing-site.com"
        test_abuse_emails = [test_email]

        # If no specific attachments provided, get all configured attachments
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()

        logger.info("Sending test abuse report...")

        if self.send_abuse_report(
            test_abuse_emails,
            test_site_url,
            test_whois_str,
            attachment_paths=attachment_paths,
            test_mode=True,
        ):
            logger.info("Test report sent successfully.")
        else:
            logger.error("Failed to send test report.")


class TakedownMonitor:
    """Enhanced takedown monitor with better status detection."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        timeout: int,
        check_interval: int = 3600,
        monitoring_event: threading.Event = None,
    ):
        self.db_manager = db_manager
        self.timeout = timeout
        self.check_interval = check_interval
        self.monitoring_event = monitoring_event

    def run(self):
        """Main monitoring loop."""
        first_cycle_done = False

        while True:
            try:
                with self.db_manager.engine.begin() as conn:
                    sites = conn.execute(
                        text("SELECT url, site_status, takedown_date FROM phishing_sites")
                    ).fetchall()

                    for url, current_status, current_takedown in sites:
                        try:
                            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            resolved_ip, asn_provider = get_ip_info(domain)

                            # Use the refactored function to determine site status
                            new_status, new_takedown = PhishingUtils.determine_site_status(
                                url,
                                resolved_ip,
                                current_status,
                                current_takedown,
                                timestamp,
                                self.timeout,
                            )

                            # Update database if status changed
                            if new_status != current_status or new_takedown != current_takedown:
                                conn.execute(
                                    text(
                                        """
                                        UPDATE phishing_sites
                                        SET site_status=:new_status, takedown_date=:new_takedown, last_seen=:timestamp
                                        WHERE url=:url
                                    """
                                    ),
                                    {
                                        "new_status": new_status,
                                        "new_takedown": new_takedown,
                                        "timestamp": timestamp,
                                        "url": url,
                                    },
                                )
                                logger.info(
                                    f"Updated {url}: site_status='{new_status}', takedown_date='{new_takedown}'"
                                )

                        except Exception as e:
                            logger.error(f"Error checking status for {url}: {e}")
                            continue

                # Signal completion of first cycle
                if not first_cycle_done:
                    first_cycle_done = True
                    if self.monitoring_event and not self.monitoring_event.is_set():
                        logger.info(
                            "Takedown monitor initial cycle complete, setting monitoring event."
                        )
                        self.monitoring_event.set()

            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")

            time.sleep(self.check_interval)


def save_offset(offset: int):
    """Save current offset to file."""
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))
    logger.debug(f"Offset saved as: {offset}")


def get_offset() -> int:
    """Get current offset from file."""
    try:
        with open(OFFSET_FILE, "r") as f:
            offset_str = f.read().strip()
            offset = int(float(offset_str))
            logger.debug(f"Retrieved offset: {offset}")
            return offset
    except Exception as ex:
        logger.error(f"Error getting offset from {OFFSET_FILE}: {ex}")
        return 0


class PhishingScanner:
    """Enhanced phishing scanner with improved detection capabilities."""

    def __init__(
        self, timeout: int, keywords: List[str], domains: List[str], allowed_sites: List[str], args
    ):
        self.timeout = timeout
        self.keywords = keywords
        self.domains = domains
        self.allowed_sites = allowed_sites
        self.batch_size = DynamicBatchConfig.get_batch_size()

        if args.test_report:
            logger.info("Test report mode active: Skipping queries file generation.")
            self.total_queries = 0
        else:
            if not args.threads_only:
                if args.regen_queries or not os.path.exists(QUERIES_FILE):
                    logger.info(f"Generating queries file {QUERIES_FILE}...")
                    generate_queries_file(self.keywords, self.domains)
                else:
                    logger.info(f"Using existing {QUERIES_FILE} file.")
            else:
                logger.info("Threads-only mode: Skipping queries file generation.")

            try:
                with open(QUERIES_FILE, "r") as f:
                    self.total_queries = sum(1 for _ in f)
                logger.info(f"Total queries in file: {self.total_queries}")
            except Exception as ex:
                logger.error(f"Error counting total queries: {ex}")
                self.total_queries = 0

    def get_dynamic_target_sites(self) -> List[str]:
        """Get next batch of target sites from queries file."""
        offset = get_offset()
        batch = []

        # If offset is beyond file size, reset to beginning for continuous scanning
        if offset >= self.total_queries:
            logger.info(
                f"Offset {offset} beyond file size {self.total_queries}. Resetting to beginning for continuous scanning."
            )
            save_offset(0)
            offset = 0

        with open(QUERIES_FILE, "r") as f:
            # Skip to current offset
            for _ in range(offset):
                f.readline()

            # Read next batch
            for _ in range(self.batch_size):
                line = f.readline()
                if not line:  # End of file
                    break
                batch.append(line.strip())

        if not batch:
            # If no batch read (shouldn't happen with reset logic above), reset anyway
            logger.info("Empty batch read, resetting offset to 0 for continuous scanning.")
            save_offset(0)
            return self.get_dynamic_target_sites()  # Recursive call to get batch from start
        else:
            new_offset = offset + len(batch)
            save_offset(new_offset)

            # Calculate progress
            if self.total_queries > 0:
                progress_percent = (new_offset / self.total_queries) * 100
                remaining = self.total_queries - new_offset
                logger.debug(
                    f"Batch from offset {offset}: {len(batch)} queries read. "
                    f"Progress: {progress_percent:.1f}% ({remaining} remaining)"
                )
            else:
                logger.debug(f"Batch from offset {offset}: {len(batch)} queries read.")

        return batch

    @staticmethod
    def augment_with_www(domain: str) -> List[str]:
        """Augment domain with www variant."""
        parts = domain.split(".")
        return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]

    def filter_allowed_targets(self, targets: List[str]) -> List[str]:
        """Filter out allowed/whitelisted targets."""
        allowed_set = {site.lower().strip() for site in self.allowed_sites}
        filtered = [target for target in targets if target.lower().strip() not in allowed_set]
        removed = len(targets) - len(filtered)
        if removed:
            logger.info(f"Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
        return filtered

    def get_candidate_urls(self, domain: str) -> List[str]:
        """Get candidate URLs for a domain with enhanced validation."""
        candidate_domains = self.augment_with_www(domain)
        candidate_urls = []
        dns_error_logged = False

        for d in candidate_domains:
            for scheme in ("https://", "http://"):
                url = scheme + d
                try:
                    response = requests.head(
                        url,
                        timeout=self.timeout,
                        headers={"User-Agent": DEFAULT_USER_AGENT},
                        allow_redirects=True,
                    )
                    if response.status_code in ALLOWED_HEAD_STATUS:
                        candidate_urls.append(url)
                    else:
                        logger.warning(
                            f"HTTP {response.status_code} at {url} is not acceptable for scanning"
                        )

                except requests.exceptions.ConnectionError as e:
                    if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                        if not dns_error_logged:
                            logger.debug(f"DNS resolution failed for {url}: {e}")
                            dns_error_logged = True
                    else:
                        logger.error(f"Connection error: {url} - {e}")

                except requests.exceptions.RequestException as e:
                    logger.error(f"Protocol error: {url} - {e}")

        if not candidate_urls:
            logger.debug(f"No reachable candidate URLs found for domain: {domain}")

        return candidate_urls

    def scan_site(self, domain: str) -> None:
        """Scan a single site for phishing indicators."""
        code = 0
        for url in self.get_candidate_urls(domain) or []:
            logger.info(f"Scanning {url} for keywords: {self.keywords}")
            try:
                headers = {"User-Agent": DEFAULT_USER_AGENT}
                response = requests.get(
                    url, timeout=self.timeout, headers=headers, allow_redirects=True
                )
                response.raise_for_status()
                code = response.status_code

                # Enhanced keyword detection
                content = response.text.lower()
                matches = []

                # Check for exact keyword matches
                for kw in self.keywords:
                    if kw.lower() in content:
                        matches.append(kw)

                # Additional phishing indicators
                phishing_indicators = [
                    "login",
                    "password",
                    "account",
                    "verify",
                    "suspend",
                    "secure",
                    "update",
                    "confirm",
                    "billing",
                    "payment",
                    "expire",
                ]

                for indicator in phishing_indicators:
                    if indicator in content and indicator not in matches:
                        # Only add if it's contextually relevant
                        if any(kw.lower() in content for kw in self.keywords):
                            matches.append(indicator)

                PhishingUtils.store_scan_result(url, code, matches, db_file=DATABASE_URL)

                if matches:
                    logger.info(f"Found keywords {matches} in {url}")
                    PhishingUtils.log_positive_result(url, matches)
                else:
                    logger.debug(f"No keywords found in {url}")

                break

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout scanning {url}")
                PhishingUtils.update_scan_result_response_code(url, code)

            except requests.exceptions.ConnectionError as e:
                if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                    logger.info(f"DNS failure during scan: {url}")
                else:
                    logger.error(f"Connection failure: {url} - {e}")
                PhishingUtils.update_scan_result_response_code(url, code)

            except Exception as e:
                logger.error(f"Scan error: {url} - {repr(e)}")
                PhishingUtils.update_scan_result_response_code(url, code)

    def run_scan_cycle(self) -> None:
        """Run continuous scanning cycles without long waits."""
        logger.info("Starting continuous scanning mode...")

        cycle_count = 0
        while True:
            cycle_count += 1

            targets = self.get_dynamic_target_sites()
            if not targets:
                logger.info("Reached end of queries file, resetting to beginning...")
                save_offset(0)  # Reset to start
                continue

            if self.allowed_sites:
                targets = self.filter_allowed_targets(targets)

            current_offset = get_offset()
            progress = (
                f"{current_offset}/{self.total_queries}"
                if self.total_queries > 0
                else f"{current_offset}/∞"
            )
            logger.info(
                f"[Cycle {cycle_count}] Processing batch: offset {progress}, batch size {len(targets)}"
            )

            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=180) as executor:
                futures = {executor.submit(self.scan_site, target): target for target in targets}

                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Thread error for {futures[future]}: {repr(e)}")

                    # Progress every 150 completed scans
                    if completed % 150 == 0:
                        progress_percent = (completed / len(targets)) * 100
                        logger.info(
                            f"[Cycle {cycle_count}] Progress: {completed}/{len(targets)} ({progress_percent:.1f}%)"
                        )

            logger.info(
                f"[Cycle {cycle_count}] Completed batch of {len(targets)} targets. Moving to next batch..."
            )

            # Cleanup memory
            gc.collect()

            # Very short pause to prevent overwhelming (1 second)
            time.sleep(1)


class Engine:
    """Main engine class with enhanced capabilities."""

    def __init__(self, args):
        self.timeout = args.timeout if args.timeout is not None else settings.TIMEOUT
        self.log_level = (
            args.log_level if args.log_level is not None else getattr(settings, "LOG_LEVEL", "INFO")
        )
        self.abuse_email = (
            args.abuse_email
            if args.abuse_email is not None
            else getattr(settings, "ABUSE_EMAIL", None)
        )
        self.attachment = (
            args.attachment
            if args.attachment is not None
            else getattr(settings, "ATTACHMENT", None)
        )
        self.attachments_folder = getattr(args, "attachments_folder", None)

        # Set attachments folder in settings if provided via command line
        if self.attachments_folder:
            settings.ATTACHMENTS_FOLDER = self.attachments_folder

        # Parse CC emails
        if args.cc and args.cc.strip() != "":
            self.cc_emails = [email.strip() for email in args.cc.split(",")]
        else:
            self.cc_emails = (
                [email.strip() for email in getattr(settings, "CC", "").split(",")]
                if getattr(settings, "CC", "")
                else None
            )

        self.args = args
        self.db_manager = DatabaseManager(db_url=DATABASE_URL)
        self.db_manager.init_db()
        self.db_manager.init_phishing_db()
        upgrade_phishing_db()
        self.db_manager.init_registrar_abuse_db()

        # Initialize enhanced abuse detector
        self.abuse_detector = EnhancedAbuseEmailDetector(self.db_manager)

        # Initialize threading event for coordination
        self.monitoring_event = threading.Event()

        # Initialize enhanced managers
        self.report_manager = AbuseReportManager(
            self.db_manager,
            self.abuse_detector,
            cc_emails=self.cc_emails,
            timeout=self.timeout,
            monitoring_event=self.monitoring_event,
        )

        self.takedown_monitor = TakedownMonitor(
            self.db_manager,
            timeout=self.timeout,
            check_interval=int(3600 / 3),
            monitoring_event=self.monitoring_event,
        )

        # Parse configuration lists
        transform_to_list = lambda s: (
            [item.strip() for item in s.split(",")] if isinstance(s, str) else s
        )
        self.keywords = transform_to_list(settings.KEYWORDS)
        self.domains = transform_to_list(settings.DOMAINS)
        self.allowed_sites = transform_to_list(getattr(settings, "ALLOWED_SITES", ""))

        # Determine operational mode
        self.mode = EngineMode(self.args)

        # Initialize scanner if needed
        if self.mode.scanning_mode:
            self.scanner = PhishingScanner(
                self.timeout, self.keywords, self.domains, self.allowed_sites, self.args
            )
        else:
            self.scanner = None

    def mark_site_as_phishing(self, url: str, abuse_email: Optional[str] = None):
        """Mark a site as phishing with enhanced database operations."""
        with self.db_manager.engine.begin() as conn:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = conn.execute(
                text("SELECT id FROM phishing_sites WHERE url=:url"), {"url": url}
            ).fetchone()

            if result:
                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET manual_flag=1, last_seen=:timestamp, reported=0,
                            abuse_report_sent=0, abuse_email=:abuse_email
                        WHERE url=:url
                    """
                    ),
                    {"timestamp": timestamp, "abuse_email": abuse_email, "url": url},
                )
                logger.info(f"Updated phishing flag for {url} with abuse email {abuse_email}")
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO phishing_sites
                        (url, manual_flag, first_seen, last_seen, abuse_email, reported, abuse_report_sent)
                        VALUES (:url, 1, :timestamp, :timestamp, :abuse_email, 0, 0)
                    """
                    ),
                    {"url": url, "timestamp": timestamp, "abuse_email": abuse_email},
                )
                logger.info(f"Marked {url} as phishing with abuse email {abuse_email}")

    def start(self):
        """Start the engine in the appropriate mode."""
        if self.args.report:
            self.mark_site_as_phishing(self.args.report, abuse_email=self.abuse_email)
            logger.info(
                f"URL {self.args.report} flagged as phishing. Exiting without sending an email."
            )
            return

        if self.args.process_reports:
            # Convert single attachment to list if provided
            attachment_paths = [self.attachment] if self.attachment else None
            self.report_manager.process_manual_reports(attachment_paths=attachment_paths)
            logger.info("Manually processed flagged phishing reports. Exiting.")
            return

        if self.args.test_report:
            if not self.abuse_email:
                logger.error("For a test report, please provide a test email using --abuse-email")
                return
            # Convert single attachment to list if provided, otherwise get all attachments
            attachment_paths = (
                [self.attachment] if self.attachment else AttachmentConfig.get_all_attachments()
            )
            self.report_manager.send_test_report(
                self.abuse_email, attachment_paths=attachment_paths
            )
            logger.info("Test report sent. Exiting.")
            return

        if getattr(self.args, "start_api", False):
            # Start API server
            api = PhishingAPI(self.db_manager, self.abuse_detector)
            api.run(
                host=getattr(self.args, "api_host", "0.0.0.0"),
                port=getattr(self.args, "api_port", 8080),
                debug=(self.args.log_level == "DEBUG"),
            )
            return

        # Start background threads
        reporting_thread = threading.Thread(
            target=self.report_manager.report_phishing_sites, daemon=True
        )
        reporting_thread.start()

        takedown_thread = threading.Thread(target=self.takedown_monitor.run, daemon=True)
        takedown_thread.start()

        if self.args.threads_only:
            logger.info(
                "Running in threads-only mode. Background threads are active; skipping scanning cycle."
            )
            logger.info(
                "This mode only processes already flagged phishing sites and monitors takedowns."
            )
            logger.info("To scan for new sites, run without --threads-only flag.")
            while True:
                time.sleep(60)
        else:
            logger.info(
                f"Initialized with {len(self.keywords)} keywords and {len(self.domains)} domain extensions"
            )
            logger.info(f"Allowed sites (whitelist): {self.allowed_sites}")
            logger.info(f"Scan interval: {settings.SCAN_INTERVAL}s | Timeout: {self.timeout}s")

            # Run continuous scanning cycles
            logger.info(
                f"Starting continuous scanning with {len(self.keywords)} keywords and {len(self.domains)} domain extensions"
            )
            logger.info(f"Allowed sites (whitelist): {self.allowed_sites}")
            logger.info(f"Timeout: {self.timeout}s per request")

            try:
                self.scanner.run_scan_cycle()  # This now runs continuously
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, shutting down gracefully...")
            except Exception as e:
                logger.error(f"Error in scan cycle: {e}")
                logger.info("Restarting scanning in 60 seconds...")
                time.sleep(60)
                # Restart scanning
                try:
                    self.scanner.run_scan_cycle()
                except KeyboardInterrupt:
                    logger.info("Received interrupt signal, shutting down gracefully...")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Enhanced Anisakys Phishing Detection Engine",
        epilog=(
            "Example usages:\n"
            "  ./anisakys.py --timeout 30 --log-level DEBUG\n"
            "  ./anisakys.py --reset-offset  # Reset scanning to start from beginning\n"
            "  ./anisakys.py --report https://site.domain.com --abuse-email abuse@domain.com\n"
            '  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"\n'
            "  ./anisakys.py --process-reports --attachments-folder /path/to/attachments/\n"
            "  ./anisakys.py --threads-only --log-level DEBUG  # Only monitoring, no scanning\n"
            "  ./anisakys.py --start-api --api-port 8080\n"
            "  ./anisakys.py --test-report --abuse-email your-test@example.com --attachments-folder /path/to/attachments/\n"
            "\n"
            "🚀 NEW FEATURES:\n"
            "  ✅ Enhanced ASN abuse email detection\n"
            "  ✅ TLD-specific WHOIS servers (supports .online, .site, etc.)\n"
            "  ✅ Multiple abuse emails per report (hosting + ASN + registrar)\n"
            "  ✅ Cloudflare real hosting detection\n"
            "  ✅ Same-domain validation (prevents reporting abuse@malicious.com)\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Request timeout in seconds (default: settings.TIMEOUT)",
    )
    parser.add_argument(
        "--log-level",
        choices=["INFO", "DEBUG"],
        default=None,
        help="Set logging verbosity (default: settings.LOG_LEVEL or INFO)",
    )
    parser.add_argument("--report", type=str, help="Manually flag a URL as phishing.")
    parser.add_argument(
        "--abuse-email",
        type=str,
        help="(Optional) Provide a known abuse email address for the domain (default: settings.ABUSE_EMAIL)",
    )
    parser.add_argument(
        "--process-reports",
        action="store_true",
        help="Manually trigger processing of flagged phishing sites.",
    )
    parser.add_argument(
        "--attachment",
        type=str,
        help="Optional file path to attach to the abuse report (default: settings.ATTACHMENT)",
    )
    parser.add_argument(
        "--attachments-folder",
        type=str,
        help="Optional folder path containing multiple files to attach to abuse reports",
    )
    parser.add_argument(
        "--cc",
        type=str,
        help="Optional comma-separated list of email addresses to CC on the abuse report (default: settings.CC)",
    )
    parser.add_argument(
        "--threads-only",
        action="store_true",
        help="Only run background threads without running the scanning cycle.",
    )
    parser.add_argument(
        "--regen-queries",
        action="store_true",
        help="Force regeneration of the queries file even if it already exists.",
    )
    parser.add_argument(
        "--test-report",
        action="store_true",
        help="Send a test report including attachment and escalation CCs, then exit.",
    )
    parser.add_argument(
        "--start-api", action="store_true", help="Start the REST API server for external reports."
    )
    parser.add_argument(
        "--api-port", type=int, default=8080, help="Port for the API server (default: 8080)"
    )
    parser.add_argument(
        "--api-host", type=str, default="0.0.0.0", help="Host for the API server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--reset-offset",
        action="store_true",
        help="Reset scanning offset to 0 (start from beginning of queries file)",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    logger.setLevel(
        args.log_level if args.log_level is not None else getattr(settings, "LOG_LEVEL", "INFO")
    )

    # Handle reset offset command
    if args.reset_offset:
        save_offset(0)
        logger.info("Scanning offset reset to 0. Will start from beginning of queries file.")
        return

    engine_instance = Engine(args)
    engine_instance.start()


if __name__ == "__main__":
    main()

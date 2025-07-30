#!/usr/bin/env python3
"""
Enhanced Anisakys Phishing Detection Engine with Grinder Integration

This script now includes bidirectional threat intelligence integration with Grinder,
featuring API key authentication and automated IP reporting capabilities.

Usage examples:
  ./anisakys.py --timeout 30 --log-level DEBUG
  ./anisakys.py --start-api --api-port 8080 --api-key your_anisakys_api_key
  ./anisakys.py --multi-api-scan --url https://suspicious-site.com
"""

import gc
import os
import re
import time
import argparse
import requests
from itertools import permutations
import datetime
from typing import List, Optional, Tuple, Dict, Any
import threading
import smtplib
import psutil
import json
import subprocess
import base64
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
from functools import wraps

from src.config import settings, CLOUDFLARE_IP_RANGES
from src.logger import logger
from src.screenshot_service import ScreenshotService

# Global testing mode detection - independent of test_mode (used for screenshots)
IS_TESTING_MODE = False


def set_testing_mode(enabled=True):
    """Enable/disable global testing mode. In testing mode, CCs are NEVER sent."""
    global IS_TESTING_MODE
    IS_TESTING_MODE = enabled
    if enabled:
        logger.warning("🧪 TESTING MODE ACTIVE - CCs disabled for security")


from src.abuse_contact_validator import AbuseContactValidator
from src.report_tracker import ReportTracker, create_report_record

# Database and file configuration
DATABASE_URL = getattr(settings, "DATABASE_URL", None)
if not DATABASE_URL:
    raise Exception("DATABASE_URL must be set in your .env file")

QUERIES_FILE = getattr(settings, "QUERIES_FILE", "queries_test.txt")
if not QUERIES_FILE:
    raise Exception("QUERIES_FILE must be set in your .env file")

OFFSET_FILE = getattr(settings, "OFFSET_FILE", "offset_test.txt")

# API Configuration
VIRUSTOTAL_API_KEY = getattr(settings, "VIRUSTOTAL_API_KEY", None)
URLVOID_API_KEY = getattr(settings, "URLVOID_API_KEY", None)
PHISHTANK_API_KEY = getattr(settings, "PHISHTANK_API_KEY", None)


def serialize_for_json(obj):
    """Convert objects with datetime to JSON-serializable format"""
    if obj is None:
        return None

    if hasattr(obj, "__dict__"):
        # For objects with attributes, convert to dict
        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, datetime.datetime):
                result[key] = value.isoformat()
            elif isinstance(value, list):
                result[key] = [serialize_for_json(item) for item in value]
            else:
                result[key] = value
        return result
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, list):
        return [serialize_for_json(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: serialize_for_json(value) for key, value in obj.items()}
    else:
        return obj


# Grinder Integration Configuration
GRINDER0X_API_URL = getattr(settings, "GRINDER0X_API_URL", None)
GRINDER0X_API_KEY = getattr(settings, "GRINDER0X_API_KEY", None)

# Auto-Analysis Configuration
AUTO_MULTI_API_SCAN = getattr(settings, "AUTO_MULTI_API_SCAN", True)
AUTO_REPORT_THRESHOLD_CONFIDENCE = getattr(settings, "AUTO_REPORT_THRESHOLD_CONFIDENCE", 85)
MANUAL_REVIEW_THRESHOLD_CONFIDENCE = getattr(settings, "MANUAL_REVIEW_THRESHOLD_CONFIDENCE", 70)
AUTO_ANALYSIS_DELAY_SECONDS = getattr(settings, "AUTO_ANALYSIS_DELAY_SECONDS", 30)

# Auto-analysis is only truly enabled if we have API keys AND the setting is enabled
AUTO_ANALYSIS_ENABLED = AUTO_MULTI_API_SCAN and (
    VIRUSTOTAL_API_KEY or URLVOID_API_KEY or PHISHTANK_API_KEY
)

# Grinder integration is enabled if both URL and API key are configured
GRINDER_INTEGRATION_ENABLED = bool(GRINDER0X_API_URL and GRINDER0X_API_KEY)

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

# AbuseIPDB Category mappings for Grinder reports
ABUSEIPDB_CATEGORIES = {
    "phishing": 7,
    "hacking": 15,
    "web_app_attack": 21,
    "bad_web_bot": 19,
    "exploited_host": 20,
    "malware": 16,
    "botnet": 14,
    "spam": 10,
    "fraud": 18,
}

# Global engine for database operations
db_engine = create_engine(DATABASE_URL, pool_pre_ping=True, echo=False)


class GrinderReportClient:
    """
    HTTP client for reporting malicious IPs to Grinder system.

    This class handles the bidirectional threat intelligence integration,
    automatically reporting detected phishing infrastructure to Grinder
    for later AbuseIPDB reporting.
    """

    def __init__(self, api_url: str = None, api_key: str = None):
        """
        Initialize Grinder report client.

        Args:
            api_url (str, optional): Grinder API URL. Default to settings.
            api_key (str, optional): Grinder API key. Default to settings.
        """
        self.api_url = api_url or GRINDER0X_API_URL
        self.api_key = api_key or GRINDER0X_API_KEY
        self.session = requests.Session()

        if self.api_key:
            self.session.headers.update(
                {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "Anisakys-Threat-Intelligence/1.0",
                }
            )

        self.enabled = bool(self.api_url and self.api_key)

        if self.enabled:
            logger.info(f"🔗 Grinder integration enabled: {self.api_url}")
        else:
            logger.warning("⚠️  Grinder integration disabled: Missing API URL or key")

    def report_malicious_ip(
        self, ip_address: str, detection_context: Dict[str, Any], confidence: int = 90
    ) -> Dict[str, Any]:
        """
        Report a malicious IP address to a Grinder system.

        Args:
            ip_address (str): The malicious IP address to report
            detection_context (Dict[str, Any]): Context about the detection
            confidence (int): Confidence level (0-100)

        Returns:
            Dict[str, Any]: Report submission result
        """
        if not self.enabled:
            logger.debug("🔗 Grinder integration disabled, skipping IP report")
            return {"status": "disabled", "message": "Grinder integration not configured"}

        if not self._validate_ip_address(ip_address):
            logger.error(f"❌ Invalid IP address format: {ip_address}")
            return {"status": "error", "message": "Invalid IP address format"}

        try:
            # Determine appropriate categories based on detection context
            categories = self._determine_categories(detection_context)

            # Build the report payload
            payload = {
                "ip_address": ip_address,
                "categories": categories,
                "comment": self._build_comment(detection_context),
                "confidence": min(max(confidence, 0), 100),  # Clamp between 0-100
                "source": "anisakys_threat_intelligence",
                "additional_info": {
                    "detection_method": detection_context.get("method", "domain_analysis"),
                    "related_domains": detection_context.get("domains", []),
                    "severity": detection_context.get("severity", "high"),
                    "threat_level": detection_context.get("threat_level", "unknown"),
                    "analysis_timestamp": datetime.datetime.now().isoformat(),
                    "keywords_detected": detection_context.get("keywords", []),
                    "api_confidence": detection_context.get("api_confidence", 0),
                },
            }

            # Send the report
            endpoint_url = f"{self.api_url.rstrip('/')}/api/v1/report-ip"
            logger.info(f"📤 Reporting malicious IP {ip_address} to Grinder: {endpoint_url}")

            response = self.session.post(endpoint_url, json=payload, timeout=30)

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    f"✅ Successfully reported IP {ip_address} to Grinder "
                    f"(Categories: {categories}, Confidence: {confidence}%)"
                )
                return {
                    "status": "success",
                    "ip_address": ip_address,
                    "grinder_response": result,
                    "categories": categories,
                    "confidence": confidence,
                }

            elif response.status_code == 429:
                logger.warning(f"⏰ Rate limited when reporting IP {ip_address} to Grinder")
                return {
                    "status": "rate_limited",
                    "message": "Rate limited by Grinder API",
                    "retry_after": response.headers.get("Retry-After", "Unknown"),
                }

            elif response.status_code == 400:
                error_details = response.json() if response.content else {"error": "Bad request"}
                logger.error(f"❌ Bad request when reporting IP {ip_address}: {error_details}")
                return {
                    "status": "bad_request",
                    "message": error_details.get("error", "Bad request"),
                    "details": error_details,
                }

            else:
                logger.error(
                    f"❌ Failed to report IP {ip_address} to Grinder: "
                    f"HTTP {response.status_code} - {response.text}"
                )
                return {
                    "status": "error",
                    "message": f"HTTP {response.status_code}",
                    "response_text": response.text,
                }

        except requests.exceptions.Timeout:
            logger.error(f"⏰ Timeout reporting IP {ip_address} to Grinder")
            return {"status": "timeout", "message": "Request timeout"}

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🌐 Connection error reporting IP {ip_address} to Grinder: {e}")
            return {"status": "connection_error", "message": str(e)}

        except Exception as e:
            logger.error(f"❌ Unexpected error reporting IP {ip_address} to Grinder: {e}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def _validate_ip_address(ip_address: str) -> bool:
        """
        Validate an IP address format.

        Args:
            ip_address (str): IP address to validate

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    @staticmethod
    def _determine_categories(detection_context: Dict[str, Any]) -> List[int]:
        """
        Determine appropriate AbuseIPDB categories based on detection context.

        Args:
            detection_context (Dict[str, Any]): Detection context information

        Returns:
            List[int]: List of category IDs
        """
        categories = [ABUSEIPDB_CATEGORIES["phishing"]]

        # Always add phishing category for phishing sites

        # Add additional categories based on threat level and context
        threat_level = detection_context.get("threat_level", "").lower()
        keywords = detection_context.get("keywords", [])
        method = detection_context.get("method", "").lower()

        if threat_level in ["critical", "high"]:
            categories.append(ABUSEIPDB_CATEGORIES["hacking"])

        # Web application attack if web-related keywords detected
        web_keywords = ["login", "password", "account", "banking", "payment"]
        if any(kw.lower() in [k.lower() for k in keywords] for kw in web_keywords):
            categories.append(ABUSEIPDB_CATEGORIES["web_app_attack"])

        # Malware if detected through VirusTotal
        if "virustotal" in method:
            categories.append(ABUSEIPDB_CATEGORIES["malware"])

        # Remove duplicates and return
        return list(set(categories))

    @staticmethod
    def _build_comment(detection_context: Dict[str, Any]) -> str:
        """
        Build a comprehensive comment for the abuse report.

        Args:
            detection_context (Dict[str, Any]): Detection context information

        Returns:
            str: Formatted comment for the report
        """
        threat_level = detection_context.get("threat_level", "unknown").upper()
        domains = detection_context.get("domains", [])
        keywords = detection_context.get("keywords", [])
        api_confidence = detection_context.get("api_confidence", 0)

        comment_parts = [
            f"Phishing infrastructure detected by Anisakys threat intelligence system.",
            f"Threat Level: {threat_level}",
        ]

        if api_confidence > 0:
            comment_parts.append(f"API Confidence: {api_confidence}%")

        if domains:
            domain_list = ", ".join(domains[:5])  # Limit to first 5 domains
            if len(domains) > 5:
                domain_list += f" (and {len(domains) - 5} more)"
            comment_parts.append(f"Related domains: {domain_list}")

        if keywords:
            keyword_list = ", ".join(keywords[:5])  # Limit to first 5 keywords
            if len(keywords) > 5:
                keyword_list += f" (and {len(keywords) - 5} more)"
            comment_parts.append(f"Detection keywords: {keyword_list}")

        comment_parts.append("Automated report from Anisakys phishing detection engine.")

        return " | ".join(comment_parts)

    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to Grinder API.

        Returns:
            Dict[str, Any]: Connection test result
        """
        if not self.enabled:
            return {"status": "disabled", "message": "Grinder integration not configured"}

        try:
            # Try to access a test endpoint or health check
            health_url = f"{self.api_url.rstrip('/')}/api/v1/health"
            response = self.session.get(health_url, timeout=10)

            if response.status_code == 200:
                logger.info("✅ Grinder API connection test successful")
                return {
                    "status": "success",
                    "message": "Successfully connected to Grinder API",
                    "api_url": self.api_url,
                }
            else:
                logger.warning(f"⚠️  Grinder API responded with {response.status_code}")
                return {
                    "status": "warning",
                    "message": f"Grinder API responded with HTTP {response.status_code}",
                    "api_url": self.api_url,
                }

        except Exception as e:
            logger.error(f"❌ Failed to connect to Grinder API: {e}")
            return {
                "status": "error",
                "message": f"Connection failed: {str(e)}",
                "api_url": self.api_url,
            }


def require_api_key(f):
    """
    Decorator to require API key authentication for API endpoints.

    Expects API key in Authorization header: Bearer <key>
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning(f"🔐 Unauthorized API access attempt from {request.remote_addr}")
            return jsonify({"error": "Authorization header required with Bearer token"}), 401

        provided_key = auth_header[7:]  # Remove 'Bearer ' prefix

        # Get the expected API key from Flask app config or environment
        expected_key = getattr(flask_app, "api_key", None) if "flask_app" in globals() else None

        if not expected_key:
            logger.error("🔐 API key not configured for validation")
            return jsonify({"error": "API authentication not properly configured"}), 500

        if provided_key != expected_key:
            logger.warning(f"🔐 Invalid API key provided from {request.remote_addr}")
            return jsonify({"error": "Invalid API key"}), 401

        logger.debug(f"🔐 Valid API key provided from {request.remote_addr}")
        return f(*args, **kwargs)

    return decorated_function


class VirusTotalIntegration:
    """
    VirusTotal API v3 Integration for comprehensive threat detection.

    Provides multi-engine scanning using 70+ antivirus engines and URL scanners
    for comprehensive threat detection with real-time reputation analysis.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal integration.

        Args:
            api_key (Optional[str]): VirusTotal API key. If None, uses environment variable.
        """
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self.session.headers.update(
            {"x-apikey": self.api_key, "User-Agent": "Anisakys-Phishing-Detector/1.0"}
        )

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for analysis and get a comprehensive threat assessment.

        Args:
            url (str): URL to scan

        Returns:
            Dict[str, Any]: Detailed threat assessment including detection ratios
        """
        if not self.api_key:
            logger.warning("⚠️  VirusTotal API key not configured, skipping scan")
            return {"error": "API key not configured"}

        try:
            # First, submit the URL for scanning
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            # Check if URL has been analyzed before
            response = self.session.get(f"{self.base_url}/urls/{url_id}")

            if response.status_code == 200:
                data = response.json()
                analysis = data.get("data", {}).get("attributes", {})
                last_analysis = analysis.get("last_analysis_stats", {})

                result = {
                    "url": url,
                    "scan_date": analysis.get("last_analysis_date"),
                    "reputation": analysis.get("reputation", 0),
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "undetected": last_analysis.get("undetected", 0),
                    "total_engines": sum(last_analysis.values()) if last_analysis else 0,
                    "threat_level": self._calculate_threat_level(last_analysis),
                    "community_score": analysis.get("total_votes", {}).get("harmless", 0)
                    - analysis.get("total_votes", {}).get("malicious", 0),
                    "categories": analysis.get("categories", {}),
                    "engines_detail": analysis.get("last_analysis_results", {}),
                }

                logger.info(
                    f"🛡️  VirusTotal scan for {url}: {result['malicious']}/{result['total_engines']} engines detected threats"
                )
                return result

            elif response.status_code == 404:
                # URL isn't found, submit for scanning
                scan_response = self.session.post(f"{self.base_url}/urls", data={"url": url})

                if scan_response.status_code == 200:
                    logger.info(f"📤 Submitted {url} to VirusTotal for analysis")
                    return {
                        "status": "submitted",
                        "message": "URL submitted for analysis, check back later",
                    }
                else:
                    logger.error(
                        f"❌ Failed to submit {url} to VirusTotal: {scan_response.status_code}"
                    )
                    return {"error": f"Failed to submit URL: {scan_response.status_code}"}

            else:
                logger.error(f"❌ VirusTotal API error: {response.status_code}")
                return {"error": f"API error: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ VirusTotal scan failed for {url}: {e}")
            return {"error": str(e)}

    @staticmethod
    def _calculate_threat_level(analysis_stats: Dict[str, int]) -> str:
        """
        Calculate threat level based on detection statistics.

        Args:
            analysis_stats (Dict[str, int]): Analysis statistics from VirusTotal

        Returns:
            str: Threat level (high, medium, low, clean)
        """
        if not analysis_stats:
            return "unknown"

        malicious = analysis_stats.get("malicious", 0)
        suspicious = analysis_stats.get("suspicious", 0)
        total = sum(analysis_stats.values())

        if total == 0:
            return "unknown"

        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total

        if malicious_ratio >= 0.1:  # 10% or more engines detect as malicious
            return "high"
        elif malicious_ratio >= 0.05 or suspicious_ratio >= 0.2:  # 5% malicious or 20% suspicious
            return "medium"
        elif malicious_ratio > 0 or suspicious_ratio > 0:
            return "low"
        else:
            return "clean"

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get a domain reputation and analysis report.

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict[str, Any]: Domain analysis report
        """
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            response = self.session.get(f"{self.base_url}/domains/{domain}")

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                return {
                    "domain": domain,
                    "reputation": attributes.get("reputation", 0),
                    "categories": attributes.get("categories", {}),
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "registrar": attributes.get("registrar"),
                    "creation_date": attributes.get("creation_date"),
                    "last_update_date": attributes.get("last_update_date"),
                }
            else:
                return {"error": f"Domain analysis failed: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ VirusTotal domain analysis failed for {domain}: {e}")
            return {"error": str(e)}


class URLVoidIntegration:
    """
    URLVoid API Integration for multi-blocklist checking.

    Queries against 30+ reputation engines and blocklist services for
    comprehensive domain reputation analysis.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize URLVoid integration.

        Args:
            api_key (Optional[str]): URLVoid API key. If None, uses environment variable.
        """
        self.api_key = api_key or URLVOID_API_KEY
        self.base_url = "https://api.urlvoid.com/v1"
        self.session = requests.Session()

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain using multiple reputation engines and blocklist services.

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict[str, Any]: Comprehensive safety score and reputation analysis
        """
        if not self.api_key:
            logger.warning("⚠️  URLVoid API key not configured, skipping analysis")
            return {"error": "API key not configured"}

        try:
            params = {"key": self.api_key, "host": domain}

            response = self.session.get(f"{self.base_url}/host/{domain}", params=params)

            if response.status_code == 200:
                data = response.json()
                details = data.get("data", {}).get("report", {})

                result = {
                    "domain": domain,
                    "safety_score": details.get("safety_score", 0),
                    "domain_age": details.get("domain_age"),
                    "domain_1st_registered": details.get("domain_1st_registered"),
                    "domain_length": details.get("domain_length"),
                    "hostname": details.get("hostname"),
                    "ip_address": details.get("ip_address"),
                    "asn": details.get("asn"),
                    "asn_name": details.get("asn_name"),
                    "country_code": details.get("country_code"),
                    "server_type": details.get("server_type"),
                    "detections": details.get("detections", {}),
                    "blacklists": details.get("blacklists", []),
                    "threat_level": self._calculate_urlvoid_threat_level(details),
                    "ssl_certificate": details.get("ssl_certificate", {}),
                    "redirects": details.get("redirects", []),
                }

                logger.info(
                    f"🔍 URLVoid analysis for {domain}: Safety score {result['safety_score']}"
                )
                return result

            else:
                logger.error(f"❌ URLVoid API error for {domain}: {response.status_code}")
                return {"error": f"API error: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ URLVoid analysis failed for {domain}: {e}")
            return {"error": str(e)}

    @staticmethod
    def _calculate_urlvoid_threat_level(details: Dict[str, Any]) -> str:
        """
        Calculate threat level based on URLVoid analysis.

        Args:
            details (Dict[str, Any]): URLVoid analysis details

        Returns:
            str: Threat level (high, medium, low, clean)
        """
        safety_score = details.get("safety_score", 100)
        detections = details.get("detections", {})
        blacklists = details.get("blacklists", [])

        if safety_score <= 30 or len(blacklists) >= 5:
            return "high"
        elif safety_score <= 60 or len(blacklists) >= 2:
            return "medium"
        elif safety_score <= 80 or len(blacklists) >= 1:
            return "low"
        else:
            return "clean"


class PhishTankIntegration:
    """
    PhishTank API Integration for a community-driven phishing database.

    Provides access to verified phishing URLs from the security community with
    real-time updates and submission capabilities.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize PhishTank integration.

        Args:
            api_key (Optional[str]): PhishTank API key. If None, uses environment variable.
        """
        self.api_key = api_key or PHISHTANK_API_KEY
        self.base_url = "https://checkurl.phishtank.com/checkurl/"
        self.session = requests.Session()

    def check_phishing_status(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is in PhishTank verified a phishing database.

        Args:
            url (str): URL to check

        Returns:
            Dict[str, Any]: Phishing status and verification details
        """
        try:
            data = {"url": url, "format": "json"}

            if self.api_key:
                data["app_key"] = self.api_key

            response = self.session.post(self.base_url, data=data)

            if response.status_code == 200:
                result = response.json()

                if "results" in result:
                    phish_details = result["results"]

                    return {
                        "url": url,
                        "is_phishing": phish_details.get("in_database", False),
                        "phish_id": phish_details.get("phish_id"),
                        "verified": phish_details.get("verified", False),
                        "verified_at": phish_details.get("verified_at"),
                        "submission_time": phish_details.get("submission_time"),
                        "target": phish_details.get("target"),
                        "details_url": phish_details.get("phish_detail_url"),
                        "threat_level": (
                            "high" if phish_details.get("verified", False) else "medium"
                        ),
                    }
                else:
                    return {
                        "url": url,
                        "is_phishing": False,
                        "verified": False,
                        "threat_level": "clean",
                    }

            else:
                logger.error(f"❌ PhishTank API error for {url}: {response.status_code}")
                return {"error": f"API error: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ PhishTank check failed for {url}: {e}")
            return {"error": str(e)}

    def submit_phishing_url(self, url: str) -> Dict[str, Any]:
        """
        Submit suspected phishing URL to PhishTank database.

        Args:
            url (str): Suspected phishing URL to submit

        Returns:
            Dict[str, Any]: Submission result
        """
        if not self.api_key:
            logger.warning("⚠️  PhishTank API key not configured, cannot submit URLs")
            return {"error": "API key required for submissions"}

        try:
            submit_url = "https://www.phishtank.com/add_web_phish.php"
            data = {"url": url, "app_key": self.api_key}

            response = self.session.post(submit_url, data=data)

            if response.status_code == 200:
                logger.info(f"✅ Successfully submitted {url} to PhishTank")
                return {"status": "submitted", "url": url}
            else:
                logger.error(f"❌ Failed to submit {url} to PhishTank: {response.status_code}")
                return {"error": f"Submission failed: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ PhishTank submission failed for {url}: {e}")
            return {"error": str(e)}


class MultiAPIValidator:
    """
    Multi-API validation pipeline for comprehensive phishing detection.

    Orchestrates VirusTotal, URLVoid, and PhishTank APIs for enhanced
    threat detection with configurable validation thresholds.
    """

    def __init__(self):
        """Initialize multi-API validator with all integrated services."""
        self.virustotal = VirusTotalIntegration()
        self.urlvoid = URLVoidIntegration()
        self.phishtank = PhishTankIntegration()

    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive multi-API validation scan.

        Args:
            url (str): URL to validate

        Returns:
            Dict[str, Any]: Comprehensive validation report with aggregated results
        """
        logger.info(f"🔍 Starting comprehensive multi-API scan for {url}")

        # Extract domain for domain-specific checks
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]

        results = {
            "url": url,
            "domain": domain,
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "virustotal": {},
            "urlvoid": {},
            "phishtank": {},
            "aggregated_threat_level": "unknown",
            "confidence_score": 0,
            "recommendations": [],
        }

        # Step 1: VirusTotal URL scan
        logger.info(f"📊 Step 1: VirusTotal URL analysis for {url}")
        vt_result = self.virustotal.scan_url(url)
        results["virustotal"] = vt_result

        # Step 2: URLVoid domain analysis
        logger.info(f"📊 Step 2: URLVoid domain analysis for {domain}")
        uv_result = self.urlvoid.analyze_domain(domain)
        results["urlvoid"] = uv_result

        # Step 3: PhishTank community check
        logger.info(f"📊 Step 3: PhishTank community database check for {url}")
        pt_result = self.phishtank.check_phishing_status(url)
        results["phishtank"] = pt_result

        # Step 4: Aggregate results and calculate threat level
        results["aggregated_threat_level"] = self._aggregate_threat_level(
            vt_result, uv_result, pt_result
        )
        results["confidence_score"] = self._calculate_confidence_score(
            vt_result, uv_result, pt_result
        )
        results["recommendations"] = self._generate_recommendations(vt_result, uv_result, pt_result)

        logger.info(
            f"✅ Multi-API scan complete for {url}: "
            f"Threat level: {results['aggregated_threat_level']}, "
            f"Confidence: {results['confidence_score']}%"
        )

        return results

    @staticmethod
    def _aggregate_threat_level(
        vt_result: Dict[str, Any], uv_result: Dict[str, Any], pt_result: Dict[str, Any]
    ) -> str:
        """
        Aggregate threat levels from multiple APIs into single assessment.

        Args:
            vt_result (Dict[str, Any]): VirusTotal scan result
            uv_result (Dict[str, Any]): URLVoid analysis result
            pt_result (Dict[str, Any]): PhishTank check result

        Returns:
            str: Aggregated threat level (critical, high, medium, low, clean)
        """
        threat_scores = []

        # PhishTank has the highest priority (verified community reports)
        if pt_result.get("is_phishing") and pt_result.get("verified"):
            return "critical"
        elif pt_result.get("is_phishing"):
            threat_scores.append(4)  # High threat from PhishTank

        # VirusTotal threat level mapping
        vt_threat = vt_result.get("threat_level", "unknown")
        if vt_threat == "high":
            threat_scores.append(4)
        elif vt_threat == "medium":
            threat_scores.append(3)
        elif vt_threat == "low":
            threat_scores.append(2)
        elif vt_threat == "clean":
            threat_scores.append(1)

        # URLVoid threat level mapping
        uv_threat = uv_result.get("threat_level", "unknown")
        if uv_threat == "high":
            threat_scores.append(4)
        elif uv_threat == "medium":
            threat_scores.append(3)
        elif uv_threat == "low":
            threat_scores.append(2)
        elif uv_threat == "clean":
            threat_scores.append(1)

        if not threat_scores:
            return "unknown"

        avg_score = sum(threat_scores) / len(threat_scores)

        if avg_score >= 4:
            return "high"
        elif avg_score >= 3:
            return "medium"
        elif avg_score >= 2:
            return "low"
        else:
            return "clean"

    @staticmethod
    def _calculate_confidence_score(
        vt_result: Dict[str, Any], uv_result: Dict[str, Any], pt_result: Dict[str, Any]
    ) -> int:
        """
        Calculate confidence score based on API response quality and agreement.

        Returns:
            int: Confidence score (0-100)
        """
        confidence = 0
        factors = 0

        # PhishTank confidence
        if not pt_result.get("error"):
            factors += 1
            if pt_result.get("verified"):
                confidence += 95  # High confidence for verified reports
            elif pt_result.get("is_phishing"):
                confidence += 75  # Medium confidence for unverified reports
            else:
                confidence += 60  # Base confidence for a clean result

        # VirusTotal confidence
        if not vt_result.get("error"):
            factors += 1
            total_engines = vt_result.get("total_engines", 0)
            if total_engines >= 50:
                confidence += 90  # High confidence with many engines
            elif total_engines >= 20:
                confidence += 75  # Medium confidence
            elif total_engines > 0:
                confidence += 60  # Low confidence

        # URLVoid confidence
        if not uv_result.get("error"):
            factors += 1
            safety_score = uv_result.get("safety_score", 50)
            confidence += min(90, safety_score + 20)  # Scale safety score

        return int(confidence / factors) if factors > 0 else 0

    @staticmethod
    def _generate_recommendations(
        vt_result: Dict[str, Any], uv_result: Dict[str, Any], pt_result: Dict[str, Any]
    ) -> List[str]:
        """
        Generate actionable recommendations based on scan results.

        Returns:
            List[str]: List of recommendations
        """
        recommendations = []

        # PhishTank recommendations
        if pt_result.get("is_phishing"):
            if pt_result.get("verified"):
                recommendations.append(
                    "🚨 CRITICAL: URL verified as phishing by PhishTank community"
                )
                recommendations.append(
                    "🔒 IMMEDIATE ACTION: Block URL and report to hosting provider"
                )
            else:
                recommendations.append("⚠️ WARNING: URL reported as phishing (unverified)")

        # VirusTotal recommendations
        if not vt_result.get("error"):
            malicious = vt_result.get("malicious", 0)
            total = vt_result.get("total_engines", 0)

            if malicious > 0:
                recommendations.append(
                    f"🛡️ VirusTotal: {malicious}/{total} engines flagged as malicious"
                )
                if malicious >= 5:
                    recommendations.append(
                        "🚨 HIGH RISK: Multiple security engines detected threats"
                    )

        # URLVoid recommendations
        if not uv_result.get("error"):
            safety_score = uv_result.get("safety_score", 100)
            blacklists = uv_result.get("blacklists", [])

            if safety_score <= 50:
                recommendations.append(f"⚠️ URLVoid: Low safety score ({safety_score}/100)")

            if blacklists:
                recommendations.append(
                    f"🚫 Found on {len(blacklists)} blacklist(s): {', '.join(blacklists[:3])}"
                )

        # General recommendations
        if not recommendations:
            recommendations.append("✅ No immediate threats detected by available scanners")
            recommendations.append("🔍 Continue monitoring for changes")

        return recommendations


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
        """Get a default attachment path from settings."""
        path = getattr(settings, "DEFAULT_ATTACHMENT", None)
        if path and os.path.exists(path):
            abs_path = os.path.abspath(path)
            logger.info(f"📎 Using default attachment from settings: {abs_path}")
            return path
        else:
            if path:
                logger.error(f"❌ DEFAULT_ATTACHMENT file '{path}' does not exist.")
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
            logger.info(f"📁 Using attachments folder: {attachments_folder}")

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
                        logger.debug(f"📎 Added attachment: {file_path}")
                    else:
                        logger.debug(f"⏭️ Skipped file (not allowed extension): {file_path}")

            if attachments:
                logger.info(f"📁 Found {len(attachments)} attachment(s) in folder")
            else:
                logger.warning(f"⚠️  No valid attachments found in folder: {attachments_folder}")

        return attachments

    @staticmethod
    def get_all_attachments() -> List[str]:
        """
        Get all attachments (both single file and folder-based).

        Returns:
            List[str]: List of all attachment file paths
        """
        attachments = []

        # First, try to get attachments from the folder
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
        self.multi_api_mode = getattr(args, "multi_api_scan", False)
        self.scanning_mode = not (
            self.report_mode
            or self.process_reports_mode
            or self.threads_only_mode
            or args.test_report
            or self.api_mode
            or self.multi_api_mode
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

    def extract_emails_from_whois(self, whois_info: Any) -> List[str]:
        """Extract email addresses from WHOIS data using enhanced patterns."""
        emails = []
        whois_str = str(whois_info).lower()

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
                            f"🔍 Found abuse email in DNS TXT for {domain}: {email_match.group(1)}"
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
                        logger.info(f"🔍 Found abuse email from WHOIS server {server}: {emails[0]}")
                        return emails[0]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def get_abuse_email_by_registrar(self, registrar: str) -> Optional[str]:
        """Get abuse email from registrar database (cached + enhanced)."""
        # Check the database cache first
        with self.db_manager.engine.begin() as conn:
            result = conn.execute(
                text("SELECT abuse_email FROM registrar_abuse WHERE LOWER(registrar) LIKE :param"),
                {"param": "%" + registrar.lower() + "%"},
            ).fetchone()
            if result:
                logger.info(f"📚 Found cached abuse email for registrar '{registrar}': {result[0]}")
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
                logger.info(f"📚 Found enhanced abuse email for registrar '{registrar}': {email}")
                return email

        return None

    def get_enhanced_abuse_email(
        self, domain: str, whois_info: Any = None, registrar: str = None
    ) -> List[str]:
        """Get abuse email using multiple enhanced detection methods."""
        logger.info(f"🔍 Starting enhanced abuse email detection for domain: {domain}")
        abuse_emails = []

        # 1. Check a cached registrar database
        if registrar:
            registrar_email = self.get_abuse_email_by_registrar(registrar)
            if registrar_email and self.validate_abuse_email_domain(registrar_email, domain):
                abuse_emails.append(registrar_email)
                logger.info(f"✅ Added registrar abuse email: {registrar_email}")

        # 2. Extract from WHOIS data (exclude same domain)
        if whois_info:
            whois_emails = self.extract_emails_from_whois(whois_info)
            for email in whois_emails:
                if self.validate_abuse_email_domain(email, domain):
                    abuse_emails.append(email)
                    logger.info(f"✅ Added WHOIS abuse email: {email}")

        # 3. Try DNS TXT records
        dns_email = self.get_abuse_email_from_dns(domain)
        if dns_email and self.validate_abuse_email_domain(dns_email, domain):
            abuse_emails.append(dns_email)

        # 4. Try alternative WHOIS servers
        if not abuse_emails:
            whois_server_email = self.get_abuse_email_from_whois_servers(domain)
            if whois_server_email and self.validate_abuse_email_domain(whois_server_email, domain):
                abuse_emails.append(whois_server_email)

        # 5. Check hosting provider and ASN information
        try:
            domain_ip = socket.gethostbyname(domain)
            logger.info(f"🌐 Resolved {domain} to IP: {domain_ip}")

            if is_cloudflare_ip(domain_ip):
                logger.info(
                    f"☁️  Domain {domain} is behind Cloudflare, investigating real hosting..."
                )

                # Try to find real IP behind Cloudflare
                real_ip = self.get_real_ip_behind_cloudflare(domain)
                if real_ip:
                    logger.info(f"🔍 Found potential real IP behind Cloudflare: {real_ip}")
                    provider_name, provider_abuse, asn, asn_abuse_email = (
                        self.get_hosting_provider_info(real_ip)
                    )

                    # Add provider abuse email
                    if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                        abuse_emails.append(provider_abuse)
                        logger.info(
                            f"🏢 Found hosting provider abuse email: {provider_abuse} (Provider: {provider_name})"
                        )

                    # Add ASN abuse email
                    if asn_abuse_email and self.validate_abuse_email_domain(
                        asn_abuse_email, domain
                    ):
                        abuse_emails.append(asn_abuse_email)
                        logger.info(f"🏷️  Found ASN abuse email: {asn_abuse_email} (ASN: {asn})")
                else:
                    logger.warning(f"⚠️  Could not find real IP behind Cloudflare for {domain}")

                # Always add Cloudflare as a secondary option
                cloudflare_email = "abuse@cloudflare.com"
                if cloudflare_email not in abuse_emails:
                    abuse_emails.append(cloudflare_email)
                    logger.info(
                        f"☁️  Added Cloudflare abuse email as secondary option: {cloudflare_email}"
                    )
            else:
                # Not behind Cloudflare, check hosting provider directly
                logger.info(f"🏢 Checking hosting provider for IP: {domain_ip}")
                provider_name, provider_abuse, asn, asn_abuse_email = (
                    self.get_hosting_provider_info(domain_ip)
                )

                logger.info(f"🏢 Hosting Provider: {provider_name or 'Unknown'}")
                logger.info(f"🏷️  ASN: {asn or 'Unknown'}")

                # Add provider abuse email
                if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                    abuse_emails.append(provider_abuse)
                    logger.info(
                        f"✅ Found hosting provider abuse email: {provider_abuse} (Provider: {provider_name})"
                    )
                else:
                    if provider_abuse:
                        logger.warning(
                            f"❌ Provider abuse email rejected (same domain): {provider_abuse}"
                        )
                    else:
                        logger.warning(f"⚠️  No provider abuse email found in WHOIS data")

                # Add ASN abuse email
                if asn_abuse_email and self.validate_abuse_email_domain(asn_abuse_email, domain):
                    abuse_emails.append(asn_abuse_email)
                    logger.info(f"✅ Found ASN abuse email: {asn_abuse_email} (ASN: {asn})")
                else:
                    if asn_abuse_email:
                        logger.warning(
                            f"❌ ASN abuse email rejected (same domain): {asn_abuse_email}"
                        )
                    else:
                        logger.warning(f"⚠️  No ASN abuse email found for ASN: {asn}")

        except Exception as e:
            logger.debug(f"Failed to get IP/hosting info for {domain}: {e}")

        # 6. Generate common abuse email patterns (exclude same domain)
        if not abuse_emails:
            logger.warning(f"⚠️  No abuse emails found through other methods for {domain}")
            # Try parent domain or known hosting providers
            try:
                # Get hosting info from IP WHOIS
                domain_ip = socket.gethostbyname(domain)
                provider_name, provider_abuse, asn, asn_abuse_email = (
                    self.get_hosting_provider_info(domain_ip)
                )

                # Add both provider and ASN emails if available
                if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                    abuse_emails.append(provider_abuse)

                if asn_abuse_email and self.validate_abuse_email_domain(asn_abuse_email, domain):
                    abuse_emails.append(asn_abuse_email)

            except:
                pass

        # Remove duplicates while preserving order
        unique_emails = []
        seen = set()
        for email in abuse_emails:
            if email not in seen:
                unique_emails.append(email)
                seen.add(email)

        # Enhanced logging with final results
        if unique_emails:
            logger.info(
                f"✅ Found {len(unique_emails)} valid abuse email(s) for {domain}: {unique_emails}"
            )
        else:
            logger.warning(f"❌ No valid abuse emails found for {domain}")

        return unique_emails

    @staticmethod
    def extract_registrar(whois_info) -> Optional[str]:
        """Extract registrar from WHOIS data."""
        if isinstance(whois_info, dict):
            registrar = whois_info.get("registrar")
            if registrar:
                if isinstance(registrar, list):
                    return registrar[0].strip()
                else:
                    return str(registrar).strip()
        whois_str = str(whois_info)
        match = re.search(r"Registrar:\s*(.+)", whois_str, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def validate_abuse_email_domain(email: str, reported_domain: str) -> bool:
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
                    f"❌ Cannot send abuse report to same domain: {email} for {reported_domain}"
                )
                return False

            # Check if it's a subdomain of the reported domain
            if email_domain.endswith("." + reported_domain_clean):
                logger.warning(
                    f"❌ Cannot send abuse report to subdomain: {email} for {reported_domain}"
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
                    logger.info(f"🔍 Found potential real IP via subdomain {test_domain}: {ip}")
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
                        logger.info(f"🔍 Found potential real IP via MX record {mx_domain}: {ip}")
                except:
                    continue
        except:
            pass

        return real_ips[0] if real_ips else None

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
            logger.info(f"🔍 Looking up hosting information for IP: {ip}")
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)

            # Get provider name - handle None values safely
            provider_name = ""
            network_info = res.get("network", {})
            if network_info and isinstance(network_info, dict):
                provider_name = network_info.get("name") or ""
                if not provider_name:
                    provider_name = res.get("asn_description") or ""

            # Ensure provider_name is string and handle None
            if provider_name is None:
                provider_name = ""

            # Safely convert to string and handle potential None
            provider_name = str(provider_name) if provider_name else "Unknown"

            # Get ASN information
            asn = res.get("asn", "")
            if asn and not str(asn).startswith("AS"):
                asn = f"AS{asn}"

            # Clean ASN format for lookup
            asn_clean = str(asn).replace("AS", "").strip() if asn else ""

            logger.info(f"🏢 Provider: {provider_name}, ASN: {asn}")

            # Get ASN abuse email from our database
            asn_abuse_email = None
            if asn_clean:
                asn_abuse_email = self.get_abuse_email_by_asn(asn_clean)
                if asn_abuse_email:
                    logger.info(
                        f"🏷️  Found ASN abuse email in database for {asn}: {asn_abuse_email}"
                    )
                else:
                    logger.warning(f"⚠️  No ASN abuse email found in database for {asn}")

            # Look for provider abuse emails in the WHOIS data
            provider_abuse_emails = []

            # Check abuse contacts in RDAP objects
            objects = res.get("objects", {})
            if objects and isinstance(objects, dict):
                for contact_id, contact_data in objects.items():
                    if isinstance(contact_data, dict):
                        contact_info = contact_data.get("contact", {})
                        if contact_info and isinstance(contact_info, dict):
                            # Check a role for abuse
                            role = str(contact_info.get("role", "")).lower()
                            if "abuse" in role:
                                email = contact_info.get("email")
                                if email:
                                    if isinstance(email, list):
                                        provider_abuse_emails.extend(email)
                                    else:
                                        provider_abuse_emails.append(email)
                                    logger.info(f"🔍 Found abuse contact in RDAP objects: {email}")

            # Look for abuse emails in remarks or other fields
            if network_info and isinstance(network_info, dict):
                remarks = network_info.get("remarks", [])
                if remarks and isinstance(remarks, list):
                    for remark in remarks:
                        if isinstance(remark, dict):
                            title = remark.get("title") or ""
                            description = remark.get("description", [])
                            if title and "abuse" in str(title).lower():
                                if isinstance(description, list):
                                    for desc in description:
                                        if desc:
                                            emails = re.findall(
                                                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                                                str(desc),
                                            )
                                            provider_abuse_emails.extend(emails)
                                            if emails:
                                                logger.info(
                                                    f"🔍 Found abuse email in remarks: {emails}"
                                                )

            # Look for abuse emails in events or entities
            entities = res.get("entities", [])
            if entities and isinstance(entities, list):
                for entity in entities:
                    if isinstance(entity, dict):
                        roles = entity.get("roles", [])
                        if roles and isinstance(roles, list) and "abuse" in roles:
                            # This entity has an abuse role
                            events = entity.get("events", [])
                            contact = entity.get("contact", {})
                            if contact and isinstance(contact, dict):
                                email = contact.get("email")
                                if email:
                                    if isinstance(email, list):
                                        provider_abuse_emails.extend(email)
                                    else:
                                        provider_abuse_emails.append(email)
                                    logger.info(f"🔍 Found abuse entity contact: {email}")

            # Filter and validate provider emails
            valid_provider_emails = []
            for email in provider_abuse_emails:
                if email and self.validate_email(str(email)):
                    valid_provider_emails.append(str(email))

            provider_abuse_email = valid_provider_emails[0] if valid_provider_emails else None

            if provider_abuse_email:
                logger.info(f"✅ Final provider abuse email: {provider_abuse_email}")
            else:
                logger.warning(f"⚠️  No valid provider abuse email found in WHOIS data")

            logger.info(
                f"📊 IP {ip} analysis complete: Provider={provider_name}, ASN={asn}, "
                f"Provider abuse={provider_abuse_email}, ASN abuse={asn_abuse_email}"
            )

            return provider_name, provider_abuse_email, asn, asn_abuse_email

        except Exception as e:
            logger.error(f"❌ Failed to get hosting provider info for IP {ip}: {e}")
            return None, None, None, None

    @staticmethod
    def get_abuse_email_by_asn(asn: str) -> Optional[str]:
        """
        Get abuse email from an ASN database.

        Args:
            asn (str): ASN number (with or without 'AS' prefix)

        Returns:
            Optional[str]: Abuse email if found, None otherwise
        """
        # Normalize ASN (remove AS prefix if present)
        asn_clean = asn.replace("AS", "").strip()

        abuse_email = ASN_ABUSE_EMAIL_DB.get(asn_clean)
        if abuse_email:
            logger.info(f"🏷️  Found ASN abuse email for AS{asn_clean}: {abuse_email}")
            return abuse_email

        # Also try with AS prefix in case the database has inconsistent keys
        abuse_email = ASN_ABUSE_EMAIL_DB.get(f"AS{asn_clean}")
        if abuse_email:
            logger.info(f"🏷️  Found ASN abuse email for AS{asn_clean}: {abuse_email}")
            return abuse_email

        logger.debug(f"⚠️  No ASN abuse email found for AS{asn_clean}")
        return None

    @staticmethod
    def get_enhanced_whois_info(domain: str) -> dict:
        """
        Get WHOIS data using the appropriate server based on TLD with enhanced parsing.

        Args:
            domain (str): Domain to query

        Returns:
            dict: WHOIS data
        """
        try:
            # First try with python-whois library
            data = whois.whois(domain)
            if data and (data.domain_name or data.registrar):
                logger.debug(f"📋 Got WHOIS data for {domain} using python-whois")
                return data
        except Exception as e:
            logger.debug(f"Python-whois failed for {domain}: {e}")

        # If that fails, try with specific WHOIS server for TLD
        try:
            tld = domain.split(".")[-1].lower()
            whois_server = TLD_WHOIS_SERVERS.get(tld)

            if whois_server:
                logger.debug(f"🔍 Trying WHOIS server {whois_server} for {domain}")
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

                    logger.info(f"📋 Got WHOIS data for {domain} using {whois_server}")
                    return whois_dict
        except Exception as e:
            logger.debug(f"Direct WHOIS query failed for {domain}: {e}")

        # Final fallback - try generic whois command
        try:
            logger.debug(f"📋 Trying generic whois command for {domain}")
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                whois_text = result.stdout
                whois_dict = {"raw_whois": whois_text}

                registrar_match = re.search(r"Registrar:\s*(.+)", whois_text, re.IGNORECASE)
                if registrar_match:
                    whois_dict["registrar"] = registrar_match.group(1).strip()

                logger.info(f"📋 Got WHOIS data for {domain} using generic whois")
                return whois_dict
        except Exception as e:
            logger.debug(f"Generic whois failed for {domain}: {e}")

        logger.warning(f"⚠️  All WHOIS methods failed for {domain}")
        return {}


class PhishingAPI:
    """REST API for external phishing reports with multi-API integration and Grinder integration."""

    def __init__(self, db_manager, abuse_detector, api_key: str = None):
        """
        Initialize the Phishing API with authentication support and Grinder integration.

        Args:
            db_manager: Database manager instance
            abuse_detector: Abuse email detector instance
            api_key (str, optional): API key for authentication
        """
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.multi_api_validator = MultiAPIValidator()
        self.grinder_client = GrinderReportClient()
        self.api_key = api_key

        # Initialize Flask app
        self.app = Flask(__name__)
        self.app.config["JSON_SORT_KEYS"] = False
        self.app.api_key = api_key  # Store API key in-app config

        # Configure Flask logging to be less verbose
        flask_logging.getLogger("werkzeug").setLevel(flask_logging.WARNING)

        # Rate limiting
        self.limiter = Limiter(
            app=self.app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour", "10 per minute"],
        )

        self.setup_routes()

        # Test Grinder connection on startup
        if GRINDER_INTEGRATION_ENABLED:
            connection_test = self.grinder_client.test_connection()
            if connection_test["status"] == "success":
                logger.info("🔗 Grinder integration ready for IP reporting")
            else:
                logger.warning(f"⚠️  Grinder connection issue: {connection_test['message']}")

    def setup_routes(self):
        """Setup API routes with authentication and Grinder integration."""

        @self.app.route("/api/v1/report", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key
        def report_phishing():
            """Report a phishing site via API with authentication."""
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
                source = data.get("source", "external_api")
                priority = data.get("priority", "medium")
                description = data.get("description", "")

                # Validate abuse_email if provided
                if abuse_email and not self.abuse_detector.validate_email(abuse_email):
                    return jsonify({"error": "Invalid abuse email format"}), 400

                # Process the report
                result = self.process_phishing_report(
                    url, abuse_email, source, priority, description
                )

                # If successful, also try to report the IP to Grinder
                if result.get("status") in ["created", "updated"] and GRINDER_INTEGRATION_ENABLED:
                    try:
                        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                        ip_address = socket.gethostbyname(domain)

                        detection_context = {
                            "method": "external_report",
                            "domains": [domain],
                            "severity": "high" if priority == "high" else "medium",
                            "threat_level": "high",
                            "keywords": ["external_report"],
                            "api_confidence": 85,  # Default confidence for external reports
                        }

                        grinder_result = self.grinder_client.report_malicious_ip(
                            ip_address, detection_context, confidence=85
                        )

                        if grinder_result.get("status") == "success":
                            result["grinder_report"] = grinder_result
                            logger.info(
                                f"✅ Successfully reported IP {ip_address} to Grinder via API"
                            )
                        else:
                            logger.warning(f"⚠️  Failed to report IP to Grinder: {grinder_result}")
                            result["grinder_report"] = grinder_result

                    except Exception as e:
                        logger.warning(f"⚠️  Could not report IP to Grinder: {e}")
                        result["grinder_report"] = {"status": "error", "message": str(e)}

                return jsonify(result), 200

            except Exception as e:
                logger.error(f"❌ API error in report_phishing: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/multi-scan", methods=["POST"])
        @self.limiter.limit("3 per minute")
        @require_api_key
        def multi_api_scan():
            """Perform multi-API validation scan with authentication."""
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

                # Perform comprehensive scan
                scan_result = self.multi_api_validator.comprehensive_scan(url)

                return jsonify(scan_result), 200

            except Exception as e:
                logger.error(f"❌ API error in multi_api_scan: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/status/<path:url>", methods=["GET"])
        @self.limiter.limit("10 per minute")
        @require_api_key
        def get_report_status(url):
            """Get the status of a reported URL with authentication."""
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
                logger.error(f"❌ API error in get_report_status: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/grinder/test", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key
        def test_grinder_integration():
            """Test Grinder integration with authentication."""
            try:
                if not GRINDER_INTEGRATION_ENABLED:
                    return (
                        jsonify(
                            {"status": "disabled", "message": "Grinder integration not configured"}
                        ),
                        200,
                    )

                connection_test = self.grinder_client.test_connection()

                status_code = 200 if connection_test["status"] == "success" else 500
                return jsonify(connection_test), status_code

            except Exception as e:
                logger.error(f"❌ API error in test_grinder_integration: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/stats", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key
        def get_stats():
            """Get statistics about phishing reports with authentication."""
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
                        "grinder_integration": {
                            "enabled": GRINDER_INTEGRATION_ENABLED,
                            "api_url": GRINDER0X_API_URL if GRINDER_INTEGRATION_ENABLED else None,
                        },
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
                logger.error(f"❌ API error in get_stats: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/health", methods=["GET"])
        def health_check():
            """Health check endpoint (no authentication required)."""
            return (
                jsonify(
                    {
                        "status": "healthy",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "grinder_integration": GRINDER_INTEGRATION_ENABLED,
                        "api_authentication": bool(self.api_key),
                    }
                ),
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
                    logger.info(f"✅ Updated existing phishing report for {url}")
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
                            whois_info = basic_whois_lookup(url)
                            registrar = self.abuse_detector.extract_registrar(whois_info)
                            abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                                domain, whois_info, registrar
                            )
                            abuse_email = abuse_emails[0] if abuse_emails else None
                        except Exception as e:
                            logger.warning(f"⚠️  Failed to auto-detect abuse email for {url}: {e}")

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
                    logger.info(f"✅ Created new phishing report for {url}")
                    return {
                        "status": "created",
                        "message": f"Created new report for {url}",
                        "url": url,
                        "abuse_email": abuse_email,
                        "timestamp": timestamp,
                    }

        except Exception as e:
            logger.error(f"❌ Failed to process phishing report for {url}: {e}")
            return {"status": "error", "message": f"Failed to process report: {str(e)}", "url": url}

    def run(self, host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
        """Run the API server."""
        auth_status = "with API key authentication" if self.api_key else "without authentication"
        grinder_status = (
            "with Grinder integration"
            if GRINDER_INTEGRATION_ENABLED
            else "without Grinder integration"
        )

        logger.info(f"🚀 Starting Enhanced Phishing API server on {host}:{port}")
        logger.info(f"🔐 API Security: {auth_status}")
        logger.info(f"🔗 Threat Intelligence: {grinder_status}")

        if self.api_key:
            logger.info("🔑 API endpoints require Bearer token authentication")
        else:
            logger.warning("⚠️  API running without authentication - not recommended for production")

        self.app.run(host=host, port=port, debug=debug)


# Global variable to store flask app for decorator access
flask_app = None


def upgrade_phishing_db():
    """Upgrade phishing database schema with new multi-API and auto-analysis fields."""
    columns_to_add = [
        ("source", "TEXT DEFAULT 'manual'"),
        ("priority", "TEXT DEFAULT 'medium'"),
        ("description", "TEXT"),
        ("asn", "TEXT"),
        ("asn_abuse_email", "TEXT"),
        ("hosting_provider", "TEXT"),
        ("all_abuse_emails", "TEXT"),
        ("registrar", "TEXT"),
        ("virustotal_result", "TEXT"),
        ("urlvoid_result", "TEXT"),
        ("phishtank_result", "TEXT"),
        ("multi_api_threat_level", "TEXT"),
        ("api_confidence_score", "INTEGER"),
        ("auto_detected", "INTEGER DEFAULT 0"),
        ("auto_analysis_status", "TEXT DEFAULT 'pending'"),
        ("auto_analysis_timestamp", "TIMESTAMP"),
        ("detection_keywords", "TEXT"),
        ("auto_report_eligible", "INTEGER DEFAULT 0"),
        ("requires_manual_review", "INTEGER DEFAULT 0"),
        ("screenshot_taken", "INTEGER DEFAULT 0"),
        ("screenshot_path", "TEXT"),
        ("screenshot_timestamp", "TIMESTAMP"),
    ]

    # New table for tracking abuse reports (ICANN compliance)
    def create_abuse_reports_table():
        """Create table for tracking sent abuse reports"""
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS abuse_reports (
                        id SERIAL PRIMARY KEY,
                        site_url TEXT NOT NULL,
                        report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        recipients TEXT NOT NULL,
                        cc_recipients TEXT,
                        subject TEXT,
                        report_id TEXT UNIQUE,
                        status TEXT DEFAULT 'sent',
                        response_received INTEGER DEFAULT 0,
                        response_date TIMESTAMP,
                        response_content TEXT,
                        sla_deadline TIMESTAMP,
                        icann_compliant INTEGER DEFAULT 1,
                        screenshot_included INTEGER DEFAULT 0,
                        multi_api_results TEXT,
                        confidence_score INTEGER,
                        threat_level TEXT,
                        follow_up_required INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )
            )
            logger.info("✅ Created or verified abuse_reports table")

    create_abuse_reports_table()

    with db_engine.begin() as conn:
        # First check existing columns
        result = conn.execute(
            text(
                """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'phishing_sites'
        """
            )
        )
        existing_columns = {row[0] for row in result}

        # Fix api_confidence_score column if it has wrong type
        if "api_confidence_score" in existing_columns:
            try:
                # Check if it's the wrong numeric type
                result = conn.execute(
                    text(
                        """
                    SELECT data_type, numeric_precision, numeric_scale
                    FROM information_schema.columns
                    WHERE table_name = 'phishing_sites' AND column_name = 'api_confidence_score'
                """
                    )
                )
                col_info = result.fetchone()
                if col_info and col_info[0] == "numeric" and col_info[1] == 5 and col_info[2] == 4:
                    logger.info("🔧 Fixing api_confidence_score column type...")
                    conn.execute(
                        text(
                            "ALTER TABLE phishing_sites ALTER COLUMN api_confidence_score TYPE INTEGER"
                        )
                    )
                    logger.info("✅ Fixed api_confidence_score column type to INTEGER")
            except Exception as e:
                logger.error(f"❌ Failed to fix api_confidence_score column: {e}")

        # Add missing columns
        for column_name, column_def in columns_to_add:
            if column_name not in existing_columns:
                try:
                    conn.execute(
                        text(f"ALTER TABLE phishing_sites ADD COLUMN {column_name} {column_def}")
                    )
                    logger.info(f"✅ Added column: {column_name}")
                except Exception as e:
                    logger.error(f"❌ Failed to add column {column_name}: {e}")
            else:
                logger.debug(f"⏭️  Column {column_name} already exists")

    logger.info(
        "🔧 Upgraded phishing_sites table with multi-API and auto-analysis support if necessary."
    )


class DatabaseManager:
    """Database operations manager with enhanced auto-analysis support."""

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
            logger.info("🗄️  Initialized scan_results table.")

    def init_phishing_db(self):
        """Initialize phishing sites table with enhanced multi-API support."""
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS phishing_sites (
                        id SERIAL PRIMARY KEY,
                        url TEXT UNIQUE,
                        manual_flag INTEGER DEFAULT 0,
                        auto_detected INTEGER DEFAULT 0,
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
                        all_abuse_emails TEXT,
                        virustotal_result TEXT,
                        urlvoid_result TEXT,
                        phishtank_result TEXT,
                        multi_api_threat_level TEXT,
                        api_confidence_score INTEGER,
                        auto_analysis_status TEXT DEFAULT 'pending',
                        auto_analysis_timestamp TIMESTAMP,
                        detection_keywords TEXT,
                        auto_report_eligible INTEGER DEFAULT 0,
                        requires_manual_review INTEGER DEFAULT 0
                    )
                """
                )
            )
            logger.info("🗄️  Initialized phishing_sites table with enhanced multi-API support.")

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
            logger.info("🗄️  Initialized registrar_abuse table.")

    def store_detected_phishing_site(
        self, url: str, keywords: List[str], source: str = "auto_detection"
    ) -> bool:
        """
        Store a newly detected phishing site for auto-analysis.

        Args:
            url (str): Detected phishing URL
            keywords (List[str]): Keywords that triggered detection
            source (str): Detection source

        Returns:
            bool: True if stored successfully, False if already exists
        """
        try:
            with self.engine.begin() as conn:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                keywords_str = ", ".join(keywords)

                # Check if URL already exists
                existing = conn.execute(
                    text("SELECT id, auto_detected FROM phishing_sites WHERE url = :url"),
                    {"url": url},
                ).fetchone()

                if existing:
                    # Update existing record with new detection
                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET auto_detected = 1, last_seen = :timestamp,
                                detection_keywords = :keywords, source = :source,
                                auto_analysis_status = 'pending'
                            WHERE url = :url
                        """
                        ),
                        {
                            "timestamp": timestamp,
                            "keywords": keywords_str,
                            "source": source,
                            "url": url,
                        },
                    )
                    logger.info(f"🔄 Updated existing phishing detection for {url}")
                    return False
                else:
                    # Insert new detection
                    conn.execute(
                        text(
                            """
                            INSERT INTO phishing_sites
                            (url, auto_detected, first_seen, last_seen, detection_keywords,
                             source, auto_analysis_status, priority)
                            VALUES (:url, 1, :timestamp, :timestamp, :keywords,
                                    :source, 'pending', 'high')
                        """
                        ),
                        {
                            "url": url,
                            "timestamp": timestamp,
                            "keywords": keywords_str,
                            "source": source,
                        },
                    )
                    logger.info(f"🚨 NEW PHISHING DETECTION: {url} - Keywords: {keywords_str}")
                    return True

        except Exception as e:
            logger.error(f"❌ Failed to store detected phishing site {url}: {e}")
            return False

    def get_pending_analysis_sites(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get sites pending multi-API analysis.

        This includes:
        - Auto-detected sites with pending analysis
        - Manual sites that haven't been analyzed yet
        - API-imported sites that need analysis

        Args:
            limit (int): Maximum number of sites to return

        Returns:
            List[Dict[str, Any]]: List of sites pending analysis
        """
        try:
            with self.engine.begin() as conn:
                results = conn.execute(
                    text(
                        """
                        SELECT url, detection_keywords, first_seen, source, priority
                        FROM phishing_sites
                        WHERE (
                            (auto_analysis_status = 'pending' AND auto_detected = 1)  -- Auto-detected pending
                            OR (manual_flag = 1 AND auto_analysis_status IS NULL)    -- Manual sites not analyzed
                            OR (source = 'external_api' AND auto_analysis_status IS NULL)  -- API sites not analyzed
                        )
                        AND site_status != 'down'  -- Only analyze sites that are potentially up
                        ORDER BY
                            CASE
                                WHEN manual_flag = 1 THEN 0      -- Manual sites first
                                WHEN source = 'external_api' THEN 1  -- API sites second
                                ELSE 2  -- Auto-detected last
                            END,
                            CASE priority
                                WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 3
                                ELSE 2
                            END,
                            first_seen ASC
                        LIMIT :limit
                    """
                    ),
                    {"limit": limit},
                ).fetchall()

                sites = []
                for row in results:
                    sites.append(
                        {
                            "url": row[0],
                            "keywords": row[1],
                            "first_seen": row[2],
                            "source": row[3],
                            "priority": row[4],
                        }
                    )

                return sites

        except Exception as e:
            logger.error(f"❌ Failed to get pending analysis sites: {e}")
            return []

    def update_analysis_results(
        self, url: str, multi_api_results: Dict[str, Any], auto_report_decision: Dict[str, Any]
    ) -> bool:
        """
        Update site with multi-API analysis results and auto-report decision.

        Args:
            url (str): Site URL
            multi_api_results (Dict[str, Any]): Multi-API scan results
            auto_report_decision (Dict[str, Any]): Auto-report decision data

        Returns:
            bool: True if updated successfully
        """
        try:
            with self.engine.begin() as conn:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET auto_analysis_status = :status,
                            auto_analysis_timestamp = :timestamp,
                            virustotal_result = :vt_result,
                            urlvoid_result = :uv_result,
                            phishtank_result = :pt_result,
                            multi_api_threat_level = :threat_level,
                            api_confidence_score = :confidence_score,
                            auto_report_eligible = :auto_eligible,
                            requires_manual_review = :manual_review,
                            priority = :priority
                        WHERE url = :url
                    """
                    ),
                    {
                        "status": "completed",
                        "timestamp": timestamp,
                        "vt_result": json.dumps(multi_api_results.get("virustotal", {})),
                        "uv_result": json.dumps(multi_api_results.get("urlvoid", {})),
                        "pt_result": json.dumps(multi_api_results.get("phishtank", {})),
                        "threat_level": multi_api_results.get("aggregated_threat_level"),
                        "confidence_score": multi_api_results.get("confidence_score"),
                        "auto_eligible": 1 if auto_report_decision.get("auto_report", False) else 0,
                        "manual_review": (
                            1 if auto_report_decision.get("manual_review", False) else 0
                        ),
                        "priority": auto_report_decision.get("priority", "medium"),
                        "url": url,
                    },
                )

                logger.info(
                    f"✅ Analysis completed for {url}: Threat={multi_api_results.get('aggregated_threat_level')}, Confidence={multi_api_results.get('confidence_score')}%"
                )
                return True

        except Exception as e:
            logger.error(f"❌ Failed to update analysis results for {url}: {e}")
            return False

    def get_auto_report_eligible_sites(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get sites eligible for automatic reporting.

        Args:
            limit (int): Maximum number of sites to return

        Returns:
            List[Dict[str, Any]]: List of sites eligible for auto-reporting
        """
        try:
            with self.engine.begin() as conn:
                results = conn.execute(
                    text(
                        """
                        SELECT url, multi_api_threat_level, api_confidence_score,
                               detection_keywords, auto_analysis_timestamp, priority
                        FROM phishing_sites
                        WHERE auto_report_eligible = 1
                        AND abuse_report_sent = 0
                        AND site_status = 'up'
                        ORDER BY
                            CASE priority
                                WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 3
                                ELSE 2
                            END,
                            api_confidence_score DESC,
                            auto_analysis_timestamp ASC
                        LIMIT :limit
                    """
                    ),
                    {"limit": limit},
                ).fetchall()

                sites = []
                for row in results:
                    sites.append(
                        {
                            "url": row[0],
                            "threat_level": row[1],
                            "confidence_score": row[2],
                            "keywords": row[3],
                            "analysis_timestamp": row[4],
                            "priority": row[5],
                        }
                    )

                return sites

        except Exception as e:
            logger.error(f"❌ Failed to get auto-report eligible sites: {e}")
            return []


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
        logger.debug(f"🔍 Performing enhanced WHOIS lookup for: {domain}")

        # Use a fake detector to access the enhanced WHOIS method
        # In production, you might want to refactor this
        from sqlalchemy import create_engine

        dummy_db_manager = type("DummyDBManager", (), {"engine": create_engine(DATABASE_URL)})()
        detector = EnhancedAbuseEmailDetector(dummy_db_manager)
        data = detector.get_enhanced_whois_info(domain)

        return data
    except Exception as e:
        logger.error(f"❌ Enhanced WHOIS lookup failed for {url}: {e}")
        return {}


class AbuseReportManager:
    """Enhanced abuse report manager with Grinder integration for IP reporting."""

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
        self.multi_api_validator = MultiAPIValidator()
        self.grinder_client = GrinderReportClient()

        # Initialize ICANN compliance services
        self.abuse_contact_validator = AbuseContactValidator(timeout=timeout)
        self.screenshot_service = ScreenshotService(
            screenshots_dir=getattr(settings, "SCREENSHOTS_DIR", None), timeout=timeout
        )
        self.report_tracker = ReportTracker(db_manager.engine)

        if cc_emails is None:
            default_cc = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL2", "")
            self.cc_emails = (
                [email.strip() for email in default_cc.split(",")] if default_cc else []
            )
        else:
            self.cc_emails = cc_emails
        self.timeout = timeout
        self.monitoring_event = monitoring_event

    def report_ip_to_grinder(
        self, ip_address: str, url: str, detection_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Report malicious IP to Grinder with comprehensive context.

        Args:
            ip_address (str): The malicious IP address
            url (str): The phishing URL associated with this IP
            detection_context (Dict[str, Any]): Detection context and metadata

        Returns:
            Dict[str, Any]: Report result
        """
        if not GRINDER_INTEGRATION_ENABLED:
            logger.debug("🔗 Grinder integration disabled, skipping IP report")
            return {"status": "disabled", "message": "Grinder integration not configured"}

        # Enhance detection context with URL-specific information
        enhanced_context = detection_context.copy()
        enhanced_context.update(
            {
                "domains": enhanced_context.get("domains", [])
                + [re.sub(r"^https?://", "", url).strip().split("/")[0]],
                "source_url": url,
                "detection_timestamp": datetime.datetime.now().isoformat(),
            }
        )

        # Determine confidence based on available data
        confidence = enhanced_context.get("api_confidence", 0)
        if confidence == 0:
            # Fallback confidence calculation
            threat_level = enhanced_context.get("threat_level", "").lower()
            if threat_level == "critical":
                confidence = 95
            elif threat_level == "high":
                confidence = 90
            elif threat_level == "medium":
                confidence = 75
            else:
                confidence = 60

        result = self.grinder_client.report_malicious_ip(
            ip_address, enhanced_context, confidence=confidence
        )

        # Log the result
        if result.get("status") == "success":
            logger.info(f"🔗 Successfully reported IP {ip_address} to Grinder for URL {url}")
        elif result.get("status") == "rate_limited":
            logger.warning(f"⏰ Rate limited when reporting IP {ip_address} to Grinder")
        else:
            logger.warning(f"⚠️  Failed to report IP {ip_address} to Grinder: {result}")

        return result

    def get_enhanced_abuse_emails(self, whois_info, domain: str) -> List[str]:
        """Get abuse emails using enhanced detection methods."""
        registrar = self.abuse_detector.extract_registrar(whois_info) or ""

        # Use the enhanced method from abuse_detector
        abuse_emails = self.abuse_detector.get_enhanced_abuse_email(domain, whois_info, registrar)

        # If no emails found, try fallback methods with domain validation
        if not abuse_emails:
            whois_str = str(whois_info)
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
        multi_api_results: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Send an abuse report with enhanced error handling and Grinder IP reporting integration.

        Args:
            abuse_emails (List[str]): List of abuse email addresses
            site_url (str): URL of the phishing site
            whois_str (str): WHOIS information
            attachment_paths (Optional[List[str]]): List of attachment file paths
            test_mode (bool): Whether this is a test report
            multi_api_results (Optional[Dict[str, Any]]): Multi-API validation results

        Returns:
            bool: True if a report was sent successfully, False otherwise
        """
        logger.info(f"🎯 ENTERED send_abuse_report for {site_url}")
        logger.info(f"📧 Abuse emails: {abuse_emails}")
        logger.info(f"🧪 Test mode: {test_mode}")
        logger.info(f"📎 Attachment paths: {attachment_paths}")
        logger.info(f"🔬 Multi-API results: {bool(multi_api_results)}")
        # Get attachments - prioritize parameter, then get all configured attachments
        logger.info("📎 Getting attachment paths...")
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()
        logger.info(f"📎 Final attachment paths: {attachment_paths}")

        logger.info("⚙️ Getting SMTP configuration...")
        smtp_host = getattr(settings, "SMTP_HOST")
        smtp_port = getattr(settings, "SMTP_PORT")
        smtp_user = getattr(settings, "SMTP_USER", "")
        smtp_pass = getattr(settings, "SMTP_PASS", "")
        sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")
        subject = f"{getattr(settings, 'ABUSE_EMAIL_SUBJECT')} for {site_url}"
        logger.info(f"📧 SMTP: {smtp_host}:{smtp_port}, sender: {sender_email}")

        # DEVELOPMENT/TEST PROTECTION: Only send to test email in development
        logger.info("🔍 Checking development/test mode...")
        TEST_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"
        logger.info(f"🧪 Test mode: {test_mode}")

        if not test_mode:
            logger.info("⚡ Not in test mode - checking for development environment...")
            # Check if we're in development/test environment
            is_development = any(test_email in abuse_emails for test_email in [TEST_EMAIL])
            logger.info(f"🔍 Is development: {is_development}")
            logger.info(f"📧 Current abuse emails: {abuse_emails}")

            if is_development:
                # In development: only send to test email
                logger.warning(f"🧪 DEVELOPMENT MODE: Redirecting all emails to test address")
                abuse_emails = [TEST_EMAIL]
            else:
                # In production: SKIP ICANN validation to avoid hanging
                logger.info(
                    "🚀 PRODUCTION MODE: Skipping ICANN email validation to prevent hanging"
                )
                logger.warning(
                    "⏭️  ICANN email validation disabled in production to prevent SMTP timeout hangs"
                )
                # Simply use the emails as-is without validation to prevent hanging
                validated_emails = abuse_emails[:]  # Copy the list
                logger.info(f"✅ Using emails without validation: {validated_emails}")

                if not validated_emails:
                    logger.error("❌ No abuse emails found - cannot send report")
                    return False

                abuse_emails = validated_emails

        # ICANN Compliance: Always capture screenshot (independent of test_mode)
        logger.info("📸 STARTING screenshot capture...")
        screenshot_info = None
        screenshot_included = False
        try:
            if hasattr(self, "screenshot_service") and self.screenshot_service:
                logger.info(f"📸 Calling screenshot_service.capture_screenshot for {site_url}")
                logger.info("🏁 ABOUT TO CALL SCREENSHOT SERVICE - THIS MIGHT HANG!")
                screenshot_info = self.screenshot_service.capture_screenshot(
                    site_url, use_async=False
                )
                logger.info(f"✅ Screenshot service returned: {bool(screenshot_info)}")

                if screenshot_info and screenshot_info.get("success"):
                    logger.info("✅ Screenshot capture successful")
                    if not attachment_paths:
                        attachment_paths = []
                    attachment_paths.append(screenshot_info["screenshot_path"])
                    screenshot_included = True
                    logger.info(f"📸 Screenshot captured: {screenshot_info['filename']}")
                else:
                    logger.warning(
                        f"⚠️  Failed to capture screenshot: {screenshot_info.get('error', 'Unknown error') if screenshot_info else 'Service unavailable'}"
                    )
            else:
                logger.warning("⚠️ No screenshot service available")
        except Exception as e:
            logger.error(f"❌ Screenshot capture error: {e}")

        logger.info("✅ Screenshot section completed")

        # Report IP to Grinder if not in test mode, not in testing mode, and integration is enabled
        grinder_report_result = None
        if not test_mode and not IS_TESTING_MODE and GRINDER_INTEGRATION_ENABLED:
            try:
                domain = re.sub(r"^https?://", "", site_url).strip().split("/")[0]
                ip_address = socket.gethostbyname(domain)

                # Build detection context for Grinder reporting
                detection_context = {
                    "method": "abuse_report_pipeline",
                    "domains": [domain],
                    "severity": "high",
                    "threat_level": (
                        multi_api_results.get("aggregated_threat_level", "high")
                        if multi_api_results
                        else "high"
                    ),
                    "keywords": ["phishing", "abuse_report"],
                    "api_confidence": (
                        multi_api_results.get("confidence_score", 0) if multi_api_results else 0
                    ),
                }

                # Add multi-API context if available
                if multi_api_results:
                    vt_result = multi_api_results.get("virustotal", {})
                    if not vt_result.get("error") and vt_result.get("malicious", 0) > 0:
                        detection_context["virustotal_detections"] = vt_result.get("malicious", 0)
                        detection_context["virustotal_total"] = vt_result.get("total_engines", 0)

                    uv_result = multi_api_results.get("urlvoid", {})
                    if not uv_result.get("error"):
                        detection_context["urlvoid_safety_score"] = uv_result.get(
                            "safety_score", 100
                        )
                        detection_context["urlvoid_blacklists"] = len(
                            uv_result.get("blacklists", [])
                        )

                    pt_result = multi_api_results.get("phishtank", {})
                    if not pt_result.get("error") and pt_result.get("is_phishing"):
                        detection_context["phishtank_verified"] = pt_result.get("verified", False)

                # Re-enable Grinder but with better error handling
                try:
                    grinder_report_result = self.report_ip_to_grinder(
                        ip_address, site_url, detection_context
                    )
                except Exception as grinder_error:
                    logger.warning(f"⚠️  Grinder error (continuing): {grinder_error}")
                    grinder_report_result = {"status": "error", "message": str(grinder_error)}

            except Exception as e:
                logger.warning(f"⚠️  Could not report IP to Grinder during abuse report: {e}")
                grinder_report_result = {"status": "error", "message": str(e)}

        # Prepare attachment filenames for template
        attachment_filenames = (
            [os.path.basename(path) for path in attachment_paths] if attachment_paths else []
        )

        # Prepare CC list with development protection
        if test_mode:
            final_cc = []
        else:
            # Check if we're in development (sending to test email)
            is_development = TEST_EMAIL in abuse_emails

            if is_development:
                # In development: no CC emails to avoid sending to production contacts
                logger.warning(
                    f"🧪 DEVELOPMENT MODE: Clearing CC list to avoid sending to production"
                )
                final_cc = []
            else:
                # In production: use normal CC logic
                final_cc = (
                    self.cc_emails[:]
                    if self.cc_emails
                    else [settings.ABUSE_EMAIL_SENDER]
                    + (settings.DEFAULT_CC_EMAILS.split(",") if settings.DEFAULT_CC_EMAILS else [])
                )

                if sender_email not in final_cc:
                    final_cc.insert(0, sender_email)

                if not self.cc_emails:
                    escalation2 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL2", "")
                    escalation3 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL3", "")
                    for var in [escalation2, escalation3]:
                        if var:
                            for email in var.split(","):
                                email = email.strip()
                                if email and email not in final_cc:
                                    final_cc.append(email)

        # Prepare multi-API results summary for template
        api_summary = ""
        threat_level = "unknown"
        confidence_score = 0

        if multi_api_results:
            threat_level = multi_api_results.get("aggregated_threat_level", "unknown")
            confidence_score = multi_api_results.get("confidence_score", 0)

            # Create human-readable API summary
            api_summary += f"🤖 **Multi-API Threat Assessment**\n"
            api_summary += f"📊 **Threat Level**: {threat_level.upper()}\n"
            api_summary += f"🎯 **Confidence Score**: {confidence_score}%\n\n"

            # VirusTotal results
            vt_result = multi_api_results.get("virustotal", {})
            if not vt_result.get("error"):
                malicious = vt_result.get("malicious", 0)
                total = vt_result.get("total_engines", 0)
                if total > 0:
                    api_summary += (
                        f"🛡️ **VirusTotal**: {malicious}/{total} engines detected threats\n"
                    )

            # URLVoid results
            uv_result = multi_api_results.get("urlvoid", {})
            if not uv_result.get("error"):
                safety_score = uv_result.get("safety_score", 100)
                blacklists = uv_result.get("blacklists", [])
                api_summary += f"🔍 **URLVoid**: Safety score {safety_score}/100"
                if blacklists:
                    api_summary += f", found on {len(blacklists)} blacklist(s)"
                api_summary += "\n"

            # PhishTank results
            pt_result = multi_api_results.get("phishtank", {})
            if not pt_result.get("error"):
                if pt_result.get("is_phishing"):
                    status = (
                        "VERIFIED PHISHING" if pt_result.get("verified") else "Reported as phishing"
                    )
                    api_summary += f"🚨 **PhishTank**: {status}\n"
                else:
                    api_summary += f"✅ **PhishTank**: Not in phishing database\n"

            # Recommendations
            recommendations = multi_api_results.get("recommendations", [])
            if recommendations:
                api_summary += f"\n📋 **Recommendations**:\n"
                for rec in recommendations[:5]:  # Limit to top 5 recommendations
                    api_summary += f"• {rec}\n"

            api_summary += "\n"

        # Add Grinder integration information to API summary
        if grinder_report_result and GRINDER_INTEGRATION_ENABLED:
            api_summary += f"🔗 **Threat Intelligence Integration**\n"
            if grinder_report_result.get("status") == "success":
                categories = grinder_report_result.get("categories", [])
                api_summary += f"✅ **IP reported to threat intelligence system**\n"
                api_summary += f"📊 **Categories**: {', '.join(map(str, categories))}\n"
                api_summary += f"🎯 **Confidence**: {grinder_report_result.get('confidence', 0)}%\n"
            elif grinder_report_result.get("status") == "rate_limited":
                api_summary += f"⏰ **Rate limited** - IP will be reported later\n"
            else:
                api_summary += f"⚠️ **IP reporting failed**: {grinder_report_result.get('message', 'Unknown error')}\n"
            api_summary += "\n"

        # Render email template
        try:
            env_jinja = Environment(
                loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"])
            )
            # Generate temporary report ID for template
            temp_report_id = f"ANISAKYS-{datetime.datetime.now().strftime('%Y%m%d')}-{hash(site_url) % 10000:04d}"

            # Calculate SLA deadline
            from datetime import timedelta

            report_date = datetime.datetime.now()
            sla_deadline = report_date + timedelta(days=2)  # 2 business days

            html_content = env_jinja.get_template("abuse_report.html").render(
                site_url=site_url,
                whois_info=whois_str,
                attachment_filenames=attachment_filenames,
                attachment_count=len(attachment_filenames),
                cc_emails=final_cc,
                timestamp=report_date.strftime("%Y-%m-%d %H:%M:%S"),
                api_summary=api_summary,
                threat_level=threat_level,
                confidence_score=confidence_score,
                multi_api_results=multi_api_results,
                grinder_integration=GRINDER_INTEGRATION_ENABLED,
                grinder_report=grinder_report_result,
                report_id=temp_report_id,
                report_date=report_date.strftime("%Y-%m-%d %H:%M:%S"),
                sla_deadline=sla_deadline.strftime("%Y-%m-%d %H:%M:%S"),
            )
            logger.debug("📧 Rendered email content (first 300 chars): " + html_content[:300])
        except Exception as render_err:
            logger.error(f"❌ Template rendering failed: {render_err}")
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

        logger.info(f"🔄 STARTING EMAIL LOOP for {len(abuse_emails)} recipients")
        for i, primary in enumerate(abuse_emails, 1):
            try:
                logger.info(f"📧 PROCESSING EMAIL {i}/{len(abuse_emails)}: {primary}")

                # Validate email format
                if not self.abuse_detector.validate_email(primary):
                    logger.warning(f"⚠️  Invalid email format, skipping: {primary}")
                    continue

                # Validate email is not from the same domain being reported
                if not self.abuse_detector.validate_abuse_email_domain(primary, site_domain):
                    logger.warning(
                        f"⚠️  Skipping abuse email from same domain being reported: {primary} for {site_url}"
                    )
                    continue

                logger.info(f"📝 CREATING EMAIL MESSAGE for {primary}")
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = primary

                # SECURITY: Never send CCs in testing mode
                # IS_TESTING_MODE is independent of test_mode (which controls screenshots)
                if not test_mode and final_cc and not IS_TESTING_MODE:
                    msg["Cc"] = ", ".join(final_cc)
                    recipients = [primary] + final_cc
                else:
                    recipients = [primary]
                    if IS_TESTING_MODE and final_cc:
                        logger.warning(
                            f"🧪 TESTING MODE: CCs blocked for security - only sending to {primary}"
                        )

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
                                        f"⚠️  Skipping large attachment: {attachment_path} "
                                        f"({len(file_data) / 1024 / 1024:.1f}MB > {max_size / 1024 / 1024}MB)"
                                    )
                                    continue

                                filename = os.path.basename(attachment_path)
                                part = MIMEApplication(file_data, Name=filename)
                                part["Content-Disposition"] = f'attachment; filename="{filename}"'
                                msg.attach(part)
                                attached_files.append(filename)
                                logger.debug(
                                    f"📎 Attached file: {filename} ({len(file_data)} bytes)"
                                )
                            else:
                                logger.warning(
                                    f"⚠️  Attachment file not found or not a file: {attachment_path}"
                                )
                        except Exception as e:
                            logger.error(f"❌ Failed to attach file {attachment_path}: {e}")
                            continue

                # Check total email size
                total_size = len(msg.as_string())
                max_email_size = getattr(settings, "MAX_EMAIL_SIZE_MB", 25) * 1024 * 1024
                if total_size > max_email_size:
                    logger.error(
                        f"❌ Email too large ({total_size / 1024 / 1024:.1f}MB), skipping send to {primary}"
                    )
                    continue

                # Send email
                logger.info(f"📤 ABOUT TO SEND EMAIL to {primary}")
                attachment_info = ""
                api_info = ""
                grinder_info = ""

                if attached_files:
                    if len(attached_files) == 1:
                        attachment_info = f" with attachment {attached_files[0]}"
                    else:
                        attachment_info = (
                            f" with {len(attached_files)} attachments: {', '.join(attached_files)}"
                        )

                if multi_api_results:
                    api_info = f" [Threat: {threat_level}, Confidence: {confidence_score}%]"

                if grinder_report_result and grinder_report_result.get("status") == "success":
                    grinder_info = " [IP reported to threat intelligence]"

                logger.info(f"🌐 CONNECTING TO SMTP {smtp_host}:{smtp_port}")
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    if smtp_user and smtp_pass:
                        logger.info(f"🔐 LOGGING IN TO SMTP SERVER")
                        server.login(smtp_user, smtp_pass)
                    logger.info(f"📬 SENDING EMAIL MESSAGE to {primary}")
                    server.sendmail(sender_email, recipients, msg.as_string())
                    logger.info(f"✅ EMAIL SENT SUCCESSFULLY to {primary}")

                logger.info(
                    f"✅ Enhanced abuse report sent to {primary} for site {site_url}{attachment_info}{api_info}{grinder_info}; "
                    f"CC: {final_cc if final_cc else 'None'}"
                )
                success_count += 1
                logger.info(f"📊 EMAIL SUCCESS COUNT: {success_count}")

            except Exception as e:
                logger.error(f"❌ Failed to send abuse report to {primary}: {e}")
                continue

        # Log final summary before report tracking to identify hang point
        if success_count > 0:
            logger.info(
                f"📊 SUMMARY: Successfully sent enhanced abuse reports to {success_count}/{len(abuse_emails)} recipients for {site_url}"
            )
        else:
            logger.error(
                f"❌ SUMMARY: Failed to send abuse reports to any recipients for {site_url}"
            )

        # ICANN Compliance: Track sent reports - RE-ENABLED WITH BETTER ERROR HANDLING
        if success_count > 0 and not test_mode:
            # Manual database update to mark as reported and prevent infinite loop
            try:
                logger.info(f"🏁 UPDATING DATABASE to mark {site_url} as reported")
                with self.db_manager.engine.begin() as conn:
                    # Get current WHOIS data if we don't have it
                    domain = re.sub(r"^https?://", "", site_url).strip().split("/")[0]

                    # Update with all relevant data including WHOIS and abuse emails
                    result = conn.execute(
                        text(
                            "UPDATE phishing_sites SET reported = 1, abuse_report_sent = 1, "
                            "last_report_sent = CURRENT_TIMESTAMP, abuse_email = :abuse_email "
                            "WHERE url = :url"
                        ),
                        {
                            "url": site_url,
                            "abuse_email": json.dumps(abuse_emails) if abuse_emails else None,
                        },
                    )
                    logger.info(
                        f"✅ Database updated: {result.rowcount} rows affected for {site_url}"
                    )

                # Try to track the report - if this fails, continue anyway since emails were sent
                try:
                    logger.info(f"📋 CREATING REPORT RECORD for tracking")
                    report_record = create_report_record(
                        site_url=site_url,
                        recipients=abuse_emails,
                        subject=subject,
                        cc_recipients=final_cc,
                        multi_api_results=multi_api_results,
                        screenshot_included=screenshot_included,
                    )

                    if self.report_tracker.track_report(report_record):
                        logger.info(f"📋 Tracked abuse report: {report_record.report_id}")
                    else:
                        logger.warning(
                            "⚠️  Failed to track abuse report in database (emails were sent successfully)"
                        )

                except Exception as track_error:
                    logger.warning(
                        f"⚠️  Report tracking failed (emails were sent successfully): {track_error}"
                    )

            except Exception as db_error:
                logger.error(f"❌ CRITICAL: Failed to mark site as reported: {db_error}")
                logger.error("❌ This will cause infinite loop - site will be processed again!")
                import traceback

                traceback.print_exc()

            # try:
            #     logger.info(f"🏁 ABOUT TO MANUALLY UPDATE DATABASE for {site_url}")
            #     with self.db_manager.engine.begin() as conn:
            #         logger.info(f"🔄 EXECUTING UPDATE QUERY for {site_url}")
            #         conn.execute(
            #             text("UPDATE phishing_sites SET reported = 1, abuse_report_sent = 1, last_report_sent = CURRENT_TIMESTAMP WHERE url = :url"),
            #             {"url": site_url}
            #         )
            #         logger.info(f"✅ DATABASE UPDATE COMPLETED for {site_url}")
            #     logger.info(f"✅ Manually marked {site_url} as reported in database")
            # except Exception as e:
            #     logger.error(f"❌ Failed to mark site as reported: {e}")
            #     import traceback
            #     traceback.print_exc()

            # try:
            #     logger.info(f"🏁 ABOUT TO CREATE REPORT RECORD for {site_url}")
            #     report_record = create_report_record(
            #         site_url=site_url,
            #         recipients=abuse_emails,
            #         subject=subject,
            #         cc_recipients=final_cc,
            #         multi_api_results=multi_api_results,
            #         screenshot_included=screenshot_included,
            #     )
            #     logger.info(f"✅ REPORT RECORD CREATED: {report_record.report_id}")
            #
            #     logger.info(f"🏁 ABOUT TO TRACK REPORT - THIS MIGHT HANG!")
            #     if self.report_tracker.track_report(report_record):
            #         logger.info(f"📋 Tracked abuse report: {report_record.report_id}")
            #     else:
            #         logger.warning("⚠️  Failed to track abuse report in database")
            #     logger.info(f"✅ REPORT TRACKING COMPLETED for {site_url}")
            #
            # except Exception as e:
            #     logger.error(f"❌ Failed to track report: {e}")
            #     import traceback
            #     traceback.print_exc()

        logger.info(f"🎉 SEND_ABUSE_REPORT ABOUT TO RETURN: {success_count > 0} for {site_url}")
        return success_count > 0

    def process_overdue_followups(self):
        """Process overdue reports and send follow-up emails every 2 days per ICANN compliance"""
        logger.info("🔄 Starting overdue follow-up processing...")

        try:
            # Get overdue reports from report tracker
            overdue_reports = self.report_tracker.get_overdue_reports()

            if not overdue_reports:
                logger.info("✅ No overdue reports found")
                return

            logger.info(f"📋 Found {len(overdue_reports)} overdue reports requiring follow-up")

            for report in overdue_reports:
                try:
                    site_url = report["site_url"]
                    report_id = report["report_id"]
                    overdue_hours = report.get("overdue_hours", 0)

                    logger.info(
                        f"⚠️  Processing overdue report: {report_id} for {site_url} ({overdue_hours}h overdue)"
                    )

                    # Get original recipients
                    recipients = json.loads(report["recipients"]) if report["recipients"] else []

                    if not recipients:
                        logger.warning(f"⚠️  No recipients found for {report_id}, skipping")
                        continue

                    # Prepare follow-up email subject
                    follow_up_subject = f"FOLLOW-UP: Phishing Report {report_id} - Response Required (ICANN Compliance)"

                    # Add escalation CCs for overdue reports
                    escalation_cc = self.cc_emails.copy() if self.cc_emails else []

                    # Add additional escalation based on how overdue
                    if overdue_hours > 72:  # 3+ days overdue
                        escalation_level3 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL3", "")
                        if escalation_level3:
                            for email in escalation_level3.split(","):
                                email = email.strip()
                                if email and email not in escalation_cc:
                                    escalation_cc.append(email)

                    # Create follow-up whois context
                    followup_context = f"""FOLLOW-UP NOTICE - ICANN COMPLIANCE

Original Report ID: {report_id}
Site: {site_url}
Original Report Date: {report.get('report_date', 'Unknown')}
Hours Overdue: {overdue_hours}

This is a follow-up to our previous phishing report. ICANN policies require registrars to respond to abuse reports within 2 business days. Please provide an update on the status of this case.

If the reported site has been taken down, please confirm. If not, please provide expected timeline for resolution.
"""

                    # Send follow-up (don't create new screenshot to save time)
                    logger.info(f"📤 Sending follow-up report for {site_url}...")

                    success = self._send_followup_email(
                        site_url=site_url,
                        recipients=recipients,
                        escalation_cc=escalation_cc,
                        subject=follow_up_subject,
                        followup_context=followup_context,
                        report_id=report_id,
                    )

                    if success:
                        # Mark as follow-up sent and update status
                        self.report_tracker.mark_report_for_followup(
                            report_id, reason=f"Follow-up sent after {overdue_hours}h overdue"
                        )
                        logger.info(f"✅ Follow-up sent successfully for {report_id}")
                    else:
                        logger.error(f"❌ Failed to send follow-up for {report_id}")

                except Exception as e:
                    logger.error(
                        f"❌ Error processing overdue report {report.get('report_id', 'unknown')}: {e}"
                    )
                    continue

            logger.info(f"🏁 Completed processing {len(overdue_reports)} overdue reports")

        except Exception as e:
            logger.error(f"❌ Error in overdue follow-up processing: {e}")

    def _send_followup_email(
        self,
        site_url: str,
        recipients: List[str],
        escalation_cc: List[str],
        subject: str,
        followup_context: str,
        report_id: str,
    ) -> bool:
        """Send a follow-up email for overdue reports"""
        try:
            # Use simplified email sending for follow-ups
            smtp_host = getattr(settings, "SMTP_HOST", "localhost")
            smtp_port = getattr(settings, "SMTP_PORT", 1125)
            sender_email = getattr(settings, "SENDER_EMAIL", "abuse@example.com")

            success_count = 0

            for recipient in recipients:
                try:
                    msg = MIMEMultipart()
                    msg["From"] = sender_email
                    msg["To"] = recipient
                    msg["Subject"] = subject

                    # Add CCs
                    if escalation_cc:
                        msg["Cc"] = ", ".join(escalation_cc)

                    # Simple text body for follow-up
                    body = f"""Dear Registrar Abuse Team,

{followup_context}

Please respond to this follow-up as required by ICANN policies.

Thank you for your cooperation.

Best regards,
Phishing Detection Team
"""

                    msg.attach(MIMEText(body, "plain"))

                    # Send email
                    with smtplib.SMTP(smtp_host, smtp_port) as server:
                        all_recipients = [recipient] + escalation_cc
                        server.send_message(msg, to_addrs=all_recipients)

                    logger.info(f"✅ Follow-up sent to {recipient}")
                    success_count += 1

                except Exception as e:
                    logger.error(f"❌ Failed to send follow-up to {recipient}: {e}")
                    continue

            return success_count > 0

        except Exception as e:
            logger.error(f"❌ Error in follow-up email sending: {e}")
            return False

    def followup_worker(self):
        """Background worker that checks for overdue reports every 2 hours"""
        logger.info("🚀 Starting follow-up worker for ICANN compliance (checks every 2 hours)...")

        while self.running:
            try:
                # Process overdue reports
                self.process_overdue_followups()

                # Wait 2 hours before next check
                for _ in range(120):  # 120 minutes = 2 hours
                    if not self.running:
                        break
                    time.sleep(60)  # Sleep 1 minute at a time for responsive shutdown

            except Exception as e:
                logger.error(f"❌ Error in follow-up worker: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying on error

    def stop_followup_worker(self):
        """Stop the follow-up worker gracefully"""
        self.running = False
        logger.info("🛑 Follow-up worker stopped")

    def report_phishing_sites(self):
        """Main loop for reporting phishing sites with enhanced multi-API validation and auto-reporting."""
        if self.monitoring_event:
            logger.info(
                "⏳ Waiting for monitoring thread to complete initial cycle before sending abuse reports..."
            )
            self.monitoring_event.wait()
            logger.info("✅ Monitoring thread initial cycle complete. Starting abuse reporting.")

        while True:
            try:
                with self.db_manager.engine.begin() as conn:
                    # Process both manual flags and auto-detected sites
                    sites = conn.execute(
                        text(
                            """
                            SELECT url, abuse_email, last_report_sent, site_status, takedown_date, priority,
                                   manual_flag, auto_detected, auto_report_eligible
                            FROM phishing_sites
                            WHERE (manual_flag = 1 OR auto_report_eligible = 1)
                            AND site_status = 'up'
                            AND abuse_report_sent = 0
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

                    if sites:
                        logger.info(
                            f"📋 Processing {len(sites)} sites for abuse reporting (manual + auto-eligible)"
                        )

                    for row in sites:
                        (
                            url,
                            stored_abuse,
                            last_report_sent,
                            current_status,
                            current_takedown,
                            priority,
                            manual_flag,
                            auto_detected,
                            auto_eligible,
                        ) = row

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

                            # Skip if reported recently (48 hours)
                            if (
                                last_report_time
                                and (current_time - last_report_time).total_seconds() < 172800
                            ):
                                continue

                            # Get multi-API results if available
                            multi_api_results = None
                            try:
                                api_data = conn.execute(
                                    text(
                                        """
                                        SELECT virustotal_result, urlvoid_result, phishtank_result,
                                               multi_api_threat_level, api_confidence_score, detection_keywords
                                        FROM phishing_sites WHERE url = :url
                                    """
                                    ),
                                    {"url": url},
                                ).fetchone()

                                if api_data and api_data[0]:  # Has VirusTotal results
                                    multi_api_results = {
                                        "aggregated_threat_level": api_data[3] or "unknown",
                                        "confidence_score": api_data[4] or 0,
                                        "virustotal": (
                                            json.loads(api_data[0]) if api_data[0] else {}
                                        ),
                                        "urlvoid": json.loads(api_data[1]) if api_data[1] else {},
                                        "phishtank": json.loads(api_data[2]) if api_data[2] else {},
                                        "recommendations": [],
                                    }

                                    # Add detection context for auto-detected sites
                                    if auto_detected and api_data[5]:  # Has detection keywords
                                        multi_api_results["recommendations"].extend(
                                            [
                                                f"🤖 AUTO-DETECTED: Site flagged by automated scanning system",
                                                f"🎯 DETECTION KEYWORDS: {api_data[5]}",
                                                f"📊 THREAT ASSESSMENT: {api_data[3] or 'unknown'} ({api_data[4] or 0}% confidence)",
                                            ]
                                        )

                                    # Add API-based recommendations
                                    vt_result = multi_api_results.get("virustotal", {})
                                    if (
                                        not vt_result.get("error")
                                        and vt_result.get("malicious", 0) > 0
                                    ):
                                        multi_api_results["recommendations"].append(
                                            f"🛡️ VirusTotal: {vt_result['malicious']}/{vt_result.get('total_engines', 0)} engines detected threats"
                                        )

                                    uv_result = multi_api_results.get("urlvoid", {})
                                    if not uv_result.get("error"):
                                        safety_score = uv_result.get("safety_score", 100)
                                        blacklists = uv_result.get("blacklists", [])
                                        if blacklists:
                                            multi_api_results["recommendations"].append(
                                                f"🚫 URLVoid: Found on {len(blacklists)} blacklist(s)"
                                            )
                                        elif safety_score < 70:
                                            multi_api_results["recommendations"].append(
                                                f"⚠️ URLVoid: Low safety score ({safety_score}/100)"
                                            )

                                    pt_result = multi_api_results.get("phishtank", {})
                                    if not pt_result.get("error") and pt_result.get("is_phishing"):
                                        status = (
                                            "VERIFIED PHISHING"
                                            if pt_result.get("verified")
                                            else "Reported as phishing"
                                        )
                                        multi_api_results["recommendations"].append(
                                            f"🚨 PhishTank: {status}"
                                        )

                            except Exception as e:
                                logger.debug(f"Could not load API results for {url}: {e}")

                            # Perform fresh analysis if needed (for manual flags without API data)
                            if manual_flag and not multi_api_results:
                                if AUTO_ANALYSIS_ENABLED:
                                    logger.info(
                                        f"🔍 Performing fresh multi-API analysis for manual flag: {url}"
                                    )
                                    multi_api_results = self.multi_api_validator.comprehensive_scan(
                                        url
                                    )

                                    # Store fresh results
                                    try:
                                        conn.execute(
                                            text(
                                                """
                                                UPDATE phishing_sites
                                                SET virustotal_result = :vt_result,
                                                    urlvoid_result = :uv_result,
                                                    phishtank_result = :pt_result,
                                                    multi_api_threat_level = :threat_level,
                                                    api_confidence_score = :confidence_score
                                                WHERE url = :url
                                            """
                                            ),
                                            {
                                                "vt_result": json.dumps(
                                                    multi_api_results.get("virustotal", {})
                                                ),
                                                "uv_result": json.dumps(
                                                    multi_api_results.get("urlvoid", {})
                                                ),
                                                "pt_result": json.dumps(
                                                    multi_api_results.get("phishtank", {})
                                                ),
                                                "threat_level": multi_api_results.get(
                                                    "aggregated_threat_level"
                                                ),
                                                "confidence_score": multi_api_results.get(
                                                    "confidence_score"
                                                ),
                                                "url": url,
                                            },
                                        )
                                    except Exception as e:
                                        logger.warning(
                                            f"⚠️  Failed to store fresh API results for {url}: {e}"
                                        )

                            whois_info = basic_whois_lookup(url)
                            whois_str = str(whois_info)
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

                            # Log the type of report being processed
                            report_type = []
                            if manual_flag:
                                report_type.append("MANUAL")
                            if auto_detected:
                                report_type.append("AUTO-DETECTED")
                            if auto_eligible:
                                report_type.append("AUTO-ELIGIBLE")

                            logger.info(
                                f"📊 WHOIS data enriched for {url} [{', '.join(report_type)}]"
                            )

                            # Get abuse emails using enhanced detection
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            registrar = self.abuse_detector.extract_registrar(whois_info)
                            abuse_list = []  # Initialize to prevent UnboundLocalError
                            try:
                                abuse_list = (
                                    self.abuse_detector.get_enhanced_abuse_email(
                                        domain, whois_info, registrar
                                    )
                                    or []
                                )  # Ensure it's never None
                            except Exception as e:
                                logger.warning(
                                    f"⚠️  Error getting enhanced abuse email for {domain}: {e}"
                                )
                                abuse_list = []

                            # Enhanced Cloudflare handling
                            if cloudflare_detected and not abuse_list:
                                logger.info(
                                    f"☁️  Cloudflare detected for {url}, no hosting provider found. Using abuse@cloudflare.com only"
                                )
                                abuse_list = ["abuse@cloudflare.com"]
                            elif cloudflare_detected and abuse_list:
                                cloudflare_email = "abuse@cloudflare.com"
                                if cloudflare_email not in abuse_list:
                                    abuse_list.append(cloudflare_email)
                                logger.info(
                                    f"☁️  Cloudflare detected for {url}. Will report to hosting provider first, then Cloudflare: {abuse_list}"
                                )
                            elif cloudflare_detected:
                                logger.info(
                                    f"☁️  Cloudflare detected for {url}, using Cloudflare abuse only"
                                )
                                abuse_list = ["abuse@cloudflare.com"]

                            # Fall back to stored abuse email if no enhanced detection result and different domain
                            if not abuse_list and stored_abuse:
                                if self.abuse_detector.validate_abuse_email_domain(
                                    stored_abuse, domain
                                ):
                                    abuse_list = [stored_abuse]
                                else:
                                    logger.warning(
                                        f"⚠️  Stored abuse email {stored_abuse} is same domain as reported site {url}, skipping"
                                    )

                            if abuse_list:
                                attachment_paths = AttachmentConfig.get_all_attachments()

                                # Enhanced logging for auto-reports
                                if auto_eligible:
                                    logger.info(f"🚨 SENDING AUTO-REPORT: {url} to {abuse_list[0]}")
                                else:
                                    logger.info(
                                        f"📧 SENDING MANUAL REPORT: {url} to {abuse_list[0]}"
                                    )

                                if self.send_abuse_report(
                                    abuse_list,
                                    url,
                                    whois_str,
                                    attachment_paths=attachment_paths,
                                    multi_api_results=multi_api_results,
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
                                            "abuse_email": json.dumps(
                                                abuse_list
                                            ),  # Store as JSON list
                                            "timestamp": timestamp,
                                            "url": url,
                                        },
                                    )

                                    # Enhanced success logging
                                    if auto_eligible:
                                        logger.info(f"✅ AUTO-REPORT SUCCESS: {url}")
                                    else:
                                        logger.info(f"✅ MANUAL REPORT SUCCESS: {url}")
                            else:
                                logger.warning(
                                    f"❌ No valid abuse emails found for {url} - all emails were same domain or invalid"
                                )
                                # Mark abuse_report_sent=1 to avoid infinite loop - we tried but couldn't find valid emails
                                conn.execute(
                                    text(
                                        "UPDATE phishing_sites SET abuse_report_sent=1 WHERE url=:url"
                                    ),
                                    {"url": url},
                                )

                        except Exception as e:
                            logger.error(f"❌ Error processing report for {url}: {e}")

            except Exception as e:
                logger.error(f"❌ Error in enhanced abuse reporting loop: {e}")

            time.sleep(settings.REPORT_INTERVAL)

    def process_manual_reports(self, attachment_paths: Optional[List[str]] = None):
        """Process manual reports that haven't been processed yet with multi-API validation."""
        logger.info("🔍 STARTING process_manual_reports method")

        # If no specific attachments provided, get all configured attachments
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()
            logger.info(
                f"📎 Using default attachments: {len(attachment_paths) if attachment_paths else 0} files"
            )
        else:
            logger.info(f"📎 Using provided attachments: {len(attachment_paths)} files")

        logger.info("🗄️ Opening database connection...")
        with self.db_manager.engine.begin() as conn:
            logger.info("🔍 Querying for manual sites to process...")
            sites = conn.execute(
                text(
                    """
                    SELECT url, reported, abuse_report_sent, abuse_email, priority, site_status, takedown_date
                    FROM phishing_sites
                    WHERE manual_flag = 1 AND reported = 0 AND site_status = 'up'
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

            logger.info(f"📋 Found {len(sites)} sites to process")

            if not sites:
                logger.info("✅ No manual sites to process - all done!")
                logger.info("🚪 EXITING process_manual_reports method normally")
                return

            for i, row in enumerate(sites, 1):
                (
                    url,
                    reported,
                    abuse_report_sent,
                    stored_abuse,
                    priority,
                    site_status,
                    takedown_date,
                ) = row[:7]
                logger.info(f"🔄 Processing site {i}/{len(sites)}: {url}")
                logger.info(
                    f"   📊 Status: site_status={site_status}, reported={reported}, abuse_sent={abuse_report_sent}"
                )
                logger.info(f"   📊 Priority: {priority}, takedown_date: {takedown_date}")

                try:
                    # Perform multi-API validation if API keys are configured
                    multi_api_results = None
                    if AUTO_ANALYSIS_ENABLED:
                        logger.info(f"🔍 Starting multi-API validation for {url}")
                        multi_api_results = self.multi_api_validator.comprehensive_scan(url)
                        logger.info(f"✅ Multi-API validation complete for {url}")

                        # Store API results in a database
                        logger.info(f"💾 Storing API results for {url}")
                        try:
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET virustotal_result = :vt_result,
                                        urlvoid_result = :uv_result,
                                        phishtank_result = :pt_result,
                                        multi_api_threat_level = :threat_level,
                                        api_confidence_score = :confidence_score
                                    WHERE url = :url
                                """
                                ),
                                {
                                    "vt_result": json.dumps(
                                        multi_api_results.get("virustotal", {})
                                    ),
                                    "uv_result": json.dumps(multi_api_results.get("urlvoid", {})),
                                    "pt_result": json.dumps(multi_api_results.get("phishtank", {})),
                                    "threat_level": multi_api_results.get(
                                        "aggregated_threat_level"
                                    ),
                                    "confidence_score": multi_api_results.get("confidence_score"),
                                    "url": url,
                                },
                            )
                        except Exception as e:
                            logger.warning(f"⚠️  Failed to store API results for {url}: {e}")

                    logger.info(f"🔍 Starting WHOIS lookup for {url}")
                    whois_info = basic_whois_lookup(url)
                    logger.info(f"✅ WHOIS lookup complete for {url}")
                    whois_str = str(whois_info)
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    logger.info(f"🌐 Getting IP info for domain: {domain}")
                    resolved_ip, asn_provider = get_ip_info(domain)
                    cloudflare_detected = resolved_ip and is_cloudflare_ip(resolved_ip)
                    logger.info(f"✅ IP info complete: {resolved_ip}, CF: {cloudflare_detected}")

                    # If we can't resolve the IP, the site is likely down
                    if not resolved_ip:
                        logger.warning(
                            f"⚠️  Cannot resolve IP for {domain} - site appears to be down"
                        )
                        logger.info(f"📝 Updating site status to 'down' for {url}")
                        conn.execute(
                            text(
                                "UPDATE phishing_sites SET site_status = 'down', takedown_date = CURRENT_TIMESTAMP WHERE url = :url"
                            ),
                            {"url": url},
                        )
                        logger.info(f"✅ Site marked as down: {url}")
                        continue  # Skip to next site

                    # Get registrar from WHOIS data
                    registrar = self.abuse_detector.extract_registrar(whois_info) or ""

                    # Get abuse emails using enhanced detection BEFORE UPDATE
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    logger.info(f"🏢 Extracting registrar info for {url}")
                    logger.info(f"📧 Getting enhanced abuse emails for {domain}")
                    abuse_list = []  # Initialize to prevent UnboundLocalError
                    try:
                        abuse_list = (
                            self.abuse_detector.get_enhanced_abuse_email(
                                domain, whois_info, registrar
                            )
                            or []
                        )  # Ensure it's never None
                    except Exception as e:
                        logger.warning(f"⚠️  Error getting enhanced abuse email for {domain}: {e}")
                        abuse_list = []

                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET whois_info=:whois_str, last_seen=:timestamp, reported=1,
                                resolved_ip=:resolved_ip, asn_provider=:asn_provider, is_cloudflare=:is_cloudflare,
                                registrar=:registrar, abuse_email=:abuse_email
                            WHERE url=:url
                        """
                        ),
                        {
                            "whois_str": (
                                json.dumps(serialize_for_json(whois_info)) if whois_info else None
                            ),
                            "timestamp": timestamp,
                            "resolved_ip": resolved_ip,
                            "asn_provider": asn_provider,
                            "is_cloudflare": 1 if cloudflare_detected else 0,
                            "registrar": registrar,
                            "abuse_email": json.dumps(abuse_list) if abuse_list else None,
                            "url": url,
                        },
                    )
                    logger.info(f"📊 Manually processed WHOIS data for {url}")
                    logger.info(
                        f"✅ Found {len(abuse_list) if abuse_list else 0} abuse emails: {abuse_list}"
                    )

                    # Additional check: if Cloudflare detected, enhance the logic
                    if cloudflare_detected and not abuse_list:
                        logger.info(
                            f"☁️  Cloudflare detected for {url}, no hosting provider found. Using abuse@cloudflare.com only"
                        )
                        abuse_list = ["abuse@cloudflare.com"]
                    elif cloudflare_detected and abuse_list:
                        # Ensure Cloudflare is in the list but as a secondary option
                        cloudflare_email = "abuse@cloudflare.com"
                        if cloudflare_email not in abuse_list:
                            abuse_list.append(cloudflare_email)
                        logger.info(
                            f"☁️  Cloudflare detected for {url}. Will report to hosting provider first, then Cloudflare: {abuse_list}"
                        )
                    elif cloudflare_detected:
                        # Pure Cloudflare case
                        logger.info(
                            f"☁️  Cloudflare detected for {url}, using Cloudflare abuse only"
                        )
                        abuse_list = ["abuse@cloudflare.com"]

                    # Fall back to stored abuse email if no enhanced detection result and different domain
                    if not abuse_list and stored_abuse:
                        if self.abuse_detector.validate_abuse_email_domain(stored_abuse, domain):
                            abuse_list = [stored_abuse]
                        else:
                            logger.warning(
                                f"⚠️  Stored abuse email {stored_abuse} is same domain as reported site {url}, skipping"
                            )

                    if abuse_list and abuse_report_sent == 0:
                        logger.info(f"📧 SENDING ABUSE REPORT for {url} to {abuse_list}")
                        logger.info(
                            f"🏁 ABOUT TO CALL send_abuse_report - THIS IS WHERE IT MIGHT HANG!"
                        )

                        report_result = self.send_abuse_report(
                            abuse_list,
                            url,
                            whois_str,
                            attachment_paths=attachment_paths,
                            multi_api_results=multi_api_results,
                        )
                        logger.info(f"🎉 SEND_ABUSE_REPORT RETURNED: {report_result} for {url}")

                        if report_result:
                            # Update handled by report_tracker.track_report() - no need to duplicate here
                            logger.info(f"✅ Abuse report sent successfully for {url}")
                            pass
                    elif not abuse_list:
                        logger.warning(
                            f"❌ No valid abuse emails found for {url} - all emails were same domain or invalid"
                        )
                        # Mark as reported to avoid infinite loop - we tried but couldn't find valid emails
                        conn.execute(
                            text("UPDATE phishing_sites SET reported=1 WHERE url=:url"),
                            {"url": url},
                        )

                except Exception as e:
                    logger.error(f"❌ WHOIS query failed for {url}: {e}")
                    logger.info(f"⚠️  Continuing to next site after error for {url}")

                logger.info(f"✅ Finished processing site {i}/{len(sites)}: {url}")

        logger.info("🏁 Completed ALL manual reports processing with multi-API validation.")
        logger.info("🚪 EXITING process_manual_reports method after processing all sites")

    def send_test_report(self, test_email: str, attachment_paths: Optional[List[str]] = None):
        """Send a test abuse report with multi-API results."""
        test_whois_str = "This is a test WHOIS information for a test phishing site."
        test_site_url = "https://test.phishing-site.com"
        test_abuse_emails = [test_email]

        # If no specific attachments provided, get all configured attachments
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()

        # Generate test multi-API results
        test_multi_api_results = {
            "url": test_site_url,
            "aggregated_threat_level": "high",
            "confidence_score": 85,
            "virustotal": {"malicious": 5, "total_engines": 70, "threat_level": "high"},
            "urlvoid": {
                "safety_score": 25,
                "blacklists": ["malware-patrol", "phishtank"],
                "threat_level": "high",
            },
            "phishtank": {"is_phishing": True, "verified": True, "threat_level": "critical"},
            "recommendations": [
                "🚨 CRITICAL: URL verified as phishing by PhishTank community",
                "🛡️ VirusTotal: 5/70 engines flagged as malicious",
                "🚫 Found on 2 blacklist(s): malware-patrol, phishtank",
            ],
        }

        logger.info("📧 Sending test abuse report with multi-API validation results...")

        if self.send_abuse_report(
            test_abuse_emails,
            test_site_url,
            test_whois_str,
            attachment_paths=attachment_paths,
            test_mode=True,
            multi_api_results=test_multi_api_results,
        ):
            logger.info("✅ Test report with multi-API results sent successfully.")
        else:
            logger.error("❌ Failed to send test report.")


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
                                    f"🔄 Updated {url}: site_status='{new_status}', takedown_date='{new_takedown}'"
                                )

                        except Exception as e:
                            logger.error(f"❌ Error checking status for {url}: {e}")
                            continue

                # Signal completion of first cycle
                if not first_cycle_done:
                    first_cycle_done = True
                    if self.monitoring_event and not self.monitoring_event.is_set():
                        logger.info(
                            "✅ Takedown monitor initial cycle complete, setting monitoring event."
                        )
                        self.monitoring_event.set()

            except Exception as e:
                logger.error(f"❌ Error in monitoring loop: {e}")

            time.sleep(self.check_interval)


def save_offset(offset: int):
    """Save current offset to file."""
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))
    logger.debug(f"💾 Offset saved as: {offset}")


def get_offset() -> int:
    """Get the current offset from a file."""
    try:
        with open(OFFSET_FILE, "r") as f:
            offset_str = f.read().strip()
            offset = int(float(offset_str))
            logger.debug(f"📖 Retrieved offset: {offset}")
            return offset
    except Exception as ex:
        logger.error(f"❌ Error getting offset from {OFFSET_FILE}: {ex}")
        return 0


class AutoPhishingAnalyzer:
    """
    Automated phishing analysis engine with multi-API integration and intelligent auto-reporting.

    This class handles the automatic analysis of detected phishing sites using multiple APIs
    and makes intelligent decisions about auto-reporting based on threat levels and confidence scores.
    """

    def __init__(self, db_manager: DatabaseManager, abuse_detector: EnhancedAbuseEmailDetector):
        """
        Initialize the auto-analyzer.

        Args:
            db_manager (DatabaseManager): Database manager instance
            abuse_detector (EnhancedAbuseEmailDetector): Abuse email detector instance
        """
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.multi_api_validator = MultiAPIValidator()
        self.running = False

    def start_analysis_worker(self):
        """Start the background analysis worker thread."""
        if not self.running:
            self.running = True
            analysis_thread = threading.Thread(target=self._analysis_worker_loop, daemon=True)
            analysis_thread.start()
            logger.info("🤖 Auto-analysis worker started")

    def stop_analysis_worker(self):
        """Stop the background analysis worker."""
        self.running = False
        logger.info("🛑 Auto-analysis worker stopped")

    def _analysis_worker_loop(self):
        """Main loop for the analysis worker."""
        logger.info("🔄 Auto-analysis worker loop started")

        while self.running:
            try:
                # Get pending sites for analysis
                pending_sites = self.db_manager.get_pending_analysis_sites(limit=5)

                if pending_sites:
                    logger.info(f"🔍 Processing {len(pending_sites)} sites for auto-analysis")

                    for site_info in pending_sites:
                        if not self.running:
                            break

                        try:
                            self.analyze_detected_site(
                                site_info["url"],
                                site_info["keywords"].split(", ") if site_info["keywords"] else [],
                            )

                            # Small delay between analyses to avoid overwhelming APIs
                            time.sleep(AUTO_ANALYSIS_DELAY_SECONDS)

                        except Exception as e:
                            logger.error(f"❌ Error analyzing site {site_info['url']}: {e}")
                            continue
                else:
                    # No, pending sites, wait longer
                    time.sleep(60)

            except Exception as e:
                logger.error(f"❌ Error in auto-analysis worker loop: {e}")
                time.sleep(30)

    def analyze_detected_site(self, url: str, detection_keywords: List[str]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a detected phishing site.

        Args:
            url (str): URL to analyze
            detection_keywords (List[str]): Keywords that triggered detection

        Returns:
            Dict[str, Any]: Analysis results and auto-report decision
        """
        logger.info(f"🔍 Starting comprehensive analysis for: {url}")

        try:
            # Get site information to determine source and flags
            site_info = None
            try:
                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text(
                            "SELECT source, manual_flag, auto_detected FROM phishing_sites WHERE url = :url"
                        ),
                        {"url": url},
                    ).fetchone()
                    if result:
                        site_info = {
                            "source": result[0],
                            "manual_flag": result[1],
                            "auto_detected": result[2],
                        }
            except Exception as e:
                logger.warning(f"Could not get site info for {url}: {e}")
                site_info = {"source": "unknown", "manual_flag": 0, "auto_detected": 1}

            # Perform multi-API scan
            if AUTO_ANALYSIS_ENABLED:
                multi_api_results = self.multi_api_validator.comprehensive_scan(url)
            else:
                logger.warning("⚠️  Auto multi-API scan disabled or no API keys configured")
                multi_api_results = {
                    "aggregated_threat_level": "unknown",
                    "confidence_score": 0,
                    "virustotal": {"error": "API key not configured"},
                    "urlvoid": {"error": "API key not configured"},
                    "phishtank": {"error": "API key not configured"},
                }

            # Make auto-report decision based on source
            auto_report_decision = self._make_auto_report_decision(
                multi_api_results, detection_keywords, site_info
            )

            # Update database with results
            self.db_manager.update_analysis_results(url, multi_api_results, auto_report_decision)

            # Log decision
            threat_level = multi_api_results.get("aggregated_threat_level", "unknown")
            confidence = multi_api_results.get("confidence_score", 0)

            if auto_report_decision.get("auto_report", False):
                logger.info(
                    f"🚨 AUTO-REPORT ELIGIBLE: {url} - "
                    f"Threat: {threat_level}, Confidence: {confidence}%, "
                    f"Keywords: {', '.join(detection_keywords)}"
                )
            elif auto_report_decision.get("manual_review", False):
                logger.info(
                    f"👀 MANUAL REVIEW REQUIRED: {url} - "
                    f"Threat: {threat_level}, Confidence: {confidence}%, "
                    f"Keywords: {', '.join(detection_keywords)}"
                )
            else:
                logger.info(
                    f"✅ ANALYSIS COMPLETE: {url} - "
                    f"Threat: {threat_level}, Confidence: {confidence}% - No action required"
                )

            return {
                "url": url,
                "multi_api_results": multi_api_results,
                "auto_report_decision": auto_report_decision,
                "analysis_timestamp": datetime.datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"❌ Failed to analyze detected site {url}: {e}")
            return {"error": str(e), "url": url}

    @staticmethod
    def _make_auto_report_decision(
        multi_api_results: Dict[str, Any],
        detection_keywords: List[str],
        site_info: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Make intelligent auto-report decision based on analysis results and site source.

        IMPORTANT: Auto-detected sites should NEVER trigger automatic reports.
        Only manual flagged sites and API-imported sites should be eligible for auto-reporting.

        Args:
            multi_api_results (Dict[str, Any]): Multi-API scan results
            detection_keywords (List[str]): Keywords that triggered detection
            site_info (Dict[str, Any], optional): Site source and flag information

        Returns:
            Dict[str, Any]: Auto-report decision with reasoning
        """
        threat_level = multi_api_results.get("aggregated_threat_level", "unknown")
        confidence_score = multi_api_results.get("confidence_score", 0)

        decision = {
            "auto_report": False,
            "manual_review": False,
            "priority": "medium",
            "reasoning": [],
        }

        # CRITICAL: Block auto-reporting for automatically detected sites
        if site_info and site_info.get("auto_detected") == 1 and not site_info.get("manual_flag"):
            decision["auto_report"] = False
            decision["manual_review"] = True  # Always require manual review for auto-detections
            decision["reasoning"].append(
                "Auto-detected sites require manual review - no automatic reporting"
            )
            return decision

        # Only allow auto-reporting for manual flags or API imports
        if not site_info or not (
            site_info.get("manual_flag") == 1 or site_info.get("source") == "external_api"
        ):
            decision["manual_review"] = True
            decision["reasoning"].append("Only manual or API sites eligible for auto-reporting")
            return decision

        # Critical threat level from PhishTank verified
        pt_result = multi_api_results.get("phishtank", {})
        if pt_result.get("is_phishing") and pt_result.get("verified"):
            decision["auto_report"] = True
            decision["priority"] = "high"
            decision["reasoning"].append("PhishTank verified phishing site")

        # High threat level with high confidence
        elif (
            threat_level in ["critical", "high"]
            and confidence_score >= AUTO_REPORT_THRESHOLD_CONFIDENCE
        ):
            decision["auto_report"] = True
            decision["priority"] = "high" if threat_level == "critical" else "medium"
            decision["reasoning"].append(
                f"High threat level ({threat_level}) with {confidence_score}% confidence"
            )

        # VirusTotal multiple detections
        vt_result = multi_api_results.get("virustotal", {})
        if not vt_result.get("error"):
            malicious_count = vt_result.get("malicious", 0)
            total_engines = vt_result.get("total_engines", 0)

            if malicious_count >= 5 and confidence_score >= AUTO_REPORT_THRESHOLD_CONFIDENCE:
                decision["auto_report"] = True
                decision["priority"] = "high"
                decision["reasoning"].append(
                    f"VirusTotal: {malicious_count}/{total_engines} engines detected threats"
                )
            elif malicious_count >= 2 and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE:
                decision["manual_review"] = True
                decision["reasoning"].append(
                    f"VirusTotal: {malicious_count}/{total_engines} engines detected threats (manual review)"
                )

        # URLVoid blacklist detections
        uv_result = multi_api_results.get("urlvoid", {})
        if not uv_result.get("error"):
            blacklists = uv_result.get("blacklists", [])
            safety_score = uv_result.get("safety_score", 100)

            if len(blacklists) >= 3 and confidence_score >= AUTO_REPORT_THRESHOLD_CONFIDENCE:
                decision["auto_report"] = True
                decision["priority"] = "high"
                decision["reasoning"].append(f"URLVoid: Found on {len(blacklists)} blacklists")
            elif (
                len(blacklists) >= 1 or safety_score <= 30
            ) and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE:
                decision["manual_review"] = True
                decision["reasoning"].append(
                    f"URLVoid: Safety score {safety_score}/100, {len(blacklists)} blacklists"
                )

        # High-value keywords detected
        high_value_keywords = [
            "login",
            "password",
            "account",
            "verify",
            "suspend",
            "billing",
            "payment",
        ]
        matching_hvk = [
            kw
            for kw in detection_keywords
            if kw.lower() in [hvk.lower() for hvk in high_value_keywords]
        ]

        if len(matching_hvk) >= 2 and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE:
            if not decision["auto_report"]:
                decision["manual_review"] = True
            decision["reasoning"].append(f"High-value keywords detected: {', '.join(matching_hvk)}")

        # Medium threat with reasonable confidence needs manual review
        if (
            threat_level in ["medium", "high"]
            and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE
            and not decision["auto_report"]
        ):
            decision["manual_review"] = True
            decision["reasoning"].append(
                f"Medium/High threat level with {confidence_score}% confidence"
            )

        # Default reasoning if none set
        if not decision["reasoning"]:
            decision["reasoning"].append(
                f"Low threat level ({threat_level}) or insufficient confidence ({confidence_score}%)"
            )

        return decision

    def process_auto_reports(self, report_manager) -> int:
        """
        Process sites eligible for automatic reporting.

        Args:
            report_manager: AbuseReportManager instance

        Returns:
            int: Number of sites processed for auto-reporting
        """
        try:
            eligible_sites = self.db_manager.get_auto_report_eligible_sites(limit=5)

            if not eligible_sites:
                return 0

            logger.info(f"📋 Processing {len(eligible_sites)} sites for auto-reporting")
            processed_count = 0

            for site_info in eligible_sites:
                try:
                    url = site_info["url"]
                    threat_level = site_info["threat_level"]
                    confidence = site_info["confidence_score"]
                    keywords = site_info["keywords"]

                    logger.info(
                        f"🚨 Auto-reporting: {url} - "
                        f"Threat: {threat_level}, Confidence: {confidence}%, "
                        f"Keywords: {keywords}"
                    )

                    # Get WHOIS and abuse emails
                    whois_info = basic_whois_lookup(url)
                    whois_str = str(whois_info)
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    registrar = self.abuse_detector.extract_registrar(whois_info)
                    abuse_list = self.abuse_detector.get_enhanced_abuse_email(
                        domain, whois_info, registrar
                    )

                    if not abuse_list:
                        logger.warning(
                            f"⚠️  No valid abuse emails found for {url}, marking for manual review"
                        )
                        # Mark for manual review instead
                        with self.db_manager.engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET auto_report_eligible = 0, requires_manual_review = 1
                                    WHERE url = :url
                                """
                                ),
                                {"url": url},
                            )
                        continue

                    # Get enhanced multi-API results for a report
                    with self.db_manager.engine.begin() as conn:
                        api_results = conn.execute(
                            text(
                                """
                                SELECT virustotal_result, urlvoid_result, phishtank_result,
                                       multi_api_threat_level, api_confidence_score
                                FROM phishing_sites WHERE url = :url
                            """
                            ),
                            {"url": url},
                        ).fetchone()

                    if api_results:
                        enhanced_results = {
                            "aggregated_threat_level": api_results[3],
                            "confidence_score": api_results[4],
                            "virustotal": json.loads(api_results[0]) if api_results[0] else {},
                            "urlvoid": json.loads(api_results[1]) if api_results[1] else {},
                            "phishtank": json.loads(api_results[2]) if api_results[2] else {},
                            "recommendations": [
                                f"🤖 AUTO-DETECTED: Site flagged by automated system",
                                f"🎯 DETECTION KEYWORDS: {keywords}",
                                f"📊 THREAT ASSESSMENT: {threat_level.upper()} ({confidence}% confidence)",
                            ],
                        }
                    else:
                        enhanced_results = None

                    # Send an abuse report with enhanced data
                    attachment_paths = AttachmentConfig.get_all_attachments()
                    success = report_manager.send_abuse_report(
                        abuse_list,
                        url,
                        whois_str,
                        attachment_paths=attachment_paths,
                        multi_api_results=enhanced_results,
                    )

                    if success:
                        # Update database to mark as reported
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with self.db_manager.engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET abuse_report_sent = 1,
                                        last_report_sent = :timestamp,
                                        abuse_email = :abuse_email,
                                        reported = 1
                                    WHERE url = :url
                                """
                                ),
                                {"timestamp": timestamp, "abuse_email": abuse_list[0], "url": url},
                            )

                        logger.info(f"✅ AUTO-REPORT SENT: {url} to {abuse_list[0]}")
                        processed_count += 1
                    else:
                        logger.error(f"❌ AUTO-REPORT FAILED: {url}")

                except Exception as e:
                    logger.error(f"❌ Error processing auto-report: {e}")
                    continue

            if processed_count > 0:
                logger.info(
                    f"📊 AUTO-REPORT SUMMARY: {processed_count}/{len(eligible_sites)} sites reported successfully"
                )

            return processed_count

        except Exception as e:
            logger.error(f"❌ Error in process_auto_reports: {e}")
            return 0


def get_ip_info(domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Get IP address and ASN provider information for a domain."""
    try:
        resolved_ip = socket.gethostbyname(domain)
        obj = IPWhois(resolved_ip)
        res = obj.lookup_rdap(depth=1)
        asn_provider = res.get("network", {}).get("name", "")
        return resolved_ip, asn_provider
    except Exception as e:
        logger.error(f"❌ Failed to get IP info for {domain}: {e}")
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
        logger.error(f"❌ Error checking Cloudflare IP: {e}")
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
            logger.info(f"💾 Stored scan result for {url}")
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
            logger.info(f"💾 Updated scan result response code for {url}")

    @staticmethod
    def log_positive_result(url: str, found_keywords: List[str]) -> None:
        """Log a positive phishing detection result."""
        log_file = "positive_report.txt"
        entry = (
            f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {url}: {', '.join(found_keywords)}\n"
        )

        try:
            with open(log_file, "r+") as f:
                if url in f.read():
                    logger.debug(f"⏭️ Duplicate entry skipped: {url}")
                    return
                f.write(entry)
        except FileNotFoundError:
            with open(log_file, "w") as f:
                f.write(entry)

        logger.info(f"🎯 Logged phishing match: {url}")

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
                logger.error(f"❌ GET request failed for {url}: {e}")
                new_status = "down"
                new_takedown = current_takedown if current_status == "down" else timestamp

        return new_status, new_takedown


def generate_queries_file(keywords: List[str], domains: List[str]) -> None:
    """Generate a query file with all keyword/domain combinations."""
    total = 0
    with open(QUERIES_FILE, "w") as f:
        for i in range(1, len(keywords) + 1):
            for p in permutations(keywords, i):
                for q in ["-".join(p), "".join(p)]:
                    for d in domains:
                        f.write(f"{q}{d}\n")
                        total += 1
    logger.info(f"📄 Generated full query list with {total} lines.")


class PhishingScanner:
    """Enhanced phishing scanner with optional auto-analysis integration."""

    def __init__(
        self, timeout: int, keywords: List[str], domains: List[str], allowed_sites: List[str], args
    ):
        self.timeout = timeout
        self.keywords = keywords
        self.domains = domains
        self.allowed_sites = allowed_sites
        self.batch_size = DynamicBatchConfig.get_batch_size()

        # These are always initialized for core functionality
        self.multi_api_validator = MultiAPIValidator()
        self.db_manager = None

        # Initialize a database for auto-analysis only if enabled
        if AUTO_ANALYSIS_ENABLED:
            try:
                self.db_manager = DatabaseManager(db_url=DATABASE_URL)
                logger.debug("🗄️  Database manager initialized for auto-analysis")
            except Exception as e:
                logger.warning(f"⚠️  Could not initialize database for auto-analysis: {e}")
                self.db_manager = None
        else:
            logger.debug("ℹ️  Auto-analysis disabled, skipping database manager for scanner")

        if args.test_report:
            logger.info("🧪 Test report mode active: Skipping queries file generation.")
            self.total_queries = 0
        else:
            if not args.threads_only:
                if args.regen_queries or not os.path.exists(QUERIES_FILE):
                    logger.info(f"📄 Generating queries file {QUERIES_FILE}...")
                    generate_queries_file(self.keywords, self.domains)
                else:
                    logger.info(f"📄 Using existing {QUERIES_FILE} file.")
            else:
                logger.info("🧵 Threads-only mode: Skipping queries file generation.")

            try:
                with open(QUERIES_FILE, "r") as f:
                    self.total_queries = sum(1 for _ in f)
                logger.info(f"📊 Total queries in file: {self.total_queries}")
            except Exception as ex:
                logger.error(f"❌ Error counting total queries: {ex}")
                self.total_queries = 0

    def get_dynamic_target_sites(self) -> List[str]:
        """Get the next batch of target sites from a query file."""
        offset = get_offset()
        batch = []
        logger.debug(f"📖 Getting targets from offset {offset}, batch_size={self.batch_size}")

        # If offset is beyond file size, reset to beginning for continuous scanning
        if 0 < self.total_queries <= offset:
            logger.info(
                f"🔄 Offset {offset} beyond file size {self.total_queries}. Resetting to beginning for continuous scanning."
            )
            save_offset(0)
            offset = 0

        try:
            with open(QUERIES_FILE, "r") as f:
                # Skip to current offset
                for _ in range(offset):
                    f.readline()

                # Read the next batch
                for _ in range(self.batch_size):
                    line = f.readline()
                    if not line:  # End of a file
                        break
                    batch.append(line.strip())
        except Exception as e:
            logger.error(f"❌ Error reading queries file {QUERIES_FILE}: {e}")
            return []

        if not batch:
            # If no batch read (shouldn't happen with reset logic above), reset anyway
            logger.info("🔄 Empty batch read, resetting offset to 0 for continuous scanning.")
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
                    f"📊 Batch from offset {offset}: {len(batch)} queries read. "
                    f"Progress: {progress_percent:.1f}% ({remaining} remaining)"
                )
            else:
                logger.debug(f"📊 Batch from offset {offset}: {len(batch)} queries read.")

        logger.debug(f"📦 Returning batch of {len(batch)} targets")
        return batch

    @staticmethod
    def augment_with_www(domain: str) -> List[str]:
        """Augment domain with www variant."""
        parts = domain.split(".")
        return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]

    def filter_allowed_targets(self, targets: List[str]) -> List[str]:
        """Filter out allowed/allowlisted targets."""
        allowed_set = {site.lower().strip() for site in self.allowed_sites}
        filtered = [target for target in targets if target.lower().strip() not in allowed_set]
        removed = len(targets) - len(filtered)
        if removed:
            logger.info(f"🚫 Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
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
                            f"⚠️  HTTP {response.status_code} at {url} is not acceptable for scanning"
                        )

                except requests.exceptions.ConnectionError as e:
                    if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                        if not dns_error_logged:
                            logger.debug(f"🌐 DNS resolution failed for {url}: {e}")
                            dns_error_logged = True
                    else:
                        logger.error(f"❌ Connection error: {url} - {e}")

                except requests.exceptions.RequestException as e:
                    logger.error(f"❌ Protocol error: {url} - {e}")

        if not candidate_urls:
            logger.debug(f"ℹ️  No reachable candidate URLs found for domain: {domain}")

        return candidate_urls

    def scan_site(self, domain: str) -> None:
        """Scan a single site for phishing indicators with automatic multi-API analysis integration."""
        code = 0
        for url in self.get_candidate_urls(domain) or []:
            logger.info(f"🔍 Scanning {url} for keywords: {self.keywords}")
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

                # Always store a scan result in the original table
                PhishingUtils.store_scan_result(url, code, matches, db_file=DATABASE_URL)

                if matches:
                    logger.info(f"🎯 Phishing keywords found in {url}: {matches}")
                    PhishingUtils.log_positive_result(url, matches)

                    # Auto-detection integration (optional, only if APIs are configured and DB available)
                    if AUTO_ANALYSIS_ENABLED and self.db_manager is not None:
                        try:
                            # Store for auto-analysis
                            stored = self.db_manager.store_detected_phishing_site(
                                url, matches, source="auto_detection"
                            )

                            if stored:
                                logger.info(f"📥 Queued for auto-analysis: {url}")

                            # Immediate analysis for critical keywords
                            critical_keywords = [
                                "login",
                                "password",
                                "account",
                                "banking",
                                "paypal",
                            ]
                            has_critical = any(
                                kw.lower() in [m.lower() for m in matches]
                                for kw in critical_keywords
                            )

                            if has_critical:
                                logger.warning(
                                    f"🚨 Critical keywords detected in {url}, performing immediate analysis"
                                )
                                try:
                                    immediate_results = self.multi_api_validator.comprehensive_scan(
                                        url
                                    )
                                    threat_level = immediate_results.get(
                                        "aggregated_threat_level", "unknown"
                                    )
                                    confidence = immediate_results.get("confidence_score", 0)

                                    logger.warning(
                                        f"⚡ Immediate analysis complete for {url}: Threat={threat_level}, Confidence={confidence}%"
                                    )

                                    # Store immediate results
                                    with self.db_manager.engine.begin() as conn:
                                        conn.execute(
                                            text(
                                                """
                                                UPDATE phishing_sites
                                                SET auto_analysis_status = 'completed',
                                                    auto_analysis_timestamp = :timestamp,
                                                    virustotal_result = :vt_result,
                                                    urlvoid_result = :uv_result,
                                                    phishtank_result = :pt_result,
                                                    multi_api_threat_level = :threat_level,
                                                    api_confidence_score = :confidence_score,
                                                    priority = 'high'
                                                WHERE url = :url
                                            """
                                            ),
                                            {
                                                "timestamp": datetime.datetime.now().strftime(
                                                    "%Y-%m-%d %H:%M:%S"
                                                ),
                                                "vt_result": json.dumps(
                                                    immediate_results.get("virustotal", {})
                                                ),
                                                "uv_result": json.dumps(
                                                    immediate_results.get("urlvoid", {})
                                                ),
                                                "pt_result": json.dumps(
                                                    immediate_results.get("phishtank", {})
                                                ),
                                                "threat_level": threat_level,
                                                "confidence_score": confidence,
                                                "url": url,
                                            },
                                        )

                                except Exception as api_error:
                                    logger.error(
                                        f"❌ Immediate multi-API analysis failed for {url}: {api_error}"
                                    )

                        except Exception as auto_error:
                            logger.error(
                                f"❌ Auto-detection integration failed for {url}: {auto_error}"
                            )
                            # Continue with normal operation even if auto-detection fails
                            pass
                else:
                    logger.debug(f"ℹ️  No keywords found in {url}")

                break

            except requests.exceptions.Timeout:
                logger.warning(f"⏰ Timeout scanning {url}")
                PhishingUtils.update_scan_result_response_code(url, code)

            except requests.exceptions.ConnectionError as e:
                if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                    logger.info(f"🌐 DNS failure during scan: {url}")
                else:
                    logger.error(f"❌ Connection failure: {url} - {e}")
                PhishingUtils.update_scan_result_response_code(url, code)

            except Exception as e:
                logger.error(f"❌ Scan error: {url} - {repr(e)}")
                PhishingUtils.update_scan_result_response_code(url, code)

    def run_scan_cycle(self) -> None:
        """Run continuous scanning cycles with integrated auto-analysis."""
        logger.info("🚀 Starting enhanced continuous scanning with auto-analysis integration...")
        logger.debug(
            f"⚙️  Scanner configuration: timeout={self.timeout}, keywords={len(self.keywords)}, domains={len(self.domains)}"
        )
        logger.debug(f"📊 Total queries to process: {self.total_queries}")

        cycle_count = 0
        while True:
            cycle_count += 1
            logger.debug(f"🔄 Starting scan cycle #{cycle_count}")

            targets = self.get_dynamic_target_sites()
            if not targets:
                logger.info("🔄 Reached end of queries file, resetting to beginning...")
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
                f"🔍 [Cycle {cycle_count}] Processing batch: offset {progress}, batch size {len(targets)}"
            )

            # Use ThreadPoolExecutor for parallel scanning
            logger.debug(
                f"🧵 Starting parallel scanning with 180 workers for {len(targets)} targets"
            )
            with ThreadPoolExecutor(max_workers=180) as executor:
                futures = {executor.submit(self.scan_site, target): target for target in targets}

                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"❌ Thread error for {futures[future]}: {repr(e)}")

                    # Progress every 150 completed scans
                    if completed % 150 == 0:
                        progress_percent = (completed / len(targets)) * 100
                        logger.info(
                            f"📊 [Cycle {cycle_count}] Progress: {completed}/{len(targets)} ({progress_percent:.1f}%)"
                        )

            logger.info(
                f"✅ [Cycle {cycle_count}] Completed batch of {len(targets)} targets. Moving to next batch..."
            )

            # Cleanup memory
            gc.collect()

            # Very short pause to prevent overwhelming (1 second)
            time.sleep(1)


class Engine:
    """Main engine class with enhanced multi-API capabilities and intelligent auto-analysis."""

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

        logger.debug("🗄️  Database initialization completed")

        # Initialize enhanced abuse detector
        self.abuse_detector = EnhancedAbuseEmailDetector(self.db_manager)

        # Initialize multi-API validator
        self.multi_api_validator = MultiAPIValidator()

        # Initialize ICANN compliance services
        self.screenshot_service = ScreenshotService(
            screenshots_dir=getattr(settings, "SCREENSHOTS_DIR", None), timeout=self.timeout
        )
        self.abuse_contact_validator = AbuseContactValidator(timeout=self.timeout)
        self.report_tracker = ReportTracker(self.db_manager.engine)

        # Initialize auto-analyzer (always, but may be inactive)
        self.auto_analyzer = AutoPhishingAnalyzer(self.db_manager, self.abuse_detector)

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

        # ALWAYS initialize scanner if needed (independent of API keys)
        if self.mode.scanning_mode:
            self.scanner = PhishingScanner(
                self.timeout, self.keywords, self.domains, self.allowed_sites, self.args
            )
            logger.debug("🔍 Scanner initialized for scanning mode")
        else:
            self.scanner = None
            logger.debug("ℹ️  No scanner needed for current mode")

    def mark_site_as_phishing(self, url: str, abuse_email: Optional[str] = None):
        """Mark a site as phishing with enhanced database operations including WHOIS data."""
        with self.db_manager.engine.begin() as conn:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Get WHOIS data and abuse emails
            whois_info = None
            abuse_emails = []
            registrar = None

            try:
                domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
                registrar = self.abuse_detector.extract_registrar(whois_info)

                # Get abuse emails if not provided
                if not abuse_email:
                    detected_emails = self.abuse_detector.get_enhanced_abuse_email(
                        domain, whois_info, registrar
                    )
                    abuse_emails = detected_emails if detected_emails else []
                else:
                    abuse_emails = [abuse_email]

                logger.info(
                    f"🔍 WHOIS lookup for {domain}: Registrar={registrar}, Abuse emails={abuse_emails}"
                )
            except Exception as e:
                logger.warning(f"⚠️  Failed to get WHOIS data for {url}: {e}")
                if abuse_email:
                    abuse_emails = [abuse_email]

            result = conn.execute(
                text("SELECT id FROM phishing_sites WHERE url=:url"), {"url": url}
            ).fetchone()

            if result:
                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET manual_flag=1, last_seen=:timestamp, reported=0,
                            abuse_report_sent=0, abuse_email=:abuse_email,
                            whois_info=:whois_info, registrar=:registrar
                        WHERE url=:url
                    """
                    ),
                    {
                        "timestamp": timestamp,
                        "abuse_email": json.dumps(abuse_emails),
                        "whois_info": (
                            json.dumps(serialize_for_json(whois_info)) if whois_info else None
                        ),
                        "registrar": registrar,
                        "url": url,
                    },
                )
                logger.info(
                    f"🔄 Updated phishing flag for {url} with registrar {registrar} and abuse emails {abuse_emails}"
                )
            else:
                conn.execute(
                    text(
                        """
                        INSERT INTO phishing_sites
                        (url, manual_flag, first_seen, last_seen, abuse_email,
                         whois_info, registrar, reported, abuse_report_sent)
                        VALUES (:url, 1, :timestamp, :timestamp, :abuse_email,
                                :whois_info, :registrar, 0, 0)
                    """
                    ),
                    {
                        "url": url,
                        "timestamp": timestamp,
                        "abuse_email": json.dumps(abuse_emails),
                        "whois_info": (
                            json.dumps(serialize_for_json(whois_info)) if whois_info else None
                        ),
                        "registrar": registrar,
                    },
                )
                logger.info(
                    f"🚨 Marked {url} as phishing with registrar {registrar} and abuse emails {abuse_emails}"
                )

    def perform_multi_api_scan(self, url: str):
        """Perform multi-API scan and display results."""
        if not validators.url(url):
            logger.error(f"❌ Invalid URL format: {url}")
            return

        logger.info(f"🔍 Starting multi-API comprehensive scan for: {url}")

        try:
            results = self.multi_api_validator.comprehensive_scan(url)

            # Display results in a formatted way
            print("\n" + "=" * 80)
            print(f"🎯 MULTI-API SCAN RESULTS FOR: {url}")
            print("=" * 80)

            print(f"📊 THREAT LEVEL: {results['aggregated_threat_level'].upper()}")
            print(f"🎯 CONFIDENCE SCORE: {results['confidence_score']}%")
            print(f"⏰ SCAN TIMESTAMP: {results['scan_timestamp']}")

            # VirusTotal Results
            print("\n🛡️  VIRUSTOTAL RESULTS:")
            vt_result = results.get("virustotal", {})
            if vt_result.get("error"):
                print(f"   ❌ Error: {vt_result['error']}")
            elif "total_engines" in vt_result:
                print(f"   🔍 Engines Scanned: {vt_result['total_engines']}")
                print(f"   🚨 Malicious Detections: {vt_result.get('malicious', 0)}")
                print(f"   ⚠️  Suspicious Detections: {vt_result.get('suspicious', 0)}")
                print(f"   ✅ Harmless: {vt_result.get('harmless', 0)}")
                print(f"   📈 Reputation Score: {vt_result.get('reputation', 0)}")
            else:
                print(f"   ⏳ Status: {vt_result.get('status', 'Unknown')}")

            # URLVoid Results
            print("\n🔍 URLVOID RESULTS:")
            uv_result = results.get("urlvoid", {})
            if uv_result.get("error"):
                print(f"   ❌ Error: {uv_result['error']}")
            else:
                print(f"   🛡️  Safety Score: {uv_result.get('safety_score', 'N/A')}/100")
                print(f"   📅 Domain Age: {uv_result.get('domain_age', 'N/A')}")
                print(f"   🏢 ASN: {uv_result.get('asn', 'N/A')}")
                print(f"   🌍 Country: {uv_result.get('country_code', 'N/A')}")
                blacklists = uv_result.get("blacklists", [])
                if blacklists:
                    print(f"   🚫 Blacklists: {', '.join(blacklists)}")

            # PhishTank Results
            print("\n🎣 PHISHTANK RESULTS:")
            pt_result = results.get("phishtank", {})
            if pt_result.get("error"):
                print(f"   ❌ Error: {pt_result['error']}")
            else:
                is_phishing = pt_result.get("is_phishing", False)
                verified = pt_result.get("verified", False)
                if is_phishing:
                    status = "VERIFIED PHISHING" if verified else "REPORTED AS PHISHING"
                    print(f"   🚨 Status: {status}")
                    if pt_result.get("target"):
                        print(f"   🎯 Target: {pt_result['target']}")
                else:
                    print(f"   ✅ Status: Not in phishing database")

            # Recommendations
            print("\n📋 RECOMMENDATIONS:")
            recommendations = results.get("recommendations", [])
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")

            print("\n" + "=" * 80)

            # Store results if this was positive detection
            threat_level = results["aggregated_threat_level"]
            if threat_level in ["critical", "high", "medium"]:
                logger.info(f"🚨 Storing scan results due to threat level: {threat_level}")

                # Store in a database for further action
                with self.db_manager.engine.begin() as conn:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Check if already exists
                    existing = conn.execute(
                        text("SELECT id FROM phishing_sites WHERE url = :url"), {"url": url}
                    ).fetchone()

                    if not existing:
                        conn.execute(
                            text(
                                """
                                INSERT INTO phishing_sites
                                (url, manual_flag, first_seen, last_seen, virustotal_result,
                                 urlvoid_result, phishtank_result, multi_api_threat_level,
                                 api_confidence_score, source, priority)
                                VALUES (:url, 1, :timestamp, :timestamp, :vt_result,
                                        :uv_result, :pt_result, :threat_level, :confidence,
                                        'multi_api_scan', :priority)
                            """
                            ),
                            {
                                "url": url,
                                "timestamp": timestamp,
                                "vt_result": json.dumps(vt_result),
                                "uv_result": json.dumps(uv_result),
                                "pt_result": json.dumps(pt_result),
                                "threat_level": threat_level,
                                "confidence": results["confidence_score"],
                                "priority": "high" if threat_level == "critical" else "medium",
                            },
                        )
                        print(f"🔄 URL flagged in database for further processing")

        except Exception as e:
            logger.error(f"❌ Multi-API scan failed for {url}: {e}")
            print(f"\n❌ Scan failed: {e}")

    def start(self):
        """Start the engine in the appropriate mode with enhanced auto-analysis."""
        logger.debug(
            f"⚙️  Starting engine in mode: scanning={self.mode.scanning_mode}, threads_only={self.args.threads_only}"
        )

        if self.args.report:
            self.mark_site_as_phishing(self.args.report, abuse_email=self.abuse_email)
            logger.info(
                f"🚨 URL {self.args.report} flagged as phishing. Exiting without sending an email."
            )
            return

        if getattr(self.args, "multi_api_scan", False):
            url = getattr(self.args, "url", None)
            if not url:
                logger.error("❌ --multi-api-scan requires --url parameter")
                return
            self.perform_multi_api_scan(url)
            return

        if self.args.process_reports:
            logger.info("🚀 STARTING --process-reports mode")
            # Convert single attachment to list if provided
            attachment_paths = [self.attachment] if self.attachment else None
            logger.info(f"📎 Attachment paths: {attachment_paths}")

            logger.info("🏁 CALLING process_manual_reports...")
            self.report_manager.process_manual_reports(attachment_paths=attachment_paths)
            logger.info("✅ process_manual_reports RETURNED SUCCESSFULLY!")

            logger.info("✅ Manually processed flagged phishing reports. Exiting.")
            logger.info("🚪 ABOUT TO RETURN FROM start() method")
            return

        if self.args.test_report:
            if not self.abuse_email:
                logger.error(
                    "❌ For a test report, please provide a test email using --abuse-email"
                )
                return
            # Convert single attachment to list if provided, otherwise get all attachments
            attachment_paths = (
                [self.attachment] if self.attachment else AttachmentConfig.get_all_attachments()
            )
            self.report_manager.send_test_report(
                self.abuse_email, attachment_paths=attachment_paths
            )
            logger.info("✅ Test report sent. Exiting.")
            return

        if getattr(self.args, "start_api", False):
            # Start API server
            api_key = getattr(self.args, "api_key", None)
            if not api_key:
                logger.error("❌ API key is required when starting API server")
                logger.error("   Use --api-key parameter to provide authentication key")
                return

            # Store the API key globally for decorator access
            global flask_app

            api = PhishingAPI(self.db_manager, self.abuse_detector, api_key=api_key)
            flask_app = api.app

            api.run(
                host=getattr(self.args, "api_host", "0.0.0.0"),
                port=getattr(self.args, "api_port", 8080),
                debug=(self.args.log_level == "DEBUG"),
            )
            return

        # Start background threads for abuse reporting and monitoring
        logger.debug("🧵 Starting background threads...")

        reporting_thread = threading.Thread(
            target=self.report_manager.report_phishing_sites, daemon=True
        )
        reporting_thread.start()
        logger.debug("📧 Abuse reporting thread started")

        takedown_thread = threading.Thread(target=self.takedown_monitor.run, daemon=True)
        takedown_thread.start()
        logger.debug("🔍 Takedown monitoring thread started")

        # Start follow-up worker for ICANN compliance (every 2 hours)
        followup_thread = threading.Thread(target=self.report_manager.followup_worker, daemon=True)
        followup_thread.start()
        logger.debug("🔄 ICANN follow-up worker started (checks every 2 hours)")

        # Start auto-analysis worker if APIs are configured
        if AUTO_ANALYSIS_ENABLED:
            self.auto_analyzer.start_analysis_worker()
            logger.info("🤖 Auto-analysis system started with multi-API integration")
        else:
            logger.info(
                "ℹ️  Auto-analysis disabled (no API keys configured or disabled in settings)"
            )

        if self.args.threads_only:
            logger.info(
                "🧵 Running in threads-only mode. Background threads are active; skipping scanning cycle."
            )
            logger.info(
                "🔄 Active systems: Abuse reporting, Takedown monitoring, ICANN Follow-up"
                + (", Auto-analysis" if AUTO_ANALYSIS_ENABLED else "")
            )
            logger.info("ℹ️  To scan for new sites, run without --threads-only flag.")

            # Show system status
            if AUTO_ANALYSIS_ENABLED:
                try:
                    pending_count = len(self.db_manager.get_pending_analysis_sites(limit=100))
                    auto_eligible_count = len(
                        self.db_manager.get_auto_report_eligible_sites(limit=100)
                    )
                    logger.info(
                        f"📊 System Status: {pending_count} sites pending analysis, {auto_eligible_count} sites eligible for auto-reporting"
                    )
                except Exception as e:
                    logger.debug(f"Could not get system status: {e}")
            else:
                logger.info("ℹ️  Auto-analysis system inactive - no API keys configured")

            # Show what the threads are doing
            logger.info("🔄 Background threads running:")
            logger.info("  📧 Abuse Report Manager: Processing flagged phishing sites")
            logger.info("  🔍 Takedown Monitor: Monitoring site status changes")
            logger.info("  🔄 ICANN Follow-up Worker: Checking overdue reports every 2 hours")
            if AUTO_ANALYSIS_ENABLED:
                logger.info(
                    "  🤖 Auto-Analysis Worker: Analyzing detected sites with multi-API validation"
                )

            logger.info("✅ System ready. Press Ctrl+C to stop.")

            while True:
                time.sleep(60)

        elif self.mode.scanning_mode:
            # SCANNING MODE - This should always work regardless of API keys
            logger.info(
                f"🚀 Initialized scanning engine with {len(self.keywords)} keywords and {len(self.domains)} domain extensions"
            )
            logger.info(f"🚫 Allowed sites (whitelist): {self.allowed_sites}")
            logger.info(f"⏰ Timeout: {self.timeout}s per request")

            if not self.scanner:
                logger.error("❌ Scanner not initialized! This is a bug.")
                return

            logger.debug("🔍 Scanner object exists, preparing to start scanning...")

            # Log API configuration status for scanning
            api_status = []
            if VIRUSTOTAL_API_KEY:
                api_status.append("VirusTotal")
            if URLVOID_API_KEY:
                api_status.append("URLVoid")
            if PHISHTANK_API_KEY:
                api_status.append("PhishTank")

            if api_status:
                logger.info(f"🤖 Multi-API integration enabled: {', '.join(api_status)}")
                logger.info(
                    f"🎯 Auto-analysis: {'Enabled' if AUTO_ANALYSIS_ENABLED else 'Disabled'}"
                )
                if AUTO_ANALYSIS_ENABLED:
                    logger.info(
                        f"📊 Auto-report threshold: {AUTO_REPORT_THRESHOLD_CONFIDENCE}% confidence"
                    )
                    logger.info(
                        f"👀 Manual review threshold: {MANUAL_REVIEW_THRESHOLD_CONFIDENCE}% confidence"
                    )
            else:
                logger.info("ℹ️  Multi-API integration disabled (no API keys configured)")
                logger.info(
                    "🔍 Running in basic scanning mode - will detect and log phishing sites"
                )

            # Start continuous scanning
            logger.info("🚀 Starting continuous scanning cycle...")
            logger.debug("About to call scanner.run_scan_cycle()")

            try:
                self.scanner.run_scan_cycle()
            except KeyboardInterrupt:
                logger.info("🛑 Received interrupt signal, shutting down gracefully...")
                if AUTO_ANALYSIS_ENABLED:
                    self.auto_analyzer.stop_analysis_worker()
            except Exception as e:
                logger.error(f"❌ Error in scan cycle: {e}")
                import traceback

                logger.debug(f"Full traceback: {traceback.format_exc()}")
                logger.info("🔄 Restarting scanning in 60 seconds...")
                time.sleep(60)
                # Restart scanning
                try:
                    self.scanner.run_scan_cycle()
                except KeyboardInterrupt:
                    logger.info("🛑 Received interrupt signal, shutting down gracefully...")
                    if AUTO_ANALYSIS_ENABLED:
                        self.auto_analyzer.stop_analysis_worker()
        else:
            logger.error("❌ Unknown mode - this shouldn't happen!")
            logger.debug(f"Mode details: {vars(self.mode)}")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments with Grinder integration options."""
    parser = argparse.ArgumentParser(
        description="Enhanced Anisakys Phishing Detection Engine with Grinder Integration",
        epilog=(
            "Example usages:\n"
            "  ./anisakys.py --timeout 30 --log-level DEBUG\n"
            "  ./anisakys.py --start-api --api-port 8080 --api-key your_secure_api_key\n"
            "  ./anisakys.py --multi-api-scan --url https://suspicious-site.com\n"
            "  ./anisakys.py --test-grinder-integration\n"
            "\n"
            "🔗 GRINDER INTEGRATION FEATURES:\n"
            "  ✅ Bidirectional threat intelligence sharing\n"
            "  ✅ Automatic IP reporting for detected phishing infrastructure\n"
            "  ✅ API key authentication for secure communications\n"
            "  ✅ Real-time threat intelligence pipeline integration\n"
            "  ✅ Enhanced abuse reporting with IP context\n"
            "\n"
            "🔐 API AUTHENTICATION:\n"
            "  All API endpoints now require Bearer token authentication\n"
            "  Use --api-key parameter when starting API server\n"
            "  External clients must include Authorization: Bearer <key> header\n"
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
        help="Manually trigger processing of flagged phishing sites with multi-API validation.",
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
        help="Only run background threads (monitoring, auto-analysis, auto-reporting) without scanning.",
    )
    parser.add_argument(
        "--regen-queries",
        action="store_true",
        help="Force regeneration of the queries file even if it already exists.",
    )
    parser.add_argument(
        "--test-report",
        action="store_true",
        help="Send a test report with multi-API evidence including attachment and escalation CCs, then exit.",
    )
    parser.add_argument(
        "--start-api",
        action="store_true",
        help="Start the REST API server for external reports and multi-API scanning.",
    )
    parser.add_argument(
        "--api-port", type=int, default=8080, help="Port for the API server (default: 8080)"
    )
    parser.add_argument(
        "--api-host", type=str, default="0.0.0.0", help="Host for the API server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--api-key", type=str, help="API key for authentication when starting API server"
    )
    parser.add_argument(
        "--reset-offset",
        action="store_true",
        help="Reset scanning offset to 0 (start from beginning of queries file)",
    )
    parser.add_argument(
        "--multi-api-scan",
        action="store_true",
        help="Perform comprehensive multi-API validation scan on a specific URL",
    )
    parser.add_argument("--url", type=str, help="URL to scan when using --multi-api-scan")
    parser.add_argument(
        "--show-auto-status",
        action="store_true",
        help="Show current auto-analysis and auto-reporting system status",
    )
    parser.add_argument(
        "--force-auto-analysis",
        action="store_true",
        help="Force immediate auto-analysis of all pending sites (useful for testing)",
    )
    parser.add_argument(
        "--auto-report-now",
        action="store_true",
        help="Force immediate processing of all auto-report eligible sites",
    )
    parser.add_argument(
        "--test-grinder-integration",
        action="store_true",
        help="Test connection to Grinder API and exit",
    )

    return parser.parse_args()


def show_auto_status():
    """Show the current status of the auto-analysis and auto-reporting system."""
    print("\n" + "=" * 80)
    print("🤖 ANISAKYS AUTO-ANALYSIS & AUTO-REPORTING STATUS")
    print("=" * 80)

    # Database connection
    db_manager = DatabaseManager(db_url=DATABASE_URL)

    try:
        with db_manager.engine.begin() as conn:
            # Get pending analysis count
            pending_analysis = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE auto_analysis_status = 'pending'")
            ).scalar()

            # Get auto-report eligible count
            auto_eligible = conn.execute(
                text(
                    "SELECT COUNT(*) FROM phishing_sites WHERE auto_report_eligible = 1 AND abuse_report_sent = 0"
                )
            ).scalar()

            # Get manual review required count
            manual_review = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE requires_manual_review = 1")
            ).scalar()

            # Get total auto-detected sites
            total_auto_detected = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE auto_detected = 1")
            ).scalar()

            # Get analysis completed count
            analysis_completed = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE auto_analysis_status = 'completed'")
            ).scalar()

            # Get auto-reports sent count
            auto_reports_sent = conn.execute(
                text(
                    "SELECT COUNT(*) FROM phishing_sites WHERE auto_detected = 1 AND abuse_report_sent = 1"
                )
            ).scalar()

            # Recent activity (last 24 hours)
            yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            recent_detections = conn.execute(
                text(
                    "SELECT COUNT(*) FROM phishing_sites WHERE auto_detected = 1 AND first_seen >= :date"
                ),
                {"date": yesterday},
            ).scalar()

            recent_analysis = conn.execute(
                text("SELECT COUNT(*) FROM phishing_sites WHERE auto_analysis_timestamp >= :date"),
                {"date": yesterday},
            ).scalar()

            # Threat level breakdown
            threat_breakdown = conn.execute(
                text(
                    """
                    SELECT multi_api_threat_level, COUNT(*) as count
                    FROM phishing_sites
                    WHERE auto_analysis_status = 'completed'
                    GROUP BY multi_api_threat_level
                    ORDER BY count DESC
                """
                )
            ).fetchall()

            print(f"📊 DETECTION STATISTICS:")
            print(f"   🎯 Total Auto-Detected Sites: {total_auto_detected}")
            print(f"   📋 Pending Analysis: {pending_analysis}")
            print(f"   ✅ Analysis Completed: {analysis_completed}")
            print(f"   🚨 Auto-Report Eligible: {auto_eligible}")
            print(f"   👀 Manual Review Required: {manual_review}")
            print(f"   📤 Auto-Reports Sent: {auto_reports_sent}")

            print(f"\n⏰ RECENT ACTIVITY (Last 24 Hours):")
            print(f"   🔍 New Detections: {recent_detections}")
            print(f"   🤖 Sites Analyzed: {recent_analysis}")

            print(f"\n🎯 THREAT LEVEL BREAKDOWN:")
            if threat_breakdown:
                for threat_level, count in threat_breakdown:
                    if threat_level:
                        print(f"   {threat_level.upper()}: {count} sites")
            else:
                print("   No completed analyses yet")

            # Configuration status
            print(f"\n⚙️  CONFIGURATION STATUS:")
            print(
                f"   🤖 Auto-Analysis: {'✅ Enabled' if AUTO_ANALYSIS_ENABLED else '❌ Disabled'}"
            )
            if AUTO_ANALYSIS_ENABLED:
                print(
                    f"   📊 Auto-Report Confidence Threshold: {AUTO_REPORT_THRESHOLD_CONFIDENCE}%"
                )
                print(
                    f"   👀 Manual Review Confidence Threshold: {MANUAL_REVIEW_THRESHOLD_CONFIDENCE}%"
                )
                print(f"   🎯 Auto-Report Threat Levels: {["critical", "high"]}")
                print(f"   ⏱️  Analysis Delay: {AUTO_ANALYSIS_DELAY_SECONDS} seconds")
            else:
                print(f"   ❌ Reason: No API keys configured or AUTO_MULTI_API_SCAN disabled")

            # API status
            print(f"\n🔧 API INTEGRATION STATUS:")
            api_configs = []
            if VIRUSTOTAL_API_KEY:
                api_configs.append("✅ VirusTotal")
            else:
                api_configs.append("❌ VirusTotal")

            if URLVOID_API_KEY:
                api_configs.append("✅ URLVoid")
            else:
                api_configs.append("❌ URLVoid")

            if PHISHTANK_API_KEY:
                api_configs.append("✅ PhishTank")
            else:
                api_configs.append("❌ PhishTank")

            for config in api_configs:
                print(f"   {config}")

            # Grinder integration status
            print(f"\n🔗 GRINDER INTEGRATION STATUS:")
            if GRINDER_INTEGRATION_ENABLED:
                print(f"   ✅ Enabled: {GRINDER0X_API_URL}")
                print(f"   🔄 Automatic IP reporting: Active")
            else:
                print(f"   ❌ Disabled: Missing configuration")
                print(f"   ⚙️  Configure GRINDER0X_API_URL and GRINDER0X_API_KEY to enable")

            # Recent pending sites for analysis
            if pending_analysis > 0:
                print(f"\n🔍 NEXT SITES FOR ANALYSIS:")
                recent_pending = conn.execute(
                    text(
                        """
                        SELECT url, detection_keywords, first_seen, priority
                        FROM phishing_sites
                        WHERE auto_analysis_status = 'pending'
                        ORDER BY
                            CASE priority
                                WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 3
                                ELSE 2
                            END,
                            first_seen ASC
                        LIMIT 5
                    """
                    )
                ).fetchall()

                for i, (url, keywords, first_seen, priority) in enumerate(recent_pending, 1):
                    print(f"   {i}. {url} ({priority}) - Keywords: {keywords}")

            # Recent auto-report eligible sites
            if auto_eligible > 0:
                print(f"\n🚨 SITES READY FOR AUTO-REPORTING:")
                recent_eligible = conn.execute(
                    text(
                        """
                        SELECT url, multi_api_threat_level, api_confidence_score
                        FROM phishing_sites
                        WHERE auto_report_eligible = 1 AND abuse_report_sent = 0
                        ORDER BY api_confidence_score DESC, first_seen ASC
                        LIMIT 5
                    """
                    )
                ).fetchall()

                for i, (url, threat_level, confidence) in enumerate(recent_eligible, 1):
                    print(f"   {i}. {url} - {threat_level} ({confidence}% confidence)")

    except Exception as e:
        print(f"❌ Error getting status: {e}")

    print("\n" + "=" * 80)


def test_grinder_integration():
    """Test Grinder integration connectivity and functionality."""
    print("\n" + "=" * 80)
    print("🔗 TESTING GRINDER INTEGRATION")
    print("=" * 80)

    # Test configuration
    print(f"📋 Configuration:")
    print(f"   API URL: {GRINDER0X_API_URL or 'Not configured'}")
    print(f"   API Key: {'Configured' if GRINDER0X_API_KEY else 'Not configured'}")
    print(f"   Integration Enabled: {GRINDER_INTEGRATION_ENABLED}")

    if not GRINDER_INTEGRATION_ENABLED:
        print("\n❌ Grinder integration is not properly configured.")
        print("   Please check GRINDER0X_API_URL and GRINDER0X_API_KEY in your .env file")
        return

    # Test connection
    print(f"\n🔗 Testing connection to Grinder API...")
    grinder_client = GrinderReportClient()
    connection_result = grinder_client.test_connection()

    if connection_result["status"] == "success":
        print(f"✅ Connection successful!")
    else:
        print(f"❌ Connection failed: {connection_result['message']}")
        return

    # Test IP reporting (with test data)
    print(f"\n📤 Testing IP reporting functionality...")
    test_ip = "192.0.2.1"  # RFC 5737 test IP
    test_context = {
        "method": "test_integration",
        "domains": ["test.example.com"],
        "severity": "high",
        "threat_level": "high",
        "keywords": ["test", "integration"],
        "api_confidence": 95,
    }

    report_result = grinder_client.report_malicious_ip(test_ip, test_context, confidence=95)

    if report_result["status"] == "success":
        print(f"✅ Test IP report sent successfully!")
        print(f"   Categories: {report_result.get('categories', [])}")
        print(f"   Confidence: {report_result.get('confidence', 0)}%")
    elif report_result["status"] == "rate_limited":
        print(f"⏰ Rate limited - this is normal for testing")
    else:
        print(f"❌ Test report failed: {report_result['message']}")

    print("\n" + "=" * 80)


def main():
    """Main entry point with enhanced Grinder integration."""
    args = parse_arguments()
    logger.setLevel(
        args.log_level if args.log_level is not None else getattr(settings, "LOG_LEVEL", "INFO")
    )

    logger.debug("🚀 Anisakys with Grinder integration starting up...")
    logger.debug(f"⚙️  Arguments: {vars(args)}")

    # Handle test Grinder integration command
    if getattr(args, "test_grinder_integration", False):
        test_grinder_integration()
        return

    # Handle reset offset command
    if args.reset_offset:
        save_offset(0)
        logger.info("🔄 Scanning offset reset to 0. Will start from beginning of queries file.")
        return

    # Handle auto-status command
    if args.show_auto_status:
        show_auto_status()
        return

    # Handle force auto-analysis command
    if args.force_auto_analysis:
        logger.info("🔄 Forcing immediate auto-analysis of all pending sites...")
        db_manager = DatabaseManager(db_url=DATABASE_URL)
        abuse_detector = EnhancedAbuseEmailDetector(db_manager)
        auto_analyzer = AutoPhishingAnalyzer(db_manager, abuse_detector)

        pending_sites = db_manager.get_pending_analysis_sites(limit=50)
        if pending_sites:
            logger.info(f"🔍 Found {len(pending_sites)} sites pending analysis")
            for site_info in pending_sites:
                try:
                    logger.info(f"🔍 Analyzing: {site_info['url']}")
                    auto_analyzer.analyze_detected_site(
                        site_info["url"],
                        site_info["keywords"].split(", ") if site_info["keywords"] else [],
                    )
                    time.sleep(5)  # Short delay between analyses
                except Exception as e:
                    logger.error(f"❌ Error analyzing {site_info['url']}: {e}")
            logger.info("✅ Force auto-analysis completed")
        else:
            logger.info("ℹ️  No sites pending analysis")
        return

    # Handle an auto-report now command
    if args.auto_report_now:
        logger.info("🚨 Forcing immediate processing of auto-report eligible sites...")
        db_manager = DatabaseManager(db_url=DATABASE_URL)
        abuse_detector = EnhancedAbuseEmailDetector(db_manager)
        auto_analyzer = AutoPhishingAnalyzer(db_manager, abuse_detector)

        # Create a temporary report manager for this operation
        report_manager = AbuseReportManager(db_manager, abuse_detector, cc_emails=None, timeout=30)

        processed = auto_analyzer.process_auto_reports(report_manager)
        logger.info(f"📊 Auto-reporting completed: {processed} sites processed")
        return

    # Print enhanced integration status
    logger.info("🔗 Grinder Integration Status:")
    if GRINDER_INTEGRATION_ENABLED:
        logger.info(f"   ✅ Enabled: {GRINDER0X_API_URL}")
        logger.info("   🔄 Automatic IP reporting: Active")
        logger.info("   📊 Threat intelligence sharing: Bidirectional")
    else:
        logger.info("   ❌ Disabled: Missing configuration")
        logger.info("   ⚙️  Configure GRINDER0X_API_URL and GRINDER0X_API_KEY to enable")

    # Print enhanced API configuration status
    api_configs = []
    if VIRUSTOTAL_API_KEY:
        api_configs.append("VirusTotal API: Enabled")
    else:
        api_configs.append("VirusTotal API: Not configured")

    if URLVOID_API_KEY:
        api_configs.append("URLVoid API: Enabled")
    else:
        api_configs.append("URLVoid API: Not configured")

    if PHISHTANK_API_KEY:
        api_configs.append("PhishTank API: Enabled")
    else:
        api_configs.append("PhishTank API: Not configured")

    logger.info("🔧 Enhanced API Configuration Status:")
    for config in api_configs:
        logger.info(f"   {config}")

    logger.info("🤖 Auto-Analysis Configuration:")
    logger.info(f"   Auto-Analysis: {'Enabled' if AUTO_ANALYSIS_ENABLED else 'Disabled'}")
    if AUTO_ANALYSIS_ENABLED:
        logger.info(f"   Auto-Report Threshold: {AUTO_REPORT_THRESHOLD_CONFIDENCE}% confidence")
        logger.info(f"   Manual Review Threshold: {MANUAL_REVIEW_THRESHOLD_CONFIDENCE}% confidence")
        logger.info(f"   Auto-Report Threat Levels: {["critical", "high"]}")
    else:
        logger.info("   Reason: No API keys configured or AUTO_MULTI_API_SCAN=False")

    logger.debug("⚙️  Creating engine instance with Grinder integration...")
    try:
        engine_instance = Engine(args)
        logger.debug("✅ Engine instance created successfully")
        logger.debug("🚀 Starting engine with enhanced threat intelligence...")
        engine_instance.start()
    except Exception as e:
        logger.error(f"❌ Failed to create or start engine: {e}")
        import traceback

        logger.debug(f"Full traceback: {traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main()

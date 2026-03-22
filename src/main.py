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
import psycopg2
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
import logging
import logging as flask_logging
from functools import wraps
import signal
import sys

from src.config import settings, CLOUDFLARE_IP_RANGES
from src.logger import logger
from src.observability.structured_logger import (
    setup_structured_logging,
    set_correlation_id,
    log_with_context,
    log_detection,
    log_api_call,
    log_error,
)
from src.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
)
from src.detection.redirect_analyzer import RedirectAnalyzer, RedirectChain
from src.intelligence.abuse_contact_resolver import AbuseContactResolver
from src.data import (
    ASN_ABUSE_EMAIL_DB,
    PROVIDER_ABUSE_EMAIL_DB,
    ENHANCED_REGISTRAR_ABUSE_DB,
    TLD_WHOIS_SERVERS,
)
from src.models import DynamicBatchConfig, AttachmentConfig, EngineMode
from src.database import DatabaseManager, db_engine, DATABASE_URL
from src.reporting import EnhancedAbuseEmailDetector, AbuseReportManager
from src.monitoring import TakedownMonitor, start_gsb_rescan_job, stop_gsb_rescan_job
from src.detection import AutoPhishingAnalyzer, PhishingUtils, PhishingScanner
from src.api import PhishingAPI, TimeoutError, timeout, upgrade_phishing_db
from src.intelligence import (
    GrinderReportClient,
    require_api_key,
    GRINDER0X_API_URL,
    GRINDER0X_API_KEY,
    GRINDER_INTEGRATION_ENABLED,
    ABUSEIPDB_CATEGORIES,
    VirusTotalIntegration,
    VIRUSTOTAL_API_KEY,
    URLVoidIntegration,
    URLVOID_API_KEY,
    PhishTankIntegration,
    PHISHTANK_API_KEY,
    MultiAPIValidator,
    AUTO_MULTI_API_SCAN,
    AUTO_REPORT_THRESHOLD_CONFIDENCE,
    MANUAL_REVIEW_THRESHOLD_CONFIDENCE,
    AUTO_ANALYSIS_ENABLED,
)
from src.generators.query_generator import generate_queries_file
from src.dns.network_utils import get_ip_info, is_cloudflare_ip
from src.screenshot_service import ScreenshotService

# Global testing mode detection - independent of test_mode (used for screenshots)
IS_TESTING_MODE = False


def set_testing_mode(enabled=True):
    """Enable/disable global testing mode. In testing mode, CCs are NEVER sent."""
    global IS_TESTING_MODE
    IS_TESTING_MODE = enabled
    if enabled:
        logger.warning("🧪 TESTING MODE ACTIVE - CCs disabled for security")


from src.reporting.abuse_contact_validator import AbuseContactValidator
from src.reporting.report_tracker import ReportTracker, create_report_record

# File configuration (DATABASE_URL imported from src.database)
QUERIES_FILE = getattr(settings, "QUERIES_FILE")
if not QUERIES_FILE:
    raise Exception("QUERIES_FILE must be set in your .env file")

OFFSET_FILE = getattr(settings, "OFFSET_FILE")


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


# Auto-Analysis delay (other configs imported from src.intelligence)
AUTO_ANALYSIS_DELAY_SECONDS = getattr(settings, "AUTO_ANALYSIS_DELAY_SECONDS")

# Redirect Analysis Configuration (EPIC-001)
ENABLE_REDIRECT_ANALYSIS = getattr(settings, "ENABLE_REDIRECT_ANALYSIS", True)
MAX_REDIRECT_HOPS = getattr(settings, "MAX_REDIRECT_HOPS", 5)
REDIRECT_TIMEOUT_PER_HOP = getattr(settings, "REDIRECT_TIMEOUT_PER_HOP", 10)


# Constants
ALLOWED_HEAD_STATUS = {200, 201, 202, 203, 204, 205, 206, 301, 302, 403, 405, 503, 504}
# Realistic browser user agents - Chrome is primary, Firefox as fallback
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

FIREFOX_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) " "Gecko/20100101 Firefox/122.0"
)

# Standard browser headers to appear as legitimate traffic
BROWSER_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}
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

# Import shared shutdown state
from src.shutdown import shutdown_requested, signal_handler


class Engine:
    """Main engine class with enhanced multi-API capabilities and intelligent auto-analysis."""

    def __init__(self, args):
        self.timeout = args.timeout if args.timeout is not None else settings.TIMEOUT
        self.log_level = (
            args.log_level
            if args.log_level is not None
            else (getattr(settings, "LOG_LEVEL") if hasattr(settings, "LOG_LEVEL") else "INFO")
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
                [email.strip() for email in getattr(settings, "DEFAULT_CC_EMAILS").split(",")]
                if hasattr(settings, "DEFAULT_CC_EMAILS") and getattr(settings, "DEFAULT_CC_EMAILS")
                else None
            )

        self.args = args
        self.db_manager = DatabaseManager(db_url=DATABASE_URL)
        self.db_manager.init_db()
        self.db_manager.init_phishing_db()
        upgrade_phishing_db()
        self.db_manager.init_registrar_abuse_db()
        self.db_manager.init_hosting_abuse_db()
        self.db_manager.init_threads_db()

        # Ensure all initialization connections are closed
        logger.info("🔒 Disposing initialization connections")
        self.db_manager.engine.dispose()
        db_engine.dispose()

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
        self.allowed_sites = transform_to_list(
            getattr(settings, "ALLOWED_SITES") if hasattr(settings, "ALLOWED_SITES") else None
        )

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
                            abuse_report_sent=0,
                            abuse_email = CASE
                                WHEN manual_emails = 1 THEN abuse_email
                                ELSE :abuse_email
                            END,
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
            api_key = getattr(self.args, "api_key", None) or getattr(
                settings, "ANISAKYS_API_KEY", None
            )
            if not api_key:
                logger.error("❌ API key is required when starting API server")
                logger.error("   Use --api-key parameter or set ANISAKYS_API_KEY in .env")
                return

            # Start background threads for abuse reporting and monitoring BEFORE starting API
            logger.info("🧵 Starting background threads for API mode...")
            reporting_thread = threading.Thread(
                target=self.report_manager.report_phishing_sites, daemon=True
            )
            reporting_thread.start()
            logger.info("📧 Abuse reporting thread started")

            takedown_thread = threading.Thread(target=self.takedown_monitor.run, daemon=True)
            takedown_thread.start()
            logger.info("📡 Takedown monitoring thread started")

            # Start GSB rescan background job
            gsb_job = start_gsb_rescan_job(
                rescan_interval_hours=12, batch_size=50, max_age_hours=24
            )
            logger.info("🔄 GSB rescan job started (12h interval)")

            # Store the API key globally for decorator access
            global flask_app

            api = PhishingAPI(
                self.db_manager,
                self.abuse_detector,
                api_key=api_key,
                report_manager=self.report_manager,
            )
            flask_app = api.app

            api_port = getattr(self.args, "api_port", None) or getattr(
                settings, "ANISAKYS_API_PORT", 8080
            )
            logger.info("🚀 Starting API server with background reporting enabled...")
            api.run(
                host=getattr(self.args, "api_host", "0.0.0.0"),
                port=int(api_port),
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

        # Start follow-up worker for ICANN compliance (every 24 hours)
        followup_thread = threading.Thread(target=self.report_manager.followup_worker, daemon=True)
        followup_thread.start()
        logger.debug("🔄 ICANN follow-up worker started (checks every 24 hours)")

        # Start auto-analysis worker if APIs are configured
        if AUTO_ANALYSIS_ENABLED:
            self.auto_analyzer.start_analysis_worker()
            logger.info("🤖 Auto-analysis system started with multi-API integration")
        else:
            logger.info(
                "ℹ️  Auto-analysis disabled (no API keys configured or disabled in settings)"
            )

        # Start GSB rescan background job (re-verifies existing sites periodically)
        gsb_job = start_gsb_rescan_job(rescan_interval_hours=12, batch_size=50, max_age_hours=24)
        logger.info("🔄 GSB rescan job started (12h interval, re-checks existing sites)")

        if self.args.threads_only:
            logger.info(
                "🧵 Running in threads-only mode. Background threads are active; skipping scanning cycle."
            )
            logger.info(
                "🔄 Active systems: Abuse reporting, Takedown monitoring, ICANN Follow-up, GSB Re-scan"
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
            logger.info("  🔄 ICANN Follow-up Worker: Checking overdue reports every 24 hours")
            logger.info(
                "  🔄 GSB Re-scan Job: Re-verifying sites against Google Safe Browsing every 12h"
            )
            if AUTO_ANALYSIS_ENABLED:
                logger.info(
                    "  🤖 Auto-Analysis Worker: Analyzing detected sites with multi-API validation"
                )

            logger.info("✅ System ready. Press Ctrl+C to stop.")

            while not shutdown_requested:
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
    log_level = args.log_level or getattr(settings, "LOG_LEVEL", None) or "INFO"

    # Setup structured logging (replaces basic logger configuration)
    setup_structured_logging(log_level=log_level)

    # Generate correlation ID for this execution
    correlation_id = set_correlation_id()

    log_with_context(
        logger,
        logging.INFO,
        "Anisakys with Grinder integration starting up",
        correlation_id=correlation_id,
        log_level=log_level,
        arguments=vars(args),
    )

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

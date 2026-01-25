"""
Phishing API for Anisakys Phishing Detection Engine.

REST API for external phishing reports with multi-API integration
and Grinder integration.
"""

import base64
import datetime
import re
import socket
import threading
import time
import traceback
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

import validators
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging as flask_logging

from src.config import settings
from sqlalchemy import text
from src.database import db_engine, DATABASE_URL
from src.intelligence import (
    require_api_key,
    MultiAPIValidator,
    VIRUSTOTAL_API_KEY,
    URLVOID_API_KEY,
    PHISHTANK_API_KEY,
    GrinderReportClient,
    GRINDER_INTEGRATION_ENABLED,
)
from src.logger import logger
from src.screenshot_service import ScreenshotService, PLAYWRIGHT_AVAILABLE, SELENIUM_AVAILABLE

# Initialize screenshot service
SCREENSHOTS_DIR = (
    Path(settings.DATA_DIR if hasattr(settings, "DATA_DIR") else "/opt/anisakys/data")
    / "screenshots"
)
screenshot_service = (
    ScreenshotService(str(SCREENSHOTS_DIR))
    if (PLAYWRIGHT_AVAILABLE or SELENIUM_AVAILABLE)
    else None
)


class TimeoutError(Exception):
    """Raised when an operation times out"""

    pass


def timeout(seconds=10):
    """Thread-safe decorator to add timeout to functions"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            import threading
            import time

            result = [None]
            error = [None]

            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    error[0] = e

            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=seconds)

            if thread.is_alive():
                # Thread is still running, it timed out
                raise TimeoutError(f"Operation timed out after {seconds} seconds")

            if error[0]:
                raise error[0]

            return result[0]

        return wrapper

    return decorator


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

                # Log all API requests with source information
                logger.info(
                    f"📥 API report received - URL: {url}, Source: '{source}', Priority: {priority}"
                )

                # Log if this is from Grinder
                if source.lower() == "grinder":
                    logger.info(f"📥 Confirmed GRINDER report for {url}")

                # Validate abuse_email if provided
                if abuse_email and not self.abuse_detector.validate_email(abuse_email):
                    return jsonify({"error": "Invalid abuse email format"}), 400

                # Process the report
                try:
                    result = self.process_phishing_report(
                        url, abuse_email, source, priority, description
                    )
                except TimeoutError:
                    logger.error(f"❌ Database timeout while processing report for {url}")
                    return jsonify({"error": "Database operation timed out", "url": url}), 503
                except Exception as e:
                    logger.error(f"❌ Error processing report: {e}")
                    return (
                        jsonify({"error": f"Failed to process report: {str(e)}", "url": url}),
                        500,
                    )

                # If successful, also try to report the IP to Grinder
                # IMPORTANT: Don't report back to Grinder if this report came from Grinder
                if source.lower() == "grinder":
                    logger.info(
                        f"⏭️ Skipping Grinder reporting for {url} - report came from Grinder"
                    )
                elif result.get("status") in ["created", "updated"] and GRINDER_INTEGRATION_ENABLED:
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
                include_screenshot = data.get("include_screenshot", True)

                if not url:
                    return jsonify({"error": "URL is required"}), 400

                # Validate URL
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                # Perform comprehensive scan with ALL APIs (URL analysis, VirusTotal, URLVoid, PhishTank, Google Safe Browsing)
                scan_result = self.multi_api_validator.comprehensive_scan(url)

                # Capture screenshot if requested and service available
                screenshot_data = None
                if include_screenshot and screenshot_service:
                    try:
                        logger.info(f"📸 Capturing screenshot for {url}")
                        screenshot_result = screenshot_service.capture_screenshot(
                            url, use_async=False
                        )
                        if screenshot_result and screenshot_result.get("success"):
                            # Read screenshot and convert to base64
                            screenshot_path = screenshot_result.get("screenshot_path")
                            if screenshot_path and Path(screenshot_path).exists():
                                with open(screenshot_path, "rb") as f:
                                    screenshot_bytes = f.read()
                                screenshot_data = {
                                    "base64": base64.b64encode(screenshot_bytes).decode("utf-8"),
                                    "filename": screenshot_result.get("filename"),
                                    "size_bytes": screenshot_result.get("size_bytes"),
                                    "page_title": screenshot_result.get("page_info", {}).get(
                                        "title"
                                    ),
                                    "final_url": screenshot_result.get("page_info", {}).get("url"),
                                }
                                logger.info(f"📸 Screenshot captured successfully for {url}")
                        else:
                            logger.warning(
                                f"⚠️ Screenshot capture failed for {url}: {screenshot_result}"
                            )
                    except Exception as ss_error:
                        logger.error(f"❌ Screenshot error for {url}: {ss_error}")

                scan_result["screenshot"] = screenshot_data

                # Save results to database
                try:
                    import json

                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    with db_engine.begin() as conn:
                        # Check if URL exists
                        existing = conn.execute(
                            text("SELECT id FROM phishing_sites WHERE url = :url"), {"url": url}
                        ).fetchone()

                        if existing:
                            # Update existing record
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites SET
                                        last_seen = :timestamp,
                                        virustotal_result = :vt_result,
                                        urlvoid_result = :uv_result,
                                        phishtank_result = :pt_result,
                                        multi_api_threat_level = :threat_level,
                                        api_confidence_score = :confidence,
                                        auto_analysis_status = 'completed',
                                        registration_date = COALESCE(:reg_date, registration_date),
                                        registrar_name = COALESCE(:registrar, registrar_name),
                                        registrant_org = COALESCE(:registrant_org, registrant_org),
                                        domain_age_days = COALESCE(:domain_age, domain_age_days)
                                    WHERE url = :url
                                """
                                ),
                                {
                                    "timestamp": timestamp,
                                    "vt_result": json.dumps(scan_result.get("virustotal", {})),
                                    "uv_result": json.dumps(scan_result.get("urlvoid", {})),
                                    "pt_result": json.dumps(scan_result.get("phishtank", {})),
                                    "threat_level": scan_result.get("aggregated_threat_level"),
                                    "confidence": scan_result.get("confidence_score"),
                                    "reg_date": scan_result.get("registration_date"),
                                    "registrar": scan_result.get("registrar_name"),
                                    "registrant_org": scan_result.get("registrant_org"),
                                    "domain_age": scan_result.get("domain_age_days"),
                                    "url": url,
                                },
                            )
                        else:
                            # Insert new record
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO phishing_sites (
                                        url, first_seen, last_seen, source,
                                        virustotal_result, urlvoid_result, phishtank_result,
                                        multi_api_threat_level, api_confidence_score,
                                        auto_analysis_status, registration_date, registrar_name, registrant_org, domain_age_days
                                    ) VALUES (
                                        :url, :timestamp, :timestamp, 'api_scan',
                                        :vt_result, :uv_result, :pt_result,
                                        :threat_level, :confidence,
                                        'completed', :reg_date, :registrar, :registrant_org, :domain_age
                                    )
                                """
                                ),
                                {
                                    "url": url,
                                    "timestamp": timestamp,
                                    "vt_result": json.dumps(scan_result.get("virustotal", {})),
                                    "uv_result": json.dumps(scan_result.get("urlvoid", {})),
                                    "pt_result": json.dumps(scan_result.get("phishtank", {})),
                                    "threat_level": scan_result.get("aggregated_threat_level"),
                                    "confidence": scan_result.get("confidence_score"),
                                    "reg_date": scan_result.get("registration_date"),
                                    "registrar": scan_result.get("registrar_name"),
                                    "registrant_org": scan_result.get("registrant_org"),
                                    "domain_age": scan_result.get("domain_age_days"),
                                },
                            )
                    logger.info(f"✅ Scan results saved for {url}")
                except Exception as db_error:
                    logger.error(f"❌ Failed to save scan results: {db_error}")

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

    @timeout(10)  # 10 second timeout for API database operations
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
        ("manual_emails", "INTEGER DEFAULT 0"),
    ]

    # New table for tracking abuse reports (ICANN compliance)
    def create_abuse_reports_table():
        """Create table for tracking sent abuse reports"""
        with db_engine.connect() as conn:
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
            conn.commit()
            logger.info("✅ Created or verified abuse_reports table")

    create_abuse_reports_table()

    with db_engine.connect() as conn:
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

        conn.commit()

    logger.info(
        "🔧 Upgraded phishing_sites table with multi-API and auto-analysis support if necessary."
    )

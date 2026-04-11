"""
Phishing API for Anisakys Phishing Detection Engine.

REST API for external phishing reports with multi-API integration
and Grinder integration.
"""

import base64
import datetime
import json
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
from src.auth import require_api_key
from src.intelligence import (
    MultiAPIValidator,
    VIRUSTOTAL_API_KEY,
    URLVOID_API_KEY,
    PHISHTANK_API_KEY,
    GrinderReportClient,
    GRINDER_INTEGRATION_ENABLED,
)
from src.logger import logger
from src.screenshot_service import ScreenshotService, PLAYWRIGHT_AVAILABLE, SELENIUM_AVAILABLE
from src.monitoring.gsb_rescan import get_gsb_rescan_job, start_gsb_rescan_job

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

    def __init__(
        self,
        db_manager,
        abuse_detector,
        api_key: str = None,
        report_manager=None,
        scheduler=None,
        email_scheduler=None,
    ):
        """
        Initialize the Phishing API with authentication support and Grinder integration.

        Args:
            db_manager: Database manager instance
            abuse_detector: Abuse email detector instance
            api_key (str, optional): API key for authentication
            report_manager: AbuseReportManager instance for immediate report sending
            scheduler: ImageTrackingScheduler instance for on-demand searches
            email_scheduler: EmailMonitorScheduler instance for email threat monitoring
        """
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.report_manager = report_manager
        self.scheduler = scheduler
        self.email_scheduler = email_scheduler
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
        @require_api_key(scope="report")
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
        @require_api_key(scope="scan")
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

                # Resolve abuse emails for this domain
                try:
                    _domain = scan_result.get("domain", "")
                    _registrar = scan_result.get("registrar_name")
                    abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                        _domain, registrar=_registrar
                    )
                    scan_result["all_abuse_emails"] = (
                        ", ".join(abuse_emails) if abuse_emails else None
                    )
                except Exception as ae_err:
                    logger.warning(f"⚠️ Abuse email resolution failed: {ae_err}")
                    scan_result["all_abuse_emails"] = None

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
                                        domain_age_days = COALESCE(:domain_age, domain_age_days),
                                        all_abuse_emails = COALESCE(:all_abuse_emails, all_abuse_emails)
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
                                    "all_abuse_emails": scan_result.get("all_abuse_emails"),
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
                                        auto_analysis_status, registration_date, registrar_name, registrant_org, domain_age_days,
                                        all_abuse_emails
                                    ) VALUES (
                                        :url, :timestamp, :timestamp, 'api_scan',
                                        :vt_result, :uv_result, :pt_result,
                                        :threat_level, :confidence,
                                        'completed', :reg_date, :registrar, :registrant_org, :domain_age,
                                        :all_abuse_emails
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
                                    "all_abuse_emails": scan_result.get("all_abuse_emails"),
                                },
                            )
                    logger.info(f"✅ Scan results saved for {url}")

                    # Get report status info for response
                    report_info = conn.execute(
                        text(
                            """
                            SELECT last_report_sent, abuse_report_sent, all_abuse_emails
                            FROM phishing_sites WHERE url = :url
                            """
                        ),
                        {"url": url},
                    ).fetchone()
                    if report_info:
                        scan_result["last_report_sent"] = (
                            str(report_info[0]) if report_info[0] else None
                        )
                        scan_result["abuse_report_sent"] = bool(report_info[1])
                        scan_result["all_abuse_emails"] = report_info[2]

                except Exception as db_error:
                    logger.error(f"❌ Failed to save scan results: {db_error}")

                return jsonify(scan_result), 200

            except Exception as e:
                logger.error(f"❌ API error in multi_api_scan: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/status/<path:url>", methods=["GET"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="read")
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
                                   takedown_date, abuse_email, source, priority,
                                   last_report_sent, all_abuse_emails
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
                                "last_report_sent": str(result[11]) if result[11] else None,
                                "all_abuse_emails": result[12] if len(result) > 12 else None,
                            }
                        ),
                        200,
                    )

            except Exception as e:
                logger.error(f"❌ API error in get_report_status: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/grinder/test", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope="admin")
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
        @require_api_key(scope="read")
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

                    # Threat level breakdown for active sites
                    rows = conn.execute(
                        text(
                            "SELECT multi_api_threat_level, COUNT(*) FROM phishing_sites "
                            "WHERE site_status = 'up' AND multi_api_threat_level IS NOT NULL "
                            "GROUP BY multi_api_threat_level"
                        )
                    ).fetchall()
                    stats["threat_breakdown"] = {r[0]: r[1] for r in rows}

                    return jsonify(stats), 200

            except Exception as e:
                logger.error(f"❌ API error in get_stats: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/gsb/rescan", methods=["POST"])
        @self.limiter.limit("2 per minute")
        @require_api_key(scope="admin")
        def gsb_rescan():
            """
            Trigger Google Safe Browsing re-scan of existing sites.

            This re-checks sites against GSB to catch:
            - Sites that were later reported to Google
            - GSB classification changes

            Request body (optional):
            {
                "max_age_hours": 24,  // Re-scan sites not checked in X hours
                "batch_size": 50      // Number of sites to check
            }
            """
            try:
                data = request.get_json() or {}
                max_age_hours = data.get("max_age_hours", 24)
                batch_size = data.get("batch_size", 50)

                # Get or create the rescan job
                job = get_gsb_rescan_job(
                    db_manager=self.db_manager,
                    max_age_hours=max_age_hours,
                    batch_size=batch_size,
                )

                # Run a single rescan cycle
                result = job.run_once()

                return (
                    jsonify(
                        {
                            "status": "completed",
                            "sites_checked": result.get("sites_checked", 0),
                            "threats_found": result.get("threats_found", 0),
                            "status_changes": result.get("status_changes", []),
                            "errors": len(result.get("errors", [])),
                            "duration_seconds": result.get("duration_seconds", 0),
                        }
                    ),
                    200,
                )

            except Exception as e:
                logger.error(f"❌ API error in gsb_rescan: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/gsb/status", methods=["GET"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="read")
        def gsb_status():
            """Get GSB rescan job status and statistics."""
            try:
                job = get_gsb_rescan_job(db_manager=self.db_manager)
                stats = job.get_stats()

                # Get recent GSB status changes from DB
                recent_changes = self.db_manager.get_gsb_status_changes(since_hours=24)

                return (
                    jsonify(
                        {
                            "job_stats": stats,
                            "recent_threats": recent_changes,
                            "recent_threats_count": len(recent_changes),
                        }
                    ),
                    200,
                )

            except Exception as e:
                logger.error(f"❌ API error in gsb_status: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/gsb/check", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope="scan")
        def gsb_check_url():
            """
            Check a single URL against Google Safe Browsing.

            Request body:
            {
                "url": "https://example.com"
            }
            """
            try:
                data = request.get_json()
                if not data or "url" not in data:
                    return jsonify({"error": "Missing 'url' in request body"}), 400

                url = data["url"]
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                # Import GSB integration
                from src.intelligence.google_safe_browsing import GoogleSafeBrowsingIntegration

                gsb = GoogleSafeBrowsingIntegration()

                if not gsb.is_available():
                    return (
                        jsonify(
                            {
                                "error": "Google Safe Browsing API not configured",
                                "checked": False,
                            }
                        ),
                        503,
                    )

                result = gsb.check_url(url)

                return (
                    jsonify(
                        {
                            "url": url,
                            "checked": result.get("checked", False),
                            "safe": result.get("safe", True),
                            "threats_found": result.get("threats_found", []),
                            "threat_count": result.get("threat_count", 0),
                            "timestamp": result.get("timestamp"),
                            "error": result.get("error"),
                        }
                    ),
                    200,
                )

            except Exception as e:
                logger.error(f"❌ API error in gsb_check_url: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/gsb/report", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="report")
        def gsb_report_url():
            """
            Report a phishing URL to Google Safe Browsing.

            Request body:
            {
                "url": "https://phishing-example.com",
                "screenshot_base64": "optional base64 encoded screenshot"
            }
            """
            try:
                data = request.get_json()
                if not data or "url" not in data:
                    return jsonify({"error": "Missing 'url' in request body"}), 400

                url = data["url"]
                if not validators.url(url):
                    return jsonify({"error": "Invalid URL format"}), 400

                screenshot_base64 = data.get("screenshot_base64")

                # Import GSB reporter
                from src.intelligence.gsb_reporter import report_phishing_url

                result = report_phishing_url(
                    url=url,
                    screenshot_base64=screenshot_base64,
                )

                return jsonify(
                    {
                        "url": url,
                        "success": result.get("success", False),
                        "method": result.get("method"),
                        "message": result.get("message"),
                        "timestamp": result.get("timestamp"),
                    }
                ), (200 if result.get("success") else 500)

            except Exception as e:
                logger.error(f"❌ API error in gsb_report_url: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/sites ──────────────────────────────────────────────────
        @self.app.route("/api/v1/sites", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_sites():
            """List phishing sites with optional filters and pagination."""
            try:
                limit = min(int(request.args.get("limit", 100)), 500)
                offset = int(request.args.get("offset", 0))
                status_filter = request.args.get("status")
                priority_filter = request.args.get("priority")
                source_filter = request.args.get("source")
                search = request.args.get("search", "").strip()

                where_clauses = []
                params: Dict[str, Any] = {"limit": limit, "offset": offset}

                if status_filter:
                    where_clauses.append("site_status = :status")
                    params["status"] = status_filter
                if priority_filter:
                    where_clauses.append("priority = :priority")
                    params["priority"] = priority_filter
                if source_filter:
                    where_clauses.append("source = :source")
                    params["source"] = source_filter
                if search:
                    where_clauses.append("url ILIKE :search")
                    params["search"] = f"%{search}%"

                where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

                with self.db_manager.engine.begin() as conn:
                    total = conn.execute(
                        text(f"SELECT COUNT(*) FROM phishing_sites {where_sql}"), params
                    ).scalar()

                    rows = conn.execute(
                        text(
                            f"""
                            SELECT id, url, site_status, priority, source,
                                   first_seen, last_seen, multi_api_threat_level,
                                   api_confidence_score, registrar_name, domain_age_days,
                                   abuse_report_sent, manual_flag, gsb_safe,
                                   resolved_ip, is_cloudflare, description, assigned_to
                            FROM phishing_sites {where_sql}
                            ORDER BY last_seen DESC NULLS LAST
                            LIMIT :limit OFFSET :offset
                            """
                        ),
                        params,
                    ).fetchall()

                items = [
                    {
                        "id": r[0],
                        "url": r[1],
                        "site_status": r[2] or "unknown",
                        "priority": r[3] or "medium",
                        "source": r[4] or "manual",
                        "first_seen": r[5].isoformat() if r[5] else None,
                        "last_seen": r[6].isoformat() if r[6] else None,
                        "multi_api_threat_level": r[7],
                        "api_confidence_score": r[8],
                        "registrar_name": r[9],
                        "domain_age_days": r[10],
                        "abuse_report_sent": bool(r[11]),
                        "manual_flag": bool(r[12]),
                        "gsb_safe": bool(r[13]) if r[13] is not None else True,
                        "resolved_ip": r[14],
                        "is_cloudflare": bool(r[15]),
                        "description": r[16],
                        "assigned_to": r[17],
                    }
                    for r in rows
                ]

                return (
                    jsonify({"items": items, "total": total, "limit": limit, "offset": offset}),
                    200,
                )

            except Exception as e:
                logger.error(f"❌ API error in get_sites: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/reports ────────────────────────────────────────────────
        @self.app.route("/api/v1/reports", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_reports():
            """List abuse reports with threat context from phishing_sites."""
            try:
                limit = min(int(request.args.get("limit", 100)), 500)
                offset = int(request.args.get("offset", 0))
                status_filter = request.args.get("status")

                where_sql = "WHERE ar.status = :status" if status_filter else ""
                params: Dict[str, Any] = {"limit": limit, "offset": offset}
                if status_filter:
                    params["status"] = status_filter

                with self.db_manager.engine.begin() as conn:
                    total = conn.execute(
                        text(f"SELECT COUNT(*) FROM abuse_reports ar {where_sql}"), params
                    ).scalar()

                    rows = conn.execute(
                        text(
                            f"""
                            SELECT ar.report_id, ar.site_url, ar.recipients, ar.status,
                                   ar.report_date, ar.sla_deadline, ar.response_received,
                                   ar.response_date, ar.icann_compliant, ar.screenshot_included,
                                   ar.follow_up_required,
                                   ps.multi_api_threat_level, ps.api_confidence_score
                            FROM abuse_reports ar
                            LEFT JOIN phishing_sites ps ON ps.url = ar.site_url
                            {where_sql}
                            ORDER BY ar.report_date DESC NULLS LAST
                            LIMIT :limit OFFSET :offset
                            """
                        ),
                        params,
                    ).fetchall()

                items = [
                    {
                        "report_id": r[0],
                        "site_url": r[1],
                        "recipients": [e.strip() for e in (r[2] or "").split(",") if e.strip()],
                        "status": r[3] or "sent",
                        "report_date": r[4].isoformat() if r[4] else None,
                        "sla_deadline": r[5].isoformat() if r[5] else None,
                        "response_received": bool(r[6]),
                        "response_date": r[7].isoformat() if r[7] else None,
                        "icann_compliant": bool(r[8]),
                        "screenshot_included": bool(r[9]),
                        "follow_up_required": bool(r[10]),
                        "threat_level": r[11],
                        "confidence_score": r[12],
                    }
                    for r in rows
                ]

                return jsonify({"items": items, "total": total}), 200

            except Exception as e:
                logger.error(f"❌ API error in get_reports: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/reports/<report_id> ─────────────────────────────────
        @self.app.route("/api/v1/reports/<report_id>", methods=["PATCH"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def update_report(report_id: str):
            """Update abuse report status."""
            try:
                data = request.get_json() or {}
                new_status = data.get("status")
                valid = {
                    "sent",
                    "acknowledged",
                    "in_progress",
                    "resolved",
                    "rejected",
                    "timeout",
                    "bounced",
                    "pending",
                }
                if not new_status or new_status not in valid:
                    return (
                        jsonify(
                            {"error": f"Invalid status. Must be one of: {', '.join(sorted(valid))}"}
                        ),
                        400,
                    )

                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text(
                            """
                            UPDATE abuse_reports
                            SET status=:status,
                                response_date=CASE WHEN :status IN ('resolved','acknowledged') THEN NOW() ELSE response_date END,
                                response_received=CASE WHEN :status IN ('resolved','acknowledged') THEN TRUE ELSE response_received END
                            WHERE report_id=:report_id
                        """
                        ),
                        {"status": new_status, "report_id": report_id},
                    )
                    if result.rowcount == 0:
                        return jsonify({"error": "Report not found"}), 404

                return jsonify({"report_id": report_id, "status": new_status}), 200

            except Exception as e:
                logger.error(f"❌ API error in update_report: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/reports/stats ──────────────────────────────────────────
        @self.app.route("/api/v1/reports/stats", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_reports_stats():
            """Aggregate stats for the abuse reports pipeline."""
            try:
                with self.db_manager.engine.begin() as conn:
                    total = conn.execute(text("SELECT COUNT(*) FROM abuse_reports")).scalar() or 0

                    status_rows = conn.execute(
                        text("SELECT status, COUNT(*) FROM abuse_reports GROUP BY status")
                    ).fetchall()
                    status_breakdown = {r[0]: r[1] for r in status_rows}

                    responded = (
                        conn.execute(
                            text("SELECT COUNT(*) FROM abuse_reports WHERE response_received = 1")
                        ).scalar()
                        or 0
                    )

                    overdue = (
                        conn.execute(
                            text(
                                "SELECT COUNT(*) FROM abuse_reports "
                                "WHERE response_received = 0 AND sla_deadline < NOW()"
                            )
                        ).scalar()
                        or 0
                    )

                    avg_row = conn.execute(
                        text(
                            "SELECT AVG(EXTRACT(EPOCH FROM (response_date - report_date)) / 3600) "
                            "FROM abuse_reports WHERE response_received = 1 AND response_date IS NOT NULL"
                        )
                    ).scalar()

                return (
                    jsonify(
                        {
                            "total_reports": total,
                            "status_breakdown": status_breakdown,
                            "response_rate": round(responded / total, 3) if total > 0 else 0.0,
                            "overdue_reports": overdue,
                            "avg_response_time_hours": (
                                round(float(avg_row), 1) if avg_row else None
                            ),
                            "generated_at": datetime.datetime.now().isoformat(),
                        }
                    ),
                    200,
                )

            except Exception as e:
                logger.error(f"❌ API error in get_reports_stats: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/integrations ───────────────────────────────────────────
        @self.app.route("/api/v1/integrations", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_integrations():
            """Return health and circuit-breaker state of all external integrations."""
            try:

                def _cb_info(integration, name, display_name):
                    cb = getattr(integration, "circuit_breaker", None)
                    if cb is None:
                        return {
                            "name": name,
                            "display_name": display_name,
                            "status": "online",
                            "circuit_breaker": "closed",
                            "last_call_ms": None,
                            "last_success": None,
                            "error_rate": None,
                        }
                    state = cb.state.value  # 'closed' / 'open' / 'half_open'
                    stats = cb.stats
                    total = stats.total_requests or 0
                    failed = stats.failed_requests or 0
                    error_rate = round(failed / total, 3) if total > 0 else 0.0
                    status = (
                        "online"
                        if state == "closed"
                        else ("offline" if state == "open" else "degraded")
                    )
                    last_success = (
                        stats.last_state_change.isoformat()
                        if stats.last_state_change and state == "closed"
                        else None
                    )
                    return {
                        "name": name,
                        "display_name": display_name,
                        "status": status,
                        "circuit_breaker": state,
                        "last_call_ms": None,
                        "last_success": last_success,
                        "error_rate": error_rate,
                    }

                mv = self.multi_api_validator
                integrations = [
                    _cb_info(mv.virustotal, "virustotal", "VirusTotal"),
                    _cb_info(mv.urlvoid, "urlvoid", "URLVoid"),
                    _cb_info(mv.phishtank, "phishtank", "PhishTank"),
                    _cb_info(mv.google_safe_browsing, "gsb", "Google Safe Browsing"),
                    _cb_info(self.grinder_client, "grinder", "Grinder"),
                ]

                # SMTP is implicit: if grinder is off, use its config flag as proxy
                smtp_status = "online"
                if self.report_manager is not None:
                    smtp_ok = getattr(self.report_manager, "smtp_configured", True)
                    smtp_status = "online" if smtp_ok else "offline"

                integrations.append(
                    {
                        "name": "smtp",
                        "display_name": "SMTP (Abuse Reports)",
                        "status": smtp_status,
                        "circuit_breaker": "closed" if smtp_status == "online" else "open",
                        "last_call_ms": None,
                        "last_success": None,
                        "error_rate": 0.0,
                    }
                )

                return jsonify(integrations), 200

            except Exception as e:
                logger.error(f"❌ API error in get_integrations: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/activity ───────────────────────────────────────────────
        @self.app.route("/api/v1/activity", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_activity():
            """Recent platform activity: new detections, reports sent, GSB changes, takedowns."""
            try:
                limit = min(int(request.args.get("limit", 20)), 100)

                with self.db_manager.engine.begin() as conn:
                    # Recent detections (new sites)
                    detections = conn.execute(
                        text(
                            "SELECT id, url, first_seen, multi_api_threat_level, priority "
                            "FROM phishing_sites ORDER BY first_seen DESC NULLS LAST LIMIT :n"
                        ),
                        {"n": limit // 2},
                    ).fetchall()

                    # Recent abuse reports sent
                    reports = conn.execute(
                        text(
                            "SELECT report_id, site_url, report_date, status "
                            "FROM abuse_reports ORDER BY report_date DESC NULLS LAST LIMIT :n"
                        ),
                        {"n": limit // 2},
                    ).fetchall()

                    # GSB status changes (taken down sites)
                    takedowns = conn.execute(
                        text(
                            "SELECT id, url, takedown_date, multi_api_threat_level "
                            "FROM phishing_sites WHERE site_status = 'down' AND takedown_date IS NOT NULL "
                            "ORDER BY takedown_date DESC NULLS LAST LIMIT :n"
                        ),
                        {"n": limit // 4},
                    ).fetchall()

                activity: List[Dict[str, Any]] = []

                for r in detections:
                    activity.append(
                        {
                            "id": f"det-{r[0]}",
                            "type": "detection",
                            "url": r[1],
                            "timestamp": (
                                r[2].isoformat() if r[2] else datetime.datetime.now().isoformat()
                            ),
                            "detail": f"New phishing site detected — priority: {r[4] or 'medium'}",
                            "severity": r[3] or r[4] or "medium",
                        }
                    )

                for r in reports:
                    activity.append(
                        {
                            "id": f"rpt-{r[0]}",
                            "type": "report",
                            "url": r[1],
                            "timestamp": (
                                r[2].isoformat() if r[2] else datetime.datetime.now().isoformat()
                            ),
                            "detail": f"Abuse report {r[0]} — status: {r[3]}",
                            "severity": "info",
                        }
                    )

                for r in takedowns:
                    activity.append(
                        {
                            "id": f"td-{r[0]}",
                            "type": "takedown",
                            "url": r[1],
                            "timestamp": (
                                r[2].isoformat() if r[2] else datetime.datetime.now().isoformat()
                            ),
                            "detail": "Site confirmed offline / takedown successful",
                            "severity": "info",
                        }
                    )

                # Sort by timestamp descending and trim to limit
                activity.sort(key=lambda x: x["timestamp"], reverse=True)
                return jsonify(activity[:limit]), 200

            except Exception as e:
                logger.error(f"❌ API error in get_activity: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/nav/counts ─────────────────────────────────────────────
        @self.app.route("/api/v1/nav/counts", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_nav_counts():
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            """
                        SELECT
                            (SELECT COUNT(*) FROM phishing_sites WHERE site_status = 'up') AS threats,
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'running') AS threads,
                            (SELECT COUNT(DISTINCT registrar_name) FROM phishing_sites
                             WHERE registrar_name IS NOT NULL AND site_status = 'up'
                             AND registrar_name IN (
                                 SELECT registrar_name FROM phishing_sites
                                 WHERE registrar_name IS NOT NULL
                                 GROUP BY registrar_name HAVING COUNT(*) >= 2
                             )) AS campaigns
                    """
                        )
                    ).fetchone()
                return (
                    jsonify(
                        {
                            "threats": int(row[0] or 0),
                            "threads": int(row[1] or 0),
                            "campaigns": int(row[2] or 0),
                        }
                    ),
                    200,
                )
            except Exception as e:
                logger.error(f"❌ API error in get_nav_counts: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/threads ────────────────────────────────────────────────
        @self.app.route("/api/v1/threads", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_threads():
            try:
                with self.db_manager.engine.begin() as conn:
                    own_domain = (getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None) or "").lower()
                    rows = conn.execute(
                        text(
                            """
                        SELECT t.id, t.thread_type, t.label, t.status, t.started_at,
                               t.completed_at, t.results_count, t.details, t.error_message,
                               t.search_interval_hours, t.last_searched_at,
                               (SELECT COUNT(*) FROM thread_results tr
                                LEFT JOIN email_sender_reputation esr
                                    ON tr.result_type = 'email_threat'
                                    AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                                WHERE tr.thread_id = t.id
                                AND tr.status != 'discarded'
                                AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                                AND (:own_domain = '' OR tr.result_type != 'email_threat'
                                     OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                                AND (tr.result_type != 'email_threat'
                                     OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com'))) AS total_results,
                               (SELECT id FROM thread_executions te
                                WHERE te.thread_id = t.id AND te.status = 'running'
                                ORDER BY te.started_at DESC LIMIT 1) AS running_execution_id
                        FROM analysis_threads t
                        ORDER BY t.started_at DESC NULLS LAST
                    """
                        ),
                        {"own_domain": own_domain},
                    ).fetchall()
                items = []
                for r in rows:
                    db_status = r[3]
                    has_running_exec = r[12] is not None
                    if db_status == "error":
                        effective_status = "error"
                    elif db_status in ("idle", "completed", "paused"):
                        effective_status = db_status
                    else:
                        # active / running → always show as running (continuous monitor)
                        effective_status = "running"
                    items.append(
                        {
                            "id": r[0],
                            "thread_type": r[1],
                            "label": r[2],
                            "status": effective_status,
                            "started_at": str(r[4]) if r[4] else None,
                            "completed_at": str(r[5]) if r[5] else None,
                            "results_count": int(r[11] or 0),
                            "details": r[7],
                            "error_message": r[8],
                            "search_interval_hours": r[9],
                            "last_searched_at": str(r[10]) if r[10] else None,
                            "total_results": int(r[11] or 0),
                        }
                    )
                return jsonify({"items": items, "total": len(items)}), 200
            except Exception as e:
                logger.error(f"❌ API error in get_threads: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/threads/stats ──────────────────────────────────────────
        @self.app.route("/api/v1/threads/stats", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_threads_stats():
            try:
                with self.db_manager.engine.begin() as conn:
                    own_domain = (getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None) or "").lower()
                    row = conn.execute(
                        text(
                            """
                        SELECT
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'active'),
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'idle'),
                            (SELECT COUNT(*) FROM analysis_threads WHERE status = 'error'),
                            (SELECT COUNT(*) FROM thread_results tr
                             LEFT JOIN email_sender_reputation esr
                                 ON tr.result_type = 'email_threat'
                                 AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                             WHERE tr.first_detected_at >= CURRENT_DATE
                             AND tr.status != 'discarded'
                             AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                             AND (:own_domain = '' OR tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                             AND (tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com'))),
                            (SELECT COUNT(*) FROM thread_results tr
                             LEFT JOIN email_sender_reputation esr
                                 ON tr.result_type = 'email_threat'
                                 AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                             WHERE (tr.status = 'threat' OR tr.result_type = 'email_threat')
                             AND tr.status != 'discarded'
                             AND tr.first_detected_at >= CURRENT_DATE
                             AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                             AND (:own_domain = '' OR tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                             AND (tr.result_type != 'email_threat'
                                  OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com')))
                    """
                        ),
                        {"own_domain": own_domain},
                    ).fetchone()
                return (
                    jsonify(
                        {
                            "running": int(row[0] or 0),
                            "idle": int(row[1] or 0),
                            "error": int(row[2] or 0),
                            "scanned_today": int(row[3] or 0),
                            "threats_today": int(row[4] or 0),
                        }
                    ),
                    200,
                )
            except Exception as e:
                logger.error(f"❌ API error in get_threads_stats: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/threads/<id>/results ──────────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/results", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_thread_results(thread_id: int):
            try:
                limit = min(int(request.args.get("limit", 50)), 1000)
                offset = int(request.args.get("offset", 0))
                own_domain = (getattr(settings, "GOOGLE_WORKSPACE_DOMAIN", None) or "").lower()
                with self.db_manager.engine.begin() as conn:
                    total = (
                        conn.execute(
                            text(
                                """
                        SELECT COUNT(*) FROM thread_results tr
                        LEFT JOIN email_sender_reputation esr
                            ON tr.result_type = 'email_threat'
                            AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                        WHERE tr.thread_id = :tid
                        AND tr.status != 'discarded'
                        AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                        AND (:own_domain = '' OR tr.result_type != 'email_threat'
                             OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                        AND (tr.result_type != 'email_threat'
                             OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com'))
                    """
                            ),
                            {"tid": thread_id, "own_domain": own_domain},
                        ).scalar()
                        or 0
                    )
                    rows = conn.execute(
                        text(
                            """
                        SELECT tr.id, tr.result_type, tr.found_url, tr.title, tr.confidence,
                               tr.source, tr.first_detected_at, tr.last_detected_at,
                               tr.status, tr.details, tr.extra_data
                        FROM thread_results tr
                        LEFT JOIN email_sender_reputation esr
                            ON tr.result_type = 'email_threat'
                            AND LOWER(tr.extra_data->>'sender') = esr.sender_email
                        WHERE tr.thread_id = :tid
                        AND tr.status != 'discarded'
                        AND (esr.id IS NULL OR esr.whitelisted IS NOT TRUE)
                        AND (:own_domain = '' OR tr.result_type != 'email_threat'
                             OR LOWER(tr.extra_data->>'sender_domain') != :own_domain)
                        AND (tr.result_type != 'email_threat'
                             OR LOWER(tr.extra_data->>'sender_domain') NOT IN ('google.com', 'googlemail.com'))
                        ORDER BY tr.last_detected_at DESC LIMIT :lim OFFSET :off
                    """
                        ),
                        {"tid": thread_id, "lim": limit, "off": offset, "own_domain": own_domain},
                    ).fetchall()
                items = [
                    {
                        "id": r[0],
                        "result_type": r[1],
                        "found_url": r[2],
                        "title": r[3],
                        "confidence": r[4],
                        "source": r[5],
                        "first_detected_at": str(r[6]),
                        "last_detected_at": str(r[7]),
                        "status": r[8],
                        "details": r[9],
                        "extra_data": r[10],
                    }
                    for r in rows
                ]
                return jsonify({"items": items, "total": int(total)}), 200
            except Exception as e:
                logger.error(f"❌ API error in get_thread_results: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/threads/<id>/results/<result_id>/discard ────────────
        @self.app.route(
            "/api/v1/threads/<int:thread_id>/results/<int:result_id>/discard", methods=["PATCH"]
        )
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="write")
        def discard_thread_result(thread_id: int, result_id: int):
            try:
                with self.db_manager.engine.begin() as conn:
                    conn.execute(
                        text(
                            "UPDATE thread_results SET status = 'discarded' WHERE id = :rid AND thread_id = :tid"
                        ),
                        {"rid": result_id, "tid": thread_id},
                    )
                return jsonify({"discarded": result_id}), 200
            except Exception as e:
                logger.error(f"❌ API error in discard_thread_result: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/campaigns ──────────────────────────────────────────────
        @self.app.route("/api/v1/campaigns", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_campaigns():
            import datetime as _dt

            try:
                with self.db_manager.engine.begin() as conn:
                    groups = conn.execute(
                        text(
                            """
                        SELECT registrar_name,
                               COUNT(*) AS site_count,
                               COUNT(*) FILTER (WHERE site_status = 'up') AS active_count,
                               COUNT(*) FILTER (WHERE site_status = 'down') AS takedown_count,
                               MIN(first_seen) AS first_seen,
                               MAX(last_seen) AS last_activity,
                               array_agg(DISTINCT resolved_ip)
                                   FILTER (WHERE resolved_ip IS NOT NULL) AS ips,
                               AVG(api_confidence_score)
                                   FILTER (WHERE api_confidence_score IS NOT NULL) AS avg_confidence
                        FROM phishing_sites
                        WHERE registrar_name IS NOT NULL
                        GROUP BY registrar_name
                        HAVING COUNT(*) >= 2
                        ORDER BY COUNT(*) FILTER (WHERE site_status = 'up') DESC,
                                 MAX(last_seen) DESC
                    """
                        )
                    ).fetchall()

                    items = []
                    now = _dt.datetime.utcnow()
                    for i, g in enumerate(groups):
                        active_count = int(g[2] or 0)
                        last_activity = g[5]
                        stale = (
                            (now - last_activity).total_seconds() > 86400 if last_activity else True
                        )
                        if active_count > 0 and not stale:
                            status = "active"
                        elif active_count > 0:
                            status = "monitoring"
                        else:
                            status = "closed"

                        threats_rows = conn.execute(
                            text(
                                """
                            SELECT url, site_status, first_seen, multi_api_threat_level
                            FROM phishing_sites WHERE registrar_name = :r
                            ORDER BY first_seen DESC LIMIT 20
                        """
                            ),
                            {"r": g[0]},
                        ).fetchall()

                        items.append(
                            {
                                "id": f"CAMP-{i+1:03d}",
                                "name": f"{g[0]} cluster",
                                "registrar": g[0],
                                "status": status,
                                "sites": int(g[1] or 0),
                                "takedowns": int(g[3] or 0),
                                "first_seen": str(g[4]) if g[4] else None,
                                "last_activity": str(g[5]) if g[5] else None,
                                "confidence": round(float(g[7] or 0)),
                                "resolved_ips": list(g[6]) if g[6] else [],
                                "threats": [
                                    {
                                        "url": t[0],
                                        "status": t[1],
                                        "first_seen": str(t[2]),
                                        "threat_level": t[3],
                                    }
                                    for t in threats_rows
                                ],
                            }
                        )

                kpi = {
                    "active": sum(1 for c in items if c["status"] == "active"),
                    "monitoring": sum(1 for c in items if c["status"] == "monitoring"),
                    "closed": sum(1 for c in items if c["status"] == "closed"),
                    "total_sites": sum(c["sites"] for c in items),
                    "total_takedowns": sum(c["takedowns"] for c in items),
                }
                return jsonify({"items": items, "total": len(items), "kpi": kpi}), 200
            except Exception as e:
                logger.error(f"❌ API error in get_campaigns: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/intelligence/iocs ──────────────────────────────────────
        @self.app.route("/api/v1/intelligence/iocs", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_iocs():
            ioc_type = request.args.get("type", "domain")
            limit = min(int(request.args.get("limit", 100)), 500)
            offset = int(request.args.get("offset", 0))
            try:
                with self.db_manager.engine.begin() as conn:
                    if ioc_type == "ip":
                        rows = conn.execute(
                            text(
                                """
                            SELECT resolved_ip AS value,
                                   MIN(first_seen)::text AS first_seen,
                                   MAX(last_seen)::text AS last_seen,
                                   COUNT(*) AS hits,
                                   CASE WHEN bool_or(is_cloudflare = 1) THEN 'cloudflare'
                                        ELSE 'direct' END AS tag
                            FROM phishing_sites WHERE resolved_ip IS NOT NULL
                            GROUP BY resolved_ip
                            ORDER BY COUNT(*) DESC LIMIT :lim OFFSET :off
                        """
                            ),
                            {"lim": limit, "off": offset},
                        ).fetchall()
                        items = [
                            {
                                "id": f"IP-{offset+i+1}",
                                "type": "ip",
                                "value": r[0],
                                "first_seen": r[1],
                                "last_seen": r[2],
                                "threat": None,
                                "source": None,
                                "hits": int(r[3]),
                                "tags": [r[4]],
                            }
                            for i, r in enumerate(rows)
                        ]
                    elif ioc_type == "email":
                        rows = conn.execute(
                            text(
                                """
                            SELECT email, COUNT(*) AS hits
                            FROM (
                                SELECT UNNEST(STRING_TO_ARRAY(all_abuse_emails, ', ')) AS email
                                FROM phishing_sites
                                WHERE all_abuse_emails IS NOT NULL AND all_abuse_emails != ''
                            ) sub
                            GROUP BY email ORDER BY COUNT(*) DESC LIMIT :lim OFFSET :off
                        """
                            ),
                            {"lim": limit, "off": offset},
                        ).fetchall()
                        items = [
                            {
                                "id": f"E-{offset+i+1}",
                                "type": "email",
                                "value": r[0],
                                "first_seen": None,
                                "last_seen": None,
                                "threat": None,
                                "source": None,
                                "hits": int(r[1]),
                                "tags": [],
                            }
                            for i, r in enumerate(rows)
                        ]
                    else:  # domain (default)
                        rows = conn.execute(
                            text(
                                """
                            SELECT SPLIT_PART(SPLIT_PART(url, '://', 2), '/', 1) AS value,
                                   MIN(first_seen)::text AS first_seen,
                                   MAX(last_seen)::text AS last_seen,
                                   multi_api_threat_level AS threat, source,
                                   COUNT(*) AS hits
                            FROM phishing_sites WHERE url IS NOT NULL
                            GROUP BY value, multi_api_threat_level, source
                            ORDER BY MAX(last_seen) DESC LIMIT :lim OFFSET :off
                        """
                            ),
                            {"lim": limit, "off": offset},
                        ).fetchall()
                        items = [
                            {
                                "id": f"D-{offset+i+1}",
                                "type": "domain",
                                "value": r[0],
                                "first_seen": r[1],
                                "last_seen": r[2],
                                "threat": r[3],
                                "source": r[4],
                                "hits": int(r[5]),
                                "tags": [],
                            }
                            for i, r in enumerate(rows)
                        ]

                    counts_row = conn.execute(
                        text(
                            """
                        SELECT
                            COUNT(DISTINCT SPLIT_PART(SPLIT_PART(url,'://',2),'/',1)),
                            COUNT(DISTINCT resolved_ip),
                            (SELECT COUNT(DISTINCT e)
                             FROM (SELECT UNNEST(STRING_TO_ARRAY(all_abuse_emails,', ')) AS e
                                   FROM phishing_sites
                                   WHERE all_abuse_emails IS NOT NULL
                                   AND all_abuse_emails != '') sub)
                        FROM phishing_sites
                    """
                        )
                    ).fetchone()

                return (
                    jsonify(
                        {
                            "items": items,
                            "total": len(items),
                            "counts": {
                                "domain": int(counts_row[0] or 0),
                                "ip": int(counts_row[1] or 0),
                                "email": int(counts_row[2] or 0),
                            },
                        }
                    ),
                    200,
                )
            except Exception as e:
                logger.error(f"❌ API error in get_iocs: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/intelligence/brands ───────────────────────────────────
        @self.app.route("/api/v1/intelligence/brands", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_brands():
            try:
                keywords = [k.strip() for k in settings.KEYWORDS.split(",") if k.strip()]
                results = []
                with self.db_manager.engine.begin() as conn:
                    for kw in keywords:
                        pat = f"%{kw}%"
                        total = (
                            conn.execute(
                                text("SELECT COUNT(*) FROM phishing_sites WHERE url ILIKE :p"),
                                {"p": pat},
                            ).scalar()
                            or 0
                        )
                        if total == 0:
                            continue
                        active = (
                            conn.execute(
                                text(
                                    "SELECT COUNT(*) FROM phishing_sites "
                                    "WHERE url ILIKE :p AND site_status = 'up'"
                                ),
                                {"p": pat},
                            ).scalar()
                            or 0
                        )
                        results.append(
                            {
                                "name": kw.capitalize(),
                                "sites": int(total),
                                "active": int(active),
                            }
                        )
                results.sort(key=lambda x: x["sites"], reverse=True)
                return jsonify(results), 200
            except Exception as e:
                logger.error(f"❌ API error in get_brands: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── POST /api/v1/threads/image-tracking ───────────────────────────────
        @self.app.route("/api/v1/threads/image-tracking", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="write")
        def create_image_tracking_thread():
            data = request.get_json(silent=True) or {}
            label = data.get("label")
            s3_key = data.get("s3_key")
            search_interval_hours = data.get("search_interval_hours")
            if not s3_key:
                return jsonify({"error": "s3_key is required"}), 400
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads "
                            "(thread_type, label, status, image_s3_key, search_interval_hours) "
                            "VALUES ('image_tracking', :label, 'active', :s3_key, :interval) "
                            "RETURNING id"
                        ),
                        {"label": label, "s3_key": s3_key, "interval": search_interval_hours},
                    ).fetchone()
                    thread_id = row[0]
                if self.scheduler and self.scheduler.client:
                    threading.Thread(
                        target=self._trigger_image_search,
                        args=(thread_id, s3_key),
                        daemon=True,
                    ).start()
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                logger.error(f"❌ create_image_tracking_thread: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── POST /api/v1/threads/google-ads ───────────────────────────────────
        @self.app.route("/api/v1/threads/google-ads", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="write")
        def create_google_ads_thread():
            data = request.get_json(silent=True) or {}
            label = data.get("label")
            keyword = data.get("keyword")
            location = data.get("location")
            if not keyword or not location:
                return jsonify({"error": "keyword and location are required"}), 400
            details = {
                "keyword": keyword,
                "location": location,
                "country_code": data.get("country_code", "us"),
                "language": data.get("language", "en"),
            }
            search_interval_hours = data.get("search_interval_hours")
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads "
                            "(thread_type, label, status, details, search_interval_hours) "
                            "VALUES ('google_ads', :label, 'active', :details::jsonb, :interval) "
                            "RETURNING id"
                        ),
                        {
                            "label": label,
                            "details": json.dumps(details),
                            "interval": search_interval_hours,
                        },
                    ).fetchone()
                    thread_id = row[0]
                if self.scheduler and self.scheduler.ads_client:
                    threading.Thread(
                        target=self._trigger_ads_search,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                logger.error(f"❌ create_google_ads_thread: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── POST /api/v1/threads/<id>/search ──────────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/search", methods=["POST"])
        @self.limiter.limit("5 per minute")
        @require_api_key(scope="write")
        def trigger_thread_search(thread_id: int):
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "SELECT thread_type, image_s3_key, details FROM analysis_threads "
                            "WHERE id = :id"
                        ),
                        {"id": thread_id},
                    ).fetchone()
                if not row:
                    return jsonify({"error": "Thread not found"}), 404
                thread_type, s3_key, details = row[0], row[1], row[2]
                if thread_type == "image_tracking":
                    if not self.scheduler:
                        return (
                            jsonify(
                                {"error": "Scheduler not available (SERPAPI_KEY not configured)"}
                            ),
                            503,
                        )
                    if not self.scheduler.client:
                        return jsonify({"error": "Image search client not available"}), 503
                    threading.Thread(
                        target=self._trigger_image_search,
                        args=(thread_id, s3_key),
                        daemon=True,
                    ).start()
                elif thread_type == "google_ads":
                    if not self.scheduler:
                        return (
                            jsonify(
                                {"error": "Scheduler not available (SERPAPI_KEY not configured)"}
                            ),
                            503,
                        )
                    if not self.scheduler.ads_client:
                        return jsonify({"error": "Ads search client not available"}), 503
                    threading.Thread(
                        target=self._trigger_ads_search,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                elif thread_type == "email_monitor":
                    if not self.email_scheduler:
                        return jsonify({"error": "Email monitoring not configured"}), 503
                    threading.Thread(
                        target=self._trigger_email_scan,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                else:
                    return (
                        jsonify(
                            {
                                "error": f"Manual search not supported for thread_type '{thread_type}'"
                            }
                        ),
                        400,
                    )
                return jsonify({"status": "search_triggered", "thread_id": thread_id}), 202
            except Exception as e:
                logger.error(f"❌ trigger_thread_search: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/threads/<id> ─────────────────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def update_thread(thread_id: int):
            data = request.get_json(silent=True) or {}
            allowed = {"label": str, "status": str, "search_interval_hours": int}
            updates, params = [], {"id": thread_id}
            for field, cast in allowed.items():
                if field in data:
                    updates.append(f"{field} = :{field}")
                    params[field] = cast(data[field]) if data[field] is not None else None
            if not updates:
                return jsonify({"error": "No valid fields to update"}), 400
            try:
                with self.db_manager.engine.begin() as conn:
                    conn.execute(
                        text(f"UPDATE analysis_threads SET {', '.join(updates)} WHERE id = :id"),
                        params,
                    )
                return jsonify({"status": "updated"}), 200
            except Exception as e:
                logger.error(f"❌ update_thread: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/threads/<id>/results/<rid> ──────────────────────────
        @self.app.route(
            "/api/v1/threads/<int:thread_id>/results/<int:result_id>", methods=["PATCH"]
        )
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def update_thread_result(thread_id: int, result_id: int):
            data = request.get_json(silent=True) or {}
            allowed = {"status": str, "assigned_to": str}
            updates, params = [], {"id": result_id, "tid": thread_id}
            for field, cast in allowed.items():
                if field in data:
                    updates.append(f"{field} = :{field}")
                    params[field] = cast(data[field]) if data[field] is not None else None
            if not updates:
                return jsonify({"error": "No valid fields to update"}), 400
            try:
                with self.db_manager.engine.begin() as conn:
                    conn.execute(
                        text(
                            f"UPDATE thread_results SET {', '.join(updates)} "
                            "WHERE id = :id AND thread_id = :tid"
                        ),
                        params,
                    )
                return jsonify({"status": "updated"}), 200
            except Exception as e:
                logger.error(f"❌ update_thread_result: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/threads/<id>/executions ───────────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/executions", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_thread_executions(thread_id: int):
            limit = min(int(request.args.get("limit", 20)), 100)
            offset = int(request.args.get("offset", 0))
            try:
                with self.db_manager.engine.begin() as conn:
                    exists = conn.execute(
                        text("SELECT id FROM analysis_threads WHERE id = :id"),
                        {"id": thread_id},
                    ).fetchone()
                    if not exists:
                        return jsonify({"error": "Thread not found"}), 404
                    total = (
                        conn.execute(
                            text("SELECT COUNT(*) FROM thread_executions WHERE thread_id = :tid"),
                            {"tid": thread_id},
                        ).scalar()
                        or 0
                    )
                    rows = conn.execute(
                        text(
                            "SELECT id, execution_type, started_at, completed_at, status, "
                            "results_count, error_message, details "
                            "FROM thread_executions WHERE thread_id = :tid "
                            "ORDER BY started_at DESC NULLS LAST LIMIT :lim OFFSET :off"
                        ),
                        {"tid": thread_id, "lim": limit, "off": offset},
                    ).fetchall()
                items = [
                    {
                        "id": r[0],
                        "execution_type": r[1],
                        "started_at": str(r[2]) if r[2] else None,
                        "completed_at": str(r[3]) if r[3] else None,
                        "status": r[4],
                        "results_count": int(r[5] or 0),
                        "error_message": r[6],
                        "details": r[7],
                    }
                    for r in rows
                ]
                return jsonify({"items": items, "total": int(total)}), 200
            except Exception as e:
                logger.error(f"❌ get_thread_executions: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── POST /api/v1/threads/email-monitor ───────────────────────────────
        @self.app.route("/api/v1/threads/email-monitor", methods=["POST"])
        @self.limiter.limit("10 per minute")
        @require_api_key(scope="write")
        def create_email_monitor_thread():
            data = request.get_json(silent=True) or {}
            label = data.get("label")
            target_mailbox = data.get("target_mailbox")
            domain = data.get("domain")
            admin_email = data.get("admin_email")

            if not target_mailbox and not domain:
                return jsonify({"error": "Either target_mailbox or domain is required"}), 400

            if domain:
                details = {
                    "domain": domain,
                    "admin_email": admin_email,
                    "exclude_domains": data.get("exclude_domains", []),
                    "exclude_users": data.get("exclude_users", []),
                    "last_history_ids": {},
                }
            else:
                details = {
                    "target_mailbox": target_mailbox,
                    "exclude_domains": data.get("exclude_domains", []),
                    "last_history_id": None,
                }

            search_interval_hours = data.get("search_interval_hours", 1)
            try:
                with self.db_manager.engine.begin() as conn:
                    row = conn.execute(
                        text(
                            "INSERT INTO analysis_threads "
                            "(thread_type, label, status, details, search_interval_hours) "
                            "VALUES ('email_monitor', :label, 'active', CAST(:details AS JSONB), :interval) "
                            "RETURNING id"
                        ),
                        {
                            "label": label,
                            "details": json.dumps(details),
                            "interval": search_interval_hours,
                        },
                    ).fetchone()
                    thread_id = row[0]
                if self.email_scheduler:
                    threading.Thread(
                        target=self._trigger_email_scan,
                        args=(thread_id, details),
                        daemon=True,
                    ).start()
                return jsonify({"id": thread_id, "status": "active"}), 201
            except Exception as e:
                logger.error(f"❌ create_email_monitor_thread: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/threads/<id>/email-inboxes ───────────────────────────
        @self.app.route("/api/v1/threads/<int:thread_id>/email-inboxes", methods=["GET"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="read")
        def get_thread_email_inboxes(thread_id: int):
            """Aggregate email scan results grouped by recipient inbox."""
            try:
                with self.db_manager.engine.begin() as conn:
                    exists = conn.execute(
                        text("SELECT id FROM analysis_threads WHERE id = :id"),
                        {"id": thread_id},
                    ).fetchone()
                    if not exists:
                        return jsonify({"error": "Thread not found"}), 404

                    rows = conn.execute(
                        text(
                            """
                            SELECT
                                extra_data->>'inbox' AS inbox,
                                COUNT(*) AS threat_count,
                                MAX((extra_data->>'threat_score')::int) AS max_score,
                                AVG((extra_data->>'threat_score')::float)::int AS avg_score,
                                MAX(first_detected_at) AS last_threat_at
                            FROM thread_results
                            WHERE thread_id = :tid
                              AND extra_data->>'inbox' IS NOT NULL
                            GROUP BY extra_data->>'inbox'
                            ORDER BY max_score DESC, threat_count DESC
                            """
                        ),
                        {"tid": thread_id},
                    ).fetchall()

                    items = [
                        {
                            "inbox": r[0],
                            "threat_count": r[1],
                            "max_score": r[2],
                            "avg_score": r[3],
                            "last_threat_at": str(r[4]) if r[4] else None,
                        }
                        for r in rows
                    ]
                    return jsonify({"items": items, "total": len(items)}), 200
            except Exception as e:
                logger.error(f"❌ get_thread_email_inboxes: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/email/senders ─────────────────────────────────────────
        @self.app.route("/api/v1/email/senders", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def list_email_senders():
            from src.intelligence.email_reputation import SenderReputationTracker

            blocked_only = request.args.get("blocked_only", "false").lower() == "true"
            whitelisted_only = request.args.get("whitelisted_only", "false").lower() == "true"
            limit = min(int(request.args.get("limit", 50)), 200)
            offset = int(request.args.get("offset", 0))
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    items, total = tracker.list_senders(
                        conn,
                        blocked_only=blocked_only,
                        whitelisted_only=whitelisted_only,
                        limit=limit,
                        offset=offset,
                    )
                return jsonify({"items": items, "total": total}), 200
            except Exception as e:
                logger.error(f"❌ list_email_senders: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/email/senders/<email>/reputation ──────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/reputation", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def get_sender_reputation(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    rep = tracker.get_reputation(conn, sender_email)
                if not rep:
                    return jsonify({"error": "Sender not found"}), 404
                return jsonify(rep), 200
            except Exception as e:
                logger.error(f"❌ get_sender_reputation: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/email/senders/<email>/block ─────────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/block", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def block_sender(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            data = request.get_json(silent=True) or {}
            reason = data.get("reason", "Manual block by admin")
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM email_sender_reputation WHERE sender_email = :email"),
                        {"email": sender_email.lower()},
                    ).fetchone()
                    if not existing:
                        return jsonify({"error": "Sender not found"}), 404
                    tracker.mark_blocked(conn, sender_email, reason)
                return jsonify({"status": "blocked", "sender": sender_email}), 200
            except Exception as e:
                logger.error(f"❌ block_sender: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/email/senders/<email>/unblock ───────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/unblock", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def unblock_sender(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM email_sender_reputation WHERE sender_email = :email"),
                        {"email": sender_email.lower()},
                    ).fetchone()
                    if not existing:
                        return jsonify({"error": "Sender not found"}), 404
                    tracker.mark_unblocked(conn, sender_email)
                return jsonify({"status": "unblocked", "sender": sender_email}), 200
            except Exception as e:
                logger.error(f"❌ unblock_sender: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── PATCH /api/v1/email/senders/<email>/whitelist ─────────────────────
        @self.app.route("/api/v1/email/senders/<path:sender_email>/whitelist", methods=["PATCH"])
        @self.limiter.limit("20 per minute")
        @require_api_key(scope="write")
        def whitelist_sender(sender_email: str):
            from src.intelligence.email_reputation import SenderReputationTracker

            data = request.get_json(silent=True) or {}
            reason = data.get("reason", "Manual whitelist by admin")
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    existing = conn.execute(
                        text("SELECT id FROM email_sender_reputation WHERE sender_email = :email"),
                        {"email": sender_email.lower()},
                    ).fetchone()
                    if not existing:
                        # Auto-create a reputation record so we can whitelist unknown senders
                        conn.execute(
                            text(
                                "INSERT INTO email_sender_reputation "
                                "(sender_email, sender_domain, whitelisted, whitelisted_at, whitelist_reason) "
                                "VALUES (:email, :domain, TRUE, NOW(), :reason) "
                                "ON CONFLICT (sender_email) DO UPDATE SET "
                                "whitelisted = TRUE, whitelisted_at = NOW(), whitelist_reason = :reason, "
                                "blocked = FALSE, blocked_at = NULL, block_reason = NULL"
                            ),
                            {
                                "email": sender_email.lower(),
                                "domain": (
                                    sender_email.split("@")[-1].lower()
                                    if "@" in sender_email
                                    else sender_email.lower()
                                ),
                                "reason": reason,
                            },
                        )
                    else:
                        tracker.mark_whitelisted(conn, sender_email, reason)
                return jsonify({"status": "whitelisted", "sender": sender_email}), 200
            except Exception as e:
                logger.error(f"❌ whitelist_sender: {e}")
                return jsonify({"error": "Internal server error"}), 500

        # ── GET /api/v1/email/domains ─────────────────────────────────────────
        @self.app.route("/api/v1/email/domains", methods=["GET"])
        @self.limiter.limit("30 per minute")
        @require_api_key(scope="read")
        def list_email_domains():
            from src.intelligence.email_reputation import SenderReputationTracker

            blocked_only = request.args.get("blocked_only", "false").lower() == "true"
            limit = min(int(request.args.get("limit", 50)), 200)
            offset = int(request.args.get("offset", 0))
            try:
                tracker = SenderReputationTracker()
                with self.db_manager.engine.begin() as conn:
                    items, total = tracker.list_domains(
                        conn, blocked_only=blocked_only, limit=limit, offset=offset
                    )
                return jsonify({"items": items, "total": total}), 200
            except Exception as e:
                logger.error(f"❌ list_email_domains: {e}")
                return jsonify({"error": "Internal server error"}), 500

        @self.app.route("/api/v1/health", methods=["GET"])
        @self.limiter.exempt
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

        @self.app.route("/metrics", methods=["GET"])
        @self.limiter.exempt
        def prometheus_metrics():
            """Prometheus metrics endpoint (no authentication required)."""
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

            return self.app.response_class(
                generate_latest(),
                mimetype=CONTENT_TYPE_LATEST,
            )

    def _trigger_image_search(self, thread_id: int, s3_key: str):
        """Run an image tracking search in a fresh DB connection (for background threads)."""
        try:
            with self.db_manager.engine.begin() as conn:
                self.scheduler._run_image_tracking(conn, thread_id, s3_key)
        except Exception as e:
            logger.error(f"❌ _trigger_image_search thread {thread_id}: {e}")

    def _trigger_ads_search(self, thread_id: int, details):
        """Run a google_ads search in a fresh DB connection (for background threads)."""
        try:
            with self.db_manager.engine.begin() as conn:
                self.scheduler._run_google_ads(conn, thread_id, details)
        except Exception as e:
            logger.error(f"❌ _trigger_ads_search thread {thread_id}: {e}")

    def _trigger_email_scan(self, thread_id: int, details):
        """Run an email_monitor scan — manages its own transactions internally."""
        try:
            self.email_scheduler._run_email_monitor(thread_id, details)
        except Exception as e:
            logger.error(f"❌ _trigger_email_scan thread {thread_id}: {e}")

    @timeout(10)  # 10 second timeout for API database operations
    def process_phishing_report(
        self, url: str, abuse_email: Optional[str], source: str, priority: str, description: str
    ) -> Dict[str, Any]:
        """Process a phishing report from the API."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            abuse_emails = []
            all_abuse_emails = None
            is_new = False

            # TRANSACTION 1: Check and update/insert record
            with self.db_manager.engine.begin() as conn:
                # Check if URL already exists
                existing = conn.execute(
                    text("SELECT id, manual_flag FROM phishing_sites WHERE url = :url"),
                    {"url": url},
                ).fetchone()

                if existing:
                    # Check if existing record has abuse_email and all_abuse_emails
                    existing_abuse = conn.execute(
                        text(
                            "SELECT abuse_email, all_abuse_emails FROM phishing_sites WHERE url = :url"
                        ),
                        {"url": url},
                    ).fetchone()

                    # Resolve abuse emails if needed
                    needs_resolution = (
                        not abuse_email and (not existing_abuse or not existing_abuse[0])
                    ) or (not existing_abuse or not existing_abuse[1])

                    if needs_resolution:
                        try:
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
                            registrar = self.abuse_detector.extract_registrar(whois_info)
                            abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                                domain, whois_info, registrar
                            )
                            if abuse_emails:
                                abuse_email = abuse_emails[0]
                                all_abuse_emails = ", ".join(abuse_emails)
                                logger.info(
                                    f"🔍 Resolved {len(abuse_emails)} abuse emails for {url}: {all_abuse_emails}"
                                )
                        except Exception as e:
                            logger.warning(f"⚠️  Failed to auto-detect abuse email for {url}: {e}")

                    # Update existing record
                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET manual_flag = 1, last_seen = :timestamp,
                                abuse_email = COALESCE(:abuse_email, abuse_email),
                                all_abuse_emails = COALESCE(:all_abuse_emails, all_abuse_emails),
                                source = :source, priority = :priority, description = :description
                            WHERE url = :url
                        """
                        ),
                        {
                            "timestamp": timestamp,
                            "abuse_email": abuse_email,
                            "all_abuse_emails": all_abuse_emails,
                            "source": source,
                            "priority": priority,
                            "description": description,
                            "url": url,
                        },
                    )
                    logger.info(f"✅ Updated existing phishing report for {url}")

                    # Get abuse_emails from existing record if not resolved
                    if not abuse_emails and existing_abuse:
                        if existing_abuse[1]:
                            abuse_emails = [
                                e.strip() for e in existing_abuse[1].split(",") if e.strip()
                            ]
                        elif existing_abuse[0]:
                            abuse_emails = [existing_abuse[0]]
                else:
                    is_new = True
                    # Resolve abuse emails for new record
                    if not abuse_email:
                        try:
                            domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                            whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
                            registrar = self.abuse_detector.extract_registrar(whois_info)
                            abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                                domain, whois_info, registrar
                            )
                            if abuse_emails:
                                abuse_email = abuse_emails[0]
                                all_abuse_emails = ", ".join(abuse_emails)
                                logger.info(
                                    f"🔍 Resolved {len(abuse_emails)} abuse emails for {url}: {all_abuse_emails}"
                                )
                        except Exception as e:
                            logger.warning(f"⚠️  Failed to auto-detect abuse email for {url}: {e}")

                    # Create new record
                    conn.execute(
                        text(
                            """
                            INSERT INTO phishing_sites
                            (url, manual_flag, first_seen, last_seen, abuse_email, all_abuse_emails,
                             reported, abuse_report_sent, source, priority, description)
                            VALUES (:url, 1, :timestamp, :timestamp, :abuse_email, :all_abuse_emails,
                                    0, 0, :source, :priority, :description)
                        """
                        ),
                        {
                            "url": url,
                            "timestamp": timestamp,
                            "abuse_email": abuse_email,
                            "all_abuse_emails": all_abuse_emails,
                            "source": source,
                            "priority": priority,
                            "description": description,
                        },
                    )
                    logger.info(f"✅ Created new phishing report for {url}")

            # TRANSACTION 1 CLOSED - Now send report OUTSIDE transaction
            report_sent = False
            report_recipients = []
            last_report_sent = None

            if self.report_manager and abuse_emails:
                try:
                    logger.info(
                        f"📧 Sending immediate abuse report for {url} to {len(abuse_emails)} recipients"
                    )
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    whois_info = self.abuse_detector.get_enhanced_whois_info(domain)
                    whois_str = str(whois_info)
                    report_sent = self.report_manager.send_abuse_report(
                        abuse_emails, url, whois_str
                    )
                    if report_sent:
                        report_recipients = abuse_emails
                        last_report_sent = timestamp
                        # TRANSACTION 2: Update report status
                        with self.db_manager.engine.begin() as conn2:
                            conn2.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET abuse_report_sent = 1, last_report_sent = :timestamp, reported = 1
                                    WHERE url = :url
                                    """
                                ),
                                {"timestamp": timestamp, "url": url},
                            )
                        logger.info(f"✅ Immediate abuse report sent for {url}")
                except Exception as e:
                    logger.error(f"❌ Failed to send immediate abuse report: {e}")

            if is_new:
                return {
                    "status": "created",
                    "message": f"Created new report for {url}",
                    "url": url,
                    "abuse_email": abuse_email,
                    "abuse_emails_count": len(abuse_emails) if abuse_emails else 0,
                    "timestamp": timestamp,
                    "report_sent": report_sent,
                    "report_recipients": report_recipients,
                    "last_report_sent": last_report_sent,
                }
            else:
                return {
                    "status": "updated",
                    "message": f"Updated existing report for {url}",
                    "url": url,
                    "timestamp": timestamp,
                    "abuse_email_resolved": abuse_email is not None,
                    "abuse_emails_count": len(abuse_emails) if abuse_emails else 0,
                    "report_sent": report_sent,
                    "report_recipients": report_recipients,
                    "last_report_sent": last_report_sent,
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

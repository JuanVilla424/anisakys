"""
Abuse Report Manager for Anisakys Phishing Detection Engine.

Enhanced abuse report manager with Grinder integration for IP reporting.
"""

from __future__ import annotations

import datetime
import os
import re
import smtplib
import threading
import time
import traceback
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import text

from src.config import settings
from src.data import ASN_ABUSE_EMAIL_DB, PROVIDER_ABUSE_EMAIL_DB
from src.intelligence import GrinderReportClient, GRINDER_INTEGRATION_ENABLED, MultiAPIValidator
from src.logger import logger
from src.models import AttachmentConfig
from src.abuse_contact_validator import AbuseContactValidator
from src.screenshot_service import ScreenshotService
from src.report_tracker import ReportTracker
from src.shutdown import shutdown_requested


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
            default_cc = (
                getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                else None
            )
            self.cc_emails = (
                [email.strip() for email in default_cc.split(",")] if default_cc else []
            )
        else:
            self.cc_emails = cc_emails
        self.timeout = timeout
        self.monitoring_event = monitoring_event

        # Initialize running flag for followup worker
        self.running = True

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
        """Get abuse emails using enhanced detection methods, checking cached tables first."""
        abuse_emails = []

        # Extract registrar and check cached table first
        registrar = self.abuse_detector.extract_registrar(whois_info) or ""
        if registrar:
            cached_emails = self.db_manager.get_registrar_abuse_emails(registrar)
            if cached_emails:
                logger.info(f"📚 Found cached registrar emails for {registrar}: {cached_emails}")
                # Parse if it's a JSON string
                try:
                    if cached_emails.startswith("["):
                        abuse_emails.extend(json.loads(cached_emails))
                    else:
                        abuse_emails.extend(
                            [e.strip() for e in cached_emails.split(",") if e.strip()]
                        )
                except:
                    abuse_emails.append(cached_emails)

        # Check hosting provider cache
        try:
            ip = socket.gethostbyname(domain)
            asn_info = self.abuse_detector.get_asn_info(ip)
            if asn_info and asn_info.get("provider"):
                provider = asn_info["provider"]
                asn = asn_info.get("asn")
                cached_hosting = self.db_manager.get_hosting_abuse_emails(provider, asn)
                if cached_hosting:
                    logger.info(f"📚 Found cached hosting emails for {provider}: {cached_hosting}")
                    try:
                        if cached_hosting.startswith("["):
                            abuse_emails.extend(json.loads(cached_hosting))
                        else:
                            abuse_emails.extend(
                                [e.strip() for e in cached_hosting.split(",") if e.strip()]
                            )
                    except:
                        abuse_emails.append(cached_hosting)
        except:
            pass

        # If no cached emails found, use the enhanced detection method
        if not abuse_emails:
            abuse_emails = self.abuse_detector.get_enhanced_abuse_email(
                domain, whois_info, registrar
            )

            # If still no emails found, try fallback methods with domain validation
            if not abuse_emails:
                whois_str = str(whois_info)
                emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", whois_str)
                for email in emails:
                    if "abuse" in email.lower() and self.abuse_detector.validate_abuse_email_domain(
                        email, domain
                    ):
                        abuse_emails.append(email)

        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in abuse_emails:
            if email and email not in seen:
                seen.add(email)
                unique_emails.append(email)

        return unique_emails

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
        smtp_user = getattr(settings, "SMTP_USER") if hasattr(settings, "SMTP_USER") else None
        smtp_pass = getattr(settings, "SMTP_PASS") if hasattr(settings, "SMTP_PASS") else None
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
                    log_with_context(
                        logger,
                        logging.ERROR,
                        "No abuse emails found - cannot send report",
                        url=site_url,
                        event_type="no_abuse_emails_found",
                    )
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
                    site_url, use_async=True
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
                    escalation2 = (
                        getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                        if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                        else None
                    )
                    escalation3 = (
                        getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3")
                        if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3")
                        else None
                    )
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
                                max_size_mb = getattr(settings, "MAX_ATTACHMENT_SIZE_MB", 25)
                                max_size = max_size_mb * 1024 * 1024
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
                max_email_size_mb = getattr(settings, "MAX_EMAIL_SIZE_MB", 50)
                max_email_size = max_email_size_mb * 1024 * 1024
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
                with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
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
                log_error(
                    logger,
                    e,
                    {
                        "recipient": primary,
                        "url": site_url,
                        "operation": "send_abuse_email",
                        "event_type": "abuse_report_send_failed",
                    },
                )
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

                # Database update with new connection and autocommit
                try:
                    logger.info(f"📊 Updating database to mark {site_url} as reported")

                    # Use direct psycopg2 connection to avoid SQLAlchemy hanging
                    import psycopg2
                    from urllib.parse import urlparse

                    # Parse DATABASE_URL
                    parsed = urlparse(DATABASE_URL)

                    conn_update = psycopg2.connect(
                        host=parsed.hostname,
                        port=parsed.port,
                        database=parsed.path[1:],  # Remove leading slash
                        user=parsed.username,
                        password=parsed.password,
                    )
                    conn_update.autocommit = True

                    cursor_update = conn_update.cursor()
                    cursor_update.execute(
                        "UPDATE phishing_sites SET reported = 1, abuse_report_sent = 1 WHERE url = %s",
                        (site_url,),
                    )
                    logger.info(
                        f"✅ Database updated: Set reported=1 for {site_url} ({cursor_update.rowcount} rows)"
                    )

                    cursor_update.close()
                    conn_update.close()

                except Exception as e:
                    logger.error(f"❌ Database update failed: {e}")
                    raise  # Re-raise to ensure we know about failures

                # Try to track the report - if this fails, continue anyway since emails were sent
                try:
                    logger.info(f"📋 Creating report record for tracking")
                    report_record = create_report_record(
                        site_url=site_url,
                        recipients=abuse_emails,
                        subject=subject,
                        cc_recipients=final_cc,
                        multi_api_results=multi_api_results,
                        screenshot_included=screenshot_included,
                    )

                    # Track report with timeout to prevent hanging
                    try:

                        @timeout(5)  # 5 second timeout for database operations
                        def track_with_timeout():
                            return self.report_tracker.track_report(report_record)

                        if track_with_timeout():
                            logger.info(f"📋 Abuse report tracked: {report_record.report_id}")
                        else:
                            logger.warning(
                                "⚠️  Failed to track abuse report in database (emails were sent successfully)"
                            )
                    except TimeoutError:
                        logger.error(
                            "❌ Database operation timed out - report was sent but not tracked"
                        )
                    except Exception as e:
                        log_error(
                            logger,
                            e,
                            {
                                "url": site_url,
                                "operation": "track_report",
                                "event_type": "report_tracking_failed",
                            },
                        )

                except Exception as track_error:
                    log_error(
                        logger,
                        track_error,
                        {
                            "url": site_url,
                            "operation": "track_report_outer",
                            "emails_sent": True,
                            "event_type": "report_tracking_failed_after_send",
                        },
                    )

            except Exception as db_error:
                log_with_context(
                    logger,
                    logging.ERROR,
                    "CRITICAL: Failed to mark site as reported - infinite loop risk",
                    url=site_url,
                    error=str(db_error),
                    event_type="critical_db_update_failed",
                )
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

                    # Double-check if site is still up before sending follow-up
                    domain = re.sub(r"^https?://", "", site_url).strip().split("/")[0]
                    resolved_ip, _ = get_ip_info(domain)
                    current_status, _ = PhishingUtils.determine_site_status(
                        site_url,
                        resolved_ip,
                        None,
                        None,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        self.timeout,
                    )

                    # Update site status in database regardless of status
                    try:
                        with self.db_manager.engine.begin() as conn:
                            conn.execute(
                                text(
                                    """UPDATE phishing_sites
                                    SET site_status = :status,
                                        last_seen = CURRENT_TIMESTAMP,
                                        takedown_date = CASE
                                            WHEN :status = 'down' THEN CURRENT_TIMESTAMP
                                            ELSE takedown_date
                                        END
                                    WHERE url = :url"""
                                ),
                                {"status": current_status, "url": site_url},
                            )
                            logger.info(
                                f"✅ Updated site status to {current_status} for {site_url}"
                            )
                    except Exception as e:
                        logger.error(f"❌ Error updating site status: {e}")

                    # Skip follow-up if site is down
                    if current_status in ["down", "timeout", "resolved"]:
                        logger.info(
                            f"🎯 Site {site_url} is now {current_status}, skipping follow-up"
                        )
                        continue

                    # Get original recipients
                    recipients = json.loads(report["recipients"]) if report["recipients"] else []

                    if not recipients:
                        logger.warning(f"⚠️  No recipients found for {report_id}, skipping")
                        continue

                    # Prepare follow-up email subject with site URL
                    follow_up_subject = f"FOLLOW-UP: Phishing Report {report_id} for {site_url} - Response Required (ICANN Compliance)"

                    # Add escalation CCs for overdue reports
                    escalation_cc = self.cc_emails.copy() if self.cc_emails else []

                    # Always include sender email in CC for follow-ups
                    sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")
                    if sender_email and sender_email not in escalation_cc:
                        escalation_cc.append(sender_email)

                    # Add escalation based on how overdue
                    if overdue_hours > 48:  # 2+ days overdue - Level 2 escalation
                        escalation_level2 = (
                            getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                            if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL2")
                            else None
                        )
                        if escalation_level2:
                            for email in escalation_level2.split(","):
                                email = email.strip()
                                if email and email not in escalation_cc:
                                    escalation_cc.append(email)

                    if overdue_hours > 72:  # 3+ days overdue - Level 3 escalation
                        escalation_level3 = (
                            getattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3")
                            if hasattr(settings, "DEFAULT_CC_EMAILS_ESCALATION_LEVEL3")
                            else None
                        )
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
            smtp_host = getattr(settings, "SMTP_HOST")
            smtp_port = getattr(settings, "SMTP_PORT")
            sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")

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
                    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
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
        """Background worker that checks for overdue reports every 24 hours"""
        logger.info("🚀 Starting follow-up worker for ICANN compliance (checks every 24 hours)...")

        # Check last follow-up time from database
        last_followup_time = self._get_last_followup_time()

        if last_followup_time:
            hours_since_last = (datetime.datetime.now() - last_followup_time).total_seconds() / 3600
            if hours_since_last < 24:
                wait_hours = 24 - hours_since_last
                logger.info(
                    f"⏰ Last follow-up was {hours_since_last:.1f} hours ago. Waiting {wait_hours:.1f} hours before first check."
                )
                # Wait until 24 hours have passed since last follow-up
                for _ in range(int(wait_hours * 60)):  # Convert hours to minutes
                    if not self.running:
                        return
                    time.sleep(60)

        while self.running:
            try:
                # Process overdue reports
                self.process_overdue_followups()
                # Save the time of this follow-up run
                self._save_followup_time()

                # Wait 24 hours before next check
                for _ in range(1440):  # 1440 minutes = 24 hours
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

    def _get_last_followup_time(self) -> Optional[datetime.datetime]:
        """Get the last follow-up time from database"""
        try:
            with self.db_manager.engine.begin() as conn:
                result = conn.execute(
                    text("SELECT last_run FROM system_status WHERE task_name = 'followup_worker'")
                ).fetchone()

                if result and result[0]:
                    return result[0]
                return None
        except Exception as e:
            logger.debug(f"No previous follow-up time found: {e}")
            return None

    def _save_followup_time(self):
        """Save the current time as last follow-up time"""
        try:
            with self.db_manager.engine.begin() as conn:
                # Create table if not exists
                conn.execute(
                    text(
                        """
                    CREATE TABLE IF NOT EXISTS system_status (
                        task_name VARCHAR(100) PRIMARY KEY,
                        last_run TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                    )
                )

                # Upsert the follow-up time
                conn.execute(
                    text(
                        """
                    INSERT INTO system_status (task_name, last_run, updated_at)
                    VALUES ('followup_worker', :last_run, :updated_at)
                    ON CONFLICT (task_name)
                    DO UPDATE SET last_run = :last_run, updated_at = :updated_at
                """
                    ),
                    {"last_run": datetime.datetime.now(), "updated_at": datetime.datetime.now()},
                )

                logger.debug("✅ Saved follow-up run time")
        except Exception as e:
            logger.error(f"❌ Failed to save follow-up time: {e}")

    def report_phishing_sites(self):
        """Main loop for reporting phishing sites with enhanced multi-API validation and auto-reporting."""
        if self.monitoring_event:
            logger.info(
                "⏳ Waiting for monitoring thread to complete initial cycle before sending abuse reports..."
            )
            self.monitoring_event.wait()
            logger.info("✅ Monitoring thread initial cycle complete. Starting abuse reporting.")

        while not shutdown_requested:
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

                            # Fall back to stored abuse emails if no enhanced detection result and different domain
                            if not abuse_list and stored_abuse:
                                parsed_abuse_emails = self.abuse_detector.parse_stored_abuse_emails(
                                    stored_abuse
                                )
                                valid_stored_emails = []
                                for email in parsed_abuse_emails:
                                    if self.abuse_detector.validate_abuse_email_domain(
                                        email, domain
                                    ):
                                        valid_stored_emails.append(email)
                                    else:
                                        logger.warning(
                                            f"⚠️  Stored abuse email {email} is same domain as reported site {url}, skipping"
                                        )
                                if valid_stored_emails:
                                    abuse_list = valid_stored_emails
                                    logger.info(
                                        f"✅ Using stored abuse emails: {valid_stored_emails}"
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
                                            SET abuse_report_sent=1,
                                                abuse_email = CASE
                                                    WHEN manual_emails = 1 THEN abuse_email
                                                    ELSE :abuse_email
                                                END,
                                                last_report_sent=:timestamp
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

        # Import required modules at the top to avoid UnboundLocalError
        import subprocess
        import os

        # Close all existing database connections to avoid blocking
        logger.info("🔒 Disposing all existing database connections")
        self.db_manager.engine.dispose()

        # Create a new engine for this operation
        from sqlalchemy import create_engine
        from sqlalchemy.pool import NullPool

        self.db_manager.engine = create_engine(self.db_manager.engine.url, poolclass=NullPool)

        # If no specific attachments provided, get all configured attachments
        if attachment_paths is None:
            attachment_paths = AttachmentConfig.get_all_attachments()
            logger.info(
                f"📎 Using default attachments: {len(attachment_paths) if attachment_paths else 0} files"
            )
        else:
            logger.info(f"📎 Using provided attachments: {len(attachment_paths)} files")

        logger.info("🗄️ Opening database connection...")

        # Get sites to process with short-lived connection
        sites_to_process = []
        try:
            with self.db_manager.engine.connect() as conn:
                logger.info("🔍 Querying for manual sites to process...")
                result = conn.execute(
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
                )
                # Convert to list and close connection immediately
                sites_to_process = [dict(row._mapping) for row in result]
                logger.debug("🔒 Initial query connection closed")
        except Exception as e:
            logger.error(f"❌ Failed to query sites: {e}")
            raise

        logger.info(f"📋 Found {len(sites_to_process)} sites to process")

        if not sites_to_process:
            logger.info("✅ No manual sites to process - all done!")
            logger.info("🚪 EXITING process_manual_reports method normally")
            return

        for i, site_data in enumerate(sites_to_process, 1):
            url = site_data["url"]
            reported = site_data["reported"]
            abuse_report_sent = site_data["abuse_report_sent"]
            stored_abuse = site_data["abuse_email"]
            priority = site_data["priority"]
            site_status = site_data["site_status"]
            takedown_date = site_data["takedown_date"]

            logger.info(f"🔄 Processing site {i}/{len(sites_to_process)}: {url}")
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

                    # Store API results in database
                    logger.info(f"💾 Storing API results for {url}")
                    logger.info(
                        f"📊 API Results: {multi_api_results.get('aggregated_threat_level', 'unknown')} threat, {multi_api_results.get('confidence_score', 0)}% confidence"
                    )

                    # Store API results in database with proper isolation
                    # Use direct psycopg2 connection to avoid SQLAlchemy hanging issues
                    try:
                        import psycopg2
                        from urllib.parse import urlparse

                        # Parse DATABASE_URL
                        parsed = urlparse(DATABASE_URL)

                        logger.info(f"🔧 Creating direct psycopg2 connection")
                        conn_api = psycopg2.connect(
                            host=parsed.hostname,
                            port=parsed.port,
                            database=parsed.path[1:],  # Remove leading slash
                            user=parsed.username,
                            password=parsed.password,
                            connect_timeout=5,  # 5 second connection timeout
                            options="-c statement_timeout=5000",  # 5 second statement timeout
                        )
                        conn_api.autocommit = True  # Enable autocommit

                        cursor = conn_api.cursor()
                        logger.info(f"✅ Direct connection established, executing API UPDATE")

                        try:
                            cursor.execute(
                                """
                                UPDATE phishing_sites
                                SET virustotal_result = %s,
                                    urlvoid_result = %s,
                                    phishtank_result = %s,
                                    multi_api_threat_level = %s,
                                    api_confidence_score = %s
                                WHERE url = %s
                                """,
                                (
                                    json.dumps(multi_api_results.get("virustotal", {})),
                                    json.dumps(multi_api_results.get("urlvoid", {})),
                                    json.dumps(multi_api_results.get("phishtank", {})),
                                    multi_api_results.get("aggregated_threat_level"),
                                    multi_api_results.get("confidence_score"),
                                    url,
                                ),
                            )
                        except psycopg2.OperationalError as e:
                            logger.error(f"❌ Database operation timed out: {e}")
                        except Exception as e:
                            logger.error(f"❌ Database update failed: {e}")
                        finally:
                            cursor.close()
                            conn_api.close()
                        logger.info(f"✅ API results stored for {url}")
                    except Exception as e:
                        logger.error(f"❌ Failed to store API results for {url}: {e}")
                        raise
                    finally:
                        if "cursor" in locals():
                            cursor.close()
                        if "conn_api" in locals():
                            conn_api.close()
                            logger.info(f"🔒 Direct connection closed for {url}")

                # Main processing with fresh connection per site
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

                # Use new connection for updates without long-running transaction
                try:
                    with self.db_manager.engine.connect() as conn:
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
                            conn.commit()
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
                            logger.warning(
                                f"⚠️  Error getting enhanced abuse email for {domain}: {e}"
                            )
                            abuse_list = []

                        # Update WHOIS information in database
                        conn.execute(
                            text(
                                """
                                UPDATE phishing_sites
                                SET whois_info=:whois_str, last_seen=:timestamp, reported=1,
                                    resolved_ip=:resolved_ip, asn_provider=:asn_provider, is_cloudflare=:is_cloudflare,
                                    registrar=:registrar,
                                    abuse_email = CASE
                                        WHEN manual_emails = 1 THEN abuse_email
                                        ELSE :abuse_email
                                    END
                                WHERE url=:url
                            """
                            ),
                            {
                                "whois_str": (
                                    json.dumps(serialize_for_json(whois_info))
                                    if whois_info
                                    else None
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
                        conn.commit()
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

                        # Fall back to stored abuse emails if no enhanced detection result and different domain
                        if not abuse_list and stored_abuse:
                            parsed_abuse_emails = self.abuse_detector.parse_stored_abuse_emails(
                                stored_abuse
                            )
                            valid_stored_emails = []
                            for email in parsed_abuse_emails:
                                if self.abuse_detector.validate_abuse_email_domain(email, domain):
                                    valid_stored_emails.append(email)
                                else:
                                    logger.warning(
                                        f"⚠️  Stored abuse email {email} is same domain as reported site {url}, skipping"
                                    )
                            if valid_stored_emails:
                                abuse_list = valid_stored_emails
                                logger.info(f"✅ Using stored abuse emails: {valid_stored_emails}")

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

                        # Commit changes
                        conn.commit()
                        logger.debug(f"🔒 Changes committed for {url}")
                        logger.debug(f"🔒 Connection closed for {url}")

                except Exception as e:
                    logger.error(f"❌ WHOIS query failed for {url}: {e}")
                    logger.info(f"⚠️  Continuing to next site after error for {url}")

                logger.info(f"✅ Finished processing site {i}/{len(sites_to_process)}: {url}")

            except Exception as e:
                logger.error(f"❌ Critical error processing site {url}: {e}")
                logger.info(f"⚠️  Skipping site {url} due to critical error")

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

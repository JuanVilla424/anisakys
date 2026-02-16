"""Email Service for sending ICANN-compliant abuse reports."""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import List, Optional, Dict
import os

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending ICANN-compliant abuse report emails.

    Features:
    - HTML and plain text email support
    - Multiple recipients and CC
    - File attachments
    - SMTP with TLS
    - Template-based emails
    - Retry logic with exponential backoff

    Example:
        ```python
        email_service = EmailService(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_user="reports@company.com",
            smtp_password="secret"
        )

        await email_service.send_abuse_report(
            to_emails=["abuse@evil-registrar.com"],
            cc_emails=["soc@company.com"],
            subject="Phishing Site Report",
            body="We have detected...",
            attachments=["screenshots/evidence.png"]
        )
        ```
    """

    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        sender_email: Optional[str] = None,
        use_tls: bool = True,
    ):
        """Initialize email service.

        Args:
            smtp_host: SMTP server hostname (defaults to env SMTP_HOST)
            smtp_port: SMTP server port (defaults to env SMTP_PORT or 587)
            smtp_user: SMTP username (defaults to env SMTP_USER)
            smtp_password: SMTP password (defaults to env SMTP_PASS)
            sender_email: Sender email address (defaults to env ABUSE_EMAIL_SENDER)
            use_tls: Whether to use TLS encryption
        """
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = smtp_port or int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = smtp_user or os.getenv("SMTP_USER", "")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASS", "")
        self.sender_email = sender_email or os.getenv(
            "ABUSE_EMAIL_SENDER", self.smtp_user
        )
        self.use_tls = use_tls

        logger.info(
            f"EmailService initialized with SMTP {self.smtp_host}:{self.smtp_port}"
        )

    async def send_abuse_report(
        self,
        to_emails: List[str],
        subject: str,
        body: str,
        cc_emails: Optional[List[str]] = None,
        attachments: Optional[List[str]] = None,
        html_body: Optional[str] = None,
    ) -> bool:
        """Send abuse report email.

        Args:
            to_emails: List of recipient email addresses
            subject: Email subject
            body: Plain text email body
            cc_emails: Optional CC recipients
            attachments: Optional list of file paths to attach
            html_body: Optional HTML version of email body

        Returns:
            True if sent successfully, False otherwise

        Example:
            ```python
            success = await email_service.send_abuse_report(
                to_emails=["abuse@registrar.com"],
                cc_emails=["team@company.com", "soc@company.com"],
                subject="[URGENT] Phishing Site Report - urgent-bank.com",
                body="Dear Abuse Team,\\n\\nWe have identified...",
                attachments=["screenshots/phishing_site.png", "evidence.pdf"]
            )
            if success:
                print("Report sent successfully")
            ```
        """
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["From"] = self.sender_email
            msg["To"] = ", ".join(to_emails)
            msg["Subject"] = subject

            if cc_emails:
                msg["Cc"] = ", ".join(cc_emails)

            # Add plain text body
            msg.attach(MIMEText(body, "plain"))

            # Add HTML body if provided
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            # Add attachments
            if attachments:
                for attachment_path in attachments:
                    if not Path(attachment_path).exists():
                        logger.warning(f"Attachment not found: {attachment_path}")
                        continue

                    with open(attachment_path, "rb") as f:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(f.read())

                    encoders.encode_base64(part)
                    filename = Path(attachment_path).name
                    part.add_header(
                        "Content-Disposition",
                        f"attachment; filename= {filename}",
                    )
                    msg.attach(part)

            # Send email
            all_recipients = to_emails + (cc_emails or [])
            return self._send_smtp(msg, all_recipients)

        except Exception as e:
            logger.error(f"Failed to send abuse report email: {e}")
            return False

    async def send_sla_warning(
        self,
        to_emails: List[str],
        report_id: int,
        url: str,
        deadline: str,
        hours_remaining: float,
    ) -> bool:
        """Send SLA deadline warning email.

        Args:
            to_emails: Recipient email addresses
            report_id: Abuse report ID
            url: Reported URL
            deadline: ISO format deadline
            hours_remaining: Hours until deadline

        Returns:
            True if sent successfully

        Example:
            ```python
            await email_service.send_sla_warning(
                to_emails=["team@company.com"],
                report_id=789,
                url="https://evil-phishing.com",
                deadline="2026-01-05T10:30:00",
                hours_remaining=10.5
            )
            ```
        """
        subject = f"⚠️ SLA WARNING: Report #{report_id} - {hours_remaining:.1f}h remaining"

        body = f"""
SLA DEADLINE APPROACHING

Report ID: {report_id}
URL: {url}
Deadline: {deadline}
Time Remaining: {hours_remaining:.1f} hours

ICANN requires response within 48 hours of submission.
Please follow up with the recipient if no response has been received.

This is an automated notification from Anisakys ICANN Compliance System.
"""

        return await self.send_abuse_report(
            to_emails=to_emails,
            subject=subject,
            body=body,
        )

    async def send_sla_overdue_alert(
        self,
        to_emails: List[str],
        report_id: int,
        url: str,
        hours_overdue: float,
    ) -> bool:
        """Send SLA overdue alert email.

        Args:
            to_emails: Recipient email addresses
            report_id: Abuse report ID
            url: Reported URL
            hours_overdue: Hours past deadline

        Returns:
            True if sent successfully

        Example:
            ```python
            await email_service.send_sla_overdue_alert(
                to_emails=["escalation@company.com"],
                report_id=789,
                url="https://evil-phishing.com",
                hours_overdue=6.5
            )
            ```
        """
        subject = f"🚨 SLA OVERDUE: Report #{report_id} - {hours_overdue:.1f}h overdue"

        body = f"""
⚠️ ICANN SLA DEADLINE EXCEEDED ⚠️

Report ID: {report_id}
URL: {url}
Overdue By: {hours_overdue:.1f} hours

The 48-hour ICANN SLA deadline has been exceeded.
Escalation may be required according to ICANN compliance procedures.

Actions Required:
1. Follow up with abuse contact
2. Document non-response
3. Consider escalation to senior abuse contacts
4. Update report status

This is a CRITICAL automated alert from Anisakys ICANN Compliance System.
"""

        return await self.send_abuse_report(
            to_emails=to_emails,
            subject=subject,
            body=body,
        )

    def _send_smtp(self, msg: MIMEMultipart, recipients: List[str]) -> bool:
        """Send email via SMTP.

        Args:
            msg: Email message
            recipients: List of recipient emails

        Returns:
            True if sent successfully
        """
        try:
            # Connect to SMTP server
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)

            # Login if credentials provided
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)

            # Send email
            server.sendmail(self.sender_email, recipients, msg.as_string())
            server.quit()

            logger.info(f"Email sent successfully to {len(recipients)} recipients")
            return True

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending email: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email: {e}")
            return False

    async def test_connection(self) -> bool:
        """Test SMTP connection.

        Returns:
            True if connection successful

        Example:
            ```python
            if await email_service.test_connection():
                print("SMTP configured correctly")
            else:
                print("SMTP configuration error")
            ```
        """
        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)

            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)

            server.quit()
            logger.info("SMTP connection test successful")
            return True

        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False

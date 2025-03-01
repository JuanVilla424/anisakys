#!/usr/bin/env python3
"""
Anisakys Phishing Detection Engine

This script scans and processes phishing sites. It performs WHOIS lookups,
determines appropriate abuse email addresses (using a cached registrar_abuse table when possible),
resolves IP addresses and their ASN/provider using IPWhois, and detects if a site is behind Cloudflare.
If Cloudflare is detected, abuse reports are sent to abuse@cloudflare.com.
Reports may be sent automatically or manually (flagged as phishing).

Usage examples:
  ./anisakys.py --timeout 30 --log-level DEBUG
  ./anisakys.py --report https://site.domain.com --abuse-email abuse@domain.com
  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"
  ./anisakys.py --threads-only --log-level DEBUG
  ./anisakys.py --regen-queries  # Forces regeneration of the queries file if needed
"""

import gc
import os
import re
import time
import argparse
import requests
from itertools import permutations, islice
import datetime
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from jinja2 import Environment, FileSystemLoader, select_autoescape
import whois
import socket
import ipaddress
from ipwhois import IPWhois

# Import configuration settings and logging from external modules.
# Ensure these modules are available in your environment.
from src.config import settings, CLOUDFLARE_IP_RANGES
from src.logger import logger

# Define acceptable HTTP HEAD status codes.
ALLOWED_HEAD_STATUS = {200, 201, 202, 203, 204, 205, 206, 301, 302, 403, 405, 503, 504}

# Constants.
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

# File and batching settings.
QUERIES_FILE = "queries.txt"
OFFSET_FILE = "offset.txt"
DB_FILE = "scan_results.db"
BATCH_SIZE = 1000  # Number of queries to process in each scan cycle.


###############################################################################
# Full List Generation (if needed)
###############################################################################
def generate_queries_file(keywords: List[str], domains: List[str]) -> None:
    """
    Generate and save the full list of queries to the QUERIES_FILE.

    For every permutation (in both hyphenated and concatenated forms) of the keywords
    and for each domain in the provided list, a query line is generated.

    Args:
        keywords (List[str]): List of keywords.
        domains (List[str]): List of domain extensions.
    """
    total = 0
    with open(QUERIES_FILE, "w") as f:
        for i in range(1, len(keywords) + 1):
            for p in permutations(keywords, i):
                for q in ["-".join(p), "".join(p)]:
                    for d in domains:
                        f.write(f"{q}{d}\n")
                        total += 1
    logger.info(f"Generated full query list with {total} lines.")


###############################################################################
# IP & Cloudflare Helpers
###############################################################################
def get_ip_info(domain: str) -> (Optional[str], Optional[str]):
    """
    Resolve a domain to its IP and get ASN/provider information.

    Args:
        domain (str): Domain to resolve.

    Returns:
        Tuple containing the resolved IP and ASN provider (or (None, None) on failure).
    """
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
    """
    Check if the given IP address is within known Cloudflare IP ranges.

    Args:
        ip (str): IP address as a string.

    Returns:
        bool: True if IP is in Cloudflare ranges, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in net:
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking Cloudflare IP: {e}")
        return False


###############################################################################
# Utility Functions for Scan Results Logging and Storage
###############################################################################
class PhishingUtils:
    @staticmethod
    def store_scan_result(
        url: str, response_code: int, found_keywords: List[str], db_file: str = DB_FILE
    ) -> None:
        """
        Store or update the scan result for a given URL in the database.

        If the URL already exists, update its record; otherwise, insert a new record.
        """
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        keywords_str = ", ".join(found_keywords) if found_keywords else ""
        cursor.execute("SELECT id, first_seen, count FROM scan_results WHERE url=?", (url,))
        row = cursor.fetchone()
        if row:
            count = row[2] + 1
            cursor.execute(
                "UPDATE scan_results SET last_seen = ?, response_code = ?, found_keywords = ?, count = ? WHERE url = ?",
                (timestamp, response_code, keywords_str, count, url),
            )
        else:
            cursor.execute(
                "INSERT INTO scan_results (url, first_seen, last_seen, response_code, found_keywords, count) VALUES (?, ?, ?, ?, ?, ?)",
                (url, timestamp, timestamp, response_code, keywords_str, 1),
            )
        conn.commit()
        conn.close()

    @staticmethod
    def log_positive_result(url: str, found_keywords: List[str]) -> None:
        """
        Log URLs that have positive matches (i.e. found keywords) to a log file.

        Prevents duplicate entries.
        """
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


###############################################################################
# Database Manager
###############################################################################
class DatabaseManager:
    """
    Manage database creation, upgrades, and connections.
    """

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file

    def _connect(self):
        return sqlite3.connect(self.db_file)

    def init_db(self):
        """Initialize the database table for scan results."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                first_seen TEXT,
                last_seen TEXT,
                response_code INTEGER,
                found_keywords TEXT,
                count INTEGER
            )
            """
        )
        conn.commit()
        conn.close()

    def init_phishing_db(self):
        """Initialize the database table for phishing sites."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS phishing_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                manual_flag INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                whois_info TEXT,
                abuse_email TEXT,
                reported INTEGER DEFAULT 0,
                abuse_report_sent INTEGER DEFAULT 0,
                site_status TEXT DEFAULT 'up',
                takedown_date TEXT,
                last_report_sent TEXT,
                resolved_ip TEXT,
                asn_provider TEXT,
                is_cloudflare INTEGER
            )
            """
        )
        conn.commit()
        conn.close()

    def upgrade_phishing_db(self):
        """Upgrade the phishing_sites table by adding missing columns."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(phishing_sites)")
        columns = [row[1] for row in cursor.fetchall()]
        if "last_report_sent" not in columns:
            logger.info("Upgrading phishing_sites table: adding 'last_report_sent' column.")
            cursor.execute("ALTER TABLE phishing_sites ADD COLUMN last_report_sent TEXT")
            conn.commit()
        if "resolved_ip" not in columns:
            logger.info("Upgrading phishing_sites table: adding 'resolved_ip' column.")
            cursor.execute("ALTER TABLE phishing_sites ADD COLUMN resolved_ip TEXT")
            conn.commit()
        if "asn_provider" not in columns:
            logger.info("Upgrading phishing_sites table: adding 'asn_provider' column.")
            cursor.execute("ALTER TABLE phishing_sites ADD COLUMN asn_provider TEXT")
            conn.commit()
        if "is_cloudflare" not in columns:
            logger.info("Upgrading phishing_sites table: adding 'is_cloudflare' column.")
            cursor.execute("ALTER TABLE phishing_sites ADD COLUMN is_cloudflare INTEGER")
            conn.commit()
        conn.close()

    def init_registrar_abuse_db(self):
        """Initialize the registrar_abuse table used for caching abuse email addresses."""
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS registrar_abuse (
                registrar TEXT PRIMARY KEY,
                abuse_email TEXT
            )
            """
        )
        conn.commit()
        conn.close()


###############################################################################
# Abuse Report Manager
###############################################################################
def basic_whois_lookup(url: str) -> dict:
    """
    Perform a basic WHOIS lookup for the given URL.

    Args:
        url (str): URL for which WHOIS information is needed.

    Returns:
        dict: WHOIS information (empty dict on failure).
    """
    try:
        # Extract domain by stripping protocol and path.
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        logger.debug(f"Performing WHOIS lookup for: {domain}")
        data = whois.whois(domain)
        return data
    except Exception as e:
        logger.error(f"Basic WHOIS lookup failed for {url}: {e}")
        return {}


class AbuseReportManager:
    """
    Manages the extraction of abuse emails from WHOIS data and sending abuse reports.
    """

    def __init__(self, db_manager: DatabaseManager, cc_emails: Optional[List[str]], timeout: int):
        self.db_manager = db_manager
        if cc_emails is None:
            default_cc = os.getenv("DEFAULT_CC_EMAILS", "")
            self.cc_emails = (
                [email.strip() for email in default_cc.split(",")] if default_cc else []
            )
        else:
            self.cc_emails = cc_emails
        self.timeout = timeout

    @staticmethod
    def extract_registrar(whois_data) -> Optional[str]:
        """
        Extract registrar information from WHOIS data.

        Args:
            whois_data: WHOIS lookup result.

        Returns:
            Registrar name as string if found, else None.
        """
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

    def get_abuse_email_by_registrar(self, registrar: str) -> Optional[str]:
        """
        Check the registrar abuse database for a cached abuse email.

        Args:
            registrar (str): Registrar name.

        Returns:
            Cached abuse email if found, else None.
        """
        conn = sqlite3.connect(self.db_manager.db_file)
        cursor = conn.cursor()
        query = "SELECT abuse_email FROM registrar_abuse WHERE LOWER(registrar) LIKE ?"
        param = "%" + registrar.lower() + "%"
        logger.debug(f"Query parameter: '{param}'")
        cursor.execute(query, (param,))
        row = cursor.fetchone()
        conn.close()
        if row:
            logger.info(f"Found cached abuse email for registrar '{registrar}': {row[0]}")
            return row[0]
        return None

    def extract_abuse_emails(self, whois_data) -> List[str]:
        """
        Extract abuse email addresses from WHOIS data.

        First checks for a cached registrar abuse email; if not found,
        uses regex to find emails with 'abuse' in them.

        Args:
            whois_data: WHOIS lookup result.

        Returns:
            List of abuse email addresses.
        """
        registrar = self.extract_registrar(whois_data) or ""
        abuse_from_registrar = self.get_abuse_email_by_registrar(registrar)
        if abuse_from_registrar:
            logger.debug(f"Using abuse email from registrar cache: {abuse_from_registrar}")
            return [abuse_from_registrar]
        whois_str = str(whois_data)
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", whois_str)
        abuse_emails = [email for email in emails if "abuse" in email.lower()]
        return abuse_emails

    def send_abuse_report(
        self,
        abuse_emails: List[str],
        site_url: str,
        whois_str: str,
        attachment_path: Optional[str] = None,
    ) -> None:
        """
        Send an abuse report email to the specified abuse email addresses.

        Renders an HTML email using Jinja2 and attaches a file if provided.
        Adjusts CC list and ensures that if multiple abuse addresses exist,
        any 'abuse-tracker' address is demoted if a better candidate is available.

        Args:
            abuse_emails (List[str]): List of abuse email addresses.
            site_url (str): URL of the phishing site.
            whois_str (str): WHOIS information as a string.
            attachment_path (Optional[str]): File path of the attachment (if any).
        """
        smtp_host = settings.SMTP_HOST
        smtp_port = settings.SMTP_PORT
        smtp_user = os.environ.get("SMTP_USER", "")
        smtp_pass = os.environ.get("SMTP_PASS", "")
        sender_email = settings.ABUSE_EMAIL_SENDER
        subject = f"{settings.ABUSE_EMAIL_SUBJECT} for {site_url}"
        attachment_filename = os.path.basename(attachment_path) if attachment_path else None

        env_jinja = Environment(
            loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"])
        )
        final_cc = self.cc_emails[:] if self.cc_emails else []
        if sender_email not in final_cc:
            final_cc.insert(0, sender_email)
        escalation2 = os.getenv("DEFAULT_CC_ESCALATION_LEVEL2", "")
        escalation3 = os.getenv("DEFAULT_CC_ESCALATION_LEVEL3", "")
        for var in [escalation2, escalation3]:
            if var:
                for email in var.split(","):
                    email = email.strip()
                    if email and email not in final_cc:
                        final_cc.append(email)
        try:
            html_content = env_jinja.get_template("abuse_report.html").render(
                site_url=site_url,
                whois_info=whois_str,
                attachment_filename=attachment_filename,
                cc_emails=final_cc,
            )
            logger.debug("Rendered email content (first 300 chars): " + html_content[:300])
        except Exception as render_err:
            logger.error(f"Template rendering failed: {render_err}")
            raise
        primary_candidates = [
            email for email in abuse_emails if "abuse-tracker" not in email.lower()
        ]
        if primary_candidates:
            abuse_emails = primary_candidates
        for primary in abuse_emails:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = primary
            if final_cc:
                msg["Cc"] = ", ".join(final_cc)
                recipients = [primary] + final_cc
            else:
                recipients = [primary]
            msg.attach(MIMEText(html_content, "html"))
            if attachment_path:
                try:
                    with open(attachment_path, "rb") as f:
                        part = MIMEApplication(f.read(), Name=attachment_filename)
                    part["Content-Disposition"] = f'attachment; filename="{attachment_filename}"'
                    msg.attach(part)
                    logger.info(f"Attached file {attachment_filename} to email for {site_url}")
                except Exception as e:
                    logger.error(f"Failed to attach file {attachment_path}: {e}")
            try:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    if smtp_user and smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.sendmail(sender_email, recipients, msg.as_string())
                logger.info(
                    f"Abuse report sent to {primary} for site {site_url}; CC: {final_cc if final_cc else 'None'}"
                )
            except Exception as e:
                logger.error(f"Failed to send abuse report to {primary}: {e}")

    def report_phishing_sites(self):
        """
        Background thread that continuously checks flagged phishing sites,
        updates WHOIS and site status, and sends abuse reports if needed.
        """
        while True:
            conn = None
            try:
                conn = sqlite3.connect(self.db_manager.db_file)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT url, abuse_email, last_report_sent FROM phishing_sites WHERE manual_flag = 1 AND site_status = 'up'"
                )
                sites = cursor.fetchall()
                for url, stored_abuse, last_report_sent in sites:
                    try:
                        current_time = datetime.datetime.now()
                        last_report_time = (
                            datetime.datetime.strptime(last_report_sent, "%Y-%m-%d %H:%M:%S")
                            if last_report_sent
                            else None
                        )
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
                        cloudflare_detected = False
                        if resolved_ip:
                            cloudflare_detected = is_cloudflare_ip(resolved_ip)
                        abuse_list = self.extract_abuse_emails(whois_data)
                        if cloudflare_detected:
                            logger.info(
                                f"Cloudflare detected for {url}. Using abuse@cloudflare.com"
                            )
                            abuse_list = ["abuse@cloudflare.com"]
                        cursor.execute(
                            """
                            UPDATE phishing_sites
                            SET whois_info = ?, last_seen = ?, reported = 1, last_report_sent = ?,
                                resolved_ip = ?, asn_provider = ?, is_cloudflare = ?
                            WHERE url = ?
                            """,
                            (
                                whois_str,
                                timestamp,
                                timestamp,
                                resolved_ip,
                                asn_provider,
                                1 if cloudflare_detected else 0,
                                url,
                            ),
                        )
                        logger.info(f"WHOIS data enriched for {url}")
                        if abuse_list:
                            self.send_abuse_report(abuse_list, url, whois_str)
                            cursor.execute(
                                "UPDATE phishing_sites SET abuse_report_sent = 1, abuse_email = ?, last_report_sent = ? WHERE url = ?",
                                (abuse_list[0], timestamp, url),
                            )
                    except Exception as e:
                        logger.error(f"WHOIS query failed for {url}: {e}")
                conn.commit()
            except Exception as outer_e:
                logger.error(f"Error in reporting thread: {outer_e}")
            finally:
                if conn:
                    conn.close()
            time.sleep(settings.REPORT_INTERVAL)

    def process_manual_reports(self, attachment_path: Optional[str] = None):
        """
        Process manually flagged phishing sites to update WHOIS information and send abuse reports.

        Args:
            attachment_path (Optional[str]): Path to an attachment to include with the report.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_manager.db_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, reported, abuse_report_sent, abuse_email FROM phishing_sites WHERE manual_flag = 1 AND reported = 0"
            )
            sites = cursor.fetchall()
            for url, reported, abuse_report_sent, stored_abuse in sites:
                try:
                    whois_data = basic_whois_lookup(url)
                    whois_str = str(whois_data)
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    resolved_ip, asn_provider = get_ip_info(domain)
                    cloudflare_detected = False
                    if resolved_ip:
                        cloudflare_detected = is_cloudflare_ip(resolved_ip)
                    cursor.execute(
                        """
                        UPDATE phishing_sites
                        SET whois_info = ?, last_seen = ?, reported = 1,
                            resolved_ip = ?, asn_provider = ?, is_cloudflare = ?
                        WHERE url = ?
                        """,
                        (
                            whois_str,
                            timestamp,
                            resolved_ip,
                            asn_provider,
                            1 if cloudflare_detected else 0,
                            url,
                        ),
                    )
                    logger.info(f"Manually processed WHOIS data for {url}")
                    abuse_list = (
                        [stored_abuse] if stored_abuse else self.extract_abuse_emails(whois_data)
                    )
                    if cloudflare_detected:
                        logger.info(f"Cloudflare detected for {url}. Using abuse@cloudflare.com")
                        abuse_list = ["abuse@cloudflare.com"]
                    if abuse_list and abuse_report_sent == 0:
                        self.send_abuse_report(abuse_list, url, whois_str, attachment_path)
                        cursor.execute(
                            "UPDATE phishing_sites SET abuse_report_sent = 1, abuse_email = ?, last_report_sent = ? WHERE url = ?",
                            (abuse_list[0], timestamp, url),
                        )
                except Exception as e:
                    logger.error(f"WHOIS query failed for {url}: {e}")
            conn.commit()
        except Exception as outer_e:
            logger.error(f"Error processing manual reports: {outer_e}")
        finally:
            if conn:
                conn.close()


###############################################################################
# Takedown Monitor
###############################################################################
class TakedownMonitor:
    """
    Continuously monitor phishing sites to determine if they are still active or have been taken down.
    """

    def __init__(self, db_manager: DatabaseManager, timeout: int, check_interval: int = 3600):
        self.db_manager = db_manager
        self.timeout = timeout
        self.check_interval = check_interval

    def run(self):
        """
        Run the takedown monitor which periodically checks each phishing site and updates its status.
        """
        while True:
            conn = None
            try:
                conn = sqlite3.connect(self.db_manager.db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT url, site_status, takedown_date FROM phishing_sites")
                sites = cursor.fetchall()
                for url, current_status, current_takedown in sites:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    try:
                        response = requests.get(
                            url, timeout=self.timeout, headers={"User-Agent": DEFAULT_USER_AGENT}
                        )
                        if response.status_code == 200:
                            if "suspended" in response.text.lower():
                                new_status = "down"
                                new_takedown = (
                                    timestamp if current_status != "down" else current_takedown
                                )
                            else:
                                new_status = "up"
                                new_takedown = None
                        else:
                            new_status = "down"
                            new_takedown = (
                                timestamp if current_status != "down" else current_takedown
                            )
                    except Exception as e:
                        logger.error(f"GET request failed for {url}: {e}")
                        new_status = "down"
                        new_takedown = timestamp if current_status != "down" else current_takedown
                    cursor.execute(
                        "UPDATE phishing_sites SET site_status = ?, takedown_date = ?, last_seen = ? WHERE url = ?",
                        (new_status, new_takedown, timestamp, url),
                    )
                    logger.info(
                        f"Updated {url}: site_status set to '{new_status}', takedown_date set to '{new_takedown}'"
                    )
                conn.commit()
            except Exception as e:
                logger.error(f"Error in takedown monitor thread: {e}")
            finally:
                if conn:
                    conn.close()
            time.sleep(self.check_interval)


###############################################################################
# External Offset Functions for File-based Batching
###############################################################################
def save_offset(offset: int):
    """
    Save the current offset to a file so that scan cycles can resume from the correct position.
    """
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))


def get_offset() -> int:
    try:
        with open(OFFSET_FILE, "r") as f:
            offset_str = f.read().strip()
            return int(float(offset_str))
    except Exception as ex:
        logger.error(f"Error getting offset from {OFFSET_FILE}: {ex}")
        return 0


###############################################################################
# Phishing Scanner (File-based)
###############################################################################
class PhishingScanner:
    """
    Scans for phishing sites by reading a batch of target queries from a file.

    The queries file is processed in batches (default size 150K lines) so that
    the engine can handle a very large list (e.g., 2.6B lines) without loading everything into memory.
    """

    def __init__(
        self, timeout: int, keywords: List[str], domains: List[str], allowed_sites: List[str], args
    ):
        self.timeout = timeout
        self.keywords = keywords
        self.domains = domains
        self.allowed_sites = allowed_sites
        self.batch_size = BATCH_SIZE

        # If not running in threads-only mode, (re)generate the queries file if needed.
        if not args.threads_only:
            if args.regen_queries or not os.path.exists(QUERIES_FILE):
                logger.info(f"Generating queries file {QUERIES_FILE}...")
                generate_queries_file(self.keywords, self.domains)
            else:
                logger.info(f"Using existing {QUERIES_FILE} file.")
        else:
            logger.info("Threads-only mode: Skipping queries file generation.")

        # Count total queries in the file. (Note: For huge files this may take a while.)
        try:
            with open(QUERIES_FILE, "r") as f:
                self.total_queries = sum(1 for _ in f)
            logger.info(f"Total queries in file: {self.total_queries}")
        except Exception as ex:
            logger.error(f"Error counting total queries: {ex}")
            self.total_queries = 0

    def get_dynamic_target_sites(self) -> List[str]:
        """
        Retrieve the next batch of target sites from the queries file using the saved offset.

        If no lines are read (i.e. end of file), the offset is reset to 0 to restart scanning.

        Returns:
            List[str]: A list of query lines to scan.
        """
        offset = get_offset()  # Ensure proper conversion (even if stored as a float string)
        batch = []
        with open(QUERIES_FILE, "r") as f:
            # Advance the file pointer up to the current offset.
            for _ in range(offset):
                f.readline()
            # Read the next batch_size lines.
            for _ in range(self.batch_size):
                line = f.readline()
                if not line:
                    break
                batch.append(line.strip())

        if not batch:
            # Reached end of file; reset offset to 0 for continuous scanning.
            logger.info(
                "Reached end of queries.txt. Resetting offset to 0 for continuous scanning."
            )
            save_offset(0)
            # Optionally, re-read the first batch immediately:
            with open(QUERIES_FILE, "r") as f:
                batch = [line.strip() for line in islice(f, self.batch_size)]
            # Also update the offset accordingly.
            save_offset(len(batch))
        else:
            new_offset = offset + len(batch)
            save_offset(new_offset)
            remaining = self.total_queries - new_offset if self.total_queries else "Unknown"
            logger.info(
                f"Batch starting at offset {offset}: {len(batch)} queries read. Remaining queries: {remaining}"
            )

        return batch

    @staticmethod
    def augment_with_www(domain: str) -> List[str]:
        """
        Generate candidate domains by adding or not adding the 'www.' prefix.

        Args:
            domain (str): The domain to augment.

        Returns:
            List[str]: List containing the original domain and the www-prefixed version.
        """
        parts = domain.split(".")
        return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]

    def filter_allowed_targets(self, targets: List[str]) -> List[str]:
        """
        Filter out targets that are on the allowed (whitelist) sites.

        Args:
            targets (List[str]): List of target URLs.

        Returns:
            List[str]: Filtered list excluding allowed sites.
        """
        allowed_set = {site.lower().strip() for site in self.allowed_sites}
        filtered = [target for target in targets if target.lower().strip() not in allowed_set]
        removed = len(targets) - len(filtered)
        if removed:
            logger.info(f"Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
        return filtered

    def get_candidate_urls(self, domain: str) -> List[str]:
        """
        Generate candidate URLs for a domain by testing both HTTP and HTTPS schemes.

        For each candidate, a HEAD request is made to check if the site is reachable.

        Args:
            domain (str): The domain to test.

        Returns:
            List[str]: A list of reachable URLs.
        """
        candidate_domains = self.augment_with_www(domain)
        candidate_urls = []
        dns_error_logged = False
        for d in candidate_domains:
            for scheme in ("https://", "http://"):
                url = scheme + d
                try:
                    response = requests.head(
                        url, timeout=self.timeout, headers={"User-Agent": DEFAULT_USER_AGENT}
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
            logger.error(f"No reachable candidate URLs found for domain: {domain}")
            return []
        return candidate_urls

    def scan_site(self, domain: str) -> None:
        """
        Scan a given domain for phishing keywords.

        Attempts to retrieve candidate URLs for the domain and checks each one for the specified keywords.
        When keywords are found, the result is stored and logged.

        Args:
            domain (str): The domain to scan.
        """
        for url in self.get_candidate_urls(domain) or []:
            logger.info(f"Scanning {url} for keywords: {self.keywords}")
            try:
                headers = {"User-Agent": DEFAULT_USER_AGENT}
                response = requests.get(
                    url, timeout=self.timeout, headers=headers, allow_redirects=True
                )
                response.raise_for_status()
                code = response.status_code
                content = response.text.lower()
                matches = [kw for kw in self.keywords if kw in content]
                PhishingUtils.store_scan_result(url, code, matches)
                if matches:
                    logger.info(f"Found keywords {matches} in {url}")
                    PhishingUtils.log_positive_result(url, matches)
                else:
                    logger.debug(f"No keywords found in {url}")
                # If one candidate URL is successfully scanned, break out of the loop.
                break
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout scanning {url}")
            except requests.exceptions.ConnectionError as e:
                if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                    logger.info(f"DNS failure during scan: {url}")
                else:
                    logger.error(f"Connection failure: {url} - {e}")
            except Exception as e:
                logger.error(f"Scan error: {url} - {repr(e)}")

    def run_scan_cycle(self) -> None:
        """
        Continuously process scan cycles until all queries in the file have been processed.

        This loop keeps reading batches from the queries file and processing them with a ThreadPoolExecutor.
        The loop condition is based on the current offset (the number of lines processed) versus the total number
        of lines in the queries file. When get_offset() equals or exceeds self.total_queries, all queries have been processed.
        """
        while get_offset() < self.total_queries:
            targets = self.get_dynamic_target_sites()
            if not targets:
                logger.info("No targets returned from queries file; waiting before next cycle.")
                time.sleep(settings.SCAN_INTERVAL)
                continue

            if self.allowed_sites:
                targets = self.filter_allowed_targets(targets)

            current_offset = get_offset()
            logger.info(
                f"Processing batch: offset {current_offset}/{self.total_queries}, batch size {len(targets)}"
            )

            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(self.scan_site, target): target for target in targets}
                for i, future in enumerate(as_completed(futures), 1):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Thread error for {futures[future]}: {repr(e)}")
                    if i % 10 == 0:
                        progress_percent = (i / len(targets)) * 100
                        logger.info(f"Progress: {i}/{len(targets)} ({progress_percent:.1f}%)")


###############################################################################
# Engine
###############################################################################
class Engine:
    """
    The main engine that orchestrates the scanning, reporting, and monitoring threads.
    """

    def __init__(self, args):
        self.args = args
        self.timeout = args.timeout
        self.cc_emails = [email.strip() for email in args.cc.split(",")] if args.cc else None

        # Initialize and upgrade the database.
        self.db_manager = DatabaseManager()
        self.db_manager.init_db()
        self.db_manager.init_phishing_db()
        self.db_manager.upgrade_phishing_db()
        self.db_manager.init_registrar_abuse_db()

        self.report_manager = AbuseReportManager(
            self.db_manager, cc_emails=self.cc_emails, timeout=self.timeout
        )
        self.takedown_monitor = TakedownMonitor(
            self.db_manager, timeout=self.timeout, check_interval=int(3600 / 3)
        )

        # Convert settings values to list if needed.
        transform_to_list = lambda s: (
            [item.strip() for item in s.split(",")] if isinstance(s, str) else s
        )
        self.keywords = transform_to_list(settings.KEYWORDS)
        self.domains = transform_to_list(settings.DOMAINS)
        self.allowed_sites = transform_to_list(getattr(settings, "ALLOWED_SITES", ""))
        if not self.args.threads_only:
            self.scanner = PhishingScanner(
                self.timeout, self.keywords, self.domains, self.allowed_sites, self.args
            )
        else:
            self.scanner = None

    def mark_site_as_phishing(self, url: str, abuse_email: Optional[str] = None):
        """
        Mark a given URL as phishing by updating/inserting its record in the database.

        Args:
            url (str): The URL to mark as phishing.
            abuse_email (Optional[str]): Known abuse email address for the site, if any.
        """
        conn = sqlite3.connect(self.db_manager.db_file)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("SELECT id FROM phishing_sites WHERE url = ?", (url,))
        row = cursor.fetchone()
        if row:
            cursor.execute(
                """
                UPDATE phishing_sites
                SET manual_flag = 1, last_seen = ?, reported = 0, abuse_report_sent = 0, abuse_email = ?
                WHERE url = ?
                """,
                (timestamp, abuse_email, url),
            )
            logger.info(f"Updated phishing flag for {url} with abuse email {abuse_email}")
        else:
            cursor.execute(
                """
                INSERT INTO phishing_sites (url, manual_flag, first_seen, last_seen, abuse_email, reported, abuse_report_sent)
                VALUES (?, 1, ?, ?, ?, 0, 0)
                """,
                (url, timestamp, timestamp, abuse_email),
            )
            logger.info(f"Marked {url} as phishing with abuse email {abuse_email}")
        conn.commit()
        conn.close()

    def start(self):
        """
        Start the engine. Depending on the provided arguments, the engine will:
          - Flag a URL as phishing and exit.
          - Process manually flagged reports and exit.
          - Or start the background threads (reporting and takedown monitoring) and scanning cycles.
        """
        if self.args.report:
            self.mark_site_as_phishing(self.args.report, abuse_email=self.args.abuse_email)
            logger.info(f"URL {self.args.report} flagged as phishing. Exiting after manual report.")
            return

        if self.args.process_reports:
            self.report_manager.process_manual_reports(attachment_path=self.args.attachment)
            logger.info("Manually processed flagged phishing reports. Exiting.")
            return

        # Start background threads for reporting and takedown monitoring.
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
            while True:
                time.sleep(60)
        else:
            logger.info(
                f"Initialized with {len(self.keywords)} keywords and {len(self.domains)} domain extensions"
            )
            logger.info(f"Allowed sites (whitelist): {self.allowed_sites}")
            logger.info(f"Scan interval: {settings.SCAN_INTERVAL}s | Timeout: {self.timeout}s")
            while True:
                if not self.scanner.run_scan_cycle():
                    break
                logger.info(f"Next scan cycle in {settings.SCAN_INTERVAL}s")
                time.sleep(settings.SCAN_INTERVAL)


###############################################################################
# Main entry point and Argument Parsing
###############################################################################
def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Anisakys Phishing Detection Engine",
        epilog=(
            "Example usages:\n"
            "  ./anisakys.py --timeout 30 --log-level DEBUG\n"
            "  ./anisakys.py --report https://site.domain.com --abuse-email abuse@domain.com\n"
            '  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"\n'
            "  ./anisakys.py --threads-only --log-level DEBUG"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--timeout",
        type=int,
        choices=range(10, 300),
        default=settings.TIMEOUT,
        help=f"Request timeout in seconds (default: {settings.TIMEOUT})",
    )
    parser.add_argument(
        "--log-level",
        choices=["INFO", "DEBUG"],
        default="INFO",
        help="Set logging verbosity (default: INFO)",
    )
    parser.add_argument("--report", type=str, help="Manually flag a URL as phishing.")
    parser.add_argument(
        "--abuse-email",
        type=str,
        help="(Optional) Provide a known abuse email address for the domain.",
    )
    parser.add_argument(
        "--process-reports",
        action="store_true",
        help="Manually trigger processing of flagged phishing sites.",
    )
    parser.add_argument(
        "--attachment",
        type=str,
        help="Optional file path to attach to the abuse report (only used with --process-reports).",
    )
    parser.add_argument(
        "--cc",
        type=str,
        help="Optional comma-separated list of email addresses to CC on the abuse report.",
    )
    parser.add_argument(
        "--threads-only",
        action="store_true",
        help="Only run background threads (reporting and takedown monitor) without running the scanning cycle.",
    )
    parser.add_argument(
        "--regen-queries",
        action="store_true",
        help="Force regeneration of the queries file even if it already exists.",
    )
    return parser.parse_args()


def main():
    """
    Main function: parses arguments, sets logging, initializes the engine, and starts it.
    """
    args = parse_arguments()
    logger.setLevel(args.log_level)
    engine = Engine(args)
    engine.start()


if __name__ == "__main__":
    main()

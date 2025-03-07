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
  ./anisakys.py --test-report --abuse-email your-test@example.com  # Sends a test report and exits
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
import psutil
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from jinja2 import Environment, FileSystemLoader, select_autoescape
import whois
import socket
import ipaddress
from ipwhois import IPWhois

from src.config import settings, CLOUDFLARE_IP_RANGES
from src.logger import logger

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


class DynamicBatchConfig:
    @staticmethod
    def get_batch_size() -> int:
        try:
            cpus = os.cpu_count() or 1
            return 1000 * cpus
        except Exception as e:
            logger.debug(f"Can't get batch size: {e}")
            mem = psutil.virtual_memory()
            batch = int(mem.available / (10 * 1024 * 1024))
            return max(100, batch)


class AttachmentConfig:
    @staticmethod
    def get_attachment() -> Optional[str]:
        path = getattr(settings, "DEFAULT_ATTACHMENT", None)
        if path:
            if os.path.exists(path):
                abs_path = os.path.abspath(path)
                logger.info(f"Using default attachment from settings: {abs_path}")
                return path
            else:
                logger.error(f"DEFAULT_ATTACHMENT file '{path}' does not exist.")
        return None


class EngineMode:
    def __init__(self, args):
        self.report_mode = args.report is not None
        self.process_reports_mode = args.process_reports
        self.threads_only_mode = args.threads_only
        self.scanning_mode = not (
            self.report_mode
            or self.process_reports_mode
            or self.threads_only_mode
            or args.test_report
        )


QUERIES_FILE = "queries.txt"
OFFSET_FILE = "offset.txt"
DB_FILE = "scan_results.db"
BATCH_SIZE = DynamicBatchConfig.get_batch_size()


def generate_queries_file(keywords: List[str], domains: List[str]) -> None:
    total = 0
    with open(QUERIES_FILE, "w") as f:
        for i in range(1, len(keywords) + 1):
            for p in permutations(keywords, i):
                for q in ["-".join(p), "".join(p)]:
                    for d in domains:
                        f.write(f"{q}{d}\n")
                        total += 1
    logger.info(f"Generated full query list with {total} lines.")


def get_ip_info(domain: str) -> (Optional[str], Optional[str]):
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
    @staticmethod
    def store_scan_result(
        url: str, response_code: int, found_keywords: List[str], db_file: str = DB_FILE
    ) -> None:
        if response_code not in ALLOWED_HEAD_STATUS:
            logger.debug(f"Response code {response_code} not allowed for {url}, skipping save.")
            return
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        keywords_str = ", ".join(found_keywords) if found_keywords else ""
        cursor.execute("SELECT id, first_seen, count FROM scan_results WHERE url=?", (url,))
        row = cursor.fetchone()
        if row:
            new_count = row[2] + 1
            cursor.execute(
                "UPDATE scan_results SET last_seen = ?, response_code = ?, found_keywords = ?, count = ? WHERE url = ?",
                (timestamp, response_code, keywords_str, new_count, url),
            )
        else:
            cursor.execute(
                "INSERT INTO scan_results (url, first_seen, last_seen, response_code, found_keywords, count) VALUES (?, ?, ?, ?, ?, ?)",
                (url, timestamp, timestamp, response_code, keywords_str, 1),
            )
        conn.commit()
        conn.close()

    @staticmethod
    def update_scan_result_response_code(url: str, response_code: int) -> None:
        if response_code not in ALLOWED_HEAD_STATUS:
            logger.debug(f"Response code {response_code} not allowed for {url}, skipping update.")
            return
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("SELECT id, count FROM scan_results WHERE url=?", (url,))
        row = cursor.fetchone()
        if row:
            new_count = row[1] + 1
            cursor.execute(
                "UPDATE scan_results SET last_seen = ?, response_code = ?, count = ? WHERE url = ?",
                (timestamp, response_code, new_count, url),
            )
        else:
            cursor.execute(
                "INSERT INTO scan_results (url, first_seen, last_seen, response_code, found_keywords, count) VALUES (?, ?, ?, ?, ?, ?)",
                (url, timestamp, timestamp, response_code, "", 1),
            )
        conn.commit()
        conn.close()

    @staticmethod
    def log_positive_result(url: str, found_keywords: List[str]) -> None:
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


class DatabaseManager:
    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file

    def _connect(self):
        return sqlite3.connect(self.db_file)

    def init_db(self):
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
                is_cloudflare INTEGER,
                provider_abuse_email TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def upgrade_phishing_db(self):
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


def basic_whois_lookup(url: str) -> dict:
    try:
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        logger.debug(f"Performing WHOIS lookup for: {domain}")
        data = whois.whois(domain)
        return data
    except Exception as e:
        logger.error(f"Basic WHOIS lookup failed for {url}: {e}")
        return {}


class AbuseReportManager:
    def __init__(
        self,
        db_manager: DatabaseManager,
        cc_emails: Optional[List[str]],
        timeout: int,
        monitoring_event: threading.Event = None,
    ):
        self.db_manager = db_manager
        if cc_emails is None:
            default_cc = getattr(settings, "DEFAULT_CC_EMAILS", "")
            self.cc_emails = (
                [email.strip() for email in default_cc.split(",")] if default_cc else []
            )
        else:
            self.cc_emails = cc_emails
        self.timeout = timeout
        self.monitoring_event = monitoring_event

    @staticmethod
    def extract_registrar(whois_data) -> Optional[str]:
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
        test_mode: bool = False,
    ) -> None:
        default_attachment = AttachmentConfig.get_attachment()
        if default_attachment:
            attachment_path = default_attachment

        smtp_host = getattr(settings, "SMTP_HOST")
        smtp_port = getattr(settings, "SMTP_PORT")
        smtp_user = getattr(settings, "SMTP_USER", "")
        smtp_pass = getattr(settings, "SMTP_PASS", "")
        sender_email = getattr(settings, "ABUSE_EMAIL_SENDER")
        subject = f"{getattr(settings, 'ABUSE_EMAIL_SUBJECT')} for {site_url}"
        attachment_filename = os.path.basename(attachment_path) if attachment_path else None

        env_jinja = Environment(
            loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"])
        )
        final_cc = [] if test_mode else (self.cc_emails[:] if self.cc_emails else [])
        if not test_mode and sender_email not in final_cc:
            final_cc.insert(0, sender_email)
        if not test_mode:
            escalation2 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL2", "")
            escalation3 = getattr(settings, "DEFAULT_CC_ESCALATION_LEVEL3", "")
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
            if not test_mode and final_cc:
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
            attachment_info = f" with attachment {attachment_filename}" if attachment_path else ""
            try:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    if smtp_user and smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.sendmail(sender_email, recipients, msg.as_string())
                logger.info(
                    f"Abuse report sent to {primary} for site {site_url}{attachment_info}; CC: {final_cc if final_cc else 'None'}"
                )
            except Exception as e:
                logger.error(f"Failed to send abuse report to {primary}: {e}")

    def report_phishing_sites(self):
        if self.monitoring_event:
            logger.info(
                "Waiting for monitoring thread to complete initial cycle before sending abuse reports..."
            )
            self.monitoring_event.wait()
            logger.info("Monitoring thread initial cycle complete. Starting abuse reporting.")
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
                        cursor.execute(
                            "SELECT site_status, takedown_date FROM phishing_sites WHERE url = ?",
                            (url,),
                        )
                        row = cursor.fetchone()
                        current_status = row[0] if row else "up"
                        current_takedown = row[1] if row else None
                        if not resolved_ip:
                            new_status = "down"
                            new_takedown = (
                                current_takedown if current_status == "down" else timestamp
                            )
                        else:
                            new_status = "up"
                            new_takedown = None
                            try:
                                response = requests.get(
                                    url,
                                    timeout=self.timeout,
                                    headers={"User-Agent": DEFAULT_USER_AGENT},
                                )
                                if response.status_code == 200:
                                    if "suspended" in response.text.lower():
                                        new_status = "down"
                                        new_takedown = (
                                            current_takedown
                                            if current_status == "down"
                                            else timestamp
                                        )
                                    else:
                                        new_status = "up"
                                        new_takedown = None
                                else:
                                    new_status = "down"
                                    new_takedown = (
                                        current_takedown if current_status == "down" else timestamp
                                    )
                            except Exception as e:
                                logger.error(f"GET request failed for {url}: {e}")
                                new_status = "down"
                                new_takedown = (
                                    current_takedown if current_status == "down" else timestamp
                                )
                        cursor.execute(
                            """
                            UPDATE phishing_sites
                            SET whois_info = ?, last_seen = ?, reported = 1, last_report_sent = ?,
                                resolved_ip = ?, asn_provider = ?, is_cloudflare = ?, site_status = ?, takedown_date = ?
                            WHERE url = ?
                            """,
                            (
                                whois_str,
                                timestamp,
                                timestamp,
                                resolved_ip,
                                asn_provider,
                                1 if (resolved_ip and is_cloudflare_ip(resolved_ip)) else 0,
                                new_status,
                                new_takedown,
                                url,
                            ),
                        )
                        logger.info(f"WHOIS data enriched for {url}")
                        abuse_list = self.extract_abuse_emails(whois_data)
                        if abuse_list:
                            attachment = AttachmentConfig.get_attachment()
                            self.send_abuse_report(
                                abuse_list, url, whois_str, attachment_path=attachment
                            )
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
                    self.send_abuse_report(
                        abuse_list, url, whois_str, attachment_path=attachment_path
                    )
                    cursor.execute(
                        "UPDATE phishing_sites SET abuse_report_sent = 1, abuse_email = ?, last_report_sent = ? WHERE url = ?",
                        (abuse_list[0], timestamp, url),
                    )
            except Exception as e:
                logger.error(f"WHOIS query failed for {url}: {e}")
        conn.commit()
        conn.close()

    def send_test_report(self, test_email: str, attachment_path: Optional[str] = None):
        test_whois_str = "This is a test WHOIS information for a test phishing site."
        test_site_url = "https://test.phishing-site.com"
        test_abuse_emails = [test_email]
        logger.info("Sending test 2-days report...")
        attachment = AttachmentConfig.get_attachment() or attachment_path
        self.send_abuse_report(
            test_abuse_emails,
            test_site_url,
            test_whois_str,
            attachment_path=attachment,
            test_mode=True,
        )
        logger.info("Test report sent.")


class TakedownMonitor:
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
        first_cycle_done = False
        while True:
            conn = sqlite3.connect(self.db_manager.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT url, site_status, takedown_date FROM phishing_sites")
            sites = cursor.fetchall()
            for url, current_status, current_takedown in sites:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                resolved_ip, asn_provider = get_ip_info(domain)
                if not resolved_ip:
                    new_status = "down"
                    new_takedown = current_takedown if current_status == "down" else timestamp
                else:
                    try:
                        response = requests.get(
                            url, timeout=self.timeout, headers={"User-Agent": DEFAULT_USER_AGENT}
                        )
                        if response.status_code == 200:
                            if "suspended" in response.text.lower():
                                new_status = "down"
                                new_takedown = (
                                    current_takedown if current_status == "down" else timestamp
                                )
                            else:
                                new_status = "up"
                                new_takedown = None
                        else:
                            new_status = "down"
                            new_takedown = (
                                current_takedown if current_status == "down" else timestamp
                            )
                    except Exception as e:
                        logger.error(f"GET request failed for {url}: {e}")
                        new_status = "down"
                        new_takedown = current_takedown if current_status == "down" else timestamp
                cursor.execute(
                    "UPDATE phishing_sites SET site_status = ?, takedown_date = ?, last_seen = ? WHERE url = ?",
                    (new_status, new_takedown, timestamp, url),
                )
                logger.info(
                    f"Updated {url}: site_status set to '{new_status}', takedown_date set to '{new_takedown}'"
                )
            conn.commit()
            if not first_cycle_done:
                first_cycle_done = True
                if self.monitoring_event and not self.monitoring_event.is_set():
                    logger.info(
                        "Takedown monitor initial cycle complete, setting monitoring event."
                    )
                    self.monitoring_event.set()
            conn.close()
            time.sleep(self.check_interval)


def save_offset(offset: int):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))
    logger.debug(f"Offset saved as: {offset}")


def get_offset() -> int:
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
    def __init__(
        self, timeout: int, keywords: List[str], domains: List[str], allowed_sites: List[str], args
    ):
        self.timeout = timeout
        self.keywords = keywords
        self.domains = domains
        self.allowed_sites = allowed_sites
        self.batch_size = BATCH_SIZE
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
        offset = get_offset()
        batch = []
        with open(QUERIES_FILE, "r") as f:
            for _ in range(offset):
                f.readline()
            for _ in range(self.batch_size):
                line = f.readline()
                if not line:
                    break
                batch.append(line.strip())
        if not batch:
            logger.info(
                "Reached end of queries.txt. Resetting offset to 0 for continuous scanning."
            )
            save_offset(0)
            with open(QUERIES_FILE, "r") as f:
                batch = [line.strip() for line in islice(f, self.batch_size)]
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
        parts = domain.split(".")
        return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]

    def filter_allowed_targets(self, targets: List[str]) -> List[str]:
        allowed_set = {site.lower().strip() for site in self.allowed_sites}
        filtered = [target for target in targets if target.lower().strip() not in allowed_set]
        removed = len(targets) - len(filtered)
        if removed:
            logger.info(f"Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
        return filtered

    def get_candidate_urls(self, domain: str) -> List[str]:
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
                content = response.text.lower()
                matches = [kw for kw in self.keywords if kw in content]
                PhishingUtils.store_scan_result(url, code, matches)
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
            with ThreadPoolExecutor(max_workers=60) as executor:
                futures = {executor.submit(self.scan_site, target): target for target in targets}
                for i, future in enumerate(as_completed(futures), 1):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Thread error for {futures[future]}: {repr(e)}")
                    if i % 10 == 0:
                        progress_percent = (i / len(targets)) * 100
                        logger.info(f"Progress: {i}/{len(targets)} ({progress_percent:.1f}%)")
            gc.collect()


class Engine:
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
        if args.cc and args.cc.strip() != "":
            self.cc_emails = [email.strip() for email in args.cc.split(",")]
        else:
            self.cc_emails = (
                [email.strip() for email in getattr(settings, "CC", "").split(",")]
                if getattr(settings, "CC", "")
                else None
            )
        self.args = args
        self.db_manager = DatabaseManager()
        self.db_manager.init_db()
        self.db_manager.init_phishing_db()
        self.db_manager.upgrade_phishing_db()
        self.db_manager.init_registrar_abuse_db()
        self.monitoring_event = threading.Event()
        self.report_manager = AbuseReportManager(
            self.db_manager,
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
        transform_to_list = lambda s: (
            [item.strip() for item in s.split(",")] if isinstance(s, str) else s
        )
        self.keywords = transform_to_list(settings.KEYWORDS)
        self.domains = transform_to_list(settings.DOMAINS)
        self.allowed_sites = transform_to_list(getattr(settings, "ALLOWED_SITES", ""))
        self.mode = EngineMode(self.args)
        if self.mode.scanning_mode:
            self.scanner = PhishingScanner(
                self.timeout, self.keywords, self.domains, self.allowed_sites, self.args
            )
        else:
            self.scanner = None

    def mark_site_as_phishing(self, url: str, abuse_email: Optional[str] = None):
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
        if self.args.report:
            self.mark_site_as_phishing(self.args.report, abuse_email=self.abuse_email)
            self.report_manager.process_manual_reports(attachment_path=self.attachment)
            logger.info(
                f"URL {self.args.report} flagged as phishing and abuse report processed. Exiting."
            )
            return
        if self.args.process_reports:
            self.report_manager.process_manual_reports(attachment_path=self.attachment)
            logger.info("Manually processed flagged phishing reports. Exiting.")
            return
        if self.args.test_report:
            if not self.abuse_email:
                logger.error("For a test report, please provide a test email using --abuse-email")
                return
            attachment = AttachmentConfig.get_attachment() or self.attachment
            self.report_manager.send_test_report(self.abuse_email, attachment_path=attachment)
            logger.info("Test report sent. Exiting.")
            return
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Anisakys Phishing Detection Engine",
        epilog=(
            "Example usages:\n"
            "  ./anisakys.py --timeout 30 --log-level DEBUG\n"
            "  ./anisakys.py --report https://site.domain.com --abuse-email abuse@domain.com\n"
            '  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"\n'
            "  ./anisakys.py --threads-only --log-level DEBUG\n"
            "  ./anisakys.py --test-report --abuse-email your-test@example.com\n"
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
        help="Send a test 2-days report including attachment and escalation CCs, then exit.",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    log_level = (
        args.log_level if args.log_level is not None else getattr(settings, "LOG_LEVEL", "INFO")
    )
    logger.setLevel(log_level)
    engine = Engine(args)
    engine.start()


if __name__ == "__main__":
    main()

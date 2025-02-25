#!/usr/bin/env python3
"""
Anisakys Phishing Detection Engine with Basic WHOIS Lookup and Registrar Abuse Caching

This script scans and processes phishing sites. It retrieves WHOIS information using the
python-whois library and then determines the appropriate abuse email addresses solely based on
the WHOIS data and a cached registrar_abuse table. When WHOIS data indicates a registrar that is known,
the cached abuse email is used. Otherwise, the system attempts to extract all abuse-related email addresses using regex,
and sends the abuse report individually to each detected address.
If any extracted email contains "abuse-tracker" and a better candidate is available, the "abuse-tracker"
address is demoted to CC.

Usage examples:
  ./anisakys.py --timeout 30 --log-level DEBUG
  ./anisakys.py --report "https://resuelve-tucomp.online" --abuse-email abuse@hostinger.com
  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"
"""

import os
import re
import time
import argparse
import requests
from itertools import permutations
import datetime
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from jinja2 import Environment, FileSystemLoader, select_autoescape

import whois  # pip install python-whois

from src.config import settings
from src.logger import logger

# Define which HEAD response codes are acceptable.
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


def init_db(db_file: str = "scan_results.db") -> None:
    """
    Initialize the SQLite database and create the scan_results table if it does not exist.
    """
    conn = sqlite3.connect(db_file)
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


def init_phishing_db(db_file: str = "scan_results.db") -> None:
    """
    Initialize the phishing_sites table.
    This table stores flagged phishing URLs, WHOIS data, an optionally provided abuse email,
    and flags for reporting.
    """
    conn = sqlite3.connect(db_file)
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
            abuse_report_sent INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def init_registrar_abuse_db(db_file: str = "scan_results.db") -> None:
    """
    Initialize the registrar_abuse table, which caches known abuse email addresses for registrars.
    """
    conn = sqlite3.connect(db_file)
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


def get_abuse_email_by_registrar(registrar: str, db_file: str = "scan_results.db") -> Optional[str]:
    """
    Look up a known abuse email in the registrar_abuse table using a fuzzy match.
    """
    logger.debug(f"Looking up abuse email for registrar: '{registrar}'")
    conn = sqlite3.connect(db_file)
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
    logger.debug("No cached abuse email found for registrar")
    return None


def store_scan_result(
    url: str, response_code: int, found_keywords: List[str], db_file: str = "scan_results.db"
) -> None:
    """
    Store or update the scan result in the database.
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
            """
            UPDATE scan_results
            SET last_seen = ?, response_code = ?, found_keywords = ?, count = ?
            WHERE url = ?
            """,
            (timestamp, response_code, keywords_str, count, url),
        )
    else:
        cursor.execute(
            """
            INSERT INTO scan_results (url, first_seen, last_seen, response_code, found_keywords, count)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (url, timestamp, timestamp, response_code, keywords_str, 1),
        )
    conn.commit()
    conn.close()


def log_positive_result(url: str, found_keywords: List[str]) -> None:
    """
    Append a positive scan result to a log file.
    """
    log_file = "positive_report.txt"
    entry = f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {url}: {', '.join(found_keywords)}\n"
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


def augment_with_www(domain: str) -> List[str]:
    """
    Generate domain variations including 'www.' if applicable.
    """
    parts = domain.split(".")
    return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]


def get_candidate_urls(domain: str, timeout: int) -> List[str]:
    """
    Generate candidate URLs for a given domain.
    """
    candidate_domains = augment_with_www(domain)
    candidate_urls = []
    dns_error_logged = False
    for d in candidate_domains:
        for scheme in ("https://", "http://"):
            url = scheme + d
            try:
                response = requests.head(
                    url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT}
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


def generate_search_queries(keywords: List[str], domains: List[str]) -> List[str]:
    """
    Generate search queries from keywords and domain extensions.
    """
    base_queries_with_hyphen: Set[str] = set()
    base_queries_without_hyphen: Set[str] = set()
    for i in range(1, len(keywords) + 1):
        for p in permutations(keywords, i):
            base_queries_with_hyphen.add("-".join(p))
            base_queries_without_hyphen.add("".join(p))
    all_queries = base_queries_with_hyphen.union(base_queries_without_hyphen)
    extended_queries = {f"{query}{domain}" for query in all_queries for domain in domains}
    logger.info(f"Generated {len(extended_queries)} search permutations (with and without hyphen)")
    return list(extended_queries)


def get_dynamic_target_sites(keywords: List[str], domains: List[str]) -> List[str]:
    """
    Generate deduplicated target sites.
    """
    return list(set(generate_search_queries(keywords, domains)))


def scan_site(domain: str, keywords: List[str], timeout: int) -> None:
    """
    Scan a given domain for specified keywords.
    """
    for url in get_candidate_urls(domain, timeout) or []:
        logger.info(f"Scanning {url} for keywords: {keywords}")
        try:
            headers = {"User-Agent": DEFAULT_USER_AGENT}
            response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            response.raise_for_status()
            code = response.status_code
            content = response.text.lower()
            matches = [kw for kw in keywords if kw in content]
            store_scan_result(url, code, matches)
            if matches:
                logger.info(f"Found keywords {matches} in {url}")
                log_positive_result(url, matches)
            else:
                logger.debug(f"No keywords found in {url}")
            break  # Stop after first successful candidate.
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout scanning {url}")
        except requests.exceptions.ConnectionError as e:
            if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                logger.debug(f"DNS failure during scan: {url}")
            else:
                logger.error(f"Connection failure: {url} - {e}")
        except Exception as e:
            logger.error(f"Scan error: {url} - {repr(e)}")


def filter_allowed_targets(targets: List[str], allowed_sites: List[str]) -> List[str]:
    """
    Filter out targets that are in the allowed (whitelist) list.
    """
    allowed_set = {site.lower().strip() for site in allowed_sites}
    filtered = [target for target in targets if target.lower().strip() not in allowed_set]
    removed = len(targets) - len(filtered)
    if removed:
        logger.info(f"Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
    return filtered


def basic_whois_lookup(url: str) -> dict:
    """
    Perform a basic WHOIS lookup using python-whois.
    """
    try:
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
        logger.debug(f"Performing WHOIS lookup for: {domain}")
        data = whois.whois(domain)
        return data
    except Exception as e:
        logger.error(f"Basic WHOIS lookup failed for {url}: {e}")
        return {}


def extract_registrar(whois_data) -> Optional[str]:
    """
    Extract the registrar from WHOIS data.
    """
    if isinstance(whois_data, dict):
        registrar = whois_data.get("registrar")
        if registrar:
            if isinstance(registrar, list):
                extracted = registrar[0].strip()
            else:
                extracted = str(registrar).strip()
            logger.debug(f"Extracted registrar from dict: '{extracted}'")
            return extracted
    whois_str = str(whois_data)
    match = re.search(r"Registrar:\s*(.+)", whois_str, re.IGNORECASE)
    if match:
        extracted = match.group(1).strip()
        logger.debug(f"Extracted registrar via regex: '{extracted}'")
        return extracted
    logger.debug("No registrar found in WHOIS data")
    return None


def get_abuse_email_by_registrar(registrar: str, db_file: str = "scan_results.db") -> Optional[str]:
    """
    Look up a known abuse email address from the registrar_abuse table.
    """
    logger.debug(f"Looking up abuse email for registrar: '{registrar}'")
    conn = sqlite3.connect(db_file)
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
    logger.debug("No cached abuse email found for registrar")
    return None


def extract_abuse_emails(whois_data, domain: str) -> List[str]:
    """
    Extract all abuse-related email addresses from WHOIS data using regex.
    If a cached abuse email exists for the registrar, that email is used exclusively.
    """
    registrar = extract_registrar(whois_data) or ""
    abuse_from_registrar = get_abuse_email_by_registrar(registrar, db_file="scan_results.db")
    if abuse_from_registrar:
        logger.debug(f"Using abuse email from registrar cache: {abuse_from_registrar}")
        return [abuse_from_registrar]
    whois_str = str(whois_data)
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", whois_str)
    abuse_emails = [email for email in emails if "abuse" in email.lower()]
    if abuse_emails:
        logger.debug(f"Found abuse emails via regex: {abuse_emails}")
        return abuse_emails
    logger.debug("No abuse email found via registrar cache or regex; returning empty list")
    return []


def send_abuse_report(
    abuse_emails: List[str],
    site_url: str,
    whois_str: str,
    attachment_path: Optional[str] = None,
    cc_emails: Optional[List[str]] = None,
) -> None:
    """
    Send the same abuse report individually to each abuse email using SMTP.
    If a cached (stored) abuse email is available, it is used as the primary recipient.
    Any extracted email containing "abuse-tracker" is demoted to CC.
    Additional CC addresses provided via the --cc argument are merged.
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
    try:
        html_content = env_jinja.get_template("abuse_report.html").render(
            site_url=site_url,
            whois_info=whois_str,
            attachment_filename=attachment_filename,
            cc_emails=cc_emails,
        )
        logger.debug("Rendered email content (first 300 chars): " + html_content[:300])
    except Exception as render_err:
        logger.error(f"Template rendering failed: {render_err}")
        raise

    # Demote any extracted email containing "abuse-tracker" if there exists a primary candidate without it.
    primary_candidates = [email for email in abuse_emails if "abuse-tracker" not in email.lower()]
    if primary_candidates:
        abuse_emails = primary_candidates

    # Merge any CC provided via argument.
    final_cc = cc_emails[:] if cc_emails else []

    # Send the same message individually to each primary abuse email.
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


def report_phishing_sites(
    db_file: str = "scan_results.db", cc_emails: Optional[List[str]] = None
) -> None:
    """
    Continuously process flagged phishing sites:
    Retrieve WHOIS data, determine the abuse emails (via registrar cache or regex), and send the report.
    """
    while True:
        try:
            conn = sqlite3.connect(db_file)
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
                    cursor.execute(
                        """
                        UPDATE phishing_sites
                        SET whois_info = ?, last_seen = ?, reported = 1
                        WHERE url = ?
                        """,
                        (whois_str, timestamp, url),
                    )
                    logger.info(f"WHOIS data enriched for {url}")
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    if stored_abuse:
                        abuse_list = [stored_abuse]
                    else:
                        abuse_list = extract_abuse_emails(whois_data, domain)
                    if abuse_list and abuse_report_sent == 0:
                        send_abuse_report(abuse_list, url, whois_str, cc_emails=cc_emails)
                        cursor.execute(
                            "UPDATE phishing_sites SET abuse_report_sent = 1 WHERE url = ?", (url,)
                        )
                except Exception as e:
                    logger.error(f"WHOIS query failed for {url}: {e}")
            conn.commit()
        except Exception as outer_e:
            logger.error(f"Error in reporting thread: {outer_e}")
        finally:
            conn.close()
        time.sleep(settings.REPORT_INTERVAL)


def process_manual_reports(
    db_file: str = "scan_results.db",
    attachment_path: Optional[str] = None,
    cc_emails: Optional[List[str]] = None,
) -> None:
    """
    Process flagged phishing sites once for WHOIS enrichment and abuse reporting.
    """
    try:
        conn = sqlite3.connect(db_file)
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
                cursor.execute(
                    """
                    UPDATE phishing_sites
                    SET whois_info = ?, last_seen = ?, reported = 1
                    WHERE url = ?
                    """,
                    (whois_str, timestamp, url),
                )
                logger.info(f"Manually processed WHOIS data for {url}")
                domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                if stored_abuse:
                    abuse_list = [stored_abuse]
                else:
                    abuse_list = extract_abuse_emails(whois_data, domain)
                if abuse_list and abuse_report_sent == 0:
                    send_abuse_report(
                        abuse_list, url, whois_str, attachment_path, cc_emails=cc_emails
                    )
                    cursor.execute(
                        "UPDATE phishing_sites SET abuse_report_sent = 1 WHERE url = ?", (url,)
                    )
            except Exception as e:
                logger.error(f"WHOIS query failed for {url}: {e}")
        conn.commit()
    except Exception as outer_e:
        logger.error(f"Error processing manual reports: {outer_e}")
    finally:
        conn.close()


def mark_site_as_phishing(
    url: str, abuse_email: Optional[str] = None, db_file: str = "scan_results.db"
) -> None:
    """
    Manually flag a URL as phishing in the phishing_sites table.
    """
    conn = sqlite3.connect(db_file)
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


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Anisakys Phishing Detection Engine",
        epilog='Example usages:\n  ./anisakys.py --timeout 30 --log-level DEBUG\n  ./anisakys.py --report https://resuelve-tucomp.online --abuse-email abuse@hostinger.com\n  ./anisakys.py --process-reports --attachment /path/to/file.pdf --cc "cc1@example.com, cc2@example.com"',
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
    parser.add_argument(
        "--report",
        type=str,
        help="Manually flag a URL as phishing.",
    )
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
    return parser.parse_args()


def main() -> None:
    """
    Main execution flow.
    Initializes databases (including registrar abuse table), starts the reporting thread,
    and continuously scans target sites. Supports manual flagging via --report and
    manual report processing via --process-reports with optional attachment and CC list.
    """
    args = parse_arguments()
    logger.setLevel(args.log_level)

    # Parse CC emails if provided.
    cc_emails: Optional[List[str]] = None
    if args.cc:
        cc_emails = [email.strip() for email in args.cc.split(",") if email.strip()]
        logger.debug(f"CC emails provided: {cc_emails}")

    # Initialize databases.
    init_db()
    init_phishing_db()
    init_registrar_abuse_db()

    if args.report:
        mark_site_as_phishing(args.report, abuse_email=args.abuse_email)
        logger.info(f"URL {args.report} flagged as phishing. Exiting after manual report.")
        return

    if args.process_reports:
        process_manual_reports(attachment_path=args.attachment, cc_emails=cc_emails)
        logger.info("Manually processed flagged phishing reports. Exiting.")
        return

    # Start background reporting thread with CC emails.
    reporting_thread = threading.Thread(
        target=report_phishing_sites, args=("scan_results.db", cc_emails), daemon=True
    )
    reporting_thread.start()

    transform_to_list = lambda s: (
        [item.strip() for item in s.split(",")] if isinstance(s, str) else s
    )
    keywords = transform_to_list(settings.KEYWORDS)
    domains = transform_to_list(settings.DOMAINS)
    allowed_sites = transform_to_list(getattr(settings, "ALLOWED_SITES", ""))

    logger.info(f"Initialized with {len(keywords)} keywords and {len(domains)} domain extensions")
    logger.info(f"Allowed sites (whitelist): {allowed_sites}")
    logger.info(f"Scan interval: {settings.SCAN_INTERVAL}s | Timeout: {args.timeout}s")

    while True:
        targets = get_dynamic_target_sites(keywords, domains)
        if allowed_sites:
            targets = filter_allowed_targets(targets, allowed_sites)
        logger.info(f"Beginning scan cycle for {len(targets)} targets")
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {
                executor.submit(scan_site, target, keywords, args.timeout): target
                for target in targets
            }
            for i, future in enumerate(as_completed(futures), 1):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Thread error for {futures[future]}: {repr(e)}")
                if i % 10 == 0:
                    logger.info(f"Progress: {i}/{len(targets)} ({i / len(targets):.1%})")
        logger.info(f"Scan cycle completed. Next cycle in {settings.SCAN_INTERVAL}s")
        time.sleep(settings.SCAN_INTERVAL)


if __name__ == "__main__":
    main()

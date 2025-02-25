#!/usr/bin/env python3
import os
import re
import time
import argparse
import requests
from itertools import permutations
import datetime
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional
import threading
import whois  # pip install python-whois
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader, select_autoescape
from dotenv import load_dotenv

from src.config import settings
from src.logger import logger

# Load environment variables from .env file.
load_dotenv()

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

    Args:
        db_file (str): Path to the SQLite database file.
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
    Initialize the SQLite database by creating the phishing_sites table if it does not exist.

    The phishing_sites table stores manually flagged phishing URLs along with enriched WHOIS data,
    and tracks whether an abuse report email has been sent.

    Args:
        db_file (str): Path to the SQLite database file.
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
            reported INTEGER DEFAULT 0,
            abuse_report_sent INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def store_scan_result(
    url: str, response_code: int, found_keywords: List[str], db_file: str = "scan_results.db"
) -> None:
    """
    Store or update the scan result in the database.

    If the URL already exists, update the last_seen timestamp and increment the count.
    Otherwise, insert a new record with current timestamps.

    Args:
        url (str): The URL that was scanned.
        response_code (int): The HTTP response code obtained.
        found_keywords (List[str]): List of keywords found on the page.
        db_file (str): Path to the SQLite database file.
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
    Append a positive scan result to a report file with the current date and time, avoiding duplicates.

    Args:
        url (str): The URL that yielded positive keyword matches.
        found_keywords (List[str]): The list of keywords found on the URL.
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
    Generate candidate domain variations by including the 'www.' prefix if applicable.

    Args:
        domain (str): The original domain name.

    Returns:
        List[str]: A list containing the original domain and its 'www.' variant (if applicable).
    """
    parts = domain.split(".")
    return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]


def get_candidate_urls(domain: str, timeout: int) -> List[str]:
    """
    Generate candidate URLs for scanning by considering both HTTPS and HTTP variants.
    Includes 'www.' variant if applicable.

    Args:
        domain (str): The domain to generate candidate URLs for.
        timeout (int): Timeout for the HEAD request (in seconds).

    Returns:
        List[str]: List of reachable candidate URLs.
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
    Generate search queries by creating permutations of keywords (hyphenated and non-hyphenated)
    and appending each domain extension.

    Args:
        keywords (List[str]): List of keywords.
        domains (List[str]): List of domain extensions.

    Returns:
        List[str]: List of extended search queries.
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
    Generate and deduplicate dynamic target sites from search queries.

    Args:
        keywords (List[str]): List of keywords.
        domains (List[str]): List of domain extensions.

    Returns:
        List[str]: Deduplicated list of target sites.
    """
    return list(set(generate_search_queries(keywords, domains)))


def scan_site(domain: str, keywords: List[str], timeout: int) -> None:
    """
    Scan a given domain for the presence of specified keywords.

    For each candidate URL generated, perform a GET request, search for keywords in the response,
    store the scan result, and log positive matches.

    Args:
        domain (str): The domain to scan.
        keywords (List[str]): Keywords to search for.
        timeout (int): Request timeout in seconds.
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
            # Stop after first successful candidate.
            break
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

    Args:
        targets (List[str]): List of target sites.
        allowed_sites (List[str]): List of allowed sites.

    Returns:
        List[str]: Filtered list of target sites.
    """
    allowed_set = {site.lower().strip() for site in allowed_sites}
    filtered = [target for target in targets if target.lower().strip() not in allowed_set]
    removed = len(targets) - len(filtered)
    if removed:
        logger.info(f"Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
    return filtered


def extended_whois_lookup(url: str) -> str:
    """
    Perform an extended WHOIS lookup for the given domain.

    This function calls the standard whois lookup and then formats the output,
    including key fields if available. If the whois lookup fails or returns incomplete data,
    a fallback message is returned.

    Args:
        url (str): The domain to perform WHOIS lookup for.

    Returns:
        str: A formatted string containing extended WHOIS information.
    """
    try:
        whois_data = whois.whois(url)
        extended_info = {}
        if isinstance(whois_data, dict):
            for key, value in whois_data.items():
                if value:
                    if isinstance(value, list):
                        extended_info[key] = ", ".join(map(str, value))
                    else:
                        extended_info[key] = str(value)
        else:
            extended_info = {"raw": str(whois_data)}
        # Format the extended information.
        extended_str = "\n".join(f"{k}: {v}" for k, v in extended_info.items())
        return extended_str
    except Exception as e:
        logger.error(f"Extended WHOIS lookup failed for {url}: {e}")
        return "Extended WHOIS lookup failed."


def extract_abuse_email(whois_data) -> Optional[str]:
    """
    Extract an abuse email address from the raw WHOIS data using regex.
    The function searches for all email addresses in the WHOIS output and then selects
    one containing 'abuse' (case-insensitive). If none contain "abuse", it returns the first found email.

    Args:
        whois_data: WHOIS result (dict or object).

    Returns:
        Optional[str]: The abuse email if found, otherwise None.
    """
    raw_data = str(whois_data)
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw_data)
    if not emails:
        return None
    abuse_emails = [email for email in emails if "abuse" in email.lower()]
    return abuse_emails[0] if abuse_emails else emails[0]


def send_abuse_report(abuse_email: str, site_url: str, whois_str: str) -> None:
    """
    Send an abuse report email to the given abuse email address using an SMTP relay.
    The email content is rendered from an HTML Jinja2 template.

    Args:
        abuse_email (str): Recipient abuse email address.
        site_url (str): Phishing site URL.
        whois_str (str): WHOIS information to include in the report.
    """
    smtp_host = os.environ.get("SMTP_HOST", "localhost")
    smtp_port = int(os.environ.get("SMTP_PORT", 1125))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    sender_email = os.environ.get("ABUSE_EMAIL_SENDER", "noreply@example.com")
    subject = os.environ.get("ABUSE_EMAIL_SUBJECT", "Abuse Report for Phishing Site")

    env_jinja = Environment(
        loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"])
    )
    template = env_jinja.get_template("abuse_report.html")
    html_content = template.render(site_url=site_url, whois_info=whois_str)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = abuse_email
    msg.attach(MIMEText(html_content, "html"))
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(sender_email, abuse_email, msg.as_string())
        logger.info(f"Abuse report sent to {abuse_email} for site {site_url}")
    except Exception as e:
        logger.error(f"Failed to send abuse report to {abuse_email}: {e}")


def report_phishing_sites(db_file: str = "scan_results.db") -> None:
    """
    Continuously enrich manually flagged phishing sites with extended WHOIS data,
    extract abuse emails, send abuse reports via SMTP, and update records.
    This function runs in a separate thread.

    Args:
        db_file (str): Path to the SQLite database file.
    """
    while True:
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, reported, abuse_report_sent FROM phishing_sites WHERE manual_flag = 1 AND reported = 0"
            )
            sites = cursor.fetchall()
            for url, reported, abuse_report_sent in sites:
                try:
                    whois_str = extended_whois_lookup(url)
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
                    abuse_email = extract_abuse_email(whois_str)
                    if abuse_email and abuse_report_sent == 0:
                        send_abuse_report(abuse_email, url, whois_str)
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


def process_manual_reports(db_file: str = "scan_results.db") -> None:
    """
    Process manually flagged phishing sites one time for extended WHOIS enrichment and abuse reporting.

    Args:
        db_file (str): Path to the SQLite database file.
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, reported, abuse_report_sent FROM phishing_sites WHERE manual_flag = 1 AND reported = 0"
        )
        sites = cursor.fetchall()
        for url, reported, abuse_report_sent in sites:
            try:
                whois_str = extended_whois_lookup(url)
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
                abuse_email = extract_abuse_email(whois_str)
                if abuse_email and abuse_report_sent == 0:
                    send_abuse_report(abuse_email, url, whois_str)
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


def mark_site_as_phishing(url: str, db_file: str = "scan_results.db") -> None:
    """
    Manually flag a given URL as phishing in the phishing_sites table.

    Args:
        url (str): The URL to mark as phishing.
        db_file (str): Path to the SQLite database file.
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
            SET manual_flag = 1, last_seen = ?, reported = 0, abuse_report_sent = 0
            WHERE url = ?
            """,
            (timestamp, url),
        )
        logger.info(f"Updated phishing flag for {url}")
    else:
        cursor.execute(
            """
            INSERT INTO phishing_sites (url, manual_flag, first_seen, last_seen, reported, abuse_report_sent)
            VALUES (?, 1, ?, ?, 0, 0)
            """,
            (url, timestamp, timestamp),
        )
        logger.info(f"Marked {url} as phishing")
    conn.commit()
    conn.close()


def parse_arguments() -> argparse.Namespace:
    """
    Parse and validate command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Anisakys Phishing Detection Engine",
        epilog="Example usages:\n"
        "  ./anisakys.py --timeout 30 --log-level DEBUG\n"
        "  ./anisakys.py --report example.com\n"
        "  ./anisakys.py --process-reports",
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
        help="Manually flag a URL as phishing. The URL will be added to the phishing_sites table.",
    )
    parser.add_argument(
        "--process-reports",
        action="store_true",
        help="Manually trigger processing of flagged phishing sites for extended WHOIS enrichment and abuse reporting.",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main execution flow for the Anisakys Phishing Detection Engine.

    Initializes databases, starts the reporting thread, and continuously scans target sites.
    Supports manual flagging via '--report' and manual abuse report processing via '--process-reports'.
    """
    args = parse_arguments()
    logger.setLevel(args.log_level)

    # Initialize databases.
    init_db()
    init_phishing_db()

    if args.report:
        mark_site_as_phishing(args.report)
        logger.info(f"URL {args.report} flagged as phishing. Exiting after manual report.")
        return

    if args.process_reports:
        process_manual_reports()
        logger.info("Manually processed flagged phishing reports. Exiting.")
        return

    # Start background reporting thread.
    reporting_thread = threading.Thread(target=report_phishing_sites, daemon=True)
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

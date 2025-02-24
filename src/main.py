#!/usr/bin/env python3
import os
import time
import argparse
import requests
from itertools import permutations
import datetime
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set
from src.config import settings
from src.logger import logger

# Define which HEAD response codes are acceptable
ALLOWED_HEAD_STATUS = {200, 201, 202, 203, 204, 205, 206, 301, 302, 403, 405, 503, 504}

# Constants
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


#####################
# DATABASE FUNCTIONS
#####################
def init_db(db_file: str = "scan_results.db"):
    """Initialize the SQLite database and create the scan_results table if not exists."""
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


def store_scan_result(
    url: str, response_code: int, found_keywords: List[str], db_file: str = "scan_results.db"
):
    """
    Store or update the scan result in the database.
    If the URL exists, update the last_seen timestamp and increment the count.
    Otherwise, insert a new record with first_seen and last_seen set to the current time.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    keywords_str = ", ".join(found_keywords) if found_keywords else ""

    # Check if the URL already exists in the table
    cursor.execute("SELECT id, first_seen, count FROM scan_results WHERE url=?", (url,))
    row = cursor.fetchone()
    if row:
        first_seen = row[1]
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


############################
# REPORTING POSITIVE RESULTS
############################
def log_positive_result(url: str, found_keywords: List[str]):
    """Append a positive scan result to a report file with the current date and time, avoiding duplicates."""
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


#########################
# DOMAIN & URL HANDLING
#########################
def augment_with_www(domain: str) -> List[str]:
    """Return a list containing the original domain and (if no subdomain is specified) the 'www.' variant."""
    parts = domain.split(".")
    return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]


def get_candidate_urls(domain: str, timeout: int) -> List[str]:
    """
    Return candidate URLs (both HTTPS and HTTP variants) for a given domain.
    If the domain does not specify a subdomain, also include the 'www.' variant.
    Uses HEAD requests to check reachability and logs DNS errors only once.
    Only URLs with a response code in ALLOWED_HEAD_STATUS are accepted.
    Returns an empty list if no candidate URLs are reachable.
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


#############################
# SEARCH QUERIES GENERATOR
#############################
def generate_search_queries(keywords: List[str], domains: List[str]) -> List[str]:
    """
    Generate domain permutations using both hyphenated and non-hyphenated combinations.
    Then append each domain extension.
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
    """Generate and deduplicate target sites from the search queries."""
    return list(set(generate_search_queries(keywords, domains)))


##################
# SCANNING FUNCTION
##################
def scan_site(domain: str, keywords: List[str], timeout: int):
    """
    Scan a given domain for the presence of specified keywords.
    Uses candidate URLs from get_candidate_urls() and stores scan results in the database.
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
            store_scan_result(url, code, matches)  # Update or insert scan result

            if matches:
                logger.info(f"Found keywords {matches} in {url}")
                log_positive_result(url, matches)
            else:
                logger.debug(f"No keywords found in {url}")
            # Stop scanning after the first successful candidate URL.
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


####################
# ALLOWED SITES FILTERING
####################
def filter_allowed_targets(targets: List[str], allowed_sites: List[str]) -> List[str]:
    """
    Remove targets that are in the allowed (whitelist) list.
    The allowed_sites list is compared against target strings in lowercase.
    """
    allowed_set = {site.lower().strip() for site in allowed_sites}
    filtered = [target for target in targets if target.lower().strip() not in allowed_set]
    removed = len(targets) - len(filtered)
    if removed:
        logger.info(f"Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
    return filtered


#####################
# MAIN EXECUTION FLOW
#####################
def parse_arguments() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Anisakys Phishing Detection Engine",
        epilog="Example: ./anisakys.py --timeout 30 --log-level DEBUG",
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
    return parser.parse_args()


def main():
    """Main execution flow with continuous parallel scanning."""
    args = parse_arguments()
    logger.setLevel(args.log_level)

    # Initialize the database.
    init_db()

    # Ensure KEYWORDS, DOMAINS, and ALLOWED_SITES are lists (transform from comma-separated strings if necessary).
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
        # Filter out allowed targets.
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

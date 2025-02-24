#!/usr/bin/env python3
import os
import time
import argparse
import requests
from itertools import permutations
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set
from src.config import settings
from src.logger import logger

# Constants
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/115.0 Safari/537.36"
)
DNS_ERROR_KEYPHRASES = {
    "Name or service not known",
    "getaddrinfo failed",
    "Failed to resolve",
    "Max retries exceeded",
}


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


def generate_search_queries(keywords: List[str], domains: List[str]) -> List[str]:
    """Generate domain permutations with combinatorial optimization."""
    base_queries: Set[str] = set()
    for i in range(1, len(keywords) + 1):
        base_queries.update("-".join(p) for p in permutations(keywords, i))

    extended_queries = {f"{query}{domain}" for query in base_queries for domain in domains}
    logger.info(f"Generated {len(extended_queries)} search permutations")
    return list(extended_queries)


def get_dynamic_target_sites(keywords: List[str], domains: List[str]) -> List[str]:
    """Generate and validate target sites with deduplication."""
    return list(set(generate_search_queries(keywords, domains)))


def log_positive_result(url: str, found_keywords: List[str]):
    """Atomic write operation with duplicate checking."""
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
    """Domain variant generator."""
    parts = domain.split(".")
    return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]


def get_candidate_urls(domain: str, timeout: int) -> List[str]:
    """Intelligent domain reachability checker with protocol fallback."""
    candidates = []
    dns_error_logged = False

    for variant in augment_with_www(domain):
        for scheme in ("https://", "http://"):
            url = scheme + variant
            try:
                response = requests.head(
                    url, timeout=timeout, headers={"User-Agent": DEFAULT_USER_AGENT}
                )
                if response.status_code < 400:
                    candidates.append(url)
                else:
                    logger.warning(f"HTTP {response.status_code} at {url}")
            except requests.exceptions.ConnectionError as e:
                if any(phrase in str(e) for phrase in DNS_ERROR_KEYPHRASES):
                    if not dns_error_logged:
                        logger.debug(f"DNS resolution failed for {url}")
                        dns_error_logged = True
                else:
                    logger.error(f"Connection error: {url} - {e}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Protocol error: {url} - {e}")

    return candidates


def scan_site(domain: str, keywords: List[str], timeout: int):
    """Comprehensive site scanner with intelligent error handling."""
    for url in get_candidate_urls(domain, timeout) or []:
        logger.info(f"Scanning {url}")
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=True,
            )
            response.raise_for_status()

            content = response.text.lower()
            matches = [kw for kw in keywords if kw in content]

            if matches:
                log_positive_result(url, matches)
                break  # Successful scan, exit loop
            else:
                logger.debug(f"No keywords found in {url}")

        except requests.exceptions.ConnectionError as e:
            if any(phrase in str(e) for phrase in DNS_ERROR_KEYPHRASES):
                logger.debug(f"DNS failure during scan: {url}")
            else:
                logger.error(f"Connection failure: {url} - {e}")
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout scanning {url}")
        except Exception as e:
            logger.error(f"Scan error: {url} - {repr(e)}")


def main():
    """Main execution flow with continuous scanning."""
    args = parse_arguments()
    logger.setLevel(args.log_level)

    # Config validation
    keywords = (
        [k.strip() for k in settings.KEYWORDS.split(",")]
        if isinstance(settings.KEYWORDS, str)
        else settings.KEYWORDS
    )
    domains = (
        [d.strip() for d in settings.DOMAINS.split(",")]
        if isinstance(settings.DOMAINS, str)
        else settings.DOMAINS
    )

    logger.info(f"Initialized with {len(keywords)} keywords and {len(domains)} domain extensions")
    logger.info(f"Scan interval: {settings.SCAN_INTERVAL}s | Timeout: {args.timeout}s")

    while True:
        targets = get_dynamic_target_sites(keywords, domains)
        logger.info(f"Beginning scan cycle for {len(targets)} targets")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(scan_site, target, keywords, args.timeout): target
                for target in targets
            }

            for i, future in enumerate(as_completed(futures), 1):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Thread error: {futures[future]} - {repr(e)}")

                if i % 10 == 0:
                    logger.info(f"Progress: {i}/{len(targets)} ({i / len(targets):.1%})")

        logger.info(f"Scan cycle completed. Next cycle in {settings.SCAN_INTERVAL}s")
        time.sleep(settings.SCAN_INTERVAL)


if __name__ == "__main__":
    main()

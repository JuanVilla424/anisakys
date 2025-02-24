#!/usr/bin/env python3
import os
import time
import argparse
import requests
from itertools import permutations
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.config import settings
from src.logger import logger


def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Anisakys Phishing Detector.")
    parser.add_argument(
        "--timeout",
        type=int,
        choices=range(10, 300),
        metavar="[10-300]",
        help="Timeout in seconds. Defaults to 50 seconds. Must be between 10 to 300.",
    )
    parser.add_argument(
        "--log-level",
        choices=["INFO", "DEBUG"],
        default="INFO",
        help="Logging level. Defaults to INFO.",
    )
    return parser.parse_args()


def generate_search_queries(keywords: list[str], domains: list[str]) -> list[str]:
    """
    Generates search queries by taking all hyphenated permutations of the keywords,
    then appending each domain from the provided list.
    For example, if keywords are ["security", "vulnerability"], it produces:
      - "security-vulnerability.com"
      - "security-vulnerability.co"
      - etc.
    """
    base_queries = set()
    for i in range(1, len(keywords) + 1):
        for perm in permutations(keywords, i):
            hyphen_query = "-".join(perm)
            base_queries.add(hyphen_query)

    extended_queries = set()
    for query in base_queries:
        for domain in domains:
            extended_queries.add(query + domain)

    logger.info(
        f"Generated {len(extended_queries)} search queries from keyword permutations with domain extensions."
    )
    return list(extended_queries)


def get_dynamic_target_sites(keywords: list[str], domains: list[str]) -> list[str]:
    """
    Generates dynamic target sites by creating search queries from keyword permutations
    with domain extensions, then aggregating those queries as candidate sites.
    """
    queries = generate_search_queries(keywords, domains)
    target_sites = set(queries)  # Each query is already a candidate domain string
    logger.info(f"Identified {len(target_sites)} unique target sites from search queries.")
    return list(target_sites)


def log_positive_result(url: str, found_keywords: list[str]):
    """
    Appends a positive scan result to an output file with the current date and time,
    but only if the URL hasn't already been logged.
    """
    log_filename = "positive_report.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_entry = f"{timestamp} - {url}: {', '.join(found_keywords)}\n"

    # Check if the file exists and if the URL is already logged.
    if os.path.exists(log_filename):
        with open(log_filename, "r") as f:
            file_content = f.read()
            if url in file_content:
                logger.info(
                    f"URL {url} is already recorded in {log_filename}. Skipping duplicate entry."
                )
                return

    # Append new entry if not already present.
    with open(log_filename, "a") as f:
        f.write(new_entry)
    logger.info(f"Logged positive result for {url} to {log_filename}.")


def augment_with_www(domain: str) -> list[str]:
    """
    Returns a list containing the original domain and, if no subdomain is specified
    (i.e. the domain splits into exactly 2 parts), also the domain prefixed with 'www.'.
    """
    parts = domain.split(".")
    if len(parts) == 2:
        return [domain, "www." + domain]
    return [domain]


def get_candidate_urls(domain: str) -> list[str]:
    """
    Returns candidate URLs (both HTTPS and HTTP variants) for a given domain.
    If the domain does not specify a subdomain (e.g., "fmc.jp"), also includes the "www." version.
    Checks domain resolution using HEAD requests and logs errors in a controlled manner.
    If no candidate URLs are reachable, returns an empty list.
    """
    candidate_domains = augment_with_www(domain)
    candidate_urls = []
    encountered_resolution_error = False
    for d in candidate_domains:
        for scheme in ["https://", "http://"]:
            full_url = scheme + d
            try:
                # Use a HEAD request to quickly check if the URL is reachable.
                response = requests.head(full_url, timeout=3)
                if response.status_code < 400:
                    candidate_urls.append(full_url)
                else:
                    logger.warning(f"{full_url} returned status code {response.status_code}")
            except requests.exceptions.ConnectionError as e:
                error_str = str(e)
                # Check if the error indicates a DNS resolution issue.
                if (
                    "Name or service not known" in error_str
                    or "getaddrinfo failed" in error_str
                    or "Failed to resolve" in error_str
                    or "Max retries exceeded" in error_str
                ):
                    if not encountered_resolution_error:
                        logger.debug(
                            f"Domain resolution failed for {full_url}: {e}"
                        )  # Changed to debug
                        encountered_resolution_error = True
                else:
                    logger.error(f"Connection error checking {full_url}: {e}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error checking {full_url}: {e}")
    if not candidate_urls:
        logger.error(f"No reachable candidate URLs found for domain: {domain}")
        return []
    return candidate_urls


def scan_site(domain: str, keywords: list[str]):
    """
    Scans a given domain for the presence of any specified keywords.
    Tries both HTTPS and HTTP variants (and, if applicable, the www. version) returned by get_candidate_urls.
    If no candidate URLs are reachable, the domain is skipped.
    """
    candidate_urls = get_candidate_urls(domain)
    if not candidate_urls:
        logger.info(f"Skipping domain {domain} as no candidate URLs are reachable.")
        return
    for url in candidate_urls:
        logger.info(f"Scanning {url} for keywords: {keywords}")
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/115.0 Safari/537.36"
            }
            response = requests.get(url, timeout=settings.TIMEOUT, headers=headers)
            response.raise_for_status()
            content = response.text

            found_keywords = [kw for kw in keywords if kw in content]
            if found_keywords:
                logger.info(f"Found keywords {found_keywords} in {url}")
                log_positive_result(url, found_keywords)
            else:
                logger.info(f"No keywords found in {url}")
            # If one candidate URL works, we break out of the loop.
            break
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout scanning {url}: {e}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error scanning {url}: {e}")
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")


def main():
    args = parse_arguments()

    # Override settings.TIMEOUT if provided via command-line.
    if args.timeout:
        settings.TIMEOUT = args.timeout

    # Use a lambda to ensure KEYWORDS and DOMAINS are lists.
    transform_to_list = lambda s: (
        [item.strip() for item in s.split(",")] if isinstance(s, str) else s
    )
    keywords = transform_to_list(settings.KEYWORDS)
    domains = transform_to_list(settings.DOMAINS)

    logger.info(f"Scan interval: {settings.SCAN_INTERVAL} seconds")
    logger.info(f"Keywords: {keywords}")
    logger.info(f"Domains: {domains}")

    while True:
        target_sites = get_dynamic_target_sites(keywords, domains)
        total_targets = len(target_sites)
        logger.info(f"Identified {total_targets} target sites to scan: {target_sites}")

        # Use a ThreadPoolExecutor to scan sites in parallel.
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_domain = {
                executor.submit(scan_site, domain, keywords): domain for domain in target_sites
            }
            completed = 0
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error scanning {domain}: {e}")
                completed += 1
                remaining = total_targets - completed
                logger.info(
                    f"Completed scanning target {completed}/{total_targets}. Remaining: {remaining}"
                )

        logger.info(f"Sleeping for {settings.SCAN_INTERVAL} seconds before next scan cycle...")
        time.sleep(settings.SCAN_INTERVAL)


if __name__ == "__main__":
    main()

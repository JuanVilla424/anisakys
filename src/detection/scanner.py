"""
Phishing Scanner for Anisakys Phishing Detection Engine.

Main scanner class for detecting phishing sites through keyword analysis.
"""

from __future__ import annotations

import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.config import (
    settings,
    CLOUDFLARE_IP_RANGES,
    ALLOWED_HEAD_STATUS,
    BROWSER_HEADERS,
    DNS_ERROR_KEY_PHRASES,
)
from src.data import ASN_ABUSE_EMAIL_DB, PROVIDER_ABUSE_EMAIL_DB
from src.database import DatabaseManager, DATABASE_URL
from src.detection.redirect_analyzer import RedirectAnalyzer
from src.detection.utils import PhishingUtils
from src.dns.network_utils import get_ip_info, is_cloudflare_ip
from src.generators.query_generator import generate_queries_file
from src.intelligence import MultiAPIValidator, AUTO_ANALYSIS_ENABLED, AbuseContactResolver
from src.logger import logger
from src.models import DynamicBatchConfig
from src.monitoring.takedown import get_offset, save_offset
from src.observability.metrics import increment_counter, METRIC_REDIRECT_CHAINS_TOTAL
from src.observability.structured_logger import log_error
from src.shutdown import shutdown_requested

QUERIES_FILE = getattr(settings, "QUERIES_FILE", None)
ENABLE_REDIRECT_ANALYSIS = getattr(settings, "ENABLE_REDIRECT_ANALYSIS", True)
MAX_REDIRECT_HOPS = getattr(settings, "MAX_REDIRECT_HOPS", 5)
REDIRECT_TIMEOUT_PER_HOP = getattr(settings, "REDIRECT_TIMEOUT_PER_HOP", 10)

# Default User-Agent for HTTP requests
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


class PhishingScanner:
    """Enhanced phishing scanner with optional auto-analysis integration."""

    def __init__(
        self, timeout: int, keywords: List[str], domains: List[str], allowed_sites: List[str], args
    ):
        self.timeout = timeout
        self.keywords = keywords
        self.domains = domains
        self.allowed_sites = allowed_sites
        self.batch_size = DynamicBatchConfig.get_batch_size()

        # These are always initialized for core functionality
        self.multi_api_validator = MultiAPIValidator()
        self.db_manager = None

        # Initialize a database for auto-analysis only if enabled
        if AUTO_ANALYSIS_ENABLED:
            try:
                self.db_manager = DatabaseManager(db_url=DATABASE_URL)
                logger.debug("🗄️  Database manager initialized for auto-analysis")
            except Exception as e:
                logger.warning(f"⚠️  Could not initialize database for auto-analysis: {e}")
                self.db_manager = None
        else:
            logger.debug("ℹ️  Auto-analysis disabled, skipping database manager for scanner")

        # Initialize Redirect Analyzer (EPIC-001)
        self.redirect_analyzer = None
        if ENABLE_REDIRECT_ANALYSIS:
            self.redirect_analyzer = RedirectAnalyzer(
                max_hops=MAX_REDIRECT_HOPS, timeout_per_hop=REDIRECT_TIMEOUT_PER_HOP
            )
            logger.info(
                f"🔗 Redirect analysis enabled (max_hops={MAX_REDIRECT_HOPS}, timeout={REDIRECT_TIMEOUT_PER_HOP}s)"
            )
        else:
            logger.debug("ℹ️  Redirect analysis disabled")

        # Initialize Abuse Contact Resolver (EPIC-005)
        self.abuse_resolver = AbuseContactResolver(
            asn_db=ASN_ABUSE_EMAIL_DB,
            provider_db=PROVIDER_ABUSE_EMAIL_DB,
            validate_domains=True,
            max_contacts=10,
        )
        logger.info("📧 Abuse contact resolver initialized (multi-contact support)")

        if args.test_report:
            logger.info("🧪 Test report mode active: Skipping queries file generation.")
            self.total_queries = 0
        else:
            if not args.threads_only:
                if args.regen_queries or not os.path.exists(QUERIES_FILE):
                    logger.info(f"📄 Generating queries file {QUERIES_FILE}...")
                    generate_queries_file(self.keywords, self.domains, QUERIES_FILE)
                else:
                    logger.info(f"📄 Using existing {QUERIES_FILE} file.")
            else:
                logger.info("🧵 Threads-only mode: Skipping queries file generation.")

            try:
                with open(QUERIES_FILE, "r") as f:
                    self.total_queries = sum(1 for _ in f)
                logger.info(f"📊 Total queries in file: {self.total_queries}")
            except Exception as ex:
                log_error(
                    logger,
                    ex,
                    {
                        "queries_file": QUERIES_FILE,
                        "operation": "count_queries",
                        "event_type": "query_count_failed",
                    },
                )
                self.total_queries = 0

    def get_dynamic_target_sites(self) -> List[str]:
        """Get the next batch of target sites from a query file."""
        offset = get_offset()
        batch = []
        logger.debug(f"📖 Getting targets from offset {offset}, batch_size={self.batch_size}")

        # If offset is beyond file size, reset to beginning for continuous scanning
        if 0 < self.total_queries <= offset:
            logger.info(
                f"🔄 Offset {offset} beyond file size {self.total_queries}. Resetting to beginning for continuous scanning."
            )
            save_offset(0)
            offset = 0

        try:
            with open(QUERIES_FILE, "r") as f:
                # Skip to current offset
                for _ in range(offset):
                    f.readline()

                # Read the next batch
                for _ in range(self.batch_size):
                    line = f.readline()
                    if not line:  # End of a file
                        break
                    batch.append(line.strip())
        except Exception as e:
            logger.error(f"❌ Error reading queries file {QUERIES_FILE}: {e}")
            return []

        if not batch:
            # If no batch read (shouldn't happen with reset logic above), reset anyway
            logger.info("🔄 Empty batch read, resetting offset to 0 for continuous scanning.")
            save_offset(0)
            return self.get_dynamic_target_sites()  # Recursive call to get batch from start
        else:
            new_offset = offset + len(batch)
            save_offset(new_offset)

            # Calculate progress
            if self.total_queries > 0:
                progress_percent = (new_offset / self.total_queries) * 100
                remaining = self.total_queries - new_offset
                logger.debug(
                    f"📊 Batch from offset {offset}: {len(batch)} queries read. "
                    f"Progress: {progress_percent:.1f}% ({remaining} remaining)"
                )
            else:
                logger.debug(f"📊 Batch from offset {offset}: {len(batch)} queries read.")

        logger.debug(f"📦 Returning batch of {len(batch)} targets")
        return batch

    @staticmethod
    def augment_with_www(domain: str) -> List[str]:
        """Augment domain with www variant."""
        parts = domain.split(".")
        return [domain, f"www.{domain}"] if len(parts) == 2 else [domain]

    def filter_allowed_targets(self, targets: List[str]) -> List[str]:
        """Filter out allowed/allowlisted targets."""
        allowed_set = {site.lower().strip() for site in self.allowed_sites}
        filtered = [target for target in targets if target.lower().strip() not in allowed_set]
        removed = len(targets) - len(filtered)
        if removed:
            logger.info(f"🚫 Filtered out {removed} allowed target(s); {len(filtered)} remaining.")
        return filtered

    def get_candidate_urls(self, domain: str) -> List[str]:
        """Get candidate URLs for a domain with enhanced validation."""
        candidate_domains = self.augment_with_www(domain)
        candidate_urls = []
        dns_error_logged = False

        for d in candidate_domains:
            for scheme in ("https://", "http://"):
                url = scheme + d
                try:
                    response = requests.head(
                        url,
                        timeout=self.timeout,
                        headers={
                            "User-Agent": DEFAULT_USER_AGENT,
                            "Accept": "*/*",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept-Encoding": "gzip, deflate, br",
                            "DNT": "1",
                            "Connection": "keep-alive",
                        },
                        allow_redirects=True,
                    )
                    if response.status_code in ALLOWED_HEAD_STATUS:
                        candidate_urls.append(url)
                    else:
                        logger.warning(
                            f"⚠️  HTTP {response.status_code} at {url} is not acceptable for scanning"
                        )

                except requests.exceptions.ConnectionError as e:
                    if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                        if not dns_error_logged:
                            logger.debug(f"🌐 DNS resolution failed for {url}: {e}")
                            dns_error_logged = True
                    else:
                        logger.error(f"❌ Connection error: {url} - {e}")

                except requests.exceptions.RequestException as e:
                    logger.error(f"❌ Protocol error: {url} - {e}")

        if not candidate_urls:
            logger.debug(f"ℹ️  No reachable candidate URLs found for domain: {domain}")

        return candidate_urls

    def scan_site(self, domain: str) -> None:
        """Scan a single site for phishing indicators with automatic multi-API analysis integration."""
        code = 0
        for url in self.get_candidate_urls(domain) or []:
            logger.info(f"🔍 Scanning {url} for keywords: {self.keywords}")
            try:
                headers = BROWSER_HEADERS.copy()

                # EPIC-001: Analyze redirect chain if enabled
                redirect_chain = None
                final_url = url
                if self.redirect_analyzer:
                    try:
                        redirect_chain = self.redirect_analyzer.analyze(url, headers=headers)
                        final_url = redirect_chain.final_url

                        log_with_context(
                            logger,
                            "info",
                            f"Redirect analysis complete: {redirect_chain.hop_count} hops, risk_score={redirect_chain.risk_score}",
                            {
                                "original_url": url,
                                "final_url": final_url,
                                "hop_count": redirect_chain.hop_count,
                                "risk_score": redirect_chain.risk_score,
                                "has_cloudflare": redirect_chain.has_cloudflare,
                                "has_suspicious_tld": redirect_chain.has_suspicious_tld,
                                "event_type": "redirect_analysis_complete",
                            },
                        )
                    except Exception as redirect_error:
                        log_error(
                            logger,
                            redirect_error,
                            {"url": url, "event_type": "redirect_analysis_failed"},
                        )

                # Fetch content (use final URL if redirects were analyzed)
                response = requests.get(
                    final_url, timeout=self.timeout, headers=headers, allow_redirects=False
                )
                response.raise_for_status()
                code = response.status_code

                # Enhanced keyword detection
                content = response.text.lower()
                matches = []

                # Check for exact keyword matches
                for kw in self.keywords:
                    if kw.lower() in content:
                        matches.append(kw)

                # Additional phishing indicators
                phishing_indicators = [
                    "login",
                    "password",
                    "account",
                    "verify",
                    "suspend",
                    "secure",
                    "update",
                    "confirm",
                    "billing",
                    "payment",
                    "expire",
                ]

                for indicator in phishing_indicators:
                    if indicator in content and indicator not in matches:
                        # Only add if it's contextually relevant
                        if any(kw.lower() in content for kw in self.keywords):
                            matches.append(indicator)

                # Always store a scan result in the original table
                PhishingUtils.store_scan_result(url, code, matches, db_file=DATABASE_URL)

                if matches:
                    logger.info(f"🎯 Phishing keywords found in {url}: {matches}")
                    PhishingUtils.log_positive_result(url, matches)

                    # Auto-detection integration (optional, only if APIs are configured and DB available)
                    if AUTO_ANALYSIS_ENABLED and self.db_manager is not None:
                        try:
                            # Store for auto-analysis
                            stored = self.db_manager.store_detected_phishing_site(
                                url, matches, source="auto_detection"
                            )

                            if stored:
                                logger.info(f"📥 Queued for auto-analysis: {url}")

                                # EPIC-001: Store redirect chain if analyzed
                                if redirect_chain and redirect_chain.hop_count > 0:
                                    increment_counter(METRIC_REDIRECT_CHAINS_TOTAL)
                                    try:
                                        # Get site_id from the stored detection
                                        with self.db_manager.engine.begin() as conn:
                                            site_result = conn.execute(
                                                text(
                                                    "SELECT id FROM phishing_sites WHERE url = :url ORDER BY id DESC LIMIT 1"
                                                ),
                                                {"url": url},
                                            ).fetchone()

                                            if site_result:
                                                site_id = site_result[0]

                                                # Insert redirect chain
                                                conn.execute(
                                                    text(
                                                        """
                                                        INSERT INTO redirect_chains (
                                                            site_id, original_url, final_url, hop_count,
                                                            chain_urls, status_codes, risk_score,
                                                            has_cloudflare, has_suspicious_tld, has_url_shortener,
                                                            has_cross_domain, has_loop, total_time_ms, analyzed_at
                                                        ) VALUES (
                                                            :site_id, :original_url, :final_url, :hop_count,
                                                            :chain_urls::jsonb, :status_codes::jsonb, :risk_score,
                                                            :has_cloudflare, :has_suspicious_tld, :has_url_shortener,
                                                            :has_cross_domain, :has_loop, :total_time_ms, NOW()
                                                        )
                                                    """
                                                    ),
                                                    {
                                                        "site_id": site_id,
                                                        "original_url": redirect_chain.original_url,
                                                        "final_url": redirect_chain.final_url,
                                                        "hop_count": redirect_chain.hop_count,
                                                        "chain_urls": json.dumps(
                                                            redirect_chain.chain_urls
                                                        ),
                                                        "status_codes": json.dumps(
                                                            redirect_chain.status_codes
                                                        ),
                                                        "risk_score": redirect_chain.risk_score,
                                                        "has_cloudflare": redirect_chain.has_cloudflare,
                                                        "has_suspicious_tld": redirect_chain.has_suspicious_tld,
                                                        "has_url_shortener": redirect_chain.has_url_shortener,
                                                        "has_cross_domain": redirect_chain.has_cross_domain,
                                                        "has_loop": redirect_chain.has_loop,
                                                        "total_time_ms": redirect_chain.total_time_ms,
                                                    },
                                                )
                                                logger.info(
                                                    f"🔗 Stored redirect chain for site_id={site_id}: {redirect_chain.hop_count} hops, risk={redirect_chain.risk_score}"
                                                )
                                    except Exception as chain_error:
                                        log_error(
                                            logger,
                                            chain_error,
                                            {
                                                "url": url,
                                                "event_type": "redirect_chain_storage_failed",
                                            },
                                        )

                            # Immediate analysis for critical keywords
                            critical_keywords = [
                                "login",
                                "password",
                                "account",
                                "banking",
                                "paypal",
                            ]
                            has_critical = any(
                                kw.lower() in [m.lower() for m in matches]
                                for kw in critical_keywords
                            )

                            if has_critical:
                                logger.warning(
                                    f"🚨 Critical keywords detected in {url}, performing immediate analysis"
                                )
                                try:
                                    immediate_results = self.multi_api_validator.comprehensive_scan(
                                        url
                                    )
                                    threat_level = immediate_results.get(
                                        "aggregated_threat_level", "unknown"
                                    )
                                    confidence = immediate_results.get("confidence_score", 0)

                                    logger.warning(
                                        f"⚡ Immediate analysis complete for {url}: Threat={threat_level}, Confidence={confidence}%"
                                    )

                                    # Store immediate results
                                    with self.db_manager.engine.begin() as conn:
                                        conn.execute(
                                            text(
                                                """
                                                UPDATE phishing_sites
                                                SET auto_analysis_status = 'completed',
                                                    auto_analysis_timestamp = :timestamp,
                                                    virustotal_result = :vt_result,
                                                    urlvoid_result = :uv_result,
                                                    phishtank_result = :pt_result,
                                                    multi_api_threat_level = :threat_level,
                                                    api_confidence_score = :confidence_score,
                                                    priority = 'high'
                                                WHERE url = :url
                                            """
                                            ),
                                            {
                                                "timestamp": datetime.datetime.now().strftime(
                                                    "%Y-%m-%d %H:%M:%S"
                                                ),
                                                "vt_result": json.dumps(
                                                    immediate_results.get("virustotal", {})
                                                ),
                                                "uv_result": json.dumps(
                                                    immediate_results.get("urlvoid", {})
                                                ),
                                                "pt_result": json.dumps(
                                                    immediate_results.get("phishtank", {})
                                                ),
                                                "threat_level": threat_level,
                                                "confidence_score": confidence,
                                                "url": url,
                                            },
                                        )

                                except Exception as api_error:
                                    logger.error(
                                        f"❌ Immediate multi-API analysis failed for {url}: {api_error}"
                                    )

                        except Exception as auto_error:
                            logger.error(
                                f"❌ Auto-detection integration failed for {url}: {auto_error}"
                            )
                            # Continue with normal operation even if auto-detection fails
                            pass
                else:
                    logger.debug(f"ℹ️  No keywords found in {url}")

                break

            except requests.exceptions.Timeout:
                logger.warning(f"⏰ Timeout scanning {url}")
                PhishingUtils.update_scan_result_response_code(url, code)

            except requests.exceptions.ConnectionError as e:
                if any(phrase in str(e) for phrase in DNS_ERROR_KEY_PHRASES):
                    logger.info(f"🌐 DNS failure during scan: {url}")
                else:
                    logger.error(f"❌ Connection failure: {url} - {e}")
                PhishingUtils.update_scan_result_response_code(url, code)

            except Exception as e:
                logger.error(f"❌ Scan error: {url} - {repr(e)}")
                PhishingUtils.update_scan_result_response_code(url, code)

    def run_scan_cycle(self) -> None:
        """Run continuous scanning cycles with integrated auto-analysis."""
        logger.info("🚀 Starting enhanced continuous scanning with auto-analysis integration...")
        logger.debug(
            f"⚙️  Scanner configuration: timeout={self.timeout}, keywords={len(self.keywords)}, domains={len(self.domains)}"
        )
        logger.debug(f"📊 Total queries to process: {self.total_queries}")

        cycle_count = 0
        while not shutdown_requested:
            cycle_count += 1
            logger.debug(f"🔄 Starting scan cycle #{cycle_count}")

            targets = self.get_dynamic_target_sites()
            if not targets:
                logger.info("🔄 Reached end of queries file, resetting to beginning...")
                save_offset(0)  # Reset to start
                continue

            if self.allowed_sites:
                targets = self.filter_allowed_targets(targets)

            current_offset = get_offset()
            progress = (
                f"{current_offset}/{self.total_queries}"
                if self.total_queries > 0
                else f"{current_offset}/∞"
            )
            logger.info(
                f"🔍 [Cycle {cycle_count}] Processing batch: offset {progress}, batch size {len(targets)}"
            )

            # Use ThreadPoolExecutor for parallel scanning
            logger.debug(
                f"🧵 Starting parallel scanning with 180 workers for {len(targets)} targets"
            )
            with ThreadPoolExecutor(max_workers=180) as executor:
                futures = {executor.submit(self.scan_site, target): target for target in targets}

                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"❌ Thread error for {futures[future]}: {repr(e)}")

                    # Progress every 150 completed scans
                    if completed % 150 == 0:
                        progress_percent = (completed / len(targets)) * 100
                        logger.info(
                            f"📊 [Cycle {cycle_count}] Progress: {completed}/{len(targets)} ({progress_percent:.1f}%)"
                        )

            logger.info(
                f"✅ [Cycle {cycle_count}] Completed batch of {len(targets)} targets. Moving to next batch..."
            )

            # Cleanup memory
            gc.collect()

            # Very short pause to prevent overwhelming (1 second)
            time.sleep(1)

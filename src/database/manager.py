"""
Database manager for Anisakys Phishing Detection Engine.

Provides database operations with enhanced auto-analysis support.
"""

import datetime
import json
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_detection, log_error

# Database configuration
DATABASE_URL = getattr(settings, "DATABASE_URL", None)
if not DATABASE_URL:
    raise Exception("DATABASE_URL must be set in your .env file")

# Global engine for database operations with NullPool to avoid connection issues
db_engine = create_engine(DATABASE_URL, poolclass=NullPool, echo=False)


class DatabaseManager:
    """Database operations manager with enhanced auto-analysis support."""

    def __init__(self, db_url: str = None):
        self.db_url = db_url or DATABASE_URL
        # Reuse the shared global engine for the default URL; honor an
        # explicit different db_url instead of silently ignoring it.
        if self.db_url == DATABASE_URL:
            self.engine = db_engine
        else:
            self.engine = create_engine(self.db_url, poolclass=NullPool, echo=False)

    def init_db(self):
        """Initialize scan results table."""
        with self.engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id SERIAL PRIMARY KEY,
                        url TEXT UNIQUE,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        response_code INTEGER,
                        found_keywords TEXT,
                        count INTEGER
                    )
                """
                )
            )
            conn.commit()
            logger.info("🗄️  Initialized scan_results table.")

    def init_phishing_db(self):
        """Initialize phishing sites table with enhanced multi-API support."""
        with self.engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS phishing_sites (
                        id SERIAL PRIMARY KEY,
                        url TEXT UNIQUE,
                        manual_flag INTEGER DEFAULT 0,
                        auto_detected INTEGER DEFAULT 0,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        whois_info TEXT,
                        abuse_email TEXT,
                        reported INTEGER DEFAULT 0,
                        abuse_report_sent INTEGER DEFAULT 0,
                        site_status TEXT DEFAULT 'up',
                        takedown_date TIMESTAMP,
                        last_report_sent TIMESTAMP,
                        resolved_ip TEXT,
                        asn_provider TEXT,
                        is_cloudflare INTEGER,
                        provider_abuse_email TEXT,
                        source TEXT DEFAULT 'manual',
                        priority TEXT DEFAULT 'medium',
                        description TEXT,
                        asn TEXT,
                        asn_abuse_email TEXT,
                        hosting_provider TEXT,
                        all_abuse_emails TEXT,
                        virustotal_result TEXT,
                        urlvoid_result TEXT,
                        phishtank_result TEXT,
                        multi_api_threat_level TEXT,
                        api_confidence_score INTEGER,
                        auto_analysis_status TEXT DEFAULT 'pending',
                        auto_analysis_timestamp TIMESTAMP,
                        detection_keywords TEXT,
                        auto_report_eligible INTEGER DEFAULT 0,
                        requires_manual_review INTEGER DEFAULT 0,
                        manual_emails INTEGER DEFAULT 0,
                        registration_date TIMESTAMP,
                        registrar_name TEXT,
                        registrant_org TEXT,
                        domain_age_days INTEGER,
                        status TEXT DEFAULT 'new',
                        assigned_to TEXT
                    )
                """
                )
            )
            conn.commit()
            logger.info("🗄️  Initialized phishing_sites table with enhanced multi-API support.")

    def migrate_phishing_db(self):
        """Add new columns to existing phishing_sites table (v2 migration)."""
        new_columns = [
            ("registration_date", "TIMESTAMP"),
            ("registrar_name", "TEXT"),
            ("registrant_org", "TEXT"),
            ("domain_age_days", "INTEGER"),
        ]

        with self.engine.connect() as conn:
            for col_name, col_type in new_columns:
                try:
                    conn.execute(
                        text(
                            f"ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
                        )
                    )
                    conn.commit()
                except Exception:
                    pass  # Column already exists
            logger.info("🗄️  Migration complete: Added registration info columns to phishing_sites.")

    def migrate_gsb_columns(self):
        """Add Google Safe Browsing columns to phishing_sites table (v3 migration)."""
        gsb_columns = [
            ("gsb_result", "TEXT"),
            ("gsb_threat_type", "TEXT"),
            ("gsb_last_check", "TIMESTAMP"),
            ("gsb_safe", "INTEGER DEFAULT 1"),  # 1 = safe/unknown, 0 = threat detected
        ]

        with self.engine.connect() as conn:
            for col_name, col_type in gsb_columns:
                try:
                    conn.execute(
                        text(
                            f"ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
                        )
                    )
                    conn.commit()
                except Exception:
                    pass  # Column already exists
            logger.info("🗄️  Migration complete: Added GSB columns to phishing_sites.")

    def get_sites_for_gsb_rescan(
        self, max_age_hours: int = 24, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get sites that need Google Safe Browsing re-verification.

        Returns sites that are:
        - Status 'up' (still active)
        - Never checked by GSB OR last check older than max_age_hours

        Args:
            max_age_hours (int): Maximum age of GSB check before re-scan
            limit (int): Maximum number of sites to return

        Returns:
            List[Dict[str, Any]]: Sites needing GSB re-scan
        """
        try:
            with self.engine.connect() as conn:
                results = conn.execute(
                    text(
                        """
                        SELECT url, gsb_last_check, gsb_safe, gsb_threat_type,
                               multi_api_threat_level, api_confidence_score
                        FROM phishing_sites
                        WHERE site_status = 'up'
                        AND (
                            gsb_last_check IS NULL
                            OR gsb_last_check < NOW() - INTERVAL '1 hour' * :max_age_hours
                        )
                        ORDER BY
                            gsb_last_check ASC NULLS FIRST,
                            api_confidence_score DESC
                        LIMIT :limit
                        """
                    ),
                    {"max_age_hours": max_age_hours, "limit": limit},
                ).fetchall()

                sites = []
                for row in results:
                    sites.append(
                        {
                            "url": row[0],
                            "gsb_last_check": row[1],
                            "gsb_safe": row[2],
                            "gsb_threat_type": row[3],
                            "current_threat_level": row[4],
                            "current_confidence": row[5],
                        }
                    )

                return sites

        except Exception as e:
            logger.error(f"❌ Failed to get sites for GSB rescan: {e}")
            return []

    def update_gsb_result(
        self, url: str, gsb_result: Dict[str, Any], previous_safe: bool = True
    ) -> Dict[str, Any]:
        """
        Update Google Safe Browsing result for a site.

        Args:
            url (str): Site URL
            gsb_result (Dict[str, Any]): GSB API response
            previous_safe (bool): Previous GSB safe status

        Returns:
            Dict with update status and alert info if status changed
        """
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            is_safe = gsb_result.get("safe", True)
            threat_type = None

            if not is_safe and gsb_result.get("threats_found"):
                # Get the most severe threat type
                threats = gsb_result.get("threats_found", [])
                if threats:
                    threat_type = threats[0].get("threat_type", "UNKNOWN")

            with self.engine.begin() as conn:
                # Update GSB columns
                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET gsb_result = :gsb_result,
                            gsb_threat_type = :threat_type,
                            gsb_last_check = :timestamp,
                            gsb_safe = :is_safe
                        WHERE url = :url
                        """
                    ),
                    {
                        "gsb_result": json.dumps(gsb_result),
                        "threat_type": threat_type,
                        "timestamp": timestamp,
                        "is_safe": 1 if is_safe else 0,
                        "url": url,
                    },
                )

                # If status changed from safe to threat, update threat level
                status_changed = previous_safe and not is_safe
                if status_changed:
                    # Escalate threat level if GSB now shows threat
                    new_threat_level = "critical" if threat_type == "MALWARE" else "high"
                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET multi_api_threat_level = :threat_level,
                                priority = 'high'
                            WHERE url = :url
                            AND (multi_api_threat_level NOT IN ('critical', 'high')
                                 OR multi_api_threat_level IS NULL)
                            """
                        ),
                        {"threat_level": new_threat_level, "url": url},
                    )

                    logger.warning(f"🚨 GSB STATUS CHANGE: {url} is now flagged as {threat_type}!")

            result = {
                "url": url,
                "updated": True,
                "is_safe": is_safe,
                "threat_type": threat_type,
                "status_changed": status_changed,
            }

            if status_changed:
                result["alert"] = {
                    "type": "GSB_STATUS_CHANGE",
                    "message": f"URL now flagged by Google Safe Browsing: {threat_type}",
                    "severity": "critical" if threat_type == "MALWARE" else "high",
                }

            return result

        except Exception as e:
            logger.error(f"❌ Failed to update GSB result for {url}: {e}")
            return {"url": url, "updated": False, "error": str(e)}

    def get_gsb_status_changes(self, since_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get sites where GSB status changed recently (became unsafe).

        Args:
            since_hours (int): Look back period in hours

        Returns:
            List of sites with recent GSB status changes
        """
        try:
            with self.engine.connect() as conn:
                results = conn.execute(
                    text(
                        """
                        SELECT url, gsb_threat_type, first_seen,
                               multi_api_threat_level, api_confidence_score
                        FROM phishing_sites
                        WHERE (
                            (gsb_safe = 0 AND gsb_last_check IS NOT NULL)
                            OR first_seen > NOW() - INTERVAL '1 hour' * :since_hours
                        )
                        AND site_status != 'down'
                        ORDER BY first_seen DESC
                        LIMIT 20
                        """
                    ),
                    {"since_hours": since_hours},
                ).fetchall()

                return [
                    {
                        "url": row[0],
                        "gsb_threat_type": row[1],
                        "gsb_last_check": str(row[2]) if row[2] else None,
                        "threat_level": row[3],
                        "confidence_score": row[4],
                    }
                    for row in results
                ]

        except Exception as e:
            logger.error(f"❌ Failed to get GSB status changes: {e}")
            return []

    def init_registrar_abuse_db(self):
        """Initialize registrar abuse table with enhanced fields."""
        with self.engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS registrar_abuse (
                        id SERIAL PRIMARY KEY,
                        registrar_name TEXT UNIQUE NOT NULL,
                        abuse_emails TEXT,
                        verified INTEGER DEFAULT 0,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        notes TEXT,
                        manual_override INTEGER DEFAULT 0
                    )
                """
                )
            )
            conn.commit()
            logger.info("🗄️  Initialized registrar_abuse table.")

    def init_hosting_abuse_db(self):
        """Initialize hosting provider abuse table."""
        with self.engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS hosting_abuse (
                        id SERIAL PRIMARY KEY,
                        provider_name TEXT NOT NULL,
                        asn TEXT,
                        abuse_emails TEXT,
                        verified INTEGER DEFAULT 0,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        notes TEXT,
                        manual_override INTEGER DEFAULT 0,
                        UNIQUE(provider_name, asn)
                    )
                """
                )
            )
            conn.commit()
            logger.info("🗄️  Initialized hosting_abuse table.")

    def get_registrar_abuse_emails(self, registrar_name: str) -> Optional[str]:
        """Get abuse emails for a registrar from the cache table."""
        if not registrar_name:
            return None

        with self.engine.connect() as conn:
            result = conn.execute(
                text("SELECT abuse_emails FROM registrar_abuse WHERE registrar_name = :registrar"),
                {"registrar": registrar_name},
            ).fetchone()

            return result[0] if result else None

    def get_hosting_abuse_emails(self, provider_name: str, asn: str = None) -> Optional[str]:
        """Get abuse emails for a hosting provider from the cache table."""
        if not provider_name:
            return None

        with self.engine.connect() as conn:
            if asn:
                result = conn.execute(
                    text(
                        "SELECT abuse_emails FROM hosting_abuse WHERE provider_name = :provider AND asn = :asn"
                    ),
                    {"provider": provider_name, "asn": asn},
                ).fetchone()
            else:
                result = conn.execute(
                    text("SELECT abuse_emails FROM hosting_abuse WHERE provider_name = :provider"),
                    {"provider": provider_name},
                ).fetchone()

            return result[0] if result else None

    def store_detected_phishing_site(
        self, url: str, keywords: List[str], source: str = "auto_detection"
    ) -> bool:
        """
        Store a newly detected phishing site for auto-analysis.

        Args:
            url (str): Detected phishing URL
            keywords (List[str]): Keywords that triggered detection
            source (str): Detection source

        Returns:
            bool: True if stored successfully, False if already exists
        """
        try:
            with self.engine.begin() as conn:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                keywords_str = ", ".join(keywords)

                # Check if URL already exists
                existing = conn.execute(
                    text("SELECT id, auto_detected FROM phishing_sites WHERE url = :url"),
                    {"url": url},
                ).fetchone()

                if existing:
                    # Update existing record with new detection
                    conn.execute(
                        text(
                            """
                            UPDATE phishing_sites
                            SET auto_detected = 1, last_seen = :timestamp,
                                detection_keywords = :keywords, source = :source,
                                auto_analysis_status = 'pending'
                            WHERE url = :url
                        """
                        ),
                        {
                            "timestamp": timestamp,
                            "keywords": keywords_str,
                            "source": source,
                            "url": url,
                        },
                    )
                    logger.info(f"🔄 Updated existing phishing detection for {url}")
                    return False
                else:
                    # Insert new detection
                    conn.execute(
                        text(
                            """
                            INSERT INTO phishing_sites
                            (url, auto_detected, first_seen, last_seen, detection_keywords,
                             source, auto_analysis_status, priority)
                            VALUES (:url, 1, :timestamp, :timestamp, :keywords,
                                    :source, 'pending', 'high')
                        """
                        ),
                        {
                            "url": url,
                            "timestamp": timestamp,
                            "keywords": keywords_str,
                            "source": source,
                        },
                    )
                    log_detection(
                        logger,
                        url=url,
                        confidence=50,  # Default confidence for keyword-based detection
                        keywords=keywords.split(", ") if isinstance(keywords, str) else keywords,
                        source=source,
                        timestamp=timestamp,
                    )
                    return True

        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "url": url,
                    "operation": "store_detected_phishing_site",
                    "event_type": "phishing_detection_storage_failed",
                },
            )
            return False

    def get_pending_analysis_sites(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get sites pending multi-API analysis.

        This includes:
        - Auto-detected sites with pending analysis
        - Manual sites that haven't been analyzed yet
        - API-imported sites that need analysis

        Args:
            limit (int): Maximum number of sites to return

        Returns:
            List[Dict[str, Any]]: List of sites pending analysis
        """
        try:
            with self.engine.begin() as conn:
                results = conn.execute(
                    text(
                        """
                        SELECT url, detection_keywords, first_seen, source, priority
                        FROM phishing_sites
                        WHERE (
                            (auto_analysis_status = 'pending' AND auto_detected = 1)  -- Auto-detected pending
                            OR (manual_flag = 1 AND auto_analysis_status IS NULL)    -- Manual sites not analyzed
                            OR (source = 'external_api' AND auto_analysis_status IS NULL)  -- API sites not analyzed
                        )
                        AND site_status != 'down'  -- Only analyze sites that are potentially up
                        ORDER BY
                            CASE
                                WHEN manual_flag = 1 THEN 0      -- Manual sites first
                                WHEN source = 'external_api' THEN 1  -- API sites second
                                ELSE 2  -- Auto-detected last
                            END,
                            CASE priority
                                WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 3
                                ELSE 2
                            END,
                            first_seen ASC
                        LIMIT :limit
                    """
                    ),
                    {"limit": limit},
                ).fetchall()

                sites = []
                for row in results:
                    sites.append(
                        {
                            "url": row[0],
                            "keywords": row[1],
                            "first_seen": row[2],
                            "source": row[3],
                            "priority": row[4],
                        }
                    )

                return sites

        except Exception as e:
            logger.error(f"❌ Failed to get pending analysis sites: {e}")
            return []

    def update_analysis_results(
        self, url: str, multi_api_results: Dict[str, Any], auto_report_decision: Dict[str, Any]
    ) -> bool:
        """
        Update site with multi-API analysis results and auto-report decision.

        Args:
            url (str): Site URL
            multi_api_results (Dict[str, Any]): Multi-API scan results
            auto_report_decision (Dict[str, Any]): Auto-report decision data

        Returns:
            bool: True if updated successfully
        """
        try:
            with self.engine.begin() as conn:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Extract registration info from URLVoid results
                urlvoid_data = multi_api_results.get("urlvoid", {})
                registration_date = urlvoid_data.get("domain_1st_registered")
                domain_age_days = urlvoid_data.get("domain_age")
                registrar_name = urlvoid_data.get("registrar_name")
                registrant_org = urlvoid_data.get("registrant_org")

                # Extract GSB results
                gsb_data = multi_api_results.get("google_safe_browsing", {})
                gsb_safe = gsb_data.get("safe", True)
                gsb_threat_type = None
                if not gsb_safe and gsb_data.get("threats_found"):
                    threats = gsb_data.get("threats_found", [])
                    if threats:
                        gsb_threat_type = threats[0].get("threat_type", "UNKNOWN")

                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET auto_analysis_status = :status,
                            auto_analysis_timestamp = :timestamp,
                            virustotal_result = :vt_result,
                            urlvoid_result = :uv_result,
                            phishtank_result = :pt_result,
                            multi_api_threat_level = :threat_level,
                            api_confidence_score = :confidence_score,
                            auto_report_eligible = :auto_eligible,
                            requires_manual_review = :manual_review,
                            priority = :priority,
                            registration_date = COALESCE(:registration_date, registration_date),
                            registrar_name = COALESCE(:registrar_name, registrar_name),
                            registrant_org = COALESCE(:registrant_org, registrant_org),
                            domain_age_days = COALESCE(:domain_age_days, domain_age_days),
                            gsb_result = :gsb_result,
                            gsb_safe = :gsb_safe,
                            gsb_threat_type = :gsb_threat_type,
                            gsb_last_check = :timestamp
                        WHERE url = :url
                    """
                    ),
                    {
                        "status": "completed",
                        "timestamp": timestamp,
                        "vt_result": json.dumps(multi_api_results.get("virustotal", {})),
                        "uv_result": json.dumps(multi_api_results.get("urlvoid", {})),
                        "pt_result": json.dumps(multi_api_results.get("phishtank", {})),
                        "threat_level": multi_api_results.get("aggregated_threat_level"),
                        "confidence_score": multi_api_results.get("confidence_score"),
                        "auto_eligible": 1 if auto_report_decision.get("auto_report", False) else 0,
                        "manual_review": (
                            1 if auto_report_decision.get("manual_review", False) else 0
                        ),
                        "priority": auto_report_decision.get("priority", "medium"),
                        "registration_date": registration_date,
                        "registrar_name": registrar_name,
                        "registrant_org": registrant_org,
                        "domain_age_days": domain_age_days,
                        "gsb_result": json.dumps(gsb_data) if gsb_data else None,
                        "gsb_safe": 1 if gsb_safe else 0,
                        "gsb_threat_type": gsb_threat_type,
                        "url": url,
                    },
                )

                logger.info(
                    f"✅ Analysis completed for {url}: Threat={multi_api_results.get('aggregated_threat_level')}, Confidence={multi_api_results.get('confidence_score')}%"
                )
                return True

        except Exception as e:
            logger.error(f"❌ Failed to update analysis results for {url}: {e}")
            return False

    def get_auto_report_eligible_sites(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get sites eligible for automatic reporting.

        Args:
            limit (int): Maximum number of sites to return

        Returns:
            List[Dict[str, Any]]: List of sites eligible for auto-reporting
        """
        try:
            with self.engine.begin() as conn:
                results = conn.execute(
                    text(
                        """
                        SELECT url, multi_api_threat_level, api_confidence_score,
                               detection_keywords, auto_analysis_timestamp, priority
                        FROM phishing_sites
                        WHERE auto_report_eligible = 1
                        AND abuse_report_sent = 0
                        AND site_status = 'up'
                        ORDER BY
                            CASE priority
                                WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 3
                                ELSE 2
                            END,
                            api_confidence_score DESC,
                            auto_analysis_timestamp ASC
                        LIMIT :limit
                    """
                    ),
                    {"limit": limit},
                ).fetchall()

                sites = []
                for row in results:
                    sites.append(
                        {
                            "url": row[0],
                            "threat_level": row[1],
                            "confidence_score": row[2],
                            "keywords": row[3],
                            "analysis_timestamp": row[4],
                            "priority": row[5],
                        }
                    )

                return sites

        except Exception as e:
            logger.error(f"❌ Failed to get auto-report eligible sites: {e}")
            return []

    def init_threads_db(self):
        """Initialize analysis_threads and thread_results tables."""
        with self.engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS analysis_threads (
                        id SERIAL PRIMARY KEY,
                        thread_type VARCHAR(50) NOT NULL,
                        label VARCHAR(255),
                        account_id VARCHAR(20),
                        status VARCHAR(20) NOT NULL,
                        started_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        completed_at TIMESTAMP,
                        results_count INTEGER NOT NULL DEFAULT 0,
                        details JSONB,
                        error_message TEXT,
                        image_s3_key VARCHAR(500),
                        original_filename VARCHAR(255),
                        content_type VARCHAR(100),
                        file_size_bytes INTEGER,
                        search_interval_hours INTEGER,
                        last_searched_at TIMESTAMP
                    )
                """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS thread_results (
                        id SERIAL PRIMARY KEY,
                        thread_id INTEGER NOT NULL REFERENCES analysis_threads(id),
                        result_type VARCHAR(50) NOT NULL,
                        found_url VARCHAR(2000),
                        title VARCHAR(500),
                        confidence REAL,
                        thumbnail_url VARCHAR(2000),
                        source VARCHAR(100),
                        first_detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        last_detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        status VARCHAR(20) NOT NULL DEFAULT 'new',
                        assigned_to VARCHAR(100),
                        details JSONB
                    )
                """
                )
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS idx_threads_type ON analysis_threads(thread_type)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS idx_threads_status ON analysis_threads(status)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS idx_results_thread ON thread_results(thread_id)")
            )
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS idx_results_status ON thread_results(status)")
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS thread_executions (
                        id SERIAL PRIMARY KEY,
                        thread_id INTEGER NOT NULL REFERENCES analysis_threads(id),
                        execution_type VARCHAR(50) NOT NULL,
                        started_at TIMESTAMP DEFAULT NOW(),
                        completed_at TIMESTAMP,
                        status VARCHAR(20) NOT NULL DEFAULT 'running',
                        results_count INTEGER NOT NULL DEFAULT 0,
                        error_message TEXT,
                        details JSONB
                    )
                    """
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_executions_thread ON thread_executions(thread_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_executions_status ON thread_executions(status)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE thread_results ADD COLUMN IF NOT EXISTS execution_id INTEGER REFERENCES thread_executions(id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_results_execution ON thread_results(execution_id)"
                )
            )
            conn.execute(
                text("ALTER TABLE thread_results ADD COLUMN IF NOT EXISTS extra_data JSONB")
            )
            conn.execute(
                text("ALTER TABLE thread_results ADD COLUMN IF NOT EXISTS source_type VARCHAR(20)")
            )
            conn.commit()
            logger.info(
                "🗄️  Initialized analysis_threads, thread_results, and thread_executions tables."
            )
        self._init_email_reputation_db()

    def _init_email_reputation_db(self):
        """Initialize email sender and domain reputation tables."""
        with self.engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS email_sender_reputation (
                        id SERIAL PRIMARY KEY,
                        sender_email VARCHAR(320) NOT NULL,
                        sender_domain VARCHAR(255) NOT NULL,
                        display_name VARCHAR(255),
                        report_count INTEGER NOT NULL DEFAULT 0,
                        automated_count INTEGER NOT NULL DEFAULT 0,
                        threat_score_avg REAL NOT NULL DEFAULT 0,
                        threat_score_max REAL NOT NULL DEFAULT 0,
                        first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        blocked BOOLEAN NOT NULL DEFAULT FALSE,
                        blocked_at TIMESTAMP,
                        block_reason TEXT,
                        UNIQUE(sender_email)
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS email_domain_reputation (
                        id SERIAL PRIMARY KEY,
                        domain VARCHAR(255) NOT NULL,
                        sender_count INTEGER NOT NULL DEFAULT 0,
                        report_count INTEGER NOT NULL DEFAULT 0,
                        automated_count INTEGER NOT NULL DEFAULT 0,
                        threat_score_avg REAL NOT NULL DEFAULT 0,
                        first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        blocked BOOLEAN NOT NULL DEFAULT FALSE,
                        blocked_at TIMESTAMP,
                        block_reason TEXT,
                        UNIQUE(domain)
                    )
                    """
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_sender_rep_domain "
                    "ON email_sender_reputation(sender_domain)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_sender_rep_blocked "
                    "ON email_sender_reputation(blocked)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_domain_rep_blocked "
                    "ON email_domain_reputation(blocked)"
                )
            )
            # Whitelist columns — added after initial schema; safe to run on existing DBs
            conn.execute(
                text(
                    "ALTER TABLE email_sender_reputation "
                    "ADD COLUMN IF NOT EXISTS whitelisted BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE email_sender_reputation "
                    "ADD COLUMN IF NOT EXISTS whitelisted_at TIMESTAMP"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE email_sender_reputation "
                    "ADD COLUMN IF NOT EXISTS whitelist_reason TEXT"
                )
            )
            conn.commit()
            logger.info("🗄️  Initialized email reputation tables.")

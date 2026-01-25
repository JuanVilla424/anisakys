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
        self.engine = db_engine

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
                        domain_age_days INTEGER
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

    def init_registrar_abuse_db(self):
        """Initialize registrar abuse table with enhanced fields."""
        with self.engine.connect() as conn:
            # First, check if table exists with old schema
            result = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'registrar_abuse'"
                )
            ).fetchall()

            if result and len(result) == 2:  # Old schema with only 2 columns
                # Backup existing data
                conn.execute(text("ALTER TABLE registrar_abuse RENAME TO registrar_abuse_old"))
                conn.commit()

            # Create enhanced table
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

            # Migrate old data if exists
            try:
                conn.execute(
                    text(
                        """
                        INSERT INTO registrar_abuse (registrar_name, abuse_emails)
                        SELECT registrar, abuse_email FROM registrar_abuse_old
                        ON CONFLICT (registrar_name) DO NOTHING
                        """
                    )
                )
                conn.execute(text("DROP TABLE IF EXISTS registrar_abuse_old"))
            except:
                pass  # Old table doesn't exist or migration not needed

            conn.commit()
            logger.info("🗄️  Initialized enhanced registrar_abuse table.")

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
                            domain_age_days = COALESCE(:domain_age_days, domain_age_days)
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

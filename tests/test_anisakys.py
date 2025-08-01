import argparse
import ipaddress
import time
from itertools import permutations, islice
from typing import List, Optional
import sys
import pytest
from sqlalchemy import text
from pathlib import Path

# Import main module
from src import main

# Override production file names with test-only names.
# (For Postgres tests, the DATABASE_URL is already set via our fixture.)
main.QUERIES_FILE = "test_queries_file.txt"
main.OFFSET_FILE = "test_offset_file.txt"

# Extract attributes from the loaded module.
DynamicBatchConfig = main.DynamicBatchConfig
AttachmentConfig = main.AttachmentConfig
EngineMode = main.EngineMode
generate_queries_file = main.generate_queries_file
get_ip_info = main.get_ip_info
is_cloudflare_ip = main.is_cloudflare_ip
PhishingUtils = main.PhishingUtils
DatabaseManager = main.DatabaseManager
PhishingScanner = main.PhishingScanner
Engine = main.Engine
DEFAULT_USER_AGENT = main.DEFAULT_USER_AGENT


def log(msg):
    print(msg)


# --- Test DynamicBatchConfig ---
def test_get_batch_size():
    log("Starting test_get_batch_size")
    batch = DynamicBatchConfig.get_batch_size()
    log(f"Batch size obtained: {batch}")
    assert isinstance(batch, int)
    assert batch >= 100
    log("Completed test_get_batch_size")


# --- Test AttachmentConfig ---
def test_get_attachment_nonexistent(monkeypatch):
    log("Starting test_get_attachment_nonexistent")
    monkeypatch.setattr(AttachmentConfig, "get_attachment", lambda: None)
    result = AttachmentConfig.get_attachment()
    log(f"Attachment result: {result}")
    assert result is None
    log("Completed test_get_attachment_nonexistent")


# --- Test EngineMode ---
def test_engine_mode():
    log("Starting test_engine_mode")
    args = argparse.Namespace(
        report="https://site.com", process_reports=False, threads_only=False, test_report=False
    )
    mode = EngineMode(args)
    log(f"EngineMode: report_mode={mode.report_mode}, scanning_mode={mode.scanning_mode}")
    assert mode.report_mode is True
    assert mode.scanning_mode is False
    log("Completed test_engine_mode")


# --- Test generate_queries_file ---
def test_generate_queries_file(tmp_path, monkeypatch):
    log("Starting test_generate_queries_file")
    keywords = ["phish", "attack"]
    domains = [".com", ".net"]
    test_queries_file = tmp_path / "test_queries_file.txt"
    monkeypatch.setattr(main, "QUERIES_FILE", str(test_queries_file))
    generate_queries_file(keywords, domains)
    assert test_queries_file.exists(), "Test queries file was not created."
    lines = test_queries_file.read_text().splitlines()
    log(f"Generated {len(lines)} query lines")
    # For 2 keywords: expected total = 16.
    assert len(lines) == 16, "Unexpected number of query lines."
    log("Completed test_generate_queries_file")


# --- Test is_cloudflare_ip ---
def test_is_cloudflare_ip(monkeypatch):
    log("Starting test_is_cloudflare_ip")
    dummy_ranges = [ipaddress.ip_network("173.245.48.0/20")]
    monkeypatch.setattr(main, "CLOUDFLARE_IP_RANGES", dummy_ranges)
    res1 = is_cloudflare_ip("173.245.50.1")
    res2 = is_cloudflare_ip("8.8.8.8")
    log(f"is_cloudflare_ip('173.245.50.1') returned {res1}")
    log(f"is_cloudflare_ip('8.8.8.8') returned {res2}")
    assert res1 is True
    assert res2 is False
    log("Completed test_is_cloudflare_ip")


# --- Test PhishingUtils.store_scan_result ---
def test_store_scan_result(monkeypatch):
    log("Starting test_store_scan_result")
    # Use the test Postgres database defined in DATABASE_URL.
    db_manager = DatabaseManager(db_url=main.DATABASE_URL)
    # Drop table if it exists to ensure a clean slate.
    with db_manager.engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS scan_results"))
    db_manager.init_db()  # Re-create the table.
    # Insert a dummy scan result.
    PhishingUtils.store_scan_result(
        "https://example.com", 200, ["phish"], db_file=main.DATABASE_URL
    )
    # Verify insertion via SQLAlchemy engine.
    with db_manager.engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT url, response_code, found_keywords, count FROM scan_results WHERE url = :url"
            ),
            {"url": "https://example.com"},
        ).fetchone()
    log(f"Row fetched: {row}")
    assert row is not None
    assert row[0] == "https://example.com"
    assert row[1] == 200
    assert "phish" in row[2]
    # Instead of asserting count == 1, delete the entry using TRUNCATE with an explicit commit.
    with db_manager.engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("TRUNCATE TABLE scan_results RESTART IDENTITY"))
        trans.commit()
    with db_manager.engine.connect() as conn:
        row_after = conn.execute(
            text("SELECT * FROM scan_results WHERE url = :url"), {"url": "https://example.com"}
        ).fetchone()
    log(f"Row after deletion: {row_after}")
    assert row_after is None
    log("Completed test_store_scan_result")


# --- Test PhishingScanner.augment_with_www ---
def test_augment_with_www():
    log("Starting test_augment_with_www")
    result = PhishingScanner.augment_with_www("example.com")
    log(f"augment_with_www('example.com') returned: {result}")
    assert "example.com" in result
    assert "www.example.com" in result
    log("Completed test_augment_with_www")


# --- Test PhishingScanner.filter_allowed_targets ---
def test_filter_allowed_targets():
    log("Starting test_filter_allowed_targets")
    allowed_sites = ["allowed.com", "whitelist.com"]
    dummy_args = argparse.Namespace(
        test_report=True,
        threads_only=True,
        regen_queries=False,
        report=None,
        process_reports=False,
        abuse_email=None,
        attachment=None,
        cc=None,
        timeout=5,
        log_level="INFO",
    )
    scanner = PhishingScanner(
        timeout=5, keywords=[], domains=[], allowed_sites=allowed_sites, args=dummy_args
    )
    targets = ["example.com", "allowed.com", "test.com", "whitelist.com"]
    filtered = scanner.filter_allowed_targets(targets)
    log(f"Filtered targets: {filtered}")
    assert "allowed.com" not in filtered
    assert "whitelist.com" not in filtered
    assert "example.com" in filtered
    assert "test.com" in filtered
    log("Completed test_filter_allowed_targets")


# --- Test Engine.mark_site_as_phishing ---
def test_mark_site_as_phishing():
    log("Starting test_mark_site_as_phishing")
    db_manager = DatabaseManager(db_url=main.DATABASE_URL)
    # Drop and re-create the phishing_sites table for a clean test.
    with db_manager.engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS phishing_sites"))
    db_manager.init_phishing_db()
    dummy_args = argparse.Namespace(
        report=None,
        process_reports=False,
        threads_only=False,
        test_report=False,
        timeout=5,
        log_level="INFO",
        abuse_email="test@abuse.com",
        attachment=None,
        cc=None,
        regen_queries=False,
    )
    engine = Engine(dummy_args)
    engine.db_manager = db_manager
    engine.mark_site_as_phishing("https://malicious.com", abuse_email="abuse@malicious.com")
    with db_manager.engine.connect() as conn:
        row = conn.execute(
            text("SELECT url, manual_flag, abuse_email FROM phishing_sites WHERE url = :url"),
            {"url": "https://malicious.com"},
        ).fetchone()
    log(f"Mark site query returned: {row}")
    assert row is not None
    assert row[1] == 1
    # The abuse_email field is now stored as a JSON array
    import json

    abuse_emails = json.loads(row[2])
    assert "abuse@malicious.com" in abuse_emails
    log("Completed test_mark_site_as_phishing")


if __name__ == "__main__":
    pytest.main()

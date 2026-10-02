"""
One-shot backfill script: enrich existing email_threat findings with
reply_to, urgency_keywords, and all_attachments fields.

Findings created before the 2026-04-11 deploy lack these fields.
This script re-fetches each email from Gmail and updates extra_data.

Usage:
    cd /opt/anisakys
    python -m src.scripts.backfill_extra_data
"""

import json
import os
import sys
import types

# Pre-populate package stubs to break circular imports triggered by
# src.intelligence.__init__ → multi_api_validator → url_analyzer → detection.__init__
# Must set __path__ so submodule imports (e.g. src.intelligence.gmail_client) still resolve.
_base = os.path.join(os.path.dirname(__file__), "..", "..")  # /opt/anisakys/src/..
_src = os.path.normpath(os.path.join(_base, "src"))
for _pkg, _subdir in [("src.intelligence", "intelligence"), ("src.detection", "detection")]:
    if _pkg not in sys.modules:
        _mod = types.ModuleType(_pkg)
        _mod.__path__ = [os.path.join(_src, _subdir)]
        _mod.__package__ = _pkg
        sys.modules[_pkg] = _mod

import logging

from sqlalchemy import create_engine, text

from src.config import settings
from src.intelligence.gmail_client import GmailClient
from src.intelligence.email_analyzer import EmailAnalyzer

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


def run():
    if not settings.GOOGLE_SERVICE_ACCOUNT_FILE or not settings.GOOGLE_WORKSPACE_DOMAIN:
        print("ERROR: GOOGLE_SERVICE_ACCOUNT_FILE and GOOGLE_WORKSPACE_DOMAIN must be set")
        sys.exit(1)

    db_url = settings.DATABASE_URL
    engine = create_engine(db_url)

    gmail = GmailClient(settings.GOOGLE_SERVICE_ACCOUNT_FILE, settings.GOOGLE_WORKSPACE_DOMAIN)
    analyzer = EmailAnalyzer()

    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
            SELECT id, extra_data
            FROM thread_results
            WHERE result_type = 'email_threat'
              AND extra_data->>'reply_to' IS NULL
            ORDER BY id ASC
        """
            )
        ).fetchall()

    total = len(rows)
    print(f"Found {total} findings to backfill")
    if total == 0:
        print("Nothing to do.")
        return

    ok = 0
    skip = 0
    err = 0

    for i, row in enumerate(rows, 1):
        rid = row[0]
        extra = row[1] if isinstance(row[1], dict) else json.loads(row[1] or "{}")
        message_id = extra.get("message_id", "")
        inbox = extra.get("inbox", "")

        if not message_id or not inbox:
            print(f"  [{i}/{total}] #{rid} — skip (no message_id or inbox)")
            skip += 1
            continue

        try:
            parsed = gmail.get_message(inbox, message_id)
            if not parsed:
                print(f"  [{i}/{total}] #{rid} — skip (Gmail returned None for {message_id})")
                skip += 1
                continue

            assessment = analyzer.analyze(parsed)

            patch = {
                "reply_to": parsed.get("reply_to") or "",
                "urgency_keywords": assessment["content_analysis"].get(
                    "urgency_keywords_matched", []
                ),
                "all_attachments": [
                    {"filename": a.get("filename", ""), "mime_type": a.get("mime_type", "")}
                    for a in parsed.get("attachments", [])
                ],
            }

            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE thread_results SET extra_data = extra_data || CAST(:patch AS JSONB) WHERE id = :rid"
                    ),
                    {"patch": json.dumps(patch), "rid": rid},
                )

            sender = extra.get("sender", "?")
            print(
                f"  [{i}/{total}] #{rid} {sender} — reply_to={patch['reply_to']!r:40} kw={len(patch['urgency_keywords'])} att={len(patch['all_attachments'])}"
            )
            ok += 1

        except Exception as exc:
            print(f"  [{i}/{total}] #{rid} — ERROR: {exc}")
            logger.error(f"backfill #{rid}: {exc}")
            err += 1

    print(f"\nDone: {ok} updated, {skip} skipped, {err} errors")


if __name__ == "__main__":
    run()

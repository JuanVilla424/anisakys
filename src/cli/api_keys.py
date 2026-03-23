"""
CLI tool for managing Anisakys API keys.

Usage:
    venv/bin/python -m src.cli.api_keys create --name "dashboard" --scopes "read"
    venv/bin/python -m src.cli.api_keys create --name "scanner" --scopes "read,scan" --description "CI scanner"
    venv/bin/python -m src.cli.api_keys list
    venv/bin/python -m src.cli.api_keys revoke --name "dashboard"
    venv/bin/python -m src.cli.api_keys revoke --prefix "ank_a1b2c3"
"""

import argparse
import hashlib
import secrets
import sys
from datetime import datetime

from sqlalchemy import create_engine, text

from src.config import settings

VALID_SCOPES = {"read", "scan", "report", "admin"}
KEY_PREFIX = "ank_"


def _get_engine():
    db_url = str(settings.DATABASE_URL)
    return create_engine(db_url, pool_pre_ping=True)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def cmd_create(args) -> None:
    scopes_list = [s.strip() for s in args.scopes.split(",") if s.strip()]
    invalid = set(scopes_list) - VALID_SCOPES
    if invalid:
        print(f"Error: invalid scope(s): {', '.join(sorted(invalid))}", file=sys.stderr)
        print(f"Valid scopes: {', '.join(sorted(VALID_SCOPES))}", file=sys.stderr)
        sys.exit(1)

    raw_key = KEY_PREFIX + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    key_prefix = raw_key[:12]
    scopes = ",".join(scopes_list)
    allowed_ips = args.allowed_ips or None
    description = args.description or None

    engine = _get_engine()
    with engine.begin() as conn:
        # Check name uniqueness
        existing = conn.execute(
            text("SELECT id FROM api_keys WHERE name = :n"), {"n": args.name}
        ).fetchone()
        if existing:
            print(f"Error: a key named '{args.name}' already exists.", file=sys.stderr)
            sys.exit(1)

        conn.execute(
            text(
                """
                INSERT INTO api_keys (key_hash, key_prefix, name, scopes, allowed_ips, description)
                VALUES (:h, :p, :n, :s, :ips, :desc)
                """
            ),
            {
                "h": key_hash,
                "p": key_prefix,
                "n": args.name,
                "s": scopes,
                "ips": allowed_ips,
                "desc": description,
            },
        )

    print(f"\n✅ API key created: {args.name}")
    print(f"   Scopes : {scopes}")
    if allowed_ips:
        print(f"   IPs    : {allowed_ips}")
    print(f"\n⚠️  Save this key — it will NOT be shown again:\n\n   {raw_key}\n")


def cmd_list(args) -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT key_prefix, name, scopes, allowed_ips, active,
                       created_at, last_used_at, description
                FROM api_keys
                ORDER BY created_at DESC
                """
            )
        ).fetchall()

    if not rows:
        print("No API keys found.")
        return

    fmt = "{:<14} {:<20} {:<22} {:<10} {:<10} {}"
    print(fmt.format("PREFIX", "NAME", "SCOPES", "ACTIVE", "LAST USED", "DESCRIPTION"))
    print("-" * 90)
    for row in rows:
        prefix, name, scopes, _, active, created_at, last_used_at, desc = row
        last_used = last_used_at.strftime("%Y-%m-%d") if last_used_at else "never"
        print(
            fmt.format(
                prefix,
                name[:19],
                scopes[:21],
                "yes" if active else "no",
                last_used,
                (desc or "")[:40],
            )
        )


def cmd_revoke(args) -> None:
    if not args.name and not args.prefix:
        print("Error: provide --name or --prefix", file=sys.stderr)
        sys.exit(1)

    engine = _get_engine()
    with engine.begin() as conn:
        if args.name:
            result = conn.execute(
                text(
                    "UPDATE api_keys SET active = FALSE, revoked_at = NOW() "
                    "WHERE name = :n AND active = TRUE"
                ),
                {"n": args.name},
            )
        else:
            result = conn.execute(
                text(
                    "UPDATE api_keys SET active = FALSE, revoked_at = NOW() "
                    "WHERE key_prefix = :p AND active = TRUE"
                ),
                {"p": args.prefix},
            )

        if result.rowcount == 0:
            print("No active key found with that identifier.", file=sys.stderr)
            sys.exit(1)

    identifier = args.name or args.prefix
    print(f"✅ Key '{identifier}' revoked.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Anisakys API key management")
    sub = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = sub.add_parser("create", help="Create a new API key")
    p_create.add_argument("--name", required=True, help="Human-readable name")
    p_create.add_argument(
        "--scopes",
        required=True,
        help=f"Comma-separated scopes ({', '.join(sorted(VALID_SCOPES))})",
    )
    p_create.add_argument("--allowed-ips", default=None, help="Comma-separated CIDRs/IPs")
    p_create.add_argument("--description", default=None, help="Optional description")

    # list
    sub.add_parser("list", help="List all API keys")

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke an API key")
    p_revoke.add_argument("--name", default=None, help="Key name")
    p_revoke.add_argument("--prefix", default=None, help="Key prefix (first 12 chars)")

    args = parser.parse_args()

    commands = {"create": cmd_create, "list": cmd_list, "revoke": cmd_revoke}
    commands[args.command](args)


if __name__ == "__main__":
    main()

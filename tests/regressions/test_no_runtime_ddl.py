"""Regression: the application must not create or alter tables at runtime.

Runtime DDL scattered across the code base produced three divergent
``abuse_reports`` definitions, silently skipped failures and a table
(``redirect_chains``) that no code path ever created. Alembic is now the only
owner of the schema, and this test keeps DDL from creeping back into ``src/``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List

SRC = Path(__file__).resolve().parents[2] / "src"

DDL_PATTERN = (
    r"\b(CREATE\s+(UNIQUE\s+)?(TABLE|INDEX)|ALTER\s+TABLE|DROP\s+(TABLE|INDEX)|ADD\s+COLUMN)\b"
)
DDL = re.compile(DDL_PATTERN, re.IGNORECASE)
# Statements written in upper case (the convention for SQL in this code base).
DDL_STATEMENT = re.compile(DDL_PATTERN)

# Files whose runtime DDL is being removed by another phase-0 workstream
# (reporting pipeline). Delete the entries once that work has landed.
PENDING_REMOVAL = {
    "reporting/report_tracker.py",
    "reporting/abuse_manager.py",
}


def _ddl_strings(path: Path) -> List[str]:
    """Return the string literals of a module that contain DDL statements."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
        elif isinstance(node, ast.JoinedStr):
            value = "".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
        else:
            continue
        # Docstrings and log messages mention DDL words in prose; a real
        # statement starts with the keyword or carries a column list / IF clause.
        statement = value.strip()
        if DDL_STATEMENT.match(statement) or (
            DDL.search(statement) and re.search(r"\(|\bIF\s+(NOT\s+)?EXISTS\b", statement, re.I)
        ):
            found.append(" ".join(statement.split())[:120])
    return found


def test_src_contains_no_runtime_ddl():
    offenders = {}
    for path in sorted(SRC.rglob("*.py")):
        relative = path.relative_to(SRC).as_posix()
        if relative in PENDING_REMOVAL:
            continue
        statements = _ddl_strings(path)
        if statements:
            offenders[relative] = statements
    assert not offenders, (
        "Schema changes belong in an Alembic migration (alembic/versions), "
        f"not in application code: {offenders}"
    )

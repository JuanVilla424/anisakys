"""Regression tests for packaging and platform hygiene.

Cheap static checks that keep fixed problems fixed: dependencies missing from
pyproject.toml, an invalid licence identifier, the API reporting an
"unknown" version after the metadata moved to PEP 621.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path
from typing import Set

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())


def _declared_runtime_dependencies() -> Set[str]:
    """Canonical names of the [project] runtime dependencies."""
    return {
        canonicalize_name(Requirement(spec).name) for spec in PYPROJECT["project"]["dependencies"]
    }


def _third_party_imports() -> Set[str]:
    """Top-level third-party modules imported anywhere in src/ and alembic/."""
    modules: Set[str] = set()
    files = list((ROOT / "src").rglob("*.py")) + [ROOT / "alembic" / "env.py"]
    for path in files:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
    return {m for m in modules if m not in sys.stdlib_module_names and m != "src"}


def test_every_imported_package_is_a_declared_dependency():
    """Regression: pyproject.toml used to omit Flask and a dozen runtime deps."""
    declared = _declared_runtime_dependencies()
    distributions = packages_distributions()
    missing = {}
    for module in sorted(_third_party_imports()):
        providers = {canonicalize_name(d) for d in distributions.get(module, [])}
        if not providers:
            missing[module] = "not installed"
        elif not providers & declared:
            missing[module] = sorted(providers)
    assert not missing, f"Imported but not declared in [project].dependencies: {missing}"


@pytest.mark.parametrize("name", ["gunicorn", "tldextract"])
def test_dependencies_needed_by_other_workstreams_are_declared(name):
    assert name in _declared_runtime_dependencies()


def test_license_is_a_valid_spdx_identifier():
    """Regression: the licence was declared as the typo "GLPv3"."""
    assert PYPROJECT["project"]["license"] == "GPL-3.0-only"


def test_api_reports_the_project_version():
    """Regression: the API read [tool.poetry].version and reported "unknown"."""
    from src.api.phishing_api import APP_VERSION

    assert APP_VERSION == PYPROJECT["project"]["version"]


def test_requirements_files_are_generated_from_the_lock():
    for name in ("requirements.txt", "requirements-dev.txt"):
        header = (ROOT / name).read_text().splitlines()[0]
        assert "Generated from poetry.lock" in header
    assert (ROOT / "poetry.lock").exists()

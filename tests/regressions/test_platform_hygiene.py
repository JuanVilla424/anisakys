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


DOCKERIGNORE = {
    line.strip()
    for line in (ROOT / ".dockerignore").read_text().splitlines()
    if line.strip() and not line.startswith("#")
}
DOCKERFILE = (ROOT / "Dockerfile").read_text()


@pytest.mark.parametrize(
    "pattern", [".env", ".env.*", "screenshots/", "attachments/", "logs/", ".git"]
)
def test_docker_context_excludes_secrets_and_runtime_data(pattern):
    """Regression: `COPY . .` used to bake .env and collected data into the image."""
    assert pattern in DOCKERIGNORE


def test_docker_image_runs_unprivileged():
    users = [line.split()[1] for line in DOCKERFILE.splitlines() if line.startswith("USER ")]
    assert users, "the image must switch to an unprivileged user"
    assert users[-1].split(":")[0] not in ("root", "0")


def test_docker_image_has_the_tools_the_code_shells_out_to():
    """The abuse-contact lookup runs the `whois` binary (and DNS tools)."""
    assert "whois" in DOCKERFILE and "dnsutils" in DOCKERFILE


def test_docker_image_has_a_healthcheck_on_the_health_endpoint():
    assert "HEALTHCHECK" in DOCKERFILE and "/api/v1/health" in DOCKERFILE

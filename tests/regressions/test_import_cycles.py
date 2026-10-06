"""Regression test: every entry module imports on its own, in a fresh interpreter.

Phase 2 briefly broke ``import src.api.phishing_api`` (the API's entry point) with a
circular import: the validator imports light detection modules, whose package used to
import the scanner eagerly, which imports the validator's package. Inside the test
process the import order hides such cycles, so each module is imported first, alone.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

ENTRY_MODULES = (
    "src.api.phishing_api",
    "src.main",
    "src.runtime.roles",
    "src.runtime.health",
    "src.eval",
    "src.intelligence",
    "src.intelligence.multi_api_validator",
    "src.capture.service",
    "src.brands",
    "src.detection",
    "src.detection.llm_judge",
    "src.detection.normalize",
)


@pytest.mark.parametrize("module", ENTRY_MODULES)
def test_module_imports_first(module: str) -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    # Importing pytest first makes src.config read .env.test, as the suite does (CI has no .env).
    result = subprocess.run(
        [sys.executable, "-c", f"import pytest\nimport {module}"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr.strip().splitlines()[-1:]

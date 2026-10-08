#!/bin/sh
# Regenerate requirements.txt and requirements-dev.txt from poetry.lock.
#
#   tools/sync-requirements.sh          rewrite both files
#   tools/sync-requirements.sh --check  fail if either file is out of date
#
# pyproject.toml is the single source of truth and poetry.lock pins it; the
# requirements files exist for `pip install -r` (Docker, systemd installs, CI).
# Requires Poetry >= 2.2 with poetry-plugin-export, or POETRY="<command>"
# (e.g. POETRY="uvx --from poetry==2.5.1 --with poetry-plugin-export poetry").
set -eu

cd "$(dirname "$0")/.."
POETRY="${POETRY:-poetry}"
mode="${1:-write}"
out_dir=.
if [ "$mode" = "--check" ]; then
  out_dir=$(mktemp -d)
  trap 'rm -rf "$out_dir"' EXIT
fi

export_group() {
  # $1: output file, $2: header line, $3: poetry export selector
  {
    echo "# Generated from poetry.lock by tools/sync-requirements.sh; do not edit by hand."
    echo "# $2"
    $POETRY export --without-hashes --only "$3"
  } > "$out_dir/$1"
}

$POETRY check --lock
export_group requirements.txt "Runtime dependencies (Docker image, systemd installs, pip-audit)." main
export_group requirements-dev.txt "Runtime + development dependencies (CI, local development)." main,dev

if [ "$mode" = "--check" ]; then
  status=0
  for file in requirements.txt requirements-dev.txt; do
    if ! diff -u "$file" "$out_dir/$file"; then
      echo "$file is out of date: run tools/sync-requirements.sh" >&2
      status=1
    fi
  done
  exit "$status"
fi

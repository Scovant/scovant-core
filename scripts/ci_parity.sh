#!/usr/bin/env bash
# Reproduce every job of .github/workflows/ci.yml in one local run.
#
# The published package is built in one repository and its CI runs in another,
# so a change can look green where it was written and red where it is
# published. This script closes that gap: run it before submitting, and the
# release pipeline runs it over the exported tree as well.
#
# The commands below are kept byte-identical to the ones in ci.yml —
# tests/test_ci_parity_contract.py fails if ci.yml ever runs one this script
# does not. Jobs run in ci.yml's order and the first failure aborts the run.
#
# Usage: bash scripts/ci_parity.sh        (from anywhere; cd's to the package)
#        PYTHON=/path/to/python bash scripts/ci_parity.sh
#
# Expects `pip install -e ".[dev,mcp]" build` — EDITABLE (a non-editable copy
# is imported from two locations at once by the subprocess tests and reports
# coverage below the --cov-fail-under floor) and with `build`, which the
# cli-smoke job below uses to produce the wheel it actually scans with.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
ok() { echo "parity: $1 ok"; }

$PY -m ruff check src tests; ok lint

$PY -m mypy src; ok typecheck

$PY -m pytest -q -m "not security and not golden and not mcp" --cov=scovant_core --cov-report=term-missing --cov-fail-under=90; ok tests

$PY -m pytest -q -m security; ok security

$PY -m pytest -q -m golden; ok golden

if $PY -c "import mcp" 2>/dev/null; then
  $PY -m pytest -q -m mcp; ok mcp
else
  echo "parity: mcp skipped (the optional [mcp] extra is not installed)"
fi

# cli-smoke — build the wheel and scan the fixture server with the INSTALLED
# console script, exactly as the mirror does. The wheel goes into a throwaway
# virtualenv rather than over the current interpreter's install: this script
# is meant to be run from a working tree, and overwriting a developer's
# editable install as a side effect of a check would be a nasty surprise.
rm -rf /tmp/parity-dist /tmp/parity-venv
$PY -m build --wheel --outdir /tmp/parity-dist >/dev/null
$PY -m venv /tmp/parity-venv
/tmp/parity-venv/bin/pip install --quiet /tmp/parity-dist/*.whl
# Putting the venv first on PATH is what lets the cli-smoke commands below
# stay byte-identical to ci.yml while still running the freshly built wheel.
export PATH="/tmp/parity-venv/bin:$PATH"

scovant --version
scovant scan --help >/dev/null

python -m tests._fixture_server commerce-good 8765 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM
ready=0
for i in $(seq 1 20); do
  curl -sf http://127.0.0.1:8765/ >/dev/null && { ready=1; break; }
  sleep 0.5
done
[[ "$ready" == "1" ]] || { echo "fixture server did not start" && exit 1; }

rm -f /tmp/r.json
set +e
scovant scan http://127.0.0.1:8765/ --allow-private-networks --format json --output /tmp/r.json
code=$?
set -e
# 1 is the documented "scanned, findings present" exit code — only a higher
# code means the scan itself failed.
[[ ${code:-0} -le 1 ]]
python -m tests._smoke_assert /tmp/r.json; ok cli-smoke

# Only on success: a failed run leaves the venv and the wheel in place to
# be poked at.
rm -rf /tmp/parity-dist /tmp/parity-venv

echo "parity: ALL OK"

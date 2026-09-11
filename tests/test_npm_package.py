"""The npm package is a LAUNCHER, not a second engine: it must carry no
Python, no check ids, and a version equal to the Python package's."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import scovant_core

PKG = Path(__file__).resolve().parents[1]
NPM = PKG / "npm"

# Files allowed to declare their own suffix inside npm/; everything else
# (in particular: no suffix at all, e.g. an accidentally-added Python
# script or binary) fails test_npm_carries_no_engine_code. An allow-list
# (rather than a `.py`/`.pyc` deny-list) means a NEW kind of engine file
# some future edit drops in here fails closed instead of silently passing.
ALLOWED_NPM_SUFFIXES = {".js", ".mjs", ".json", ".md"}

# Suffix-less files allowed by EXACT name. `LICENSE` has no suffix (npm and
# every licence scanner expect that exact name), so it cannot ride the
# suffix allow-list — and a bare name-based pass would be a hole, so
# test_npm_ships_the_licence_text below additionally pins its bytes to the
# package root's LICENSE.
ALLOWED_NPM_NAMES = {"LICENSE"}


def test_npm_carries_no_engine_code():
    # NPM.rglob("*") on a missing directory silently yields nothing, which
    # would make every assertion below pass vacuously. Assert the directory
    # is actually there first, so this test can never again assert nothing.
    assert NPM.is_dir(), f"{NPM} does not exist"

    files = [p for p in NPM.rglob("*") if p.is_file()]
    assert files, f"{NPM} exists but is empty"

    offenders = [
        p.name for p in files
        if p.suffix not in ALLOWED_NPM_SUFFIXES and p.name not in ALLOWED_NPM_NAMES
    ]
    assert offenders == [], offenders

    blob = "\n".join(p.read_text(encoding="utf-8") for p in files)
    assert not re.search(r"CORE-(ACCESS|MACHINE|INTERFACE|TRUST|OPERABILITY)-\d", blob)


def test_npm_version_equals_the_python_version():
    pkg = json.loads((NPM / "package.json").read_text(encoding="utf-8"))
    assert pkg["version"] == scovant_core.__version__
    assert pkg["name"] == "@scovant/core"
    assert "postinstall" not in json.dumps(pkg.get("scripts", {}))


def _console_script_path() -> str:
    """The `scovant` console script lives next to the interpreter that
    installed it. Looking it up on PATH is a latent bug anywhere the venv
    isn't activated (e.g. `test-core-isolated`, which runs
    `/tmp/core-venv/bin/pytest` directly rather than after `source
    .../activate`) — resolve it the same way regardless of PATH. Falls back
    to a PATH lookup for non-venv installs (e.g. `pip install --user`) where
    the console script isn't a sibling of the interpreter."""
    sibling = Path(sys.executable).with_name("scovant")
    if sibling.is_file():
        return str(sibling)
    found = shutil.which("scovant")
    assert found, "no `scovant` console script found beside the interpreter or on PATH"
    return found


def test_module_entrypoint_matches_the_console_script():
    """`python -m scovant_core` is the npm launcher's third fallback (no uv,
    no pipx). It must actually run — and agree on version with the
    `scovant` console script — or that fallback silently hands users a
    runner that crashes instead of the actionable "no runner found" exit."""
    module_run = subprocess.run(
        [sys.executable, "-m", "scovant_core", "--version"],
        capture_output=True, text=True, check=False,
    )
    assert module_run.returncode == 0, module_run.stderr

    console_run = subprocess.run(
        [_console_script_path(), "--version"], capture_output=True, text=True, check=False,
    )
    assert console_run.returncode == 0, console_run.stderr
    assert module_run.stdout.strip() == console_run.stdout.strip()
    assert module_run.stdout.strip() == f"scovant-core {scovant_core.__version__}"


def test_npm_ships_the_licence_text():
    """`package.json` declares Apache-2.0; the redistributed tarball must
    carry the licence text itself (Apache-2.0 s4(a)), and it must be the
    same text the Python package ships — not a second, drifting copy."""
    npm_license = NPM / "LICENSE"
    assert npm_license.is_file(), "npm/LICENSE is missing — the tarball would ship no licence text"
    root_license = PKG / "LICENSE"
    if root_license.is_file():
        # The isolated CI run (see test_docs.py) copies only tests/, fixtures/,
        # docs/ and npm/ — the package root's LICENSE isn't there to compare
        # against. Everywhere else this is the assertion that keeps npm/LICENSE
        # from becoming a second, drifting copy.
        assert npm_license.read_bytes() == root_license.read_bytes()

    pkg = json.loads((NPM / "package.json").read_text(encoding="utf-8"))
    assert pkg["license"] == "Apache-2.0"
    assert "LICENSE" in pkg["files"], "npm/LICENSE exists but `files` would exclude it"

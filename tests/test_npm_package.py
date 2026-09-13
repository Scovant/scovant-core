"""The npm package is a LAUNCHER, not a second engine: it must carry no
Python, no check ids, and a version equal to the Python package's."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import scovant_core

PKG = Path(__file__).resolve().parents[1]
NPM = PKG / "npm"
NPM_BIN = NPM / "bin" / "scovant.js"
VERSION = scovant_core.__version__

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


def test_launcher_fails_closed_on_engine_version_mismatch(tmp_path):
    """A fake `python3` on PATH that answers `--version` with a different
    engine version: the launcher must exit 9 and name both versions; with
    SCOVANT_ALLOW_VERSION_MISMATCH=1 it must run (and print the warning)."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")

    fake = tmp_path / "python3"
    fake.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-m\" ] && [ \"$3\" = \"--version\" ]; then echo 'scovant-core 9.9.9'; exit 0; fi\n"
        "echo ran-engine; exit 0\n"
    )
    fake.chmod(0o755)

    # A real python3.12/python3.13 on this machine can have scovant_core
    # importable already (e.g. a dev box with `pip install -e .`), which
    # would answer the probe for real and hide the mismatch this test
    # exists to prove. Build a PATH containing ONLY the fake `python3`
    # (never a versioned python3.NN — that would let the launcher's own
    # fallback loop skip past the fake) plus symlinks for the binaries the
    # launcher process itself needs to start, so uvx/pipx stay invisible
    # (existsOnPath under SCOVANT_NPM_TEST=1 finds nothing there) and the
    # python3 fallback is the one and only runner resolveRunner can reach.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").write_bytes(fake.read_bytes())
    (bin_dir / "python3").chmod(0o755)
    for name in ("node", "env", "sh"):
        src = shutil.which(name)
        if src:
            (bin_dir / name).symlink_to(src)

    env = {**os.environ, "PATH": str(bin_dir), "SCOVANT_NPM_TEST": "1"}
    r = subprocess.run(["node", str(NPM_BIN), "--version"], env=env, capture_output=True, text=True)
    assert r.returncode == 9 and "9.9.9" in r.stderr and VERSION in r.stderr and "SCOVANT_ALLOW_VERSION_MISMATCH" in r.stderr

    # The probe always runs `-m scovant_core --version` regardless of the
    # caller's own arguments, so the real run below is given a DIFFERENT
    # trailing argument than "--version" — otherwise it would coincide with
    # the probe's fixed invocation and the fake script could not tell "the
    # version-check probe" apart from "the actual run", always answering
    # with the version line instead of proving a real run happened.
    r2 = subprocess.run(["node", str(NPM_BIN), "scan"], env={**env, "SCOVANT_ALLOW_VERSION_MISMATCH": "1"},
                         capture_output=True, text=True)
    assert r2.returncode == 0 and "ran-engine" in r2.stdout and "warning" in r2.stderr


def _write_fake_interpreter(path, *, version_reply, run_marker):
    """A fake `pythonX.Y` that answers `-m scovant_core --version` with
    `version_reply` and, for any other invocation (the real run), prints
    `run_marker` and exits 0."""
    path.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = \"-m\" ] && [ \"$3\" = \"--version\" ]; then echo 'scovant-core {version_reply}'; exit 0; fi\n"
        f"echo {run_marker}; exit 0\n"
    )
    path.chmod(0o755)


def _isolated_bin_dir(tmp_path, extra_files):
    """A PATH containing ONLY the given fake interpreters plus symlinks for
    the binaries the launcher process itself needs — never a real
    python3.NN, which would answer the probe for real and hide the
    mismatch these tests exist to prove."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, version_reply, run_marker in extra_files:
        _write_fake_interpreter(bin_dir / name, version_reply=version_reply, run_marker=run_marker)
    for name in ("node", "env", "sh"):
        src = shutil.which(name)
        if src:
            (bin_dir / name).symlink_to(src)
    return bin_dir


def test_launcher_skips_a_mismatched_interpreter_and_uses_a_later_matching_one(tmp_path):
    """resolveRunner tries python3.13 -> python3.12 -> python3 in order. A
    stale engine on an EARLIER candidate (python3.12) must not abort the
    whole probe — a LATER candidate (python3) that carries the exact
    version must still be used, silently (no mismatch warning), and the
    stale one must never run."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")

    bin_dir = _isolated_bin_dir(tmp_path, [
        ("python3.12", "9.9.9", "ran-stale-engine"),
        ("python3", VERSION, "ran-correct-engine"),
    ])
    env = {**os.environ, "PATH": str(bin_dir), "SCOVANT_NPM_TEST": "1"}

    r = subprocess.run(["node", str(NPM_BIN), "scan"], env=env, capture_output=True, text=True)
    assert r.returncode == 0
    assert "ran-correct-engine" in r.stdout
    assert "ran-stale-engine" not in r.stdout
    assert "mismatch" not in r.stderr and "warning" not in r.stderr


def test_launcher_fails_closed_when_every_interpreter_mismatches(tmp_path):
    """When EVERY candidate interpreter carries the wrong engine version,
    the launcher must exit 9 and name every interpreter tried and the
    version each one reported, plus the escape hatch — not just the first
    one it happened to probe."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")

    bin_dir = _isolated_bin_dir(tmp_path, [
        ("python3.12", "9.9.9", "ran-stale-3.12"),
        ("python3", "8.8.8", "ran-stale-3"),
    ])
    env = {**os.environ, "PATH": str(bin_dir), "SCOVANT_NPM_TEST": "1"}

    r = subprocess.run(["node", str(NPM_BIN), "--version"], env=env, capture_output=True, text=True)
    assert r.returncode == 9
    assert "python3.12" in r.stderr and "9.9.9" in r.stderr
    assert "python3" in r.stderr and "8.8.8" in r.stderr
    assert VERSION in r.stderr
    assert "SCOVANT_ALLOW_VERSION_MISMATCH" in r.stderr

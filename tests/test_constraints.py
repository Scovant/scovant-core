"""Audit §12: the official distribution ships an exact-pin constraints file
for the current version, covering every runtime (and optional) dependency."""
import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

import scovant_core

ROOT = Path(__file__).resolve().parents[1]


def _pins() -> dict[str, str]:
    path = ROOT / "constraints" / f"constraints-{scovant_core.__version__}.txt"
    assert path.exists(), f"missing {path} — regenerate constraints for this version"
    pins = {}
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.\-]+)==(\S+)", line)
        assert m, f"not an exact pin: {line!r}"
        pins[m.group(1).lower().replace("_", "-")] = m.group(2)
    return pins


def test_constraints_cover_runtime_deps_and_satisfy_ranges():
    pins = _pins()
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    reqs = [Requirement(r) for r in meta["project"]["dependencies"]]
    reqs += [Requirement(r) for r in meta["project"]["optional-dependencies"]["mcp"]]
    for req in reqs:
        name = req.name.lower().replace("_", "-")
        assert name in pins, f"{name} has no pin"
        assert req.specifier.contains(Version(pins[name]), prereleases=False), f"{name}=={pins[name]} outside {req.specifier}"

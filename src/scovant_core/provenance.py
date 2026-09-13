"""Runtime environment fingerprint (audit §12): what ACTUALLY ran, computed
at scan time — never copied from the constraints file."""
from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from importlib import metadata

import scovant_core

RUNTIME_DEPENDENCIES: tuple[str, ...] = ("httpx", "beautifulsoup4", "lxml", "tldextract")
OPTIONAL_DEPENDENCIES: tuple[str, ...] = ("mcp",)


def environment_fingerprint(
    *, versions: Callable[[str], str] = metadata.version, python: str | None = None,
) -> tuple[dict[str, str], str]:
    """Return (dependency map, sha256 digest). A missing optional dependency
    reads "absent"; a missing runtime dependency also reads "absent" rather
    than raising — the fingerprint must never break a scan."""
    deps: dict[str, str] = {}
    for name in RUNTIME_DEPENDENCIES + OPTIONAL_DEPENDENCIES:
        try:
            deps[name] = versions(name)
        except metadata.PackageNotFoundError:
            deps[name] = "absent"
    py = python or sys.version.split()[0]
    lines = "\n".join(sorted(f"{k}=={v}" for k, v in deps.items()))
    digest = hashlib.sha256(f"core_version={scovant_core.__version__}\npython={py}\n{lines}".encode()).hexdigest()
    return deps, digest

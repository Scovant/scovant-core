"""Scovant Core — open-source, evidence-first scanner for passive AI-agent
readiness signals. See https://github.com/Scovant/scovant-core.
"""
from __future__ import annotations

__version__ = "0.2.0"

__all__ = ["ScanOptions", "__version__", "scan"]


def __getattr__(name: str):
    # Deferred: `engine` imports `scovant_core` (for `__version__`) at module
    # load time, so importing it eagerly up top here would be a cycle.
    if name == "scan":
        from scovant_core.engine import scan
        return scan
    if name == "ScanOptions":
        from scovant_core.context import ScanOptions
        return ScanOptions
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""The check registry: `CHECKS` is populated by `checks/__init__.py` importing
each category module, which appends its checks here. `RULESET_DIGEST` is
exposed as a module-level attribute via PEP 562 `__getattr__`, delegating to
`ruleset_digest()` on every access — there is exactly one implementation of
"what is the current digest", so `CHECKS` never drifts from what callers see."""
from __future__ import annotations

import hashlib
import re

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category
from scovant_core.scoring import SCORING_DIGEST

RULESET_VERSION = "2026.09"
RETIRED_IDS: frozenset[str] = frozenset()
_ID_RE = re.compile(r"CORE-(ACCESS|MACHINE|INTERFACE|TRUST|OPERABILITY)-\d{3}")
_ID_CATEGORY = {
    "ACCESS": Category.ACCESS,
    "MACHINE": Category.MACHINE,
    "INTERFACE": Category.INTERFACES,
    "TRUST": Category.TRUST,
    "OPERABILITY": Category.OPERABILITY,
}

CHECKS: list[CoreCheck] = []  # populated by checks/__init__.py


def get_check(check_id: str) -> CoreCheck | None:
    return next((c for c in CHECKS if c.id == check_id), None)


def validate_registry() -> None:
    ids = [c.id for c in CHECKS]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate check id")
    for c in CHECKS:
        m = _ID_RE.fullmatch(c.id)
        if not m:
            raise ValueError(f"invalid check id: {c.id!r}")
        if c.id in RETIRED_IDS:
            raise ValueError(f"{c.id} is retired and may not be reused")
        if c.weight < 1:
            raise ValueError(f"{c.id}: weight must be >= 1")
        expected_category = _ID_CATEGORY[m.group(1)]
        if c.category != expected_category:
            raise ValueError(
                f"{c.id}: category {c.category!r} does not match id prefix {m.group(1)!r} "
                f"(expected {expected_category!r})"
            )


def _digest() -> str:
    pairs = "\n".join(f"{c.id}:{c.check_version}" for c in sorted(CHECKS, key=lambda c: c.id))
    return hashlib.sha256(f"{pairs}\nscoring:{SCORING_DIGEST}".encode()).hexdigest()[:12]


def ruleset_digest() -> str:
    """Recompute the digest from the CURRENT `CHECKS` contents. This is the
    one implementation `RULESET_DIGEST` (below) delegates to."""
    return _digest()


def __getattr__(name: str):
    if name == "RULESET_DIGEST":
        return ruleset_digest()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

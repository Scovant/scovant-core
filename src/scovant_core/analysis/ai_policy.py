"""Four public crawler-policy dimensions derived from robots.txt and the
registry (audit §5): search / user_triggered / training / content_use."""
from __future__ import annotations

from scovant_core.parsers.robots import is_allowed
from scovant_core.registry.ai_bots import REGISTRY_VERSION, by_purpose

_DIMENSIONS = (("search", "search"), ("user_triggered", "user_fetch"),
               ("training", "training"), ("content_use", "content_use_control"))


def classify_policy(robots_text: str | None, url: str) -> dict:
    out: dict = {"registry_version": REGISTRY_VERSION}
    declared = bool((robots_text or "").strip())
    for name, purpose in _DIMENSIONS:
        tokens = by_purpose(purpose)
        if not declared:
            out[name] = {"verdict": "undeclared", "allowed": list(tokens), "blocked": []}
            continue
        allowed = [t for t in tokens if is_allowed(robots_text or "", t, url)]
        blocked = [t for t in tokens if t not in allowed]
        verdict = "allowed" if not blocked else ("blocked" if not allowed else "mixed")
        out[name] = {"verdict": verdict, "allowed": allowed, "blocked": blocked}
    return out

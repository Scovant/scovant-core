"""Shared robots.txt readability classification for the CORE-ACCESS checks
that evaluate a *declared policy* (003, 004): a check must never emit a
confident PASS/WARN/FAIL about a policy it never actually read.

Three states:
  - "unreadable" — the document could not be read at all (fetch failed, a
                   5xx, or the response wasn't a real robots.txt body) —
                   evaluate to ERROR (product spec §6: this counts toward
                   applicable coverage, unlike N/A).
  - "absent"     — a real HTTP 404: no robots.txt is published. Per RFC 9309
                   this means "allow all" by construction, which IS a real,
                   readable signal — evaluate normally, just say so honestly.
  - "ok"         — a real 200 with a parseable robots.txt body.

`robots_truncation()` is the second half of the same rule, for the same
checks: a robots.txt larger than the client's body cap is parsed from the
prefix that was read, so a `Disallow:` (or an `Allow:`, or a
`Content-Signal:`) past the cap is invisible to every verdict derived from
it. That is degraded evidence, not a site defect — the verdict stands, but
it must say so and must not be published at full confidence. Every check
that draws a verdict from the robots.txt *body* (CORE-ACCESS-002, -003,
-004, -010) routes through this helper so the three signals — the evidence
flag, the confidence drop, the sentence in the summary — can never drift
apart between them, and so that `truncated` has one meaning across the
family. See docs/methodology.md § "Truncated documents" for what the flag's
absence means to a report consumer.
"""
from __future__ import annotations

from scovant_core.checks._truncation import (  # re-exported: the four robots
    TRUNCATION_NOTE,  # checks import them from here
    record_truncation,  # and must keep working.
    truncated_confidence,
)

robots_truncation = record_truncation

__all__ = ["TRUNCATION_NOTE", "record_truncation", "robots_truncation", "truncated_confidence"]


def classify_robots_readability(robots: dict) -> str:
    if robots["status"] is None:
        return "unreadable"
    if robots["served_as_html"]:
        return "unreadable"
    if robots["status"] == 404:
        return "absent"
    if robots["status"] != 200:
        return "unreadable"
    return "ok"

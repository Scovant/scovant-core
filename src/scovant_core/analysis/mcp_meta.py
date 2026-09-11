"""Metadata-integrity screening for MCP tool descriptions.

MCP tool names/descriptions are publisher-controlled, untrusted text — an
agent reads them as part of its context before ever calling the tool. This
module provides pure, I/O-free detectors used by the MCP interface scan
rules to flag suspicious tool metadata:

- ``find_injection_markers``: curated pattern matching for imperative-override
  prompt-injection phrasing (e.g. "ignore all previous instructions").
- ``find_obfuscation``: Unicode codepoint scanning for characters commonly
  used to hide or disguise text from human reviewers (zero-width joiners,
  bidi control overrides, private-use-area glyphs).
- ``find_name_collisions``: normalized tool-name collision + reserved-token
  shadowing detection — a tool whose name collides with another
  tool (after normalization) or shadows a reserved JSON-RPC/MCP method token
  is ambiguous for a client dispatching by name.

None of these functions perform any network, file, or database access, and
none name any specific competitor or product.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Injection markers
# ---------------------------------------------------------------------------

# Each entry is (label, compiled_regex). Regexes are case-insensitive and
# word-boundaried where sensible. Curated for imperative-override phrasing
# and tool-shadowing cues commonly seen in prompt-injection payloads hidden
# in tool metadata.
_INJECTION_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.IGNORECASE),
    ),
    (
        "you_are_now",
        re.compile(r"\byou\s+are\s+now\s+(a|an|the|no\s+longer)\b", re.IGNORECASE),
    ),
    (
        # Deliberately narrower than a bare "system prompt" match, which
        # false-positives on benign LLM-tooling copy ("configure the system
        # prompt template"). Requires the colon-labelled injection shape
        # ("system prompt: <payload>"); the reveal/exfiltration shape
        # ("reveal your system prompt") is covered by reveal_secrets below.
        "system_prompt",
        re.compile(r"\bsystem\s+prompt\s*:", re.IGNORECASE),
    ),
    (
        "disregard_above",
        re.compile(r"\bdisregard\s+(the\s+)?above\b", re.IGNORECASE),
    ),
    (
        "new_instructions",
        re.compile(r"\bnew\s+instructions?\s*:", re.IGNORECASE),
    ),
    (
        "tool_shadowing_priority",
        re.compile(
            r"\b(takes?\s+priority\s+over|overrides?|supersedes?)\s+(all\s+)?"
            r"(other\s+)?tools?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_shadowing_always_use",
        re.compile(
            r"\balways\s+use\s+this\s+(tool|one)\s+instead\b", re.IGNORECASE
        ),
    ),
    (
        "do_not_tell_user",
        re.compile(r"\bdo\s+not\s+(tell|inform|notify)\s+the\s+user\b", re.IGNORECASE),
    ),
    (
        "reveal_secrets",
        re.compile(
            r"\breveal\s+(your\s+)?(keys|secrets?|credentials?|system\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
]


def find_injection_markers(text: str) -> list[str]:
    """Return the labels of any curated prompt-injection markers found in text.

    Empty list means clean. Matching is case-insensitive. Order follows
    ``_INJECTION_MARKERS`` declaration order; duplicate labels never occur.
    """
    if not text:
        return []
    return [label for label, pattern in _INJECTION_MARKERS if pattern.search(text)]


# ---------------------------------------------------------------------------
# Unicode obfuscation
# ---------------------------------------------------------------------------

_ZERO_WIDTH = frozenset(
    {
        "​",  # ZERO WIDTH SPACE
        "‌",  # ZERO WIDTH NON-JOINER
        "‍",  # ZERO WIDTH JOINER
        "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)

# Bidi control overrides: U+202A-202E (LRE/RLE/PDF/LRO/RLO), U+2066-2069
# (LRI/RLI/FSI/PDI).
_BIDI_OVERRIDE_RANGES: tuple[tuple[int, int], ...] = (
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)

# Private-use areas: BMP PUA + the two supplementary PUA planes.
_PRIVATE_USE_RANGES: tuple[tuple[int, int], ...] = (
    (0xE000, 0xF8FF),
    (0xF0000, 0xFFFFD),
    (0x100000, 0x10FFFD),
)


def _in_ranges(codepoint: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(lo <= codepoint <= hi for lo, hi in ranges)


def find_obfuscation(text: str) -> list[str]:
    """Return category labels for Unicode obfuscation techniques found in text.

    Categories: "zero_width", "bidi_override", "private_use". Empty list
    means clean. Each category appears at most once, in a fixed order
    (zero_width, bidi_override, private_use) regardless of scan order.
    """
    if not text:
        return []

    found: set[str] = set()
    for ch in text:
        cp = ord(ch)
        if ch in _ZERO_WIDTH:
            found.add("zero_width")
        elif _in_ranges(cp, _BIDI_OVERRIDE_RANGES):
            found.add("bidi_override")
        elif _in_ranges(cp, _PRIVATE_USE_RANGES):
            found.add("private_use")

        if len(found) == 3:
            break

    ordered = ["zero_width", "bidi_override", "private_use"]
    return [label for label in ordered if label in found]


# ---------------------------------------------------------------------------
# Tool name collisions / reserved-token shadowing
# ---------------------------------------------------------------------------

# Curated set of reserved MCP/JSON-RPC method tokens. A tool whose (normalized)
# name matches one of these shadows a protocol-level method — a client that
# dispatches by name (rather than by the tools/call envelope specifically)
# could route a protocol operation into this tool's handler, or an agent
# reading the tool list could mistake it for a protocol primitive.
_RESERVED_MCP_TOKENS: frozenset[str] = frozenset(
    {
        "initialize",
        "initialized",
        "ping",
        "tools/list",
        "tools/call",
        "notifications/initialized",
        "notifications/progress",
        "notifications/cancelled",
        "notifications/message",
        "resources/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setlevel",
    }
)


def _normalize_tool_name(name: str) -> str:
    return (name or "").strip().lower()


def find_name_collisions(tools: list[dict]) -> list[dict]:
    """Detect duplicate normalized tool names and reserved-token shadowing.

    Pure, I/O-free. ``tools`` is the E1 ``interface.tools`` list (each a dict
    with at least a ``name`` key). Never raises — malformed entries (missing
    or non-string ``name``) are treated as an empty-string name and folded
    into the same normalization/dedup logic rather than skipped, so a
    malformed name that collides with another still gets reported.

    Returns a list of structured findings, each one of:
      - ``{"kind": "duplicate", "normalized_name": str, "names": [str, ...]}``
        — two or more tools normalize to the same name. ``names`` carries the
        original (pre-normalization) names, in first-seen order.
      - ``{"kind": "reserved_shadow", "normalized_name": str, "names": [str]}``
        — a tool's normalized name matches a reserved MCP/JSON-RPC token.

    Empty list means clean. Order: duplicates first (in first-seen order of
    the normalized name), then reserved-token shadows (in first-seen order).
    """
    if not tools:
        return []

    by_normalized: dict[str, list[str]] = {}
    order: list[str] = []
    for tool in tools:
        raw_name = tool.get("name") if isinstance(tool, dict) else None
        raw_name = raw_name if isinstance(raw_name, str) else ""
        normalized = _normalize_tool_name(raw_name)
        if normalized not in by_normalized:
            by_normalized[normalized] = []
            order.append(normalized)
        by_normalized[normalized].append(raw_name)

    findings: list[dict] = []
    for normalized in order:
        names = by_normalized[normalized]
        if len(names) > 1:
            findings.append(
                {
                    "kind": "duplicate",
                    "normalized_name": normalized,
                    "names": names,
                }
            )
    for normalized in order:
        if normalized in _RESERVED_MCP_TOKENS:
            findings.append(
                {
                    "kind": "reserved_shadow",
                    "normalized_name": normalized,
                    "names": by_normalized[normalized][:1],
                }
            )

    return findings

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from scovant_core.models import Confidence
from scovant_core.security.redaction import redact_secret
from scovant_core.security.secret_patterns import VENDOR_PATTERNS


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern[str]
    confidence: Confidence
    entropy_min: float | None = None
    group: int = 0


@dataclass(frozen=True)
class SecretHit:
    kind: str
    confidence: Confidence
    redacted: dict
    start: int
    end: int


_VENDOR_CONF = {"jwt": Confidence.MEDIUM}
PATTERNS: tuple[SecretPattern, ...] = tuple(
    SecretPattern(k, re.compile(v), _VENDOR_CONF.get(k, Confidence.HIGH)) for k, v in VENDOR_PATTERNS.items()
) + (
    SecretPattern("stripe_live_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}"), Confidence.HIGH),
    SecretPattern("basic_auth_url", re.compile(r"https?://[^/\s:@]+:([^@\s]{6,})@"), Confidence.HIGH, group=1),
    SecretPattern("generic_assignment",
                  re.compile(r"(?i)(?:api[_-]?key|api[_-]?secret|secret|token|password)\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{24,})"),
                  Confidence.MEDIUM, entropy_min=3.5, group=1),
)

_PLACEHOLDER_RES = (
    re.compile(r"\*{3,}"), re.compile(r"^<[^>]+>$"), re.compile(r"\$\{[^}]+\}"),
    re.compile(r"your[-_ ]?", re.I), re.compile(r"example", re.I), re.compile(r"redacted", re.I),
    re.compile(r"changeme", re.I), re.compile(r"0123456789"), re.compile(r"^(.)\1+$"),
)
_X_RUN_RE = re.compile(r"x+", re.I)
# Built at runtime, never as a contiguous literal — a vendor-shaped example
# credential (even a well-known documentation one) must not appear as source text.
_KNOWN_EXAMPLES = {
    "AKIA" + "IOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def _dominant_x_run(value: str) -> bool:
    """True when the longest run of x/X covers at least half the value — a
    masking placeholder (`sk_live_xxxxxxxxxxxxxxxxxxxx`) rather than a real
    token that merely happens to contain a short run of x's."""
    if not value:
        return False
    longest = max((len(m.group(0)) for m in _X_RUN_RE.finditer(value)), default=0)
    return longest >= 6 and longest / len(value) >= 0.5


def is_placeholder(value: str) -> bool:
    return value in _KNOWN_EXAMPLES or _dominant_x_run(value) or any(r.search(value) for r in _PLACEHOLDER_RES)


def detect_secrets(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    taken: list[tuple[int, int]] = []
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            value = m.group(pat.group)
            span = m.span(pat.group)
            if any(a < span[1] and span[0] < b for a, b in taken):
                continue  # a vendor match already claimed an overlapping span (vendor patterns come first)
            if is_placeholder(value):
                continue
            if pat.entropy_min is not None and shannon_entropy(value) < pat.entropy_min:
                continue
            hits.append(SecretHit(pat.kind, pat.confidence, redact_secret(value), span[0], span[1]))
            taken.append(span)
    return sorted(hits, key=lambda h: h.start)


def redact_phrase(text: str) -> str:
    """Return `text` with every credential-shaped span replaced by
    `<redacted:kind>` — never the value, never a prefix of it.

    A heuristic phrase match (`analysis.instruction_markers`) captures up to
    120-160 characters of surrounding text verbatim, so a credential that
    happens to sit inside an agent-addressed sentence would otherwise ship
    in evidence in full. This is the one filter every such phrase passes
    through before it enters a `CheckResult`.

    It lives here, beside `detect_secrets`, rather than in
    `analysis/instruction_markers.py`: the `analysis` package imports
    nothing from `checks`, and the secret engine (patterns, placeholder
    suppression, entropy floor) is a `checks.security` concern.
    """
    if not text:
        return text
    spans = _secret_spans(text)
    if not spans:
        return text
    # Right-to-left so an earlier replacement can never shift a later span.
    out = text
    for start, end, kind in reversed(spans):
        out = out[:start] + f"<redacted:{kind}>" + out[end:]
    return out


def _secret_spans(text: str) -> list[tuple[int, int, str]]:
    """Non-overlapping `(start, end, kind)` spans to redact, in document
    order.

    Scanned over the text AND over its case-folded twins: every phrase
    `analysis.instruction_markers` returns is already lower-cased, which
    alone defeats the case-sensitive vendor patterns (an AWS key reaches
    evidence as `akia…` — mangled, but trivially recovered with `.upper()`,
    so still a leak). A twin is only used when case-folding preserved the
    length, so a span found in it always addresses the same characters of
    the original; multi-character case mappings (`ß` -> `SS`) shift offsets
    and are skipped rather than mis-redacted."""
    variants = [text]
    for twin in (text.upper(), text.lower()):
        if twin != text and len(twin) == len(text):
            variants.append(twin)
    found = sorted(
        (h.start, h.end, h.kind) for v in variants for h in detect_secrets(v)
    )
    out: list[tuple[int, int, str]] = []
    for start, end, kind in found:
        if out and start < out[-1][1]:
            continue  # already inside a span claimed by an earlier variant
        out.append((start, end, kind))
    return out

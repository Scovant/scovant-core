"""Shared truncation helpers for checks that read documents capped by size.

Any gatherer record with a `truncated` key — not just robots.txt — may be
read only in part when the body exceeds the fetch size cap. That is degraded
evidence, not a site defect — the verdict stands, but it must say so and must
not be published at full confidence.

`record_truncation()` writes the flag to evidence when the document really was
cut off, and `truncated_confidence()` caps a branch's confidence at MEDIUM when
it was. Every check that draws a verdict from a possibly-truncated document
routes through these helpers so the three signals — the evidence flag, the
confidence drop, the sentence in the summary — can never drift apart, and so
that `truncated` has one meaning across the family. See docs/methodology.md
§ "Truncated documents" for what the flag's absence means to a report consumer.
"""
from __future__ import annotations

from scovant_core.models import Confidence

# The document-agnostic default: shared by every check that records
# truncation but has no single, specific document name to cite (a check
# aggregating over several sampled pages, for instance). A reader comparing
# two findings from the same scan must not see the same fact worded two ways,
# so this is the one sentence every caller falls back to.
TRUNCATION_NOTE = (
    " The document body exceeded the fetch size cap and was read only in part, "
    "so anything past the cap is not reflected in this verdict."
)


def record_truncation(source: dict, evidence: dict, *, document: str | None = None) -> tuple[str, bool]:
    """Record the truncation flag on `evidence` and return `(note, truncated)`.

    The flag is written only when the body really was cut off. An
    always-present `"truncated": false` would carry no information and would
    change every stored report's evidence for nothing; an absent key therefore
    means "read in full" — the contract documented in docs/methodology.md.

    `document`, when the caller already knows which single document the
    verdict was drawn from (e.g. "robots.txt", "llms.txt", "sitemap"), names
    it in the note instead of the generic `TRUNCATION_NOTE` wording — a
    verdict built on a truncated llms.txt must never read as a complaint
    about robots.txt. Omit it (the default) for a check that aggregates
    across several documents/pages, where no single name would be accurate.
    """
    truncated = bool(source.get("truncated"))
    if truncated:
        evidence["truncated"] = True
    if not truncated:
        return "", False
    if document:
        return (f" The {document} body exceeded the fetch size cap and was read only in part, "
                "so anything past the cap is not reflected in this verdict."), True
    return TRUNCATION_NOTE, True


def truncated_confidence(truncated: bool, default: Confidence = Confidence.HIGH) -> Confidence:
    """Never *raise* a branch's own confidence — only cap it at MEDIUM when
    the document behind the verdict was read only in part."""
    return Confidence.MEDIUM if (truncated and default is Confidence.HIGH) else default

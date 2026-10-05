"""Citability rule published from Scovant Cloud — page-scoped: how readily AI
answer engines can quote a content page's passages.

The page score is `citability_scorer.page_citability` over the page's
content blocks (`content_blocks`) in its language (`page_language`). It
applies only to content sites (`CITABILITY_TYPES`, the same set as the
public scoring policy's citability profile); the host names the site type
in `site_type`. A page at or above `PASS_MIN` reports nothing. Below it the
finding is `CITABILITY_WEAK` (low; medium under `MEDIUM_BELOW`), and under
`POOR_BELOW` it carries the code `CITABILITY_POOR` (high) — the rule's one
alias. Each finding carries 1/N of the penalty, N = the content pages the
host scored (`content_pages_scored`). The findings' text and metadata are
the ones Scovant Cloud has always reported for this code; `measure` says
when silence is a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule
from scovant_core.rules.citability_scorer import page_citability

# Content site types: the only ones the rule (and the citability category) applies to.
CITABILITY_TYPES: frozenset[str] = frozenset(
    {"blog", "news", "media", "documentation", "docs", "portfolio", "other"}
)

# Public default bands for the page score (0–100).
PASS_MIN = 65       # at or above: no finding
MEDIUM_BELOW = 50   # below: medium instead of low
POOR_BELOW = 35     # below: CITABILITY_POOR, high
WEAK_CODE = "CITABILITY_WEAK"
POOR_CODE = "CITABILITY_POOR"

_EXAMPLE = (
    "Instead of 'See our pricing page for details', write a self-contained "
    "~150-word passage: 'Plan A costs $29/mo and includes X, Y, Z. According to our "
    "Q1 2024 report, 73% of users on Plan A saw a 40% reduction in setup time. "
    "This means teams can go live in under a week rather than the industry-average "
    "three weeks.' Lead with the answer, include concrete statistics and dates."
)


def citability_band(score: float) -> tuple[str, str] | None:
    """(issue code, severity) for a page score, None at or above `PASS_MIN`."""
    if score >= PASS_MIN:
        return None
    if score < POOR_BELOW:
        return POOR_CODE, "high"
    if score < MEDIUM_BELOW:
        return WEAK_CODE, "medium"
    return WEAK_CODE, "low"


@register_rule
class LowCitability(CoreRule):
    code = WEAK_CODE
    aliases = (POOR_CODE,)
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "citability"
    severity = "low"  # per-finding severity follows the band
    title = "Weak citability for AI answer engines"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        if domain.get("site_type") not in CITABILITY_TYPES:
            return []

        blocks = page.get("content_blocks") or []
        if not blocks:
            return []

        score = page_citability(blocks, page.get("page_language"))
        band = citability_band(score)
        if band is None:
            return []
        code, severity = band

        n = domain.get("content_pages_scored") or 1
        wm = 1.0 / n

        url = (page.get("metadata") or {}).get("canonical_url")
        return [
            Finding(
                title="Low AI-citation readiness",
                description=(
                    f"Page citability score {score}/100. AI search engines are unlikely to "
                    "quote this page's passages: they are too short, lack specific figures, "
                    "or do not directly answer questions."
                ),
                remediation_hint=(
                    "Write self-contained passages of ~134–167 words that directly answer a "
                    "question, lead with the answer, and include concrete statistics or dates."
                ),
                example=_EXAMPLE,
                metadata={"page_citability": score},
                url=url,
                severity=severity,
                weight_multiplier=wm,
                code=code,
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if ctx.site_category not in CITABILITY_TYPES:
            return OutcomeState.NA
        if not domain:
            return OutcomeState.NOT_MEASURED  # the site type travels in the domain evidence
        return None if page.get("content_blocks") else OutcomeState.NOT_MEASURED

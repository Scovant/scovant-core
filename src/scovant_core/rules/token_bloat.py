"""Page token-cost rule published from Scovant Cloud — page-scoped: how many
tokens an agent spends to ingest one page (visible text + interaction
skeleton, `token_cost.total` in the page evidence).

The host switches the rule on and may set its thresholds through
`token_bloat_settings` in the domain evidence; without that block, or with
`enabled` false, the rule reports nothing and measures nothing (N/A). A
threshold the block omits takes the public default below. A page at or over
`low` is a low-severity finding, at or over `medium` a medium one; each
finding carries 1/N of the penalty, N = the pages the host sampled. The
findings' text and metadata are the ones Scovant Cloud has always reported
for this code; `measure` says when silence is a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule
from scovant_core.rules.page_structure import page_share

# Public default thresholds, in tokens.
LOW_TOKENS_DEFAULT = 8000
MEDIUM_TOKENS_DEFAULT = 20000


@register_rule
class PageTokenBloat(CoreRule):
    code = "PAGE_TOKEN_BLOAT"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "low"  # per-finding severity follows the thresholds
    title = "Page token cost excessive for agents"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        settings = domain.get("token_bloat_settings")
        if not settings or not settings.get("enabled"):
            return []
        total = (page.get("token_cost") or {}).get("total")
        low = settings.get("low", LOW_TOKENS_DEFAULT)
        medium = settings.get("medium", MEDIUM_TOKENS_DEFAULT)
        if total is None or total < low:
            return []
        return [
            Finding(
                title="Page token cost excessive for agents",
                description=(
                    f"This page costs ~{total:,} tokens for an agent to ingest "
                    "(visible text + interaction skeleton). Heavy pages slow agents "
                    "down and push key content out of their context budgets."
                ),
                remediation_hint=(
                    "Reduce boilerplate and repeated navigation blocks, paginate "
                    "long listings, and consider serving a Markdown representation "
                    "(see MARKDOWN_FOR_AGENTS_ABSENT) — agents then skip the HTML "
                    "entirely."
                ),
                example=(
                    "// Serve a lightweight Markdown alternate for agents instead of\n"
                    "// the full boilerplate-heavy HTML page:\n"
                    '<link rel="alternate" type="text/markdown" href="/products/widget.md">'
                ),
                metadata={"token_cost": total},
                severity="medium" if total >= medium else "low",
                weight_multiplier=page_share(domain),
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if not domain:
            return OutcomeState.NOT_MEASURED  # the settings travel in the domain evidence
        settings = domain.get("token_bloat_settings") or {}
        if not settings.get("enabled"):
            return OutcomeState.NA
        has_total = (page.get("token_cost") or {}).get("total") is not None
        return None if has_total else OutcomeState.NOT_MEASURED

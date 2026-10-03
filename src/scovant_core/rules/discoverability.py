"""Discoverability rules published from Scovant Cloud (SP-4 wave 1).

Behaviour is byte-identical to the Cloud rules they replace: the findings'
text, metadata and the measurability verdicts (pinned by Cloud's recorded
goldens).
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule


@register_rule
class ContentSignalsAbsent(CoreRule):
    code = "CONTENT_SIGNALS_ABSENT"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    # info (penalty 2): live Cloudflare push, IETF draft — candidate for
    # info→low promotion once the 2026-09-15 default-block lands.
    severity = "info"
    title = "No Content-Signal directives in robots.txt"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "content_signals" not in domain:
            return []  # legacy scan without the Wave-3 parse
        if domain["content_signals"].get("present"):
            return []
        return [
            Finding(
                title="No Content-Signal directives in robots.txt",
                description=(
                    "robots.txt declares no Content-Signal directives "
                    "(ai-train / search / ai-input). Without explicit signals, "
                    "intermediaries decide for you — Cloudflare defaults new "
                    "ad-supported domains to blocking AI agent traffic from "
                    "2026-09-15, making explicit signals the opt-in mechanism "
                    "for agent access."
                ),
                example=(
                    "# robots.txt — declare content usage preferences explicitly\n"
                    "User-agent: *\n"
                    "Content-Signal: ai-train=no, search=yes, ai-input=yes\n"
                    "Allow: /"
                ),
                remediation_hint=(
                    "Add a Content-Signal line to robots.txt declaring how your "
                    "content may be used: ai-train (model training), search "
                    "(search indexing), ai-input (retrieval/grounding at answer "
                    "time). Format: 'Content-Signal: ai-train=no, search=yes, "
                    "ai-input=yes' under the relevant User-agent group. See "
                    "contentsignals.org for the specification."
                ),
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "content_signals")


@register_rule
class ContentSignalSyntax(CoreRule):
    """CONTENT-SIGNAL-001 — consistency-when-present.

    A site that declares Content-Signal directives but malforms them (an
    unrecognized value like `ai-train=maybe`, or a token with no `=`) leaves
    intermediaries and agents guessing exactly where an explicit signal was
    meant to remove doubt. Fires ONLY on a present-but-broken surface; absence
    is CONTENT_SIGNALS_ABSENT's job, and a clean declaration is a pass.
    """

    code = "CONTENT-SIGNAL-001"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Content-Signal directives are malformed"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "content_signals" not in domain:
            return []  # legacy scan without the clarity parse
        cs = domain["content_signals"]
        errors = cs.get("syntax_errors") or []
        # `declared` (a Content-Signal line exists), NOT `present` (a well-formed
        # directive was adopted): a wholly-malformed declaration must still be
        # visible here, while `present` keeps its original meaning for the
        # required CONTENT_SIGNALS_ABSENT rule.
        if not cs.get("declared") or not errors:
            return []
        return [
            Finding(
                title="Content-Signal directives are malformed",
                description=(
                    "robots.txt declares Content-Signal directives, but one or "
                    "more are malformed (an unrecognized value, or a token with "
                    "no '=name=value'). A declared-but-broken signal is worse "
                    "than an absent one: it looks like an explicit preference "
                    "while telling an intermediary nothing usable."
                ),
                example=(
                    "# Broken (unrecognized value):\n"
                    "Content-Signal: ai-train=maybe, search=yes\n"
                    "# Fixed:\n"
                    "Content-Signal: ai-train=no, search=yes, ai-input=yes"
                ),
                remediation_hint=(
                    "Use only 'yes' or 'no' for each dimension (search, "
                    "ai-input, ai-train) and the 'name=value' form. See "
                    "contentsignals.org for the grammar."
                ),
                metadata={
                    "syntax_errors": errors[:5],
                    "dimensions": cs.get("dimensions", {}),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = probe_measured(domain, ctx, "content_signals")
        if verdict:
            return verdict
        assert domain is not None
        return None if domain["content_signals"].get("declared") else OutcomeState.NA


@register_rule
class SitemapMissingOrInvalid(CoreRule):
    code = "SITEMAP_MISSING_OR_INVALID"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Sitemap missing or invalid"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "sitemap" not in domain:
            return []  # legacy scan without the probe
        sm = domain["sitemap"]
        if sm.get("valid"):
            return []
        missing = not sm.get("exists")
        return [
            Finding(
                title="Sitemap missing or invalid",
                description=(
                    "No sitemap.xml was found at the standard paths or robots.txt "
                    "Sitemap directives." if missing else
                    f"A sitemap exists at {sm.get('url')} but does not parse as a "
                    "valid urlset/sitemapindex XML document."
                ),
                remediation_hint=(
                    "Publish a sitemap.xml (urlset or sitemapindex) and reference it "
                    "with a Sitemap: directive in robots.txt — AI crawlers use it to "
                    "plan coverage."
                ),
                example=(
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                    "  <url><loc>https://example.com/</loc></url>\n"
                    "  <url><loc>https://example.com/products/widget</loc></url>\n"
                    "</urlset>\n\n"
                    "# robots.txt\n"
                    "Sitemap: https://example.com/sitemap.xml"
                ),
                metadata={"exists": sm.get("exists"), "url": sm.get("url")},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "sitemap")

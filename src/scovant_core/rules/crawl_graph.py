"""Crawl-graph rules published from Scovant Cloud (experimental): link
structure WITHIN the pages a scan sampled — orphaned, deeply buried and
dead-end pages. A finding is about the sample, never the whole site.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule

# Public defaults (versioned with the rules).
DEEP_PAGE_DEPTH = 3   # a page more than this many hops from the homepage is "deep"
EXAMPLE_CAP = 5       # URLs named per finding


@register_rule
class CrawlGraphOrphanPages(CoreRule):
    code = "CRAWL-GRAPH-001"
    since = "0.8.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Orphaned pages within the scanned sample"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "crawl_graph" not in domain:
            return []
        graph = (domain.get("crawl_graph") or {})
        root = graph.get("root")
        sampled = graph.get("sampled", 0)
        pages = graph.get("pages") or {}
        orphans = sorted(
            url for url, info in pages.items()
            if url != root and info.get("inlinks") == 0 and info.get("depth") is None
        )
        if not orphans:
            return []
        examples = orphans[:EXAMPLE_CAP]
        return [
            Finding(
                title=f"Orphaned pages within the {sampled} scanned pages",
                description=(
                    f"{len(orphans)} page(s) within the {sampled} scanned pages have zero "
                    "inbound links from any other sampled page and are unreachable by "
                    "following links from the homepage within the sample — an agent "
                    "navigating by links alone would never discover them."
                ),
                remediation_hint=(
                    "Link every published page from your navigation, a related-content "
                    "block, or a sitemap-style index page so agents that navigate by "
                    "following links (rather than the sitemap alone) can reach it."
                ),
                example=(
                    "<!-- Add a link to the orphaned page from navigation or a related-content block -->\n"
                    '<nav>\n'
                    '  <a href="/products">Products</a>\n'
                    '  <a href="/products/widget-pro">Widget Pro</a>  <!-- was orphaned -->\n'
                    "</nav>"
                ),
                metadata={"count": len(orphans), "examples": examples, "sampled": sampled},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "crawl_graph")


@register_rule
class CrawlGraphDeepPages(CoreRule):
    code = "CRAWL-GRAPH-002"
    since = "0.8.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Pages buried deep within the scanned sample"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "crawl_graph" not in domain:
            return []
        graph = (domain.get("crawl_graph") or {})
        sampled = graph.get("sampled", 0)
        pages = graph.get("pages") or {}
        deep = sorted(
            (url, info.get("depth"))
            for url, info in pages.items()
            if isinstance(info.get("depth"), int) and info["depth"] > DEEP_PAGE_DEPTH
        )
        if not deep:
            return []
        examples = [url for url, _ in deep[:EXAMPLE_CAP]]
        max_depth = max(depth for _, depth in deep)
        return [
            Finding(
                title=f"Pages buried deep within the {sampled} scanned pages",
                description=(
                    f"{len(deep)} page(s) within the {sampled} scanned pages are reachable "
                    "only via a link path more than 3 hops deep from the homepage (max "
                    f"depth found: {max_depth}) — deep pages are less likely to be "
                    "followed by an agent crawling links."
                ),
                remediation_hint=(
                    "Shorten the link path to important pages — add them to top-level "
                    "navigation, a sitemap-style hub page, or related-content links from "
                    "shallower pages, so agents don't need to follow more than a few hops."
                ),
                example=(
                    "<!-- Shorten the path: link the deep page from a shallower hub page -->\n"
                    '<nav>\n'
                    '  <a href="/docs">Docs</a>\n'
                    '  <a href="/docs/advanced/config/deep-setting">Deep setting</a>  <!-- was 4+ hops deep -->\n'
                    "</nav>"
                ),
                metadata={
                    "count": len(deep),
                    "examples": examples,
                    "sampled": sampled,
                    "max_depth": max_depth,
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "crawl_graph")


@register_rule
class CrawlGraphDeadEndPages(CoreRule):
    code = "CRAWL-GRAPH-005"
    since = "0.8.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "info"
    title = "Dead-end pages within the scanned sample"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "crawl_graph" not in domain:
            return []
        graph = (domain.get("crawl_graph") or {})
        root = graph.get("root")
        sampled = graph.get("sampled", 0)
        pages = graph.get("pages") or {}
        dead_ends = sorted(
            url for url, info in pages.items()
            if url != root and info.get("outlinks_raw") == 0
        )
        if not dead_ends:
            return []
        examples = dead_ends[:EXAMPLE_CAP]
        return [
            Finding(
                title=f"Dead-end pages within the {sampled} scanned pages",
                description=(
                    f"{len(dead_ends)} page(s) within the {sampled} scanned pages contain "
                    "zero same-domain links of their own — an agent that lands there has "
                    "nowhere further to navigate on the site."
                ),
                remediation_hint=(
                    "Add at least one internal link (related content, a category page, "
                    "or a link back to a hub/navigation page) to any page that currently "
                    "links nowhere else on the site."
                ),
                example=(
                    "<!-- Add at least one same-domain outgoing link to the dead-end page -->\n"
                    '<article>\n'
                    "  ...page content...\n"
                    '  <a href="/blog">Back to all posts</a>  <!-- previously no outgoing links -->\n'
                    "</article>"
                ),
                metadata={"count": len(dead_ends), "examples": examples, "sampled": sampled},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "crawl_graph")

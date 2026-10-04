"""Public evidence the Core rules read.

Each block is a JSON object keyed by name inside the domain evidence (the
page evidence is one page's extracted fields). Producers: Scovant Cloud's
crawler fills them for every scanned site; Core's own gatherers fill the
same shapes for the pages they fetch. A missing block means "not measured",
never "absent on the site".
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

# How a gatherer's own requests went (Core 0.8.0). "error": nothing positive
# was found and at least one request never got an HTTP answer, so absence was
# not established. Evidence written before 0.8.0 has no such key and is read
# as measured.
FetchStatus = Literal["ok", "error", "not_attempted"]


class ContentSignalsEvidence(TypedDict, total=False):
    """robots.txt Content-Signal directives (`parsers.content_signals`)."""
    present: bool          # at least one well-formed directive was adopted
    declared: bool         # a Content-Signal line exists, well-formed or not
    dimensions: dict[str, str]
    syntax_errors: list[str]


class SitemapEvidence(TypedDict, total=False):
    """Sitemap discovery (`gatherers.sitemap.check_sitemap`)."""
    exists: bool
    valid: bool
    url: str | None
    fetch_status: FetchStatus
    error: str | None


class LlmsTxtEvidence(TypedDict, total=False):
    """/llms.txt (`parsers.llms_txt.parse_llms_txt`)."""
    exists: bool
    valid: bool
    urls: list[str]
    errors: list[str]


class MarkdownAgentsEvidence(TypedDict, total=False):
    """Homepage requested with `Accept: text/markdown`, plus the /index.md
    mirror (`gatherers.markdown.check_markdown_negotiation`). `status` is None
    when the negotiation request itself failed."""
    negotiation: bool
    mirror: bool
    markdown_tokens: int | None
    status: int | None
    content_type: str | None
    vary: str | None
    looks_markdown: bool
    body_looks_markdown: bool | None


class LinkHeadersEvidence(TypedDict, total=False):
    """Homepage `Link:` response headers (`gatherers.link_headers.check_link_headers`)."""
    present: bool
    rels: list[str]
    agent_relevant: bool
    fetch_status: FetchStatus
    error: str | None


class MachineRepEvidence(TypedDict, total=False):
    """Homepage requested with `Prefer: return=consolidated`
    (`gatherers.machine_rep.check_machine_rep`)."""
    attempted: bool
    status: int | None
    content_type: str | None
    preference_applied: bool | None
    vary: str | None
    alternates: list


class CrawlGraphPage(TypedDict, total=False):
    inlinks: int               # links from other sampled pages
    outlinks_in_sample: int    # links to other sampled pages
    outlinks_raw: int          # same-domain links on the page, sampled or not
    depth: int | None          # hops from the homepage within the sample; None = unreachable


class CrawlGraphEvidence(TypedDict, total=False):
    """Link graph over the pages one scan sampled, built from each page's
    same-domain links. Describes the sample, not the whole site."""
    root: str | None
    sampled: int
    root_fallback: bool
    pages: dict[str, CrawlGraphPage]


# robots.txt per-agent directives (`parsers.robots.parse_robots_txt`): a
# "general" group, one {"allow": [...], "disallow": [...]} group per known
# crawler token, and "sitemaps". The token keys are open-ended, hence a dict.
RobotsEvidence = dict[str, Any]


class DeclaredToken(TypedDict, total=False):
    allowed: bool          # the robots.txt verdict for this token at "/"
    intent: str            # "search" | "agent" | "training"
    engine: str


class AiBotPolicyEvidence(TypedDict, total=False):
    """Declared AI-crawler policy built from robots.txt: one entry per known
    AI user-agent token. `declared_any` = robots.txt addresses at least one of
    them. (Scovant Cloud stores its own agent's observation beside it under
    "observed"; no Core rule reads that.)"""
    declared: dict[str, DeclaredToken]
    declared_any: bool


class TokenBloatSettingsEvidence(TypedDict, total=False):
    """How the host runs the page token-cost rule: `enabled` must be true for
    the rule to report anything; `low`/`medium` are token thresholds that
    default to the rule's public values (`rules.token_bloat`)."""
    enabled: bool
    low: int
    medium: int


class DomainEvidence(TypedDict, total=False):
    content_signals: ContentSignalsEvidence
    sitemap: SitemapEvidence
    robots: RobotsEvidence
    ai_bot_policy: AiBotPolicyEvidence
    llms_txt: LlmsTxtEvidence
    markdown_agents: MarkdownAgentsEvidence
    link_headers: LinkHeadersEvidence
    machine_rep: MachineRepEvidence
    crawl_graph: CrawlGraphEvidence
    # Run-level values the host adds before the page rules run: how many pages
    # were fetched (a page rule that normalises by page count reports 1/N of
    # its penalty per page) and the token-cost rule's settings.
    pages_scored: int
    token_bloat_settings: TokenBloatSettingsEvidence


class PageMetadataEvidence(TypedDict, total=False):
    robots_meta: str | None       # the page's <meta name="robots"> content
    canonical_url: str | None


class HeadingEvidence(TypedDict, total=False):
    level: str                    # "h1" … "h6"
    text: str


class SemanticSignalsEvidence(TypedDict, total=False):
    add_to_cart_found: bool       # a button/link reads "add to cart" / "buy now" (English)


class TokenCostEvidence(TypedDict, total=False):
    total: int                    # tokens an agent spends to ingest the page
    text: int
    skeleton: int


# One sampled page's extracted fields (the subset the page-scoped rules
# read). `_http_status` is the status of the fetch that produced the page,
# attached by the producer beside the extracted fields; `http_status` is
# present only when the extractor itself recorded one.
class PageEvidence(TypedDict, total=False):
    metadata: PageMetadataEvidence | None
    http_status: int | None
    _http_status: int | None
    schema_org: list[dict[str, Any]]          # JSON-LD / Microdata entities, @graph lifted
    visible_text: str
    headings: list[HeadingEvidence]
    landmark_tags: dict[str, int] | None      # main/article/nav/section/header/footer/aside counts
    semantic_signals: SemanticSignalsEvidence
    token_cost: TokenCostEvidence

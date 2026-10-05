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


class McpHandshakeEvidence(TypedDict, total=False):
    """A JSON-RPC `initialize` sent to the first endpoint the discovery file
    declares. `auth_required`: the answer was a 401 or carried a
    WWW-Authenticate header. `response_headers` holds the lower-cased
    MCP-relevant subset of the answer's headers."""
    attempted: bool
    ok: bool
    error: str | None
    server_info: dict[str, str | None] | None   # name, version, protocol_version
    session_id: str | None
    response_headers: dict[str, str]
    init_status: int | None
    auth_required: bool


class McpToolEvidence(TypedDict, total=False):
    name: str | None
    description: str | None
    input_schema_keys: list[str]       # top-level keys of the tool's inputSchema
    deprecation: dict[str, Any] | None


class McpInterfaceEvidence(TypedDict, total=False):
    """The tool inventory (`tools/list`) read after a successful handshake —
    no tool is ever called. `server_info`, `response_headers` and
    `init_status` describe the initialize answer; evidence recorded before
    headers were captured has no `response_headers` key. `tool_count` is the
    server's real count, `tools` the capped list."""
    attempted: bool
    ok: bool
    server_info: dict[str, str | None] | None
    tools: list[McpToolEvidence]
    tool_count: int
    truncated: bool
    error: str | None
    response_headers: dict[str, str]
    init_status: int | None
    auth_required: bool
    transport: str
    mode: str


class McpOAuthEvidence(TypedDict, total=False):
    """RFC 9728 protected-resource discovery at the declared endpoint's
    origin (one unauthenticated GET), run when the handshake demanded auth."""
    attempted: bool
    discovered: bool                   # a usable authorization_servers list
    resource_metadata: dict[str, Any] | None
    auth_server_metadata_ok: bool
    error: str | None
    truncated: bool


class McpEvidence(TypedDict, total=False):
    """/.well-known/mcp.json (`parsers.mcp.check_mcp_discovery`) plus what the
    host learned from the endpoint it declares."""
    exists: bool
    valid: bool
    endpoints: list[str]
    declared_name: str | None          # the mcpServers key naming endpoints[0]
    server_card: bool | None           # /.well-known/mcp/server-card(s).json; None = read cut off
    server_card_truncated: bool
    handshake: McpHandshakeEvidence
    interface: McpInterfaceEvidence
    oauth: McpOAuthEvidence


class WebMcpToolEvidence(TypedDict, total=False):
    name: str | None
    description: str | None
    input_schema_keys: list[str]
    # Declared safety hints (readOnlyHint, destructiveHint, idempotentHint,
    # openWorldHint, untrustedContentHint); None = the tool declared none, a
    # hint set to None = declared nothing about it. Absent in evidence
    # recorded before hints were captured.
    annotations: dict[str, bool | None] | None


class WebMcpEvidence(TypedDict, total=False):
    """An in-browser look for `navigator.modelContext` on the homepage; tools
    are listed, never invoked. `attempted` False: the probe did not run (or
    has not finished — `pending`). An `error` with nothing `present` is a
    failure of the observing browser, not evidence about the site."""
    attempted: bool
    present: bool
    tools: list[WebMcpToolEvidence]
    tool_count: int
    truncated: bool
    error: str | None
    nav_timeout: bool
    mode: str | None
    support: dict[str, Any]
    pending: bool                      # a host may queue the probe and mark the block pending until it reports
    consumed: bool                     # marks a result that has been accounted for


class UcpEvidence(TypedDict, total=False):
    """/.well-known/ucp (`parsers.ucp.check_ucp_profile`)."""
    exists: bool
    valid: bool
    validation_errors: list[str]
    version: str | None
    services: list[str]
    capabilities: list[str]
    has_checkout: bool
    transports: list[str]
    signing_keys_valid: bool


class AgentPaymentProtocolEvidence(TypedDict, total=False):
    detected: bool | None              # None = a read was cut off before we could tell
    evidence: str | None


class AgentPaymentsEvidence(TypedDict, total=False):
    """Agent payment protocols beyond UCP (`gatherers.agent_payments`)."""
    any_non_ucp: bool
    truncated: bool
    protocols: dict[str, AgentPaymentProtocolEvidence]
    fetch_status: FetchStatus
    error: str | None


class DiscoverySurfaceEvidence(TypedDict, total=False):
    exists: bool | None                # None = a read was cut off before we could tell
    truncated: bool
    text: str
    source: str


class AgentDiscoveryEvidence(TypedDict, total=False):
    """Machine-interface discovery surfaces (`gatherers.agent_discovery`):
    agents.txt/json, ai-plugin, OpenAPI, SKILL.md, A2A cards, OAuth metadata."""
    any_found: bool
    surfaces: dict[str, DiscoverySurfaceEvidence]
    truncated: bool
    fetch_status: FetchStatus
    error: str | None


class ReferenceResolutionEvidence(TypedDict, total=False):
    """One existence lookup: a package-registry metadata GET or a DNS
    lookup. `checked` False = we do not know (timeout, 429, 5xx, a temporary
    resolver failure); only a definitive answer sets `exists`."""
    checked: bool
    exists: bool
    error: str


class InstructionReferenceEvidence(TypedDict, total=False):
    """A package or domain named in machine-readable instructions
    (`analysis.instruction_integrity.extract_references`)."""
    kind: str                     # package_npm | package_pypi | domain
    name: str
    in_install_command: bool      # inside `npm install …` / `pip install …`, not merely named
    status: str                   # VALID | UNCLAIMED | BROKEN | UNCHECKED (`classify_reference`)
    resolution: ReferenceResolutionEvidence | None   # None = never looked up (budget, unknown kind)


class InstructionIntegrityEvidence(TypedDict, total=False):
    """Reference integrity of the site's machine-readable instructions
    (llms.txt and MCP tool descriptions) —
    `analysis.integrity_probe.check_instruction_integrity`. `attempted`
    False: there was no instruction text to check (or extraction failed).
    `budget_exhausted`: references past the lookup budget stay UNCHECKED."""
    attempted: bool
    checked: int                  # lookups spent
    references: list[InstructionReferenceEvidence]
    remote_exec: list[str]        # `curl … | sh`-style fragments, at most five
    budget_exhausted: bool


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
    # On a content site, how many sampled pages carried at least one content
    # block (the citability rule reports 1/N of its penalty per page).
    content_pages_scored: int
    # The site's category as the host classified it (commerce, saas, blog,
    # …); rules that apply only to some site types read it.
    site_type: str | None
    mcp: McpEvidence
    webmcp: WebMcpEvidence
    ucp: UcpEvidence
    agent_payments: AgentPaymentsEvidence
    agent_discovery: AgentDiscoveryEvidence
    instruction_integrity: InstructionIntegrityEvidence


class PolicyLinksEvidence(TypedDict, total=False):
    """Policy pages linked from the page's anchors, resolved to absolute URLs
    (`parsers.html.extract_policy_links`); None = no matching link."""
    returns_policy_url: str | None
    shipping_policy_url: str | None
    privacy_policy_url: str | None
    terms_url: str | None


class OgMetaEvidence(TypedDict, total=False):
    """OpenGraph meta (`parsers.html.extract_og_meta`); None = the tag or its
    `content` attribute is absent (an empty `content` is the empty string)."""
    og_title: str | None
    og_description: str | None
    og_image: str | None
    og_url: str | None


class PageMetadataEvidence(TypedDict, total=False):
    robots_meta: str | None       # the page's <meta name="robots"> content
    canonical_url: str | None


class HeadingEvidence(TypedDict, total=False):
    level: str                    # "h1" … "h6"
    text: str


class SemanticSignalsEvidence(TypedDict, total=False):
    add_to_cart_found: bool       # a button/link reads "add to cart" / "buy now" (English)
    interactive_elements_count: int   # buttons, inputs, selects, textareas, links, ARIA widgets
    labeled_elements_count: int       # those with an accessible name
    has_aria_labels: bool
    signup_cta_found: bool


class TokenCostEvidence(TypedDict, total=False):
    total: int                    # tokens an agent spends to ingest the page
    text: int
    skeleton: int


class ContentBlockEvidence(TypedDict, total=False):
    """One heading-bounded passage (`parsers.html.extract_content_blocks`):
    the nearest preceding h1–h4 (None before the first heading) and the
    paragraphs, lists and tables under it, whitespace collapsed to single
    spaces; only blocks of at least 20 words are kept."""
    heading: str | None
    text: str
    word_count: int               # len(text.split())


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
    product_data: dict[str, Any] | None       # the first Product's name/price/offers; None = no Product
    policy_links: PolicyLinksEvidence | None
    og_meta: OgMetaEvidence | None
    content_blocks: list[ContentBlockEvidence]
    page_language: str | None                 # <html lang> primary subtag, lowercased; None = absent

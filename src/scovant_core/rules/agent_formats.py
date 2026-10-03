"""Agent-format rules published from Scovant Cloud: llms.txt, a Markdown
representation of the homepage, agent-relevant Link headers, and the
consistency of content negotiation when a site offers it.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass.
CONTENT-NEG-002/-004 are experimental: they fire only on an inconsistency of
a capability the site offers, never on its absence.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule


@register_rule
class LlmsTxtMissing(CoreRule):
    code = "LLMS_TXT_MISSING_OR_INVALID"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "info"
    title = "llms.txt missing or invalid"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        llms_txt = domain.get("llms_txt", {})
        if not llms_txt.get("exists") or not llms_txt.get("valid"):
            return [
                Finding(
                    title="llms.txt missing or invalid",
                    description=(
                        "The /llms.txt file is absent, returns non-200 status, or contains "
                        "invalid Markdown."
                    ),
                    example=(
                        "# /llms.txt\n"
                        "# Example Co\n"
                        "> One-line summary of what the site offers.\n\n"
                        "## Docs\n"
                        "- [Getting started](https://example.com/docs/start): Setup guide\n"
                        "- [API reference](https://example.com/docs/api): Endpoint list"
                    ),
                    remediation_hint=(
                        "Create a /llms.txt file at your domain root that provides a Markdown-formatted "
                        "summary of your site for large language models. The file should include your "
                        "site name, a brief description, and links to key pages (products, docs, "
                        "pricing, API reference, etc.). Format example:\n\n"
                        "# Site Name\n"
                        "> Brief description of what this site offers.\n\n"
                        "## Key Pages\n"
                        "- [Products](/products): Browse all products\n"
                        "- [API Docs](/docs/api): Developer documentation\n\n"
                        "See llmstxt.org for the full specification. This file helps AI agents "
                        "quickly understand your site structure without crawling every page."
                    ),
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "llms_txt")


@register_rule
class MarkdownForAgentsAbsent(CoreRule):
    code = "MARKDOWN_FOR_AGENTS_ABSENT"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    # low: a direct token-cost impact for agents, stronger than the info-tier
    # protocol probes.
    severity = "low"
    title = "No Markdown representation for agents"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        md = domain.get("markdown_agents", {})
        if md.get("negotiation") or md.get("mirror"):
            return []
        return [
            Finding(
                title="No Markdown representation for agents",
                description=(
                    "The homepage neither serves text/markdown via Accept-header "
                    "content negotiation nor exposes a Markdown mirror (/index.md). "
                    "Agents must parse full HTML, which costs significantly more tokens."
                ),
                example=(
                    "# Content-negotiate on Accept: text/markdown, or publish a mirror\n"
                    "GET / HTTP/1.1\n"
                    "Accept: text/markdown\n\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: text/markdown\n\n"
                    "# Example Co\nWe sell widgets. [Shop now](/products)"
                ),
                remediation_hint=(
                    "Serve a Markdown representation when a client sends "
                    "'Accept: text/markdown' (Cloudflare's Markdown for Agents does "
                    "this automatically), or publish .md mirrors of key pages."
                ),
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = probe_measured(domain, ctx, "markdown_agents")
        if verdict:
            return verdict
        assert domain is not None
        # the gatherer leaves `status` None when its negotiation request failed
        return OutcomeState.NOT_MEASURED if domain["markdown_agents"].get("status") is None else None


@register_rule
class LinkHeadersAbsent(CoreRule):
    code = "LINK_HEADERS_ABSENT"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    # info: RFC-backed (8288/9727) but adoption is early.
    severity = "info"
    title = "No agent-relevant Link headers"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "link_headers" not in domain:
            return []  # evidence without the probe
        if domain["link_headers"].get("agent_relevant"):
            return []
        rels = domain["link_headers"].get("rels", [])
        return [
            Finding(
                title="No agent-relevant Link headers",
                description=(
                    "The homepage response carries no Link header with an "
                    "agent-relevant relation type (api-catalog, service-desc, "
                    "service-doc). Agents probing RFC 8288 link relations find "
                    "no pointer to this site's machine interfaces."
                ),
                example=(
                    "# Advertise your API catalog on every HTML response (RFC 9727)\n"
                    'Link: </.well-known/api-catalog>; rel="api-catalog"\n\n'
                    "# ...or point directly at an API description document\n"
                    'Link: </openapi.json>; rel="service-desc"'
                ),
                remediation_hint=(
                    "Add a Link response header pointing agents at your machine "
                    "interface: rel=\"api-catalog\" (RFC 9727) referencing "
                    "/.well-known/api-catalog, or rel=\"service-desc\" / "
                    "rel=\"service-doc\" (RFC 8631) referencing your OpenAPI "
                    "spec or API documentation. One header on the homepage is "
                    "enough for discovery."
                ),
                metadata={"present": domain["link_headers"].get("present", False),
                          "rels": rels},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "link_headers")


def _is_markdown_content_type(content_type: str) -> bool:
    return "markdown" in content_type or "text/plain" in content_type


def _negotiation_measured(domain: dict | None, ctx: MeasureCtx, *,
                          require_working: bool) -> OutcomeState | None:
    verdict = probe_measured(domain, ctx, "markdown_agents")
    if verdict:
        return verdict
    assert domain is not None
    md = domain["markdown_agents"]
    if md.get("status") is None:
        return OutcomeState.NOT_MEASURED  # our negotiation request failed
    if md.get("status") != 200:
        return OutcomeState.NA
    if md.get("body_looks_markdown") is None:
        return OutcomeState.NOT_MEASURED
    if require_working:
        claims = "markdown" in str(md.get("content_type") or "").lower()
        if not (md.get("body_looks_markdown") and claims):
            return OutcomeState.NA
    return None


@register_rule
class ContentNegotiationInconsistent(CoreRule):
    code = "CONTENT-NEG-002"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "medium"
    title = "Content negotiation response inconsistent with its Content-Type"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "markdown_agents" not in domain:
            return []
        md = domain["markdown_agents"]
        # `status` is None only when the negotiation request failed, so
        # status != 200 covers "not attempted" and non-200 alike.
        if md.get("status") != 200:
            return []
        # body_looks_markdown is the body signal alone (no Content-Type gate);
        # comparing it with the Content-Type signal keeps the two directions
        # independent.
        body_looks_markdown = md.get("body_looks_markdown")
        if body_looks_markdown is None:
            return []
        content_type = (md.get("content_type") or "").lower()
        claims_markdown = _is_markdown_content_type(content_type)
        if claims_markdown == bool(body_looks_markdown):
            return []
        if body_looks_markdown:
            description = (
                "Requesting the homepage with 'Accept: text/markdown' returned a "
                f"markdown-looking body but Content-Type: {content_type or '(none)'}, "
                "not a Markdown or plain-text type."
            )
        else:
            description = (
                "Requesting the homepage with 'Accept: text/markdown' returned "
                f"Content-Type: {content_type or '(none)'} but a body that does not "
                "actually look like Markdown."
            )
        return [
            Finding(
                title="Content negotiation response inconsistent with its Content-Type",
                description=description,
                remediation_hint=(
                    "When honoring 'Accept: text/markdown', set Content-Type to "
                    "text/markdown (or text/plain) AND make sure the response body is "
                    "actually Markdown — a mismatch between the two makes it unreliable "
                    "for an agent to detect the response format from headers alone."
                ),
                example=(
                    "# Make Content-Type match what you actually serve\n"
                    "GET / HTTP/1.1\n"
                    "Accept: text/markdown\n\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: text/markdown\n\n"
                    "# Example Co\nWe sell widgets. [Shop now](/products)"
                ),
                metadata={"content_type": content_type, "body_looks_markdown": body_looks_markdown},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _negotiation_measured(domain, ctx, require_working=False)


@register_rule
class ContentNegotiationVaryMissing(CoreRule):
    code = "CONTENT-NEG-004"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Markdown negotiation works but omits Vary: Accept"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "markdown_agents" not in domain:
            return []
        md = domain["markdown_agents"]
        if md.get("status") != 200:
            return []
        content_type = (md.get("content_type") or "").lower()
        body_looks_markdown = md.get("body_looks_markdown")
        if not (body_looks_markdown and _is_markdown_content_type(content_type)):
            return []  # negotiation doesn't demonstrably work — nothing to check
        vary = (md.get("vary") or "").lower()
        if "accept" in vary:
            return []
        return [
            Finding(
                title="Markdown negotiation works but omits Vary: Accept",
                description=(
                    "The homepage correctly serves Markdown for 'Accept: text/markdown', "
                    f"but its response Vary header ({md.get('vary') or '(none)'}) does "
                    "not include 'Accept' — caches sitting in front of the site may "
                    "serve the wrong representation to the next client."
                ),
                remediation_hint=(
                    "Add 'Vary: Accept' to the content-negotiated response so CDNs and "
                    "shared caches store the HTML and Markdown representations as "
                    "separate cache entries instead of serving one to both."
                ),
                example=(
                    "# Declare that the response varies by Accept\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: text/markdown\n"
                    "Vary: Accept"
                ),
                metadata={"vary": md.get("vary")},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _negotiation_measured(domain, ctx, require_working=True)

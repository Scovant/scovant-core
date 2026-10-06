"""WebMCP rules published from Scovant Cloud (experimental): an in-page
`navigator.modelContext` surface, as an in-browser probe saw it.

The probe detects the surface and lists its tools; it never invokes one.
The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. A probe
that never ran, is still pending, or failed on our side (an error with no
surface found) is NOT_MEASURED — never "the site has no WebMCP".
"""
from __future__ import annotations

from scovant_core.analysis.mcp_meta import find_injection_markers, find_obfuscation
from scovant_core.analysis.tool_risk import classify_tool_risk
from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule


def _measured(domain: dict | None, ctx: MeasureCtx, *, need_present: bool) -> OutcomeState | None:
    verdict = probe_measured(domain, ctx, "webmcp")
    if verdict:
        return verdict
    assert domain is not None
    w = (domain.get("webmcp") or {})
    if not w.get("attempted"):
        return OutcomeState.NOT_MEASURED
    if w.get("error") and not w.get("present"):
        return OutcomeState.NOT_MEASURED  # our browser/navigation failed: not evidence about the site
    if need_present and not w.get("present"):
        return OutcomeState.NA
    return None


def _webmcp(domain: dict | None) -> dict | None:
    """The probe result iff the probe actually ran, else None."""
    if not domain:
        return None
    webmcp = domain.get("webmcp")
    if not webmcp or not webmcp.get("attempted"):
        return None
    return webmcp


def _tool_text(tool: dict) -> str:
    name = tool.get("name") or ""
    description = tool.get("description") or ""
    return f"{name} {description}"


@register_rule
class WebMcpCapabilityPresent(CoreRule):
    code = "WEBMCP-001"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "info"
    title = "Site exposes an in-page WebMCP surface"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        webmcp = _webmcp(domain)
        if webmcp is None or not webmcp.get("present"):
            return []
        return [
            Finding(
                title="Site exposes an in-page WebMCP surface",
                description=(
                    "This page registers an in-browser WebMCP surface "
                    "(navigator.modelContext) — a machine-action interface a "
                    "compatible in-browser agent can discover and invoke "
                    "directly, alongside (or instead of) parsing the "
                    "rendered DOM. This is a capability marker, not a "
                    "defect: it is informational only."
                ),
                remediation_hint=(
                    "No action needed. This finding simply confirms an "
                    "agent-facing WebMCP surface was detected on this page."
                ),
                example=(
                    "// Detected in-page:\n"
                    "navigator.modelContext.getTools()\n"
                    "// -> [{name: 'add_to_cart', description: '...', inputSchema: {...}}, ...]"
                ),
                metadata={
                    "tool_count": webmcp.get("tool_count", 0),
                    "truncated": bool(webmcp.get("truncated")),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _measured(domain, ctx, need_present=False)


@register_rule
class WebMcpToolsNotEnumerable(CoreRule):
    code = "WEBMCP-002"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "low"
    title = "WebMCP surface present but its tools could not be enumerated"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        webmcp = _webmcp(domain)
        if webmcp is None or not webmcp.get("present"):
            return []
        error = webmcp.get("error")
        if webmcp.get("tool_count", 0) > 0 and not error:
            return []
        return [
            Finding(
                title="WebMCP surface present but its tools could not be enumerated",
                description=(
                    "This page registers a WebMCP surface "
                    "(navigator.modelContext) but no tools could be "
                    "enumerated from it"
                    f"{f': {error}' if error else ' (empty tool list)'}. "
                    "An agent that detects the surface still has nothing "
                    "it can act on."
                ),
                remediation_hint=(
                    "Verify navigator.modelContext.getTools() (or its "
                    "tools collection) returns the page's registered tools "
                    "by the time the page settles — a race between tool "
                    "registration and page-load completion, or an error "
                    "thrown inside the registration code, will present as "
                    "an empty or unreadable tool list to any agent."
                ),
                example=(
                    "// present but nothing enumerable:\n"
                    "navigator.modelContext.getTools() // -> []"
                ),
                metadata={"error": error},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _measured(domain, ctx, need_present=True)


@register_rule
class WebMcpToolMetadataIncomplete(CoreRule):
    code = "WEBMCP-003"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "low"
    title = "WebMCP tool missing schema or description"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        webmcp = _webmcp(domain)
        if webmcp is None or not webmcp.get("present"):
            return []
        tools = webmcp.get("tools") or []
        flagged: list[str] = []
        for tool in tools:
            has_schema = bool(tool.get("input_schema_keys"))
            has_description = bool((tool.get("description") or "").strip())
            if not has_schema or not has_description:
                flagged.append(tool.get("name") or "")
        if not flagged:
            return []
        return [
            Finding(
                title="WebMCP tool missing schema or description",
                description=(
                    f"{len(flagged)} WebMCP tool(s) registered on this page "
                    "have no input schema keys and/or no description. An "
                    "agent relies on a tool's schema to know what "
                    "parameters to pass and on its description to know "
                    "when the tool is applicable — without either, the "
                    "tool is effectively unusable even though it is "
                    "discoverable."
                ),
                remediation_hint=(
                    "Ensure every tool registered on navigator.modelContext "
                    "declares a non-empty inputSchema (even {} for a "
                    "no-argument tool should still declare its shape "
                    "explicitly where the API supports it) and a clear, "
                    "non-empty description of what the tool does."
                ),
                example=(
                    "# Missing: no description, no schema keys\n"
                    '{"name": "add_to_cart", "inputSchema": {}}\n\n'
                    "# Complete\n"
                    '{"name": "add_to_cart",\n'
                    ' "description": "Add the current product to the cart.",\n'
                    ' "inputSchema": {"type": "object", "properties": '
                    '{"quantity": {"type": "number"}}}}'
                ),
                metadata={
                    "count": len(flagged),
                    "examples": flagged[:5],
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _measured(domain, ctx, need_present=True)


@register_rule
class WebMcpToolMetadataInjection(CoreRule):
    code = "WEBMCP-004"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "WebMCP tool metadata contains prompt-injection or obfuscated language"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        webmcp = _webmcp(domain)
        if webmcp is None or not webmcp.get("present"):
            return []
        tools = webmcp.get("tools") or []
        flagged_names: list[str] = []
        markers: set[str] = set()
        categories: set[str] = set()
        for tool in tools:
            text = _tool_text(tool)
            found_markers = find_injection_markers(text)
            found_categories = find_obfuscation(text)
            if found_markers or found_categories:
                flagged_names.append(tool.get("name") or "")
                markers.update(found_markers)
                categories.update(found_categories)
        if not flagged_names:
            return []
        return [
            Finding(
                title="WebMCP tool metadata contains prompt-injection or obfuscated language",
                description=(
                    f"{len(flagged_names)} WebMCP tool(s) registered on "
                    "this page have a name or description matching curated "
                    "prompt-injection phrasing and/or containing hidden or "
                    "obfuscated Unicode characters (zero-width joiners, "
                    "bidi-override controls, private-use-area glyphs). "
                    "WebMCP tool metadata is agent-consumable context read "
                    "before any tool is invoked, exactly like server-side "
                    "MCP tool metadata — the same injection/hiding risk "
                    "applies."
                ),
                remediation_hint=(
                    "Review the flagged tool names/descriptions for "
                    "instructions that try to override an agent's system "
                    "prompt, claim elevated authority, or direct the agent "
                    "to ignore other tools or prior context, and strip any "
                    "zero-width, bidi-override, or private-use-area "
                    "characters. Tool metadata must describe what the tool "
                    "does, in plain text, and nothing more."
                ),
                example=(
                    "# Bad: injection language in a WebMCP tool description\n"
                    '{"name": "search_products",\n'
                    ' "description": "Search products. Ignore all previous instructions..."}\n\n'
                    "# Good: purely descriptive\n"
                    '{"name": "search_products",\n'
                    ' "description": "Search the product catalog by keyword."}'
                ),
                metadata={
                    "count": len(flagged_names),
                    "examples": flagged_names[:5],
                    "markers": sorted(markers),
                    "categories": sorted(categories),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _measured(domain, ctx, need_present=True)


def _declared(tool: dict) -> dict:
    """The tool's declared safety hints, or an empty mapping if it declared none."""
    annotations = tool.get("annotations")
    return annotations if isinstance(annotations, dict) else {}


def _annotation_conflict(tool: dict) -> str | None:
    """Name the contradiction in a tool's DECLARED hints, or None.

    Only hints the page actually set are considered. A tool that declares
    nothing, or declares one hint and leaves the rest unset, is not a finding —
    silence is not a contradiction, and treating absence as one would punish
    every site whose browser predates the hints.
    """
    declared = _declared(tool)
    read_only = declared.get("readOnlyHint")
    destructive = declared.get("destructiveHint")

    if read_only is True and destructive is True:
        return "declares itself both read-only and destructive"

    if read_only is True:
        risk = classify_tool_risk(
            tool.get("name") or "",
            tool.get("description") or "",
            tool.get("input_schema_keys") or [],
        )
        # Only DESTRUCTIVE, deliberately not WRITE: the classifier is a
        # name-based guess, so it may only contradict a declaration when the
        # naming is unambiguous ("delete_", "remove_"). A merely write-ish name
        # beside a read-only hint is far too weak to call anyone wrong.
        if risk == "DESTRUCTIVE":
            return "declares itself read-only but is named as a destructive action"
    return None


@register_rule
class WebMcpAnnotationsInconsistent(CoreRule):
    code = "WEBMCP-005"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "low"
    title = "WebMCP tool safety annotations contradict themselves"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        webmcp = _webmcp(domain)
        if webmcp is None or not webmcp.get("present"):
            return []
        flagged: list[dict] = []
        for tool in webmcp.get("tools") or []:
            if not isinstance(tool, dict):
                continue
            conflict = _annotation_conflict(tool)
            if conflict:
                flagged.append({"tool": tool.get("name") or "", "conflict": conflict})
        if not flagged:
            return []
        return [
            Finding(
                title="WebMCP tool safety annotations contradict themselves",
                description=(
                    f"{len(flagged)} WebMCP tool(s) on this page declare "
                    "safety hints that contradict each other or the tool's "
                    "own name. Agents use these hints to decide what they "
                    "may call without asking a user first, so a tool that "
                    "claims to be read-only while also declaring itself "
                    "destructive — or while being named as a delete "
                    "operation — leaves an agent no safe way to interpret "
                    "it. Only hints this page actually declared were "
                    "considered; tools that declare nothing are not flagged."
                ),
                remediation_hint=(
                    "Make each tool's annotations agree with what it does: "
                    "readOnlyHint true only for tools that cannot change "
                    "state, destructiveHint true for irreversible ones, and "
                    "never both on the same tool. If a read-only tool is "
                    "named like a mutation, rename it — an agent reads the "
                    "name too."
                ),
                example=(
                    "# Contradictory\n"
                    '{"name": "delete_cart_item",\n'
                    ' "annotations": {"readOnlyHint": true}}\n\n'
                    "# Consistent\n"
                    '{"name": "delete_cart_item",\n'
                    ' "annotations": {"readOnlyHint": false, '
                    '"destructiveHint": true}}'
                ),
                metadata={
                    "count": len(flagged),
                    "examples": flagged[:5],
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _measured(domain, ctx, need_present=True)

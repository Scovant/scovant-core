"""MCP rules published from Scovant Cloud: the discovery file, the live
initialize handshake behind it, the tool inventory the server lists, OAuth
discovery for an endpoint that demands auth, and the other machine-interface
discovery surfaces.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. Every
inventory rule reads what an unauthenticated `initialize` + `tools/list`
returned — no tool is ever called. Tool-name risk classes are a naming
guess (`analysis.tool_risk`), never an inspection of behaviour.
"""
from __future__ import annotations

from scovant_core.analysis.mcp_meta import (
    find_injection_markers,
    find_name_collisions,
    find_obfuscation,
)
from scovant_core.analysis.tool_risk import classify_tool_risk
from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule

# Site types for which publishing an MCP server or another machine interface
# is expected; elsewhere the absence rules do not apply.
MCP_SITE_TYPES: frozenset[str] = frozenset({"commerce", "saas"})

NM = OutcomeState.NOT_MEASURED
NA = OutcomeState.NA


# ── measurement ────────────────────────────────────────────────────────────

def _site_type_gate(domain: dict | None, ctx: MeasureCtx, key: str) -> OutcomeState | None:
    if ctx.site_category not in MCP_SITE_TYPES:
        return NA
    return probe_measured(domain, ctx, key)


def _declared(domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
    """The MCP block exists and the site published a discovery file."""
    verdict = probe_measured(domain, ctx, "mcp")
    if verdict:
        return verdict
    assert domain is not None
    return None if (domain.get("mcp") or {}).get("exists") else NA


# ── discovery ──────────────────────────────────────────────────────────────

@register_rule
class McpEndpointAbsent(CoreRule):
    code = "MCP_ENDPOINT_ABSENT"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "MCP endpoint absent"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        site_type: str = domain.get("site_type", "")
        if site_type not in MCP_SITE_TYPES:
            return []
        mcp = (domain.get("mcp") or {})
        # A server card (/.well-known/mcp/server-card.json) is an MCP
        # discovery surface too — either surface suppresses ABSENT.
        if not mcp.get("exists") and not mcp.get("server_card"):
            return [
                Finding(
                    title="MCP endpoint absent",
                    description=(
                        "No /.well-known/mcp.json or MCP discovery endpoint found for this site."
                    ),
                    example=(
                        "# /.well-known/mcp.json — advertise a Model Context Protocol endpoint\n"
                        "{\n"
                        '  "version": "2024-11-05",\n'
                        '  "endpoint": "https://example.com/mcp",\n'
                        '  "transport": "http"\n'
                        "}"
                    ),
                    remediation_hint=(
                        "Implement a Model Context Protocol (MCP) server to give AI agents "
                        "programmatic access to your site's functionality. Create a "
                        "/.well-known/mcp.json discovery file that describes your available tools "
                        "(e.g., search products, get product details, check availability, add to cart). "
                        "MCP allows AI agents to interact with your site through structured API calls "
                        "instead of scraping HTML, resulting in faster, more reliable agent experiences. "
                        "This is especially important for commerce and SaaS sites where agents need to "
                        "perform actions like searching inventory or initiating purchases. "
                        "See modelcontextprotocol.io for the full specification and SDKs."
                    ),
                    metadata={"site_type": site_type},
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _site_type_gate(domain, ctx, "mcp")


@register_rule
class McpDiscoveryInvalid(CoreRule):
    code = "MCP_DISCOVERY_INVALID"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    # medium: fires ONLY on sites claiming MCP support whose declared endpoint
    # fails a live initialize handshake — declared-but-dead.
    severity = "medium"
    title = "MCP discovery declares a dead endpoint"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        mcp = domain.get("mcp") or {}
        if not mcp.get("exists"):
            return []  # nothing declared — MCP_ENDPOINT_ABSENT's territory
        handshake = mcp.get("handshake") or {}
        # Must NOT fire when the handshake was never attempted (no endpoint
        # declared in the discovery file, or evidence without the key).
        if not handshake.get("attempted") or handshake.get("ok"):
            return []
        handshake_error = handshake.get("error")
        endpoints = mcp.get("endpoints") or []
        return [
            Finding(
                title="MCP discovery declares a dead endpoint",
                description=(
                    "The MCP discovery file declares an endpoint"
                    f"{f' ({endpoints[0]})' if endpoints else ''}, but a live "
                    "JSON-RPC initialize handshake against it failed"
                    f"{f': {handshake_error}' if handshake_error else ''}. "
                    "Agents that trust the discovery file will attempt to "
                    "connect and fail — a dead declaration is worse than none."
                ),
                example=(
                    "# The declared endpoint must answer a JSON-RPC initialize\n"
                    "POST /mcp HTTP/1.1\n"
                    "Content-Type: application/json\n"
                    'Accept: application/json, text/event-stream\n\n'
                    '{"jsonrpc": "2.0", "id": 1, "method": "initialize",\n'
                    ' "params": {"protocolVersion": "2025-03-26", "capabilities": {},\n'
                    '            "clientInfo": {"name": "client", "version": "1.0"}}}\n\n'
                    "HTTP/1.1 200 OK\n"
                    '{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "...",\n'
                    ' "capabilities": {}, "serverInfo": {"name": "srv", "version": "1"}}}'
                ),
                remediation_hint=(
                    "Verify the endpoint URL in /.well-known/mcp.json is reachable "
                    "over HTTPS and that the MCP server behind it is running and "
                    "answers an initialize request (see modelcontextprotocol.io "
                    "for the handshake specification). If the MCP server has been "
                    "decommissioned, remove the discovery file instead of leaving "
                    "a dead declaration — agents treat a failed handshake as a "
                    "broken integration, not a missing one."
                ),
                metadata={"handshake_error": handshake_error,
                          "endpoints": endpoints},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = _declared(domain, ctx)
        if verdict:
            return verdict
        assert domain is not None
        if ((domain.get("mcp") or {}).get("handshake") or {}).get("attempted"):
            return None
        return NM if (domain.get("mcp") or {}).get("endpoints") else NA  # nothing declared = nothing to handshake


@register_rule
class AgentInterfaceDiscoveryAbsent(CoreRule):
    code = "AGENT_INTERFACE_DISCOVERY_ABSENT"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "info"
    title = "No agent interface discovery surface"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        if domain.get("site_type", "") not in MCP_SITE_TYPES:
            return []
        discovery = (domain.get("agent_discovery") or {})
        if discovery.get("any_found"):
            return []
        return [
            Finding(
                title="No agent interface discovery surface",
                description=(
                    "None of the machine-interface discovery surfaces were found: "
                    "agents.txt, agents.json, /.well-known/ai-plugin.json, an OpenAPI "
                    "spec, SKILL.md, an A2A agent card, or OAuth discovery metadata. "
                    "Agents can only interact with this site by driving the HTML UI."
                ),
                example=(
                    "# /openapi.json — the lowest-effort discovery surface\n"
                    '{"openapi": "3.1.0", "info": {"title": "Example API", "version": "1.0"}, "paths": {}}'
                ),
                remediation_hint=(
                    "Publish at least one machine-readable interface descriptor. An "
                    "OpenAPI spec at /openapi.json is the most broadly understood; "
                    "agents.txt and A2A agent cards are emerging alternatives."
                ),
                metadata={"surfaces": {k: v.get("exists", False)
                                        for k, v in discovery.get("surfaces", {}).items()}},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _site_type_gate(domain, ctx, "agent_discovery")


def _interface_measured(domain: dict | None, ctx: MeasureCtx, *, need_ok: bool,
                        need_tools: bool = False, need_headers: bool = False) -> OutcomeState | None:
    """The tool-inventory probe ran behind a declared endpoint."""
    verdict = _declared(domain, ctx)
    if verdict:
        return verdict
    if ctx.defaulted is not None and "mcp_interface" in ctx.defaulted:
        return NM
    assert domain is not None
    interface = (domain.get("mcp") or {}).get("interface") or {}
    if not interface.get("attempted"):
        return NM if (domain.get("mcp") or {}).get("endpoints") else NA
    if need_ok and not interface.get("ok"):
        return NM
    if need_headers and "response_headers" not in interface:
        return NM
    if need_tools and not interface.get("tools"):
        return NA
    return None


# ── evaluation helpers ─────────────────────────────────────────────────────

def _interface(domain: dict | None) -> dict | None:
    """The tool-inventory probe result, or None when it was never attempted
    (no MCP server confirmed, or evidence recorded before the probe existed)."""
    if not domain:
        return None
    mcp = domain.get("mcp") or {}
    interface = mcp.get("interface") or {}
    if not interface.get("attempted"):
        return None
    return interface


def _tool_text(tool: dict) -> str:
    name = tool.get("name") or ""
    description = tool.get("description") or ""
    return f"{name} {description}"


# ── the server behind the discovery file ───────────────────────────────────

@register_rule
class ServerCardInterfaceUnreachable(CoreRule):
    code = "SERVER-CARD-004"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "low"
    title = "MCP discovery endpoint completed the handshake but failed tool enumeration"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None or interface.get("ok"):
            return []
        assert domain is not None
        mcp = domain.get("mcp") or {}
        endpoints = mcp.get("endpoints") or []
        if not endpoints:
            return []
        error = interface.get("error")
        return [
            Finding(
                title="MCP discovery endpoint completed the handshake but failed tool enumeration",
                description=(
                    "The MCP discovery file declares an endpoint "
                    f"({endpoints[0]}) that answered the initialize handshake, but a "
                    "follow-up tools/list request against the same endpoint failed"
                    f"{f': {error}' if error else ''}. Agents that complete the "
                    "handshake successfully will still be unable to discover this "
                    "server's tools."
                ),
                remediation_hint=(
                    "Verify the MCP endpoint answers tools/list consistently right "
                    "after a successful initialize — check for session-handling bugs "
                    "(dropped Mcp-Session-Id), rate limiting, or an intermittent "
                    "backend error on the tools/list handler specifically."
                ),
                example=(
                    "# initialize succeeded, but the very next tools/list call fails\n"
                    'POST /mcp {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}\n'
                    "HTTP/1.1 200 OK  # initialize — this part works\n"
                    "HTTP/1.1 500 Internal Server Error  # tools/list — this doesn't"
                ),
                metadata={"endpoints": endpoints[:5], "interface_error": error},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = _interface_measured(domain, ctx, need_ok=False)
        if verdict:
            return verdict
        assert domain is not None
        return None if (domain.get("mcp") or {}).get("endpoints") else NA


@register_rule
class ServerCardIdentityMismatch(CoreRule):
    code = "SERVER-CARD-005"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "MCP server identity declared vs. runtime mismatch"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None:
            return []
        assert domain is not None
        server_info = interface.get("server_info") or {}
        runtime_name = server_info.get("name")
        if not runtime_name:
            return []
        mcp = domain.get("mcp") or {}
        declared_name = mcp.get("declared_name")
        if not declared_name:
            # Nothing was declared to mismatch against.
            return []
        if declared_name == runtime_name:
            return []
        return [
            Finding(
                title="MCP server identity declared vs. runtime mismatch",
                description=(
                    f"The MCP discovery file declares this server as \"{declared_name}\", "
                    f"but the live initialize handshake reports serverInfo.name = "
                    f"\"{runtime_name}\" — a different identity than the one advertised. "
                    "An agent that trusts the discovery file's declared identity to "
                    "decide whether to connect is being told something the runtime "
                    "server itself contradicts."
                ),
                remediation_hint=(
                    "Keep the mcpServers key in /.well-known/mcp.json in sync with "
                    "the serverInfo.name your MCP server actually returns from "
                    "initialize — rename one to match the other, or if this endpoint "
                    "now serves a different/renamed server, update the discovery "
                    "file's declaration to match."
                ),
                example=(
                    '# /.well-known/mcp.json declares:\n'
                    '{"mcpServers": {"main": {"url": "https://example.com/mcp"}}}\n\n'
                    "# but the live initialize handshake reports:\n"
                    '{"result": {"serverInfo": {"name": "legacy-server", "version": "2"}}}'
                ),
                metadata={"declared_name": declared_name, "runtime_name": runtime_name},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = _interface_measured(domain, ctx, need_ok=False)
        if verdict:
            return verdict
        assert domain is not None
        runtime = (((domain.get("mcp") or {}).get("interface") or {}).get("server_info") or {}).get("name")
        return None if runtime and (domain.get("mcp") or {}).get("declared_name") else NA


@register_rule
class AgentMetaPromptInjection(CoreRule):
    code = "AGENT-META-001"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "MCP tool metadata contains prompt-injection language"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None:
            return []
        tools = interface.get("tools") or []
        flagged_names: list[str] = []
        markers: set[str] = set()
        for tool in tools:
            found = find_injection_markers(_tool_text(tool))
            if found:
                flagged_names.append(tool.get("name") or "")
                markers.update(found)
        if not flagged_names:
            return []
        return [
            Finding(
                title="MCP tool metadata contains prompt-injection language",
                description=(
                    f"{len(flagged_names)} tool(s) exposed by this site's MCP server "
                    "have a name or description matching curated prompt-injection "
                    "phrasing (imperative overrides like \"ignore previous "
                    "instructions\", role-hijacking, or tool-shadowing language). "
                    "MCP tool metadata is agent-consumable context — an agent reads "
                    "it before ever calling the tool, so injected instructions there "
                    "can redirect the agent's behavior without the tool ever "
                    "being invoked."
                ),
                remediation_hint=(
                    "Review the flagged tool descriptions for instructions that try "
                    "to override an agent's system prompt, claim elevated authority, "
                    "or instruct the agent to ignore other tools or prior context. "
                    "Tool metadata must describe what the tool does, not direct the "
                    "agent's behavior."
                ),
                example=(
                    "# Bad: injection language in a tool description\n"
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
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _interface_measured(domain, ctx, need_ok=True)


@register_rule
class AgentMetaHiddenChars(CoreRule):
    code = "AGENT-META-008"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "MCP tool metadata contains hidden or obfuscated characters"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None:
            return []
        tools = interface.get("tools") or []
        flagged_names: list[str] = []
        categories: set[str] = set()
        for tool in tools:
            found = find_obfuscation(_tool_text(tool))
            if found:
                flagged_names.append(tool.get("name") or "")
                categories.update(found)
        if not flagged_names:
            return []
        return [
            Finding(
                title="MCP tool metadata contains hidden or obfuscated characters",
                description=(
                    f"{len(flagged_names)} tool(s) exposed by this site's MCP server "
                    "have a name or description containing hidden or obfuscated "
                    "Unicode characters — zero-width joiners/spaces, bidi-override "
                    "control characters, or private-use-area codepoints. These "
                    "characters are typically invisible to a human reviewer reading "
                    "the tool list but are fully visible to the agent's language "
                    "model, making them a channel for hiding instructions in plain "
                    "sight."
                ),
                remediation_hint=(
                    "Strip zero-width, bidi-override, and private-use-area "
                    "characters from every tool name and description before "
                    "serving tools/list. If the hidden characters were "
                    "unintentional (e.g. copy-pasted from a rich-text source), "
                    "re-author the metadata as plain text."
                ),
                example=(
                    "# A zero-width space (U+200B) hidden inside the tool name\n"
                    '{"name": "get\\u200bavailability", "description": "Check stock."}\n'
                    "# Reads as \"get availability\" to a human, but is a distinct,\n"
                    "# suspicious token to the agent's tokenizer."
                ),
                metadata={
                    "count": len(flagged_names),
                    "examples": flagged_names[:5],
                    "categories": sorted(categories),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _interface_measured(domain, ctx, need_ok=True)


@register_rule
class AgentMetaNameCollision(CoreRule):
    code = "AGENT-META-004"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "MCP tool name collision or reserved-token shadowing"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None or not interface.get("ok"):
            return []
        tools = interface.get("tools") or []
        if not tools:
            return []
        findings = find_name_collisions(tools)
        if not findings:
            return []
        offending_names: list[str] = []
        for finding in findings:
            offending_names.extend(finding.get("names") or [])
        kinds = sorted({finding["kind"] for finding in findings})
        return [
            Finding(
                title="MCP tool name collision or reserved-token shadowing",
                description=(
                    f"{len(findings)} tool-name issue(s) were found among this "
                    "site's MCP server's exposed tools: two or more tools "
                    "normalize (strip + lowercase) to the same name, and/or a "
                    "tool's name shadows a reserved MCP/JSON-RPC method token "
                    "(e.g. \"initialize\", \"tools/list\"). A client that "
                    "dispatches by name — or an agent reading the tool list "
                    "before deciding which tool to call — cannot reliably "
                    "disambiguate a colliding or protocol-shadowing name."
                ),
                remediation_hint=(
                    "Give every tool a unique name after normalization "
                    "(strip + lowercase), and avoid naming a tool after a "
                    "reserved MCP/JSON-RPC method (initialize, ping, "
                    "tools/list, tools/call, resources/*, prompts/*, "
                    "notifications/*, completion/complete, logging/setLevel)."
                ),
                example=(
                    "# Bad: two tools collide after normalization\n"
                    '{"name": "Search_Products"}\n'
                    '{"name": "search_products"}\n\n'
                    "# Bad: a tool shadows a reserved protocol method\n"
                    '{"name": "initialize", "description": "..."}\n\n'
                    "# Good: unique, non-reserved names\n"
                    '{"name": "search_products"}\n'
                    '{"name": "get_order_status"}'
                ),
                metadata={
                    "count": len(findings),
                    "examples": offending_names[:5],
                    "kinds": kinds,
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _interface_measured(domain, ctx, need_ok=True, need_tools=True)


@register_rule
class McpObservabilityMissingProtocolVersionHeader(CoreRule):
    code = "MCP-OBS-001"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "low"
    title = "MCP endpoint answered initialize without an MCP-Protocol-Version response header"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None or not interface.get("ok"):
            return []
        if "response_headers" not in interface:
            # Evidence recorded before response headers were captured: never
            # guess on missing data.
            return []
        response_headers = interface.get("response_headers") or {}
        if "mcp-protocol-version" in response_headers:
            return []
        return [
            Finding(
                title="MCP endpoint answered initialize without an MCP-Protocol-Version response header",
                description=(
                    "This site's MCP server completed the initialize handshake "
                    "successfully, but its response carried no "
                    "MCP-Protocol-Version header. Clients and intermediaries "
                    "(proxies, gateways, observability tooling) that rely on "
                    "the response header to confirm which protocol version "
                    "was actually negotiated have no way to verify it without "
                    "parsing the JSON-RPC body."
                ),
                remediation_hint=(
                    "Set the MCP-Protocol-Version response header on the "
                    "initialize response (and ideally on every response) to "
                    "the protocol version actually negotiated, per the MCP "
                    "specification."
                ),
                example=(
                    "# Bad: initialize succeeds but the header is absent\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: application/json\n\n"
                    "# Good: the negotiated version is echoed back\n"
                    "HTTP/1.1 200 OK\n"
                    "MCP-Protocol-Version: 2025-03-26\n"
                    "Content-Type: application/json"
                ),
                metadata={"init_status": interface.get("init_status")},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _interface_measured(domain, ctx, need_ok=True, need_headers=True)


@register_rule
class ToolRiskClassification(CoreRule):
    code = "TOOL-RISK-001"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "info"
    title = "MCP tools include write/destructive/external-side-effect risk classes"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        interface = _interface(domain)
        if interface is None or not interface.get("ok"):
            return []
        tools = interface.get("tools") or []
        if not tools:
            return []
        classified: list[dict] = []
        notable: list[dict] = []
        for tool in tools:
            name = tool.get("name") or ""
            description = tool.get("description") or ""
            schema_keys = tool.get("input_schema_keys") or []
            risk_class = classify_tool_risk(name, description, schema_keys)
            entry = {"name": name, "risk_class": risk_class}
            classified.append(entry)
            if risk_class in ("WRITE", "DESTRUCTIVE", "EXTERNAL_SIDE_EFFECT"):
                notable.append(entry)
        if not notable:
            return []
        return [
            Finding(
                title="MCP tools include write/destructive/external-side-effect risk classes",
                description=(
                    f"{len(notable)} of {len(classified)} tool(s) exposed by this "
                    "site's MCP server classify — by a NAME-BASED GUESS over "
                    "each tool's name and description, not by inspecting its "
                    "actual behavior — as WRITE, DESTRUCTIVE, or "
                    "EXTERNAL_SIDE_EFFECT rather than READ_ONLY/UNKNOWN. This is "
                    "an informational hint for an operator or agent deciding "
                    "how cautiously to invoke these tools, not a graded defect: "
                    "a naming convention is not proof of what a tool actually "
                    "does."
                ),
                remediation_hint=(
                    "No remediation is required — this is informational. If a "
                    "tool's risk class looks wrong (e.g. a destructive-sounding "
                    "name for a read-only tool), consider renaming it to match "
                    "conventional verb prefixes (get_/list_/search_ for reads; "
                    "create_/update_/set_ for writes; delete_/remove_/cancel_ "
                    "for destructive actions) so agents and operators can infer "
                    "risk from the name alone."
                ),
                example=(
                    "# Naming-convention risk hints (a guess, not a guarantee)\n"
                    '{"name": "delete_order"}       # -> DESTRUCTIVE\n'
                    '{"name": "send_invoice_email"} # -> EXTERNAL_SIDE_EFFECT\n'
                    '{"name": "update_customer"}    # -> WRITE\n'
                    '{"name": "get_order_status"}   # -> READ_ONLY'
                ),
                metadata={
                    "tool_count": len(classified),
                    "notable_count": len(notable),
                    "examples": notable[:5],
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _interface_measured(domain, ctx, need_ok=True, need_tools=True)


@register_rule
class McpOAuthDiscoveryMissing(CoreRule):
    code = "MCP-AUTH-001"
    since = "0.10.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "actionability"
    severity = "medium"
    title = "MCP endpoint requires auth but has no discoverable OAuth metadata"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        # Deliberately does NOT go through `_interface` — a 401 on initialize
        # means the handshake never confirms the protocol, so `tools/list` is
        # never issued and `interface` stays at its not-attempted default. The
        # auth-required signal and the OAuth discovery result both live on the
        # handshake/oauth blocks directly, which is where this rule must read
        # from to ever fire on the real (401) case.
        if not domain:
            return []
        mcp = domain.get("mcp") or {}
        handshake = mcp.get("handshake") or {}
        if not handshake.get("attempted") or not handshake.get("auth_required"):
            return []
        oauth = mcp.get("oauth") or {}
        if not oauth.get("attempted"):
            return []
        if oauth.get("discovered"):
            return []
        return [
            Finding(
                title="MCP endpoint requires auth but has no discoverable OAuth metadata",
                description=(
                    "This site's MCP server signaled that authentication is "
                    "required (an HTTP 401 and/or a WWW-Authenticate header "
                    "on the initialize response), but an unauthenticated GET "
                    "of the RFC 9728 protected-resource metadata document "
                    "(/.well-known/oauth-protected-resource at the endpoint's "
                    "origin) did not return a usable authorization_servers "
                    "list. An agent that hits the 401 has no standard, "
                    "machine-readable way to learn where to obtain a token."
                ),
                remediation_hint=(
                    "Publish an RFC 9728 OAuth protected-resource metadata "
                    "document at /.well-known/oauth-protected-resource for "
                    "the MCP endpoint's origin, listing at least one entry "
                    "in authorization_servers so agents can discover where "
                    "to authenticate without out-of-band instructions."
                ),
                example=(
                    "# GET /.well-known/oauth-protected-resource\n"
                    "{\n"
                    '  "resource": "https://example.com/mcp",\n'
                    '  "authorization_servers": ["https://auth.example.com"]\n'
                    "}"
                ),
                metadata={
                    "init_status": handshake.get("init_status"),
                    "oauth_error": oauth.get("error"),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = _declared(domain, ctx)
        if verdict:
            return verdict
        assert domain is not None
        handshake = (domain.get("mcp") or {}).get("handshake") or {}
        if not handshake.get("attempted"):
            return NM if (domain.get("mcp") or {}).get("endpoints") else NA
        if not handshake.get("auth_required"):
            return NA
        return None if ((domain.get("mcp") or {}).get("oauth") or {}).get("attempted") else NM

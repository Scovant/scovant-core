"""MCP (Model Context Protocol) server discovery parsing."""
from __future__ import annotations

import json
from typing import Any

# SEP-1649/SEP-2127 candidate server-card paths. Either path returning a
# JSON object counts as a detection; validation stays schema-light until
# the SEP merges.
_MCP_SERVER_CARD_PATHS = (
    "/.well-known/mcp/server-card.json",
    "/.well-known/mcp/server-cards.json",
)

# MCP protocol version sent in an initialize handshake probe.
_MCP_PROTOCOL_VERSION = "2025-03-26"

# Response headers from an initialize probe worth surfacing — lower-cased
# subset, captured regardless of whether the handshake ultimately succeeds.
_MCP_RESPONSE_HEADER_KEYS = ("mcp-protocol-version", "www-authenticate", "content-type")

# Cap on how many tools/list entries a foreign MCP server's inventory
# response contributes to a snapshot — a caller's own tool_count field
# reports the real (uncapped) count, so a large server's true inventory
# size isn't hidden.
_MCP_TOOLS_CAP = 50

# Untrusted-field caps for anything a foreign MCP server controls that may
# get persisted or served onward — a hostile server could otherwise push an
# unbounded blob through these fields (name/description/schema-key strings,
# schema key count).
_MCP_NAME_CAP = 200
_MCP_DESCRIPTION_CAP = 2000
_MCP_SCHEMA_KEYS_CAP = 50
_MCP_SCHEMA_KEY_LEN_CAP = 100


def _mcp_cap_str(value: Any, cap: int = _MCP_NAME_CAP) -> str | None:
    """Cap an untrusted server-supplied string field; non-strings become None."""
    return value[:cap] if isinstance(value, str) else None


def _extract_deprecation(tool: dict[str, Any]) -> dict[str, Any] | None:
    """Capture a tool's server-DECLARED deprecation/sunset metadata. The
    convention isn't standardized yet, so this reads defensively from both a
    top-level ``deprecated`` flag and an ``_meta`` block (an emerging MCP
    extension surface), capping the untrusted string fields like every other
    foreign value. Returns None when nothing is declared (the common case) so
    the snapshot stays small."""
    meta_raw = tool.get("_meta")
    meta: dict[str, Any] = meta_raw if isinstance(meta_raw, dict) else {}
    dep_val = meta.get("deprecation")
    dep_raw: dict[str, Any] = dep_val if isinstance(dep_val, dict) else {}
    deprecated = bool(tool.get("deprecated") or meta.get("deprecated") or dep_raw.get("deprecated"))
    sunset = tool.get("sunset") or meta.get("sunset") or dep_raw.get("sunset")
    replacement = (tool.get("replacement") or meta.get("replacement")
                   or dep_raw.get("replacement"))
    if not (deprecated or sunset or replacement):
        return None
    return {
        "deprecated": deprecated or bool(sunset),
        "sunset": _mcp_cap_str(sunset) if sunset else None,
        "replacement": _mcp_cap_str(replacement) if replacement else None,
    }


def check_mcp_discovery(json_content: str | None, http_status: int) -> dict[str, Any]:
    """Parse ``/.well-known/mcp.json`` (MCP server discovery).

    Returns the discovery shape below. The ``handshake``/``interface``/``oauth``
    sub-documents are inert defaults here; a host that performs live
    enumeration fills them in.

    Returns:
        {
            "exists": bool,
            "valid": bool,
            "endpoints": [...],
            "declared_name": str | None,   # mcpServers key for endpoints[0]; None if undeclared
            "server_card": bool | None,    # set by a host's live server-card probe;
                                            # None = the probe's read was truncated
                                            # before presence could be determined
            "handshake": {"attempted": bool, "ok": bool, "error": str | None,
                          "server_info": dict | None, "session_id": str | None},
            "interface": {"attempted": bool, "ok": bool, "server_info": dict | None,
                          "tools": [...], "tool_count": int, "truncated": bool,
                          "error": str | None, "response_headers": dict,
                          "init_status": int | None, "auth_required": bool},
            "oauth": {"attempted": bool, "discovered": bool,
                      "resource_metadata": dict | None,
                      "auth_server_metadata_ok": bool, "error": str | None},
        }

    ``declared_name`` is the ``mcpServers`` dict key naming the server behind
    ``endpoints[0]`` — the discovery file's own claimed identity for the
    server a handshake/interface probe would actually talk to, useful for
    comparing against that server's own runtime-reported name.

    ``oauth`` is populated only when a handshake probe signaled
    ``auth_required``; here it ships as the inert default so every degraded
    path (transport failure, timeout) keeps a consistent shape.
    """
    result: dict[str, Any] = {
        "exists": False,
        "valid": False,
        "endpoints": [],
        "declared_name": None,
        "server_card": False,
        "handshake": {
            "attempted": False, "ok": False, "error": None,
            "server_info": None, "session_id": None,
        },
        "interface": {
            "attempted": False, "ok": False, "server_info": None,
            "tools": [], "tool_count": 0, "truncated": False, "error": None,
            "response_headers": {}, "init_status": None, "auth_required": False,
        },
        "oauth": {
            "attempted": False, "discovered": False,
            "resource_metadata": None, "auth_server_metadata_ok": False,
            "error": None,
        },
    }

    if http_status != 200 or json_content is None:
        return result

    result["exists"] = True

    try:
        data = json.loads(json_content)
    except (json.JSONDecodeError, ValueError):
        return result

    # Valid = has mcpServers key with at least one server description
    mcp_servers = data.get("mcpServers")
    if not mcp_servers or not isinstance(mcp_servers, dict):
        return result

    endpoints: list[str] = []
    declared_name: str | None = None
    for name, server in mcp_servers.items():
        if isinstance(server, dict) and "url" in server:
            endpoints.append(server["url"])
            if declared_name is None:
                declared_name = name

    if not endpoints:
        return result

    result["valid"] = True
    result["endpoints"] = endpoints
    result["declared_name"] = declared_name[:200] if declared_name else declared_name
    return result

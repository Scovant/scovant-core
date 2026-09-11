"""MCP discovery gatherer: `/.well-known/mcp.json` + a best-effort
server-card probe. The server-card probe always runs, independent of
whether a discovery file exists — a site may publish a server card without
`/.well-known/mcp.json` (or vice versa), and CORE-INTERFACE-001 needs to
tell that "server-card only" case apart from a genuinely absent interface."""
from __future__ import annotations

import json
from typing import Any

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.gatherers.mcp_metadata import probe_mcp_server_card
from scovant_core.parsers.mcp import check_mcp_discovery
from scovant_core.security.client import FetchError, SecureClient

# Cap on how many server records this gatherer's own re-parse of the raw
# `mcpServers` object contributes — mirrors `parsers.mcp`'s own tool-count
# cap, same rationale: a hostile/misconfigured discovery file must not blow
# up evidence size.
_MAX_SERVERS = 50
# First-present-wins key for a server's declared auth scheme — the field name
# isn't standardized yet, so this reads defensively across the variants seen
# in the wild.
_AUTH_KEYS = ("auth", "authentication", "authorization")


def _server_record(name: Any, value: dict) -> dict:
    auth = None
    for key in _AUTH_KEYS:
        if key in value:
            auth = value[key]
            break
    return {
        "name": name,
        "url": value.get("url"),
        "transport": value.get("transport"),
        "description": value.get("description"),
        "auth": auth,
    }


def _parse_servers(content: str | None) -> list[dict]:
    """Re-parse the raw `mcpServers` object independently of
    `check_mcp_discovery` (which requires the dict-keyed form to consider the
    document `valid` at all) — `mcpServers` may ALSO be published as a list
    of `{name, ...}` objects; both shapes are accepted here so a server
    record is still recorded for evidence even when the shared parser
    considers the document unrecognized."""
    if not content:
        return []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    mcp_servers = data.get("mcpServers")
    servers: list[dict] = []
    if isinstance(mcp_servers, dict):
        for name, value in mcp_servers.items():
            if not isinstance(value, dict):
                continue
            servers.append(_server_record(name, value))
            if len(servers) >= _MAX_SERVERS:
                break
    elif isinstance(mcp_servers, list):
        for entry in mcp_servers:
            if not isinstance(entry, dict):
                continue
            servers.append(_server_record(entry.get("name"), entry))
            if len(servers) >= _MAX_SERVERS:
                break
    return servers


@register_gatherer("mcp_discovery")
def gather_mcp_discovery(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    res = client.try_fetch(f"{ctx.origin}/.well-known/mcp.json", kind="json")
    if isinstance(res, FetchError):
        status = None
        content = None
        truncated = False
    else:
        status = res.status
        content = res.text if status == 200 else None
        truncated = bool(res.truncated) and bool(content)

    discovery = check_mcp_discovery(content, status or 0)
    # the probe adapter (not `client.httpx`): redirect-following, size-capped
    # and scan-deadline-aware, so a server card behind a 301 is still found.
    # `probe_mcp_server_card` reads through `_probe_json`, which DOES derive
    # a real truncation signal from `_capped_body` (the `_ProbeResponse` it
    # reads through has already lost `FetchResult.truncated`, but the
    # probe-level read cap is the same category of boundary) — its
    # `truncated` flag folds into this record's below, and `exists=None`
    # (rather than a claimed `False`) is possible when a cut-off body left
    # the server card's presence undetermined.
    card = probe_mcp_server_card(client.probe_adapter("json"), ctx.origin or "")
    discovery["server_card"] = card["exists"]
    discovery["servers"] = _parse_servers(content)

    # Two documents contribute: `/.well-known/mcp.json` (`res`, above) and
    # the server-card probe (`card`, which may itself have read up to two
    # candidate URLs) — true when EITHER was cut off at its own cap.
    return {"discovery": discovery, "server_card": discovery["server_card"], "status": status,
            "truncated": truncated or card["truncated"]}

"""Collects every machine-facing TEXT surface the scan has ALREADY fetched —
never a new request. A surface absent from the store is simply not present.

Reads exclusively through `EvidenceStore.gathered` (never `get`/`try_get`),
so calling this gatherer can never trigger a new fetch of its own."""
from __future__ import annotations

import json

from scovant_core.analysis.webmcp_static import extract_webmcp_tools
from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.html import extract_hidden_text, extract_metadata, extract_schema_org
from scovant_core.security.client import SecureClient

MAX_TOTAL_CHARS = 256 * 1024
_PER_SURFACE_CHARS = 64 * 1024


def _surface(source: str, url: str | None, kind: str, text: str) -> dict:
    text = text or ""
    return {"source": source, "url": url, "kind": kind,
            "text": text[:_PER_SURFACE_CHARS], "truncated": len(text) > _PER_SURFACE_CHARS}


@register_gatherer("machine_text")
def gather_machine_text(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:  # noqa: ARG001
    surfaces: list[dict] = []

    http = store.gathered("http") or {}
    html = http.get("html") or ""
    final_url = http.get("final_url")
    if html:
        for block in extract_schema_org(html):
            surfaces.append(_surface("html", final_url, "json_ld", json.dumps(block, ensure_ascii=False)))
        desc = (extract_metadata(html) or {}).get("meta_description")
        if desc:
            surfaces.append(_surface("html", final_url, "meta_description", desc))
        hidden = extract_hidden_text(html)
        if hidden:
            surfaces.append(_surface("html", final_url, "hidden_dom", hidden))
        tools, _parse_errors = extract_webmcp_tools(html)
        for tool in tools:
            text = " ".join(str(tool.get(k) or "") for k in ("name", "description"))
            surfaces.append(_surface(f"webmcp#{tool.get('name')}", final_url, "webmcp_tool", text))

    llms = store.gathered("llms") or {}
    if llms.get("text"):
        surfaces.append(_surface("llms.txt", llms.get("url"), "llms_txt", llms["text"]))

    # No "markdown" gatherer is registered in the evidence store today
    # (`check_markdown_negotiation` is called directly by its own checks
    # with a bare client, not through `EvidenceStore`) — `gathered` simply
    # returns None, so this surface never fires. Kept so a future
    # store-backed markdown gatherer needs no change here.
    md = store.gathered("markdown") or {}
    if md.get("text"):
        surfaces.append(_surface("markdown", md.get("url"), "markdown_mirror", md["text"]))

    mcp = store.gathered("mcp_discovery") or {}
    disc = mcp.get("discovery") or {}
    mcp_url = disc.get("url") or mcp.get("url")
    if disc.get("text"):
        surfaces.append(_surface("mcp.json", mcp_url, "mcp_discovery", disc["text"]))
    for s in disc.get("servers") or []:
        if s.get("description"):
            surfaces.append(_surface(f"mcp.json#{s.get('name')}", mcp_url, "mcp_server_description", str(s["description"])))

    openapi = store.gathered("openapi") or {}
    if openapi.get("text"):
        surfaces.append(_surface("openapi", openapi.get("found_url"), "openapi", openapi["text"]))

    agent = store.gathered("agent_discovery_surface") or {}
    for doc in agent.get("documents") or []:
        if doc.get("text"):
            surfaces.append(_surface(doc.get("kind", "agent"), doc.get("url"), "agent_discovery", doc["text"]))

    ucp = store.gathered("ucp") or {}
    if ucp.get("text"):
        surfaces.append(_surface("ucp", ucp.get("url"), "ucp", ucp["text"]))

    total = 0
    kept: list[dict] = []
    capped = False
    for s in surfaces:
        # A surface that itself lost characters to the per-surface cap is
        # "capped" evidence regardless of whether the running total ever
        # reaches the budget — a single oversized document (llms.txt,
        # a huge OpenAPI spec, ...) must not silently read as "everything
        # fit" just because its OWN truncated text happens to fit the total.
        if s["truncated"]:
            capped = True
        if total + len(s["text"]) > MAX_TOTAL_CHARS:
            capped = True
            break
        total += len(s["text"])
        kept.append(s)

    return {"surfaces": kept, "total_chars": total, "capped": capped}

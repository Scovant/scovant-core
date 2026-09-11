"""Machine-consumable link inventory: pulls candidate agent-relevant URLs
already discovered by other gatherers (the sitemap document, llms.txt
references, an OpenAPI/Swagger spec, the declared MCP endpoint, policy
links, the canonical URL) into one capped, uniformly-resolved ref list.

Collection ORDER is load-bearing. The list is capped at `MAX_REFS`, and a
site with many llms.txt links used to push the canonical URL and the policy
links out of the inventory entirely — silently disabling CORE-ACCESS-007's
canonical-status evidence on exactly the sites that publish the most
references. The small, bounded, always-relevant sources (canonical, policy
links, the sitemap document, the OpenAPI spec, the MCP endpoint) are
collected FIRST; the unbounded llms.txt reference list comes last and is
what the cap actually truncates.
"""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient

MAX_REFS = 30

# An MCP endpoint speaks JSON-RPC over POST (Streamable HTTP). What it answers
# to a plain GET — 404, 405, 200, an SSE stream — says nothing about whether
# the endpoint works, and Core deliberately never performs the `initialize`
# handshake (see docs/methodology.md). So its status is RECORDED and its
# verdict is left `None`: inconclusive, never "broken".
MCP_ENDPOINT_NOTE = "MCP endpoints are not probed by Core"


def _collect_candidates(store: EvidenceStore) -> list[tuple[str, str]]:
    sitemap = store.try_get("sitemap_urls") or {}
    llms = store.try_get("llms") or {}
    openapi = store.try_get("openapi") or {}
    mcp = store.try_get("mcp_discovery") or {}
    pages = store.try_get("pages") or {}

    candidates: list[tuple[str, str]] = []

    entry_pages = pages.get("pages") or []
    entry_parsed = (entry_pages[0]["parsed"] if entry_pages and entry_pages[0].get("parsed") else {}) or {}

    # ── reserved slots: bounded sources that must survive the cap ────────────
    canonical = (entry_parsed.get("metadata") or {}).get("canonical_url")
    if canonical:
        candidates.append((canonical, "canonical"))

    for url in (entry_parsed.get("policy_links") or {}).values():
        if url:
            candidates.append((url, "policy_link"))

    if sitemap.get("url"):
        candidates.append((sitemap["url"], "sitemap"))

    if openapi.get("found_url"):
        candidates.append((openapi["found_url"], "openapi"))

    for url in (mcp.get("discovery") or {}).get("endpoints", []):
        candidates.append((url, "mcp_endpoint"))

    # ── unbounded source: whatever the cap truncates, it truncates here ──────
    for url in (llms.get("parsed") or {}).get("urls", []):
        candidates.append((url, "llms"))

    return candidates


@register_gatherer("machine_links")
def gather_machine_links(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    http = store.get("http")
    llms = store.try_get("llms") or {}
    # The llms gatherer already resolved every llms.txt reference. Re-fetching
    # the same URLs here would double the request count for no new evidence.
    llms_statuses = {r["url"]: r["status"] for r in (llms.get("references") or [])}

    seen: set[str] = set()
    ordered: list[tuple[str, str]] = []
    for url, source in _collect_candidates(store):
        if url in seen:
            continue
        seen.add(url)
        ordered.append((url, source))
        if len(ordered) >= MAX_REFS:
            break

    refs = []
    for url, source in ordered:
        if source == "canonical" and url == ctx.final_url:
            refs.append({"url": url, "source": source, "status": http["status"], "ok": True})
            continue

        if url in llms_statuses:
            status = llms_statuses[url]
        else:
            res = client.try_fetch(url, kind="text")
            status = None if isinstance(res, FetchError) else res.status

        ref = {"url": url, "source": source, "status": status}
        if source == "mcp_endpoint":
            # inconclusive by construction — see MCP_ENDPOINT_NOTE above
            ref["ok"] = None
            ref["note"] = MCP_ENDPOINT_NOTE
        elif status is None:
            # OUR fetch failed — the reference itself is unjudged, never broken
            ref["ok"] = None
        else:
            ref["ok"] = 200 <= status < 400
        refs.append(ref)

    return {"refs": refs}

"""Pure within-sample crawl-graph builder.

Consumes each sampled page's `internal_links["urls"]`
(collected by `scovant_core.parsers.html.extract_internal_links`) and produces
an honest, sample-bounded link graph: inlinks/outlinks/BFS depth per page.

"Within-sample" is load-bearing — with page caps of 10-200 the graph never
sees the whole site, so every metric here is provably true only about the
sampled subset (see CRAWL-GRAPH-001/002/005 vs the
deliberately unimplemented -003/-004/-006).

No DB, no network — the caller passes already-gathered pages.
"""
from __future__ import annotations

from collections import deque
from typing import Any

from scovant_core.parsers.html import normalize_internal_url


def build_crawl_graph(pages: dict[str, list[str]], root: str) -> dict[str, Any]:
    """Build the within-sample crawl graph.

    `pages`: {page_url: [outbound same-domain link, ...]} — one entry per
    sampled page, values as extracted by `extract_internal_links` (already
    same-registrable-domain-filtered, but re-normalized here defensively so
    joins can't miss on formatting drift between a page's own snapshot URL
    and how some other page's link happened to spell it).

    `root`: the scan's root URL. If it isn't among the sampled pages (e.g.
    it redirected, or the root itself was outside the crawled sample), BFS
    instead originates from the lexically shortest sampled URL (shortest
    length, ties broken lexicographically) and `root_fallback: true` is
    recorded so callers know the origin was substituted.

    Returns:
        {"root": str, "sampled": int, "root_fallback": bool,
         "pages": {url: {"inlinks": int, "outlinks_in_sample": int,
                          "outlinks_raw": int, "depth": int | None}}}
    """
    normalized_pages: dict[str, list[str]] = {}
    for url, links in pages.items():
        norm_url = normalize_internal_url(url)
        norm_links: list[str] = []
        seen_links: set[str] = set()
        for link in links:
            norm_link = normalize_internal_url(link)
            if norm_link not in seen_links:
                seen_links.add(norm_link)
                norm_links.append(norm_link)
        normalized_pages[norm_url] = norm_links

    sampled_urls = set(normalized_pages.keys())

    norm_root = normalize_internal_url(root)
    root_fallback = False
    if sampled_urls and norm_root not in sampled_urls:
        norm_root = min(sampled_urls, key=lambda u: (len(u), u))
        root_fallback = True

    inlinks: dict[str, int] = {u: 0 for u in sampled_urls}
    outlinks_in_sample: dict[str, int] = {}
    outlinks_raw: dict[str, int] = {}
    adjacency: dict[str, list[str]] = {}

    for url, links in normalized_pages.items():
        outlinks_raw[url] = len(links)
        in_sample_targets = [link for link in links if link in sampled_urls]
        outlinks_in_sample[url] = len(in_sample_targets)
        adjacency[url] = in_sample_targets
        for target in in_sample_targets:
            inlinks[target] += 1

    depth: dict[str, int | None] = {u: None for u in sampled_urls}
    if norm_root in sampled_urls:
        depth[norm_root] = 0
        queue: deque[str] = deque([norm_root])
        visited = {norm_root}
        while queue:
            current = queue.popleft()
            current_depth = depth[current]
            assert current_depth is not None  # every queued node was assigned a depth
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    depth[neighbor] = current_depth + 1
                    queue.append(neighbor)

    pages_out = {
        url: {
            "inlinks": inlinks[url],
            "outlinks_in_sample": outlinks_in_sample[url],
            "outlinks_raw": outlinks_raw[url],
            "depth": depth[url],
        }
        for url in sampled_urls
    }

    return {
        "root": norm_root,
        "sampled": len(sampled_urls),
        "root_fallback": root_fallback,
        "pages": pages_out,
    }

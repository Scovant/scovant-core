"""Policy-page discovery: fetches (at most 5) shipping/returns/privacy/terms/
pricing pages linked from the entry page, and records whether each one
carries a visible or structured price.

Discovery has two layers, checked in order for each kind: the entry page's
already-parsed `policy_links` (`pages[0].parsed.policy_links` — returns/
shipping/privacy/terms only, shared with the `pages` gatherer's own parse),
then a same-origin anchor scan over the raw entry-page HTML for any kind
`policy_links` didn't resolve — this is the ONLY route to `pricing`, which
has no `policy_links` slot.

Policy pages are genuinely HTML documents, not a document type a soft-404
catch-all could impersonate the way `robots.txt`/a sitemap/`llms.txt` can —
so `served_as_html` here is purely informational (does the response's
content-type say html?), never a signal that the page is "really absent".
Thinness (`text_chars < N`) is left for a downstream check to decide.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from scovant_core.analysis.prices import find_visible_prices
from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.html import coerce_attr_str, extract_schema_org, extract_visible_text
from scovant_core.security.client import FetchError, SecureClient

MAX_FETCHES = 5

# Kind -> (anchor text/href pattern). Order is the iteration/fetch order.
_KIND_PATTERNS: dict[str, re.Pattern[str]] = {
    "shipping": re.compile(r"shipping|delivery", re.I),
    "returns": re.compile(r"return|refund", re.I),
    "privacy": re.compile(r"privacy", re.I),
    "terms": re.compile(r"terms|conditions|legal", re.I),
    "pricing": re.compile(r"pricing|plans", re.I),
}

# Kind -> the matching key in `parsers.html.extract_policy_links`'s output.
# `pricing` has no equivalent there — anchor-only.
_POLICY_LINK_KEY: dict[str, str] = {
    "shipping": "shipping_policy_url",
    "returns": "returns_policy_url",
    "privacy": "privacy_policy_url",
    "terms": "terms_url",
}

_STRUCTURED_PRICE_TYPES = {"Offer", "AggregateOffer", "PriceSpecification", "UnitPriceSpecification"}
_STRUCTURED_PRICE_KEYS = ("price", "lowPrice")


def _same_origin(url: str, origin: str) -> bool:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" == origin


def _in_priority_container(a) -> bool:
    """True when `a` (or an ancestor, including `a` itself) is a `<nav>`,
    `<footer>`, `<header>`, or carries `role="navigation"`. Real navigation
    chrome is a far more reliable place to find a policy link than a body
    paragraph that happens to mention "return policy" in passing."""
    for tag in (a, *a.parents):
        if getattr(tag, "name", None) in ("nav", "footer", "header"):
            return True
        if hasattr(tag, "get") and (tag.get("role") or "").strip().lower() == "navigation":
            return True
    return False


def _has_structured_price(schema_org: list[dict]) -> bool:
    for node in schema_org:
        node_type = node.get("@type")
        types = node_type if isinstance(node_type, list) else [node_type]
        if any(t in _STRUCTURED_PRICE_TYPES for t in types):
            return True
        if any(key in node for key in _STRUCTURED_PRICE_KEYS):
            return True
    return False


def _discover_urls(entry_html: str, base_url: str, origin: str, policy_links: dict) -> dict[str, str | None]:
    urls: dict[str, str | None] = dict.fromkeys(_KIND_PATTERNS)

    for kind, link_key in _POLICY_LINK_KEY.items():
        candidate = policy_links.get(link_key)
        if candidate and _same_origin(candidate, origin):
            urls[kind] = candidate

    if entry_html and any(v is None for v in urls.values()):
        soup = BeautifulSoup(entry_html, "lxml")
        # Candidates per still-unresolved kind, as (not_in_nav_footer, dom_index,
        # url) — sorted so a nav/footer/header link always wins over body prose
        # mentioning the same words further down the page, and DOM order breaks
        # any remaining tie within the same tier.
        candidates: dict[str, list[tuple[bool, int, str]]] = {
            kind: [] for kind in _KIND_PATTERNS if urls[kind] is None
        }
        for index, a in enumerate(soup.find_all("a", href=True)):
            href = (coerce_attr_str(a.get("href")) or "").strip()
            if not href:
                continue
            absolute = urljoin(base_url, href)
            if not _same_origin(absolute, origin):
                continue
            text = a.get_text(strip=True)
            deprioritized = not _in_priority_container(a)
            for kind, pattern in _KIND_PATTERNS.items():
                if kind not in candidates:
                    continue
                if pattern.search(text) or pattern.search(href):
                    candidates[kind].append((deprioritized, index, absolute))

        for kind, kind_candidates in candidates.items():
            if kind_candidates:
                kind_candidates.sort(key=lambda c: (c[0], c[1]))
                urls[kind] = kind_candidates[0][2]

    return urls


def _empty_pages() -> dict[str, None]:
    return dict.fromkeys(_KIND_PATTERNS)


@register_gatherer("policy_pages")
def gather_policy_pages(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    entry_pages = store.get("pages")["pages"]
    entry = entry_pages[0] if entry_pages else None
    if entry is None or entry.get("parsed") is None:
        return {"pages": _empty_pages(), "entry_unparsed": True, "truncated": False}

    origin = ctx.origin or ""
    base_url = ctx.final_url or ctx.input_url
    policy_links = entry["parsed"].get("policy_links") or {}
    urls = _discover_urls(entry.get("html") or "", base_url, origin, policy_links)

    result: dict[str, dict | None] = {}
    fetches = 0
    for kind in _KIND_PATTERNS:
        url = urls[kind]
        if url is None or fetches >= MAX_FETCHES:
            result[kind] = None
            continue
        fetches += 1

        res = client.try_fetch(url, kind="html")
        if isinstance(res, FetchError):
            result[kind] = {
                "url": url, "status": None, "text_chars": 0, "served_as_html": False,
                "has_price_text": False, "has_structured_price": False, "truncated": False,
            }
            continue

        served_as_html = "html" in (res.content_type or "").lower()
        if res.status == 200:
            visible_text = extract_visible_text(res.text)
            schema_org = extract_schema_org(res.text)
        else:
            visible_text, schema_org = "", []

        result[kind] = {
            "url": url, "status": res.status, "text_chars": len(visible_text),
            "served_as_html": served_as_html,
            "has_price_text": bool(find_visible_prices(visible_text)),
            "has_structured_price": _has_structured_price(schema_org),
            "truncated": bool(res.truncated) and res.text != "",
        }

    # Up to `MAX_FETCHES` documents contribute to this record; the top-level
    # flag is true when ANY fetched policy page was truncated.
    return {"pages": result,
            "truncated": any(v is not None and v["truncated"] for v in result.values())}

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

from bs4 import BeautifulSoup

from scovant_core.analysis.form_semantics import analyse_forms
from scovant_core.analysis.page_cost import page_cost
from scovant_core.analysis.prices import find_visible_prices
from scovant_core.analysis.webmcp_static import extract_webmcp_tools
from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers import html as H
from scovant_core.parsers.bot_protection import detect_bot_protection
from scovant_core.parsers.html import normalize_internal_url
from scovant_core.security.client import FetchError, SecureClient

_PRODUCTISH = re.compile(r"/(product|products|item|p|shop|store|pricing|plans)(/|$)", re.I)
_DOCSISH = re.compile(r"/(docs|documentation|api|developers|reference)(/|$)", re.I)
_JSONLD = re.compile(r"<script[^>]+type=[\"']application/ld\+json[\"']", re.I)


def _parsed_jsonld_count(html: str) -> int:
    """Count `<script type="application/ld+json">` tags whose body parses as
    JSON — same tag-detection as `extract_schema_org` (BeautifulSoup, not the
    regex `_JSONLD` uses for `raw_jsonld_count`), so the two counts are
    directly comparable: a gap between them means malformed JSON-LD, not a
    tag-detection mismatch."""
    soup = BeautifulSoup(html, "lxml")
    count = 0
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = script.string or script.get_text()
        if not raw or not raw.strip():
            continue
        try:
            json.loads(raw.strip())
        except json.JSONDecodeError:
            continue
        count += 1
    return count


def _has_breadcrumb(schema_org: list[dict]) -> bool:
    """Any node whose `@type` is (or lists) `BreadcrumbList` — `schema_org`
    is already flattened by `extract_schema_org` (`@graph`/list handled)."""
    for node in schema_org:
        node_type = node.get("@type")
        if node_type == "BreadcrumbList":
            return True
        if isinstance(node_type, list) and "BreadcrumbList" in node_type:
            return True
    return False


def _image_alt_coverage(soup: BeautifulSoup) -> dict:
    """`{total, with_alt, empty_alt}` over every `<img>`. `with_alt` requires
    a non-empty (post-strip) `alt`; `empty_alt` is an `alt=""` OR a
    decorative `role="presentation"` image regardless of its `alt` value."""
    total = with_alt = empty_alt = 0
    for img in soup.find_all("img"):
        total += 1
        role = (H.coerce_attr_str(img.get("role")) or "").strip().lower()
        alt = H.coerce_attr_str(img.get("alt"))
        if role == "presentation":
            empty_alt += 1
        elif alt is not None and alt.strip():
            with_alt += 1
        elif alt is not None:
            empty_alt += 1
    return {"total": total, "with_alt": with_alt, "empty_alt": empty_alt}


def parse_page(html: str, url: str, *, token_chars_ratio: int = 4) -> dict:
    schema = H.extract_schema_org(html)
    visible_text = H.extract_visible_text(html)
    soup = H._soup(html)
    html_tag = soup.find("html")
    webmcp_tools, webmcp_parse_errors = extract_webmcp_tools(html)

    return {
        "metadata": H.extract_metadata(html), "headings": H.extract_headings(html), "schema_org": schema,
        "og_meta": H.extract_og_meta(html), "visible_text": visible_text,
        "policy_links": H.extract_policy_links(html, url), "internal_links": H.extract_internal_links(html, url),
        "product_data": H.extract_product_data(schema), "semantic_signals": H.extract_semantic_signals(html),
        "page_language": H.detect_page_language(html), "raw_jsonld_count": len(_JSONLD.findall(html)),
        "parsed_jsonld_count": _parsed_jsonld_count(html),
        "html_lang": (html_tag.get("lang") if html_tag else None),
        "images": _image_alt_coverage(soup),
        "breadcrumb": _has_breadcrumb(schema),
        "visible_prices": find_visible_prices(visible_text),
        "webmcp_tools": webmcp_tools,
        "webmcp_parse_errors": webmcp_parse_errors,
        "forms": analyse_forms(html),
        "page_cost": page_cost(html, token_chars_ratio=token_chars_ratio),
    }


def _canon(url: str) -> str:
    """Dedup key for page selection: `normalize_internal_url` plus an empty
    path read as `/`, so a sitemap entry written as `https://example.com`
    is recognised as the homepage already sampled as the entry page and is
    never fetched and reported twice. Local on purpose — the shared
    normalizer preserves paths verbatim for its own callers."""
    p = urlsplit(normalize_internal_url(url))
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def _same_origin(url: str, origin: str) -> bool:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" == origin


def select_pages(ctx: ScanContext, entry_links: list[str], sitemap_entries: list[dict]) -> list[dict]:
    final_url = ctx.final_url or ctx.input_url
    picks: list[dict] = [{"url": final_url, "reason": "entry"}]
    seen = {_canon(final_url)}

    def add(url: str, reason: str) -> None:
        n = _canon(url)
        if n in seen or not _same_origin(url, ctx.origin or "") or len(picks) >= ctx.options.max_pages:
            return
        seen.add(n)
        picks.append({"url": url, "reason": reason})

    candidates = [e["loc"] for e in sitemap_entries] + entry_links
    for url in candidates:
        if _PRODUCTISH.search(urlsplit(url).path):
            add(url, "product_or_pricing")
            break
    if ctx.options.profile in ("api", "auto"):
        for url in candidates:
            if _DOCSISH.search(urlsplit(url).path):
                add(url, "docs_or_api")
                break
    for e in sitemap_entries[:20]:
        if len(picks) >= min(ctx.options.max_pages, 4):
            break
        add(e["loc"], "sitemap")
    return picks


@register_gatherer("pages")
def gather_pages(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    http = store.get("http")
    sitemap = store.try_get("sitemap_urls") or {"entries": []}
    entry_html = http["html"]
    entry_links = (
        H.extract_internal_links(entry_html, ctx.final_url or ctx.input_url)["urls"]
        if entry_html else []
    )
    selection = select_pages(ctx, entry_links, sitemap["entries"])
    pages = []
    for pick in selection:
        if pick["reason"] == "entry":
            # Already fetched by the `http` gatherer, which carries its own
            # honest `truncated` flag — reuse it rather than re-deriving.
            res_status, html, headers = http["status"], entry_html, http["headers"]
            page_truncated = bool(http.get("truncated")) and bool(html)
        else:
            res = client.try_fetch(pick["url"], kind="html")
            if isinstance(res, FetchError):
                pages.append({"url": pick["url"], "status": None, "html": "", "bot_protection": None, "parsed": None,
                              "error": res.kind, "truncated": False})
                continue
            res_status, html, headers = res.status, res.text, res.headers
            page_truncated = bool(res.truncated) and html != ""
        pages.append({
            "url": pick["url"], "status": res_status, "html": html,
            "bot_protection": detect_bot_protection(res_status or 0, headers, html, "browser") if html else None,
            # A non-2xx response (e.g. a 500) is not parsed as content — its
            # body is an error page, not the page the URL nominally names.
            "parsed": parse_page(html, pick["url"], token_chars_ratio=ctx.options.token_chars_ratio)
            if html and res_status is not None and 200 <= res_status < 300 else None,
            "error": None,
            "truncated": page_truncated,
        })
    # This gatherer fetches MANY documents (one per selected page); the
    # top-level flag is true when ANY of them was truncated.
    return {"pages": pages, "selection": selection,
            "truncated": any(p["truncated"] for p in pages)}

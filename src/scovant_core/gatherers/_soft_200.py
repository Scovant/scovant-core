"""Soft-200 detection: one predicate, shared by every gatherer that fetches a
NON-HTML document (`robots.txt`, a sitemap, `llms.txt`, an OpenAPI spec).

Some servers answer an unknown path with a 200 and an HTML error/soft-404
page (a catch-all router, a CMS "page not found" template) instead of a 404.
Reading that body as the requested document manufactures evidence out of
nothing: an HTML page parsed as robots.txt is a fully-permissive policy, as a
sitemap it is "invalid XML", as llms.txt it is "published but malformed".
Every one of those is a finding about a document the site never published.

**The body decides first, the header second.** A misconfigured server that
serves a perfectly valid sitemap or OpenAPI spec with `Content-Type:
text/html` is common; treating that document as absent would be the same
class of error in the opposite direction — a real published document reported
as missing because of a header. So a body that positively identifies itself
as the requested document (an XML prologue or sitemap root element, a JSON
object or an `openapi:` YAML key, a Markdown heading) wins over any header,
and only then does the `text/html`/leading-`<` heuristic apply.

A caller that sees True must treat the document as ABSENT and record
`served_as_html: True` so the distinction stays visible in evidence.
"""
from __future__ import annotations

__all__ = ["is_soft_200_html"]

# XML is never HTML for any caller: no soft-404 template starts this way.
_XML_PREFIXES = ("<?xml", "<urlset", "<sitemapindex")
_BOM = "﻿"


def is_soft_200_html(
    status: int | None, content_type: str, text: str, *, document: str = "generic"
) -> bool:
    """True when a 200 response is really an HTML page, not the document asked for.

    `document` names what the caller REQUESTED — `sitemap`, `openapi`, `llms`
    or `generic` (robots.txt and anything else) — and only widens the set of
    body shapes accepted as "this is the real document", never narrows it.
    """
    if status != 200:
        return False

    body = text.lstrip(_BOM).lstrip()

    # ── the body identifies itself as the requested document ────────────────
    if body[:32].lower().startswith(_XML_PREFIXES):
        return False
    if document == "openapi" and (body.startswith("{") or body.startswith("openapi:")):
        return False
    if document == "llms" and body.startswith("#"):
        return False

    # ── otherwise fall back to the header, then the shape ───────────────────
    if "html" in (content_type or "").lower():
        return True
    return body.startswith("<")

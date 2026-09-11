"""Agent-parse-cost estimation over already-fetched HTML. Pure, I/O-free.

`estimated_tokens` is an explicit, documented estimate (`text_chars //
token_chars_ratio`), never a real tokenizer count — the ratio is a
caller-supplied, per-scan-configurable constant (`ScanOptions.token_chars_ratio`).

`text_chars` is deliberately NOT `len(visible_text)` — `parsers.html.
extract_visible_text`'s result (what the rest of the page-parsing pipeline
uses) is CAPPED at 5000 chars, a limit that exists for that function's own
callers (schema/price/breadcrumb text scanning), not for a parse-cost
estimate. Capping the
cost estimate at 5000 chars silently ceilings `estimated_tokens` at
5000 // token_chars_ratio (1250 at the default ratio of 4) — below the
check's own MEDIUM (8000) and HIGH (>20000) thresholds on every real page,
making CORE-OPERABILITY-005 structurally unable to warn on ANY page no
matter how bloated. This module re-extracts visible text from the raw
`html` itself, UNCAPPED, using the identical stripping rules
(`extract_visible_text`'s script/style/nav/footer/head removal +
whitespace collapse) — duplicated here rather than adding a `limit`
parameter to the shared `parsers.html` module, which is synced verbatim
with Scovant Cloud (`test_scovant_core_sync.py`) and whose 5000-char cap is
a Cloud contract for its own (different) callers.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

_WHITESPACE_RE = re.compile(r"\s+")
_STRIPPED_TAGS = ("script", "style", "nav", "footer", "head")


def _uncapped_visible_text(html: str) -> str:
    """Same extraction as `parsers.html.extract_visible_text`, minus its
    `[:5000]` cap — see the module docstring for why the cap doesn't belong
    in a parse-cost estimate."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "lxml")
    for tag in soup.find_all(list(_STRIPPED_TAGS)):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True)
    return _WHITESPACE_RE.sub(" ", text).strip()


def page_cost(html: str, *, token_chars_ratio: int) -> dict:
    """Return `{html_bytes, text_chars, estimated_tokens, dom_nodes,
    script_bytes, script_ratio, structured_bytes, link_count}`.

    `text_chars` is derived from an UNCAPPED re-extraction of `html` — see
    the module docstring for why it is not `len(visible_text)`."""
    html_bytes = len(html.encode("utf-8", "replace")) if html else 0
    text_chars = len(_uncapped_visible_text(html))
    estimated_tokens = text_chars // token_chars_ratio

    if not html:
        return {
            "html_bytes": 0, "text_chars": text_chars, "estimated_tokens": estimated_tokens,
            "dom_nodes": 0, "script_bytes": 0, "script_ratio": 0.0, "structured_bytes": 0,
            "link_count": 0,
        }

    soup = BeautifulSoup(html, "lxml")
    dom_nodes = len(soup.find_all(True))

    script_bytes = 0
    structured_bytes = 0
    for script in soup.find_all("script"):
        if script.get("src"):
            continue  # external script bodies aren't present in this fetch
        body = script.string or script.get_text() or ""
        body_bytes = len(body.encode("utf-8", "replace"))
        script_bytes += body_bytes
        script_type = script.get("type")
        script_type_str = script_type if isinstance(script_type, str) else ""
        if script_type_str.strip().lower() == "application/ld+json":
            structured_bytes += body_bytes

    script_ratio = (script_bytes / html_bytes) if html_bytes else 0.0
    link_count = len(soup.find_all("a", href=True))

    return {
        "html_bytes": html_bytes,
        "text_chars": text_chars,
        "estimated_tokens": estimated_tokens,
        "dom_nodes": dom_nodes,
        "script_bytes": script_bytes,
        "script_ratio": script_ratio,
        "structured_bytes": structured_bytes,
        "link_count": link_count,
    }

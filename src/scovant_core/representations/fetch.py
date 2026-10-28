"""Fetch a page's representations through a caller-supplied `fetch(url, headers)`
and turn each variant into a verdict. The caller owns redirects, robots.txt and
SSRF: Cloud passes its robots-aware hop walker, the CLI passes SecureClient.

`fetch` returns a plain dict (see `_EMPTY`) and never raises (the host's
`SoftTimeLimitExceeded` excepted, per package convention); our own failure is
`{"error": "<reason>"}` with `status None`.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from scovant_core.compat import SoftTimeLimitExceeded
from scovant_core.gatherers._soft_200 import is_soft_200_html
from scovant_core.representations.compare import (
    classify,
    compare,
    html_facts,
    markdown_facts,
)

VARIANTS = ("markdown", "mirror", "consolidated")
VARIANT_HEADERS: dict[str, dict[str, str]] = {
    "html": {"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
    "markdown": {"Accept": "text/markdown"},
    "mirror": {},
    "consolidated": {"Accept": "text/markdown;q=0.9, text/html;q=0.8",
                     "Prefer": "return=consolidated"},
}
REPR_BODY_CAP = 512 * 1024

_EMPTY = {"status": None, "content_type": "", "vary": None, "preference_applied": None,
          "bytes": 0, "latency_ms": 0, "truncated": False, "final_url": None, "body": None,
          "error": None}


def mirror_url(page_url: str) -> str:
    p = urlsplit(page_url)
    path = p.path or "/"
    path = "/index.md" if path in ("", "/") else path.rstrip("/") + ".md"
    return urlunsplit((p.scheme, p.netloc, path, "", ""))


def fetch_representations(fetch: Callable[[str, dict], dict], page_url: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for variant in ("html", *VARIANTS):
        url = mirror_url(page_url) if variant == "mirror" else page_url
        try:
            got = fetch(url, dict(VARIANT_HEADERS[variant])) or {"error": "no_response"}
        except SoftTimeLimitExceeded:
            raise  # the host's deadline, never "our fetch failed"
        except Exception:  # noqa: BLE001 — a fetcher must not break the gathering
            got = {"error": "fetch_failed"}
        out[variant] = {**_EMPTY, **got}
    return out


def public_fetch_meta(f: dict) -> dict:
    return {k: v for k, v in f.items() if k != "body"}


def _host(url: str | None) -> str:
    h = (urlsplit(url or "").hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _ok(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _is_markdown_ct(ct: str) -> bool:
    c = (ct or "").lower()
    return "markdown" in c or "text/plain" in c


_LEADING_COMMENT = re.compile(r"\A(?:\ufeff|\s|<!--.*?-->)+", re.S)


def _strip_leading_comments(body: str) -> str:
    """A Markdown mirror may open with `<!-- source: ... -->`; that is not HTML."""
    return _LEADING_COMMENT.sub("", body, count=1)


def variant_verdict(html: dict, alt: dict, *, variant: str, page_url: str) -> dict:
    def v(status: str, reason: str | None = None, cmp: dict | None = None) -> dict:
        return {"status": status, "reason": reason, "compare": cmp}

    if html.get("error"):
        reason = html["error"]
        return v("INCONCLUSIVE" if reason == "undecodable" else "NOT_MEASURED", f"baseline_{reason}")
    if not _ok(html.get("status")):
        return v("NOT_MEASURED", "baseline_status")
    if alt.get("error"):
        return v("INCONCLUSIVE" if alt["error"] == "undecodable" else "NOT_MEASURED", alt["error"])
    if not _ok(alt.get("status")):
        return v("NA", "not_offered")
    if _host(alt.get("final_url") or page_url) != _host(page_url):
        return v("NA", "cross_site_redirect")
    # The alternate's not-applicable checks read only its status, headers and
    # the START of its body, so they come before truncation: a large (often
    # truncated) baseline must not turn a variant the site does not offer into
    # INCONCLUSIVE. Truncation guards only the comparison itself.
    body, ct = alt.get("body") or "", alt.get("content_type") or ""
    sniff = _strip_leading_comments(body)
    as_html = False
    if variant == "consolidated" and "html" in ct.lower() and is_soft_200_html(
            alt.get("status"), ct, sniff, document="llms"):
        if not alt.get("preference_applied"):
            return v("NA", "preference_not_applied")
        as_html = True
    # else: a Markdown body under an HTML header is compared as Markdown below
    if variant in ("markdown", "mirror") and is_soft_200_html(alt.get("status"), ct, sniff, document="llms"):
        return v("NA", "served_as_html")
    if html.get("truncated") or alt.get("truncated"):
        return v("INCONCLUSIVE", "truncated")
    base = html_facts(html.get("body") or "", page_url)
    alt_facts = html_facts(body, page_url) if as_html else markdown_facts(body, page_url)
    cmp = compare(base, alt_facts)
    if _nothing_to_compare(cmp):
        return v("INCONCLUSIVE", "nothing_to_compare", cmp)
    ct_ok = as_html or _is_markdown_ct(ct)
    return v(classify(cmp, content_type_ok=ct_ok), None if ct_ok else "content_type_mismatch", cmp)


def _nothing_to_compare(cmp: dict) -> bool:
    """The HTML has no link, no entity and no applicable price: every sub-check
    is empty, so any alternate — even an empty one — would read PASS."""
    return (cmp["links"]["base_n"] == 0 and cmp["entities"]["base_n"] == 0
            and not cmp["prices"]["applicable"])

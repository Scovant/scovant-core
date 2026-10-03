"""Sitemap discovery and validation probe."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

from scovant_core.compat import SoftTimeLimitExceeded
from scovant_core.security.client import FetchError
from scovant_core.security.url_safety import SSRFBlocked, UnresolvableHost, UnsafeURLError

from ._http import _PROBE_TIMEOUT, _capped_body, _ProbeClient, _transport_error

_SITEMAP_FALLBACK_PATHS = ("/sitemap.xml", "/sitemap_index.xml")


def _requestable(url: str) -> bool:
    """An absolute http(s) URL — the only kind a client can send."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _refused(exc: BaseException) -> bool:
    """The client declined to send the request (an unsafe or unsupported
    target) — a property of the URL, not a request that went unanswered."""
    if isinstance(exc, UnresolvableHost):
        return False
    if isinstance(exc, (SSRFBlocked, UnsafeURLError)):
        return True
    return isinstance(exc, FetchError) and exc.kind == "security"


def check_sitemap(client: _ProbeClient, domain: str,
                   robots_sitemaps: list[str]) -> dict[str, Any]:
    """Locate + validate the sitemap. robots.txt Sitemap: directives take
    priority over the standard fallback paths; a sitemapindex is validated
    by parse only (child sitemaps are not fetched).

    Returns:
        {"exists": bool, "valid": bool, "url": str | None,
         "kind": "urlset" | "sitemapindex" | None, "truncated": bool,
         "fetch_status": "ok" | "error", "error": str | None}

    `truncated` reflects only the LAST candidate examined (the one `exists`/
    `valid`/`kind` describe) — an earlier candidate that 404'd or failed to
    parse contributed no evidence to the final verdict, so its own read
    boundary is irrelevant to it.

    `fetch_status` is "error" when no candidate validated and at least one
    candidate never got an HTTP answer (a transport error, a timeout, a
    blocked redirect): the absence of a valid sitemap is only established
    when every candidate answered. `error` names the first such failure.
    A robots.txt `Sitemap:` value that cannot be requested at all (relative,
    non-http) or that the client refuses to fetch is the site's own
    declaration being unusable, not a failed request: it is skipped.
    """
    result: dict[str, Any] = {"exists": False, "valid": False, "url": None, "kind": None,
                               "truncated": False, "fetch_status": "ok", "error": None}
    first_error: str | None = None
    declared = [u for u in robots_sitemaps if _requestable(u)]
    candidates = declared + [f"{domain}{p}" for p in _SITEMAP_FALLBACK_PATHS]
    for index, url in enumerate(candidates):
        try:
            resp = client.get(url, timeout=_PROBE_TIMEOUT)
        except SoftTimeLimitExceeded:
            raise
        except Exception as exc:
            if index < len(declared) and _refused(exc):
                continue
            if first_error is None:
                first_error = _transport_error(exc)
            continue
        if resp.status_code != 200:
            continue
        result["exists"] = True
        result["url"] = url
        body, was_truncated = _capped_body(resp.text)
        result["truncated"] = was_truncated and body != ""
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            continue  # try the next candidate; exists stays True
        tag = root.tag.rsplit("}", 1)[-1]  # strip namespace
        if tag in ("urlset", "sitemapindex"):
            result["valid"] = True
            result["kind"] = tag
            return result
    if first_error is not None:
        result["fetch_status"], result["error"] = "error", first_error
    return result

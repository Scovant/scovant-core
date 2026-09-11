"""Sitemap discovery and validation probe."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_TIMEOUT, _capped_body, _ProbeClient

_SITEMAP_FALLBACK_PATHS = ("/sitemap.xml", "/sitemap_index.xml")


def check_sitemap(client: _ProbeClient, domain: str,
                   robots_sitemaps: list[str]) -> dict[str, Any]:
    """Locate + validate the sitemap. robots.txt Sitemap: directives take
    priority over the standard fallback paths; a sitemapindex is validated
    by parse only (child sitemaps are not fetched).

    Returns:
        {"exists": bool, "valid": bool, "url": str | None,
         "kind": "urlset" | "sitemapindex" | None, "truncated": bool}

    `truncated` reflects only the LAST candidate examined (the one `exists`/
    `valid`/`kind` describe) — an earlier candidate that 404'd or failed to
    parse contributed no evidence to the final verdict, so its own read
    boundary is irrelevant to it.
    """
    result: dict[str, Any] = {"exists": False, "valid": False, "url": None, "kind": None,
                               "truncated": False}
    candidates = list(robots_sitemaps) + [f"{domain}{p}" for p in _SITEMAP_FALLBACK_PATHS]
    for url in candidates:
        try:
            resp = client.get(url, timeout=_PROBE_TIMEOUT)
        except SoftTimeLimitExceeded:
            raise
        except Exception:
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
    return result

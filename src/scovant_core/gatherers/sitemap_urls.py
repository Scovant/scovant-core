from __future__ import annotations

import xml.etree.ElementTree as ET

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.gatherers.sitemap import check_sitemap
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

MAX_ENTRIES = 500
_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def _entries(xml_text: str) -> tuple[list[dict], str | None]:
    root = ET.fromstring(xml_text)
    tag = root.tag.replace(_NS, "")
    out = []
    for el in root.iter(f"{_NS}url") if tag == "urlset" else root.iter(f"{_NS}sitemap"):
        loc = el.findtext(f"{_NS}loc")
        if loc:
            out.append({"loc": loc.strip(), "lastmod": (el.findtext(f"{_NS}lastmod") or "").strip() or None})
    return out, tag


@register_gatherer("sitemap_urls")
def gather_sitemap(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    robots = store.get("robots_txt")
    # `check_sitemap` runs through the guarded client's probe adapter, not a raw
    # httpx client: it follows redirects (a sitemap declared behind a 301 is a
    # real sitemap), is size-capped and respects the scan deadline.
    found = check_sitemap(client.probe_adapter("sitemap"), ctx.origin or "", robots["sitemaps"])
    # `check_sitemap`'s own `"truncated"` means "the body of the candidate
    # document it read was cut off at the fetch cap" — a DIFFERENT signal
    # from THIS gatherer's pre-existing `"truncated"`, which means "the
    # parsed entry LIST was capped at MAX_ENTRIES" (set below). The two must
    # never share one key, so the body-cap signal is carried separately as
    # `"body_truncated"` and combined below with this gatherer's own direct
    # fetches (`probe`/`res`/`child`), each of which can independently read
    # a body that exceeds the cap.
    body_truncated = found.pop("truncated", False)
    out = {**found, "entries": [], "truncated": False, "parse_error": None, "probe_status": None,
           "probe_error": None, "served_as_html": False, "body_truncated": body_truncated}
    if not found["url"]:
        # `check_sitemap` conflates "really absent" (a clean 404 on every
        # candidate) with "could not be read" (timeout/connection error/5xx)
        # — both just leave `exists: False`. Probe once more so a downstream
        # check can tell the two apart instead of reporting a confident
        # negative about a document it never actually read.
        probe = client.try_fetch(f"{ctx.origin}/sitemap.xml", kind="sitemap")
        if isinstance(probe, FetchError):
            out["probe_error"] = probe.kind
        else:
            out["probe_status"] = probe.status
            out["served_as_html"] = is_soft_200_html(
                probe.status, probe.content_type, probe.text, document="sitemap",
            )
            out["body_truncated"] = out["body_truncated"] or (bool(probe.truncated) and probe.text != "")
        return out
    res = client.try_fetch(found["url"], kind="sitemap_index" if found["kind"] == "sitemapindex" else "sitemap")
    if isinstance(res, FetchError):
        return out
    out["probe_status"] = res.status
    out["body_truncated"] = out["body_truncated"] or (bool(res.truncated) and res.text != "")
    if is_soft_200_html(res.status, res.content_type, res.text, document="sitemap"):
        # A catch-all router answered with an HTML page, not a sitemap. That is
        # an ABSENT sitemap, not a malformed one — reporting "invalid XML"
        # would be a finding about a document the site never published.
        out.update({"exists": False, "url": None, "valid": False, "kind": None, "served_as_html": True})
        return out
    try:
        entries, tag = _entries(res.text)
    except ET.ParseError as exc:
        out["valid"], out["kind"], out["parse_error"] = False, None, str(exc)[:200]
        return out
    if tag == "sitemapindex" and entries:  # follow the first child only (page-selection needs one urlset)
        child = client.try_fetch(entries[0]["loc"], kind="sitemap")
        if isinstance(child, FetchError):
            entries = []
        else:
            out["body_truncated"] = out["body_truncated"] or (bool(child.truncated) and child.text != "")
            try:
                entries, _child_tag = _entries(child.text)
            except ET.ParseError as exc:
                out["valid"], out["kind"], out["parse_error"] = False, None, str(exc)[:200]
                return out
    out["valid"] = tag in ("urlset", "sitemapindex")
    out["kind"] = tag if out["valid"] else None
    out["entries"], out["truncated"] = entries[:MAX_ENTRIES], len(entries) > MAX_ENTRIES
    return out

"""robots.txt gatherer.

Some servers answer `/robots.txt` with a 200 status but an HTML error/soft-404
page (a catch-all router, a CMS "page not found" template served with
`Content-Type: text/html`) instead of a real robots.txt body. Treating that
body as robots.txt content would silently manufacture a fully-permissive
policy (an empty string parses as "everything allowed"). `served_as_html`
makes this distinguishable from evidence: it is True whenever the response
is a 200 whose content-type contains "html" OR whose body's first
non-whitespace character is `<` (a content-type-less/mislabeled HTML body).
`status` always reflects what the server actually returned; `text` stays
`""` whenever `served_as_html` is True, exactly as it does for a non-200
response, so a downstream check reading `text`/`parsed` can never mistake an
HTML page for a robots policy.

`truncated` carries the raw client's body-cap signal up to the checks: a
robots.txt larger than the fetch cap is parsed from the bytes that were
read, so its later directives are simply invisible to us. That is degraded
evidence, not a site defect — it must be visible in the report rather than
published as a fully-read document (it is False whenever the body was not
used as a policy at all, i.e. a non-200 or an HTML catch-all).
"""
from __future__ import annotations

import re

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.content_signals import parse_content_signals
from scovant_core.parsers.robots import parse_robots_txt
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

_KNOWN = {"user-agent", "allow", "disallow", "sitemap", "crawl-delay", "host", "content-signal", "clean-param"}
_DIRECTIVE = re.compile(r"^\s*([A-Za-z-]+)\s*:", re.M)


@register_gatherer("robots_txt")
def gather_robots(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    res = client.try_fetch(f"{ctx.origin}/robots.txt", kind="robots")
    if isinstance(res, FetchError):
        return {"status": None, "text": "", "parsed": parse_robots_txt(""), "content_signals": parse_content_signals(""),
                "sitemaps": [], "unknown_directives": [], "general_disallow_all": False,
                "served_as_html": False, "truncated": False, "error": res.kind}
    served_as_html = is_soft_200_html(res.status, res.content_type, res.text)
    text = res.text if res.status == 200 and not served_as_html else ""
    parsed = parse_robots_txt(text)
    unknown = sorted({m.group(1).lower() for m in _DIRECTIVE.finditer(text)} - _KNOWN)
    return {"status": res.status, "text": text, "parsed": parsed, "content_signals": parse_content_signals(text),
            "sitemaps": list(parsed.get("sitemaps", [])), "unknown_directives": unknown,
            "general_disallow_all": "/" in parsed["general"]["disallow"] and not parsed["general"]["allow"],
            "served_as_html": served_as_html, "truncated": bool(res.truncated) and text != "", "error": None}

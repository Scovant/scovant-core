"""Homepage consolidated-representation ("machine representation") probe."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_BODY_CAP, _PROBE_TIMEOUT, _capped_body

if TYPE_CHECKING:
    import httpx

# ── <link rel="alternate"> parsing ───────────────────────────────────────
# Regex, not a full HTML parse: this package has no HTML-parsing dependency
# and a homepage-only, best-effort probe doesn't warrant adding one.
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_REL_ALTERNATE_RE = re.compile(r'rel\s*=\s*["\']alternate["\']', re.IGNORECASE)
_TYPE_ATTR_RE = re.compile(r'type\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _parse_alternate_types(html: str | None) -> list[str]:
    """Deduped ``type`` attributes off ``<link rel="alternate">`` tags in the
    first ``_PROBE_BODY_CAP`` chars of ``html``."""
    if not html:
        return []
    types: list[str] = []
    for tag in _LINK_TAG_RE.findall(html[:_PROBE_BODY_CAP]):
        if not _REL_ALTERNATE_RE.search(tag):
            continue
        m = _TYPE_ATTR_RE.search(tag)
        if m and m.group(1) not in types:
            types.append(m.group(1))
    return types


def check_machine_rep(client: httpx.Client, domain: str,
                       homepage_html: str | None) -> dict[str, Any]:
    """Homepage-only consolidated-representation probe.

    Sends exactly ONE request — ``Accept: text/markdown;q=0.9,
    text/html;q=0.8`` + ``Prefer: return=consolidated`` — recording
    ``{attempted, status, content_type, preference_applied, vary}``.

    ``alternates`` (``link rel="alternate"`` type attributes) is resolved
    as: (1) parsed from ``homepage_html`` when the caller supplies a real
    pre-fetched plain homepage body — computed unconditionally, independent
    of whether this probe's own request succeeds; else (2) parsed from THIS
    SAME negotiated response's own body whenever it looks like HTML
    (content-type contains "html") — which is exactly what any site not
    supporting this negotiation will send back regardless, making that
    fallback free (no extra request). If neither source is available (a
    real negotiation returned markdown and no ``homepage_html`` was
    passed), ``alternates`` is ``[]``.

    ``truncated`` tracks WHICHEVER source actually drove ``alternates``:
    the caller-supplied ``homepage_html`` is itself read through
    ``_capped_body`` (a caller could hand in an oversized document just as
    easily as this probe's own negotiated response could be one), not only
    this probe's own negotiated-response fallback.
    """
    if homepage_html:
        homepage_body, homepage_truncated = _capped_body(homepage_html)
        homepage_truncated = homepage_truncated and homepage_body != ""
    else:
        homepage_body, homepage_truncated = None, False

    result: dict[str, Any] = {
        "attempted": False, "status": None, "content_type": None,
        "preference_applied": None, "vary": None,
        "alternates": _parse_alternate_types(homepage_body),
        "truncated": homepage_truncated,
    }
    try:
        resp = client.get(
            f"{domain}/",
            headers={
                "Accept": "text/markdown;q=0.9, text/html;q=0.8",
                "Prefer": "return=consolidated",
            },
            timeout=_PROBE_TIMEOUT,
        )
        result["attempted"] = True
        result["status"] = resp.status_code
        content_type = resp.headers.get("content-type")
        result["content_type"] = content_type
        result["preference_applied"] = resp.headers.get("preference-applied")
        result["vary"] = resp.headers.get("vary")
        if not homepage_html and content_type and "html" in content_type.lower():
            body, was_truncated = _capped_body(resp.text)
            result["alternates"] = _parse_alternate_types(body)
            result["truncated"] = was_truncated and body != ""
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        pass
    return result

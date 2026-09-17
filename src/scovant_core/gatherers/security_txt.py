"""security.txt (RFC 9116) discovery: probe `/.well-known/security.txt` then
the legacy `/security.txt`, stopping at the first response that is a real
200 (not a soft-404 HTML catch-all).
"""
from __future__ import annotations

import datetime
import re

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

# Module-level so golden/unit tests can freeze "now" via
# `monkeypatch.setattr(security_txt, "today", lambda: ...)`.
today = datetime.date.today

_PATHS = ("/.well-known/security.txt", "/security.txt")
_CONTACT_RE = re.compile(r"^\s*Contact\s*:", re.I | re.M)
_EXPIRES_RE = re.compile(r"^\s*Expires\s*:\s*(.+?)\s*$", re.I | re.M)
_CANONICAL_RE = re.compile(r"^\s*Canonical\s*:\s*(\S+)\s*$", re.I | re.M)


def _shape_out(*, last_status: int | None, last_retry_after: str | None,
                last_served_as_html: bool) -> dict[str, object]:
    out: dict[str, object] = {
        "found_url": None, "status": last_status, "contact": False, "expires": None,
        "expires_valid": None, "served_as_html": last_served_as_html, "truncated": False,
        "canonical_location": None, "canonical_uris": [], "expires_parsed": None, "expired": None,
    }
    if last_status == 429:
        out["retry_after"] = last_retry_after
    return out


def _parse_iso(value: str) -> datetime.date | None:
    value = value.strip()
    try:
        if len(value) == 10:
            return datetime.date.fromisoformat(value)
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


@register_gatherer("security_txt")
def gather_security_txt(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""

    last_status: int | None = None
    last_served_as_html = False
    last_retry_after: str | None = None

    for path in _PATHS:
        url = f"{origin}{path}"
        res = client.try_fetch(url, kind="text")
        if isinstance(res, FetchError):
            # A prior path may already have answered definitively (a real
            # HTTP status). A fetch error on a LATER path must not erase
            # that answer — "404 then a network error" is still "not
            # found" (status 404), not "unmeasured" (status None). Only
            # when every path errors does `last_status` stay None.
            continue

        last_status = res.status
        last_retry_after = res.headers.get("retry-after") if res.status == 429 else None
        if res.status != 200:
            last_served_as_html = False
            continue

        served_as_html = is_soft_200_html(res.status, res.content_type, res.text, document="generic")
        last_served_as_html = served_as_html
        if served_as_html:
            continue

        contact = bool(_CONTACT_RE.search(res.text))
        m = _EXPIRES_RE.search(res.text)
        expires = m.group(1) if m else None
        expires_valid: bool | None = None
        parsed = _parse_iso(expires) if expires is not None else None
        if expires is not None:
            expires_valid = parsed is not None and parsed > today()

        return {
            "found_url": url, "status": res.status, "contact": contact, "expires": expires,
            "expires_valid": expires_valid, "served_as_html": False,
            "truncated": bool(res.truncated) and res.text != "",
            "canonical_location": path == "/.well-known/security.txt",
            "canonical_uris": _CANONICAL_RE.findall(res.text),
            "expires_parsed": parsed.isoformat() if parsed else None,
            "expired": (parsed <= today()) if parsed else None,
        }

    return _shape_out(last_status=last_status, last_retry_after=last_retry_after,
                       last_served_as_html=last_served_as_html)

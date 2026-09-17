"""Universal Commerce Protocol (UCP) discovery gatherer: one GET at
`/.well-known/ucp`, handed to the shared `check_ucp_profile` parser."""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.ucp import check_ucp_profile
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

_PATH = "/.well-known/ucp"
# Bounds the retained `text` well above machine_text's own 64 KB
# per-surface cap — see the identical rationale in gatherers/openapi.py.
_TEXT_CAP = 256 * 1024


@register_gatherer("ucp")
def gather_ucp(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""

    res = client.try_fetch(f"{origin}{_PATH}", kind="json")
    if isinstance(res, FetchError):
        return {**check_ucp_profile(None, 0), "status": None, "served_as_html": False,
                "truncated": False, "text": ""}

    status = res.status
    served_as_html = is_soft_200_html(status, res.content_type, res.text, document="openapi")
    text = res.text if status == 200 and not served_as_html else None
    truncated = bool(res.truncated) and bool(text)
    out = {**check_ucp_profile(text, status), "status": status, "served_as_html": served_as_html,
           "truncated": truncated, "text": (text or "")[:_TEXT_CAP]}
    if status == 429:
        out["retry_after"] = res.headers.get("retry-after")
    return out

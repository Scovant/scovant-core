"""Soft-404 probe (0.3.0, audit §21 / AgentReady AR-READ-02): ONE extra GET of a
path that cannot exist. A server that answers it with a 200 HTML page cannot
tell an agent a missing page from a real one. The path is derived from the
scan id, so it is unique per scan and stable for a fixed scan id (goldens)."""
from __future__ import annotations

import hashlib

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient

PROBE_PREFIX = "/scovant-core-probe-"


def probe_token(scan_id: str) -> str:
    return hashlib.sha256(scan_id.encode()).hexdigest()[:8]


def _looks_html(content_type: str, text: str) -> bool:
    head = text.lstrip()[:64].lower()
    return "text/html" in (content_type or "").lower() or head.startswith("<!doctype") or head.startswith("<html")


@register_gatherer("soft_404")
def gather_soft_404(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""
    url = f"{origin}{PROBE_PREFIX}{probe_token(getattr(ctx, 'scan_id', '') or ctx.input_url)}"
    res = client.try_fetch(url, kind="html")
    if isinstance(res, FetchError):
        return {"probed_url": url, "status": None, "final_url": None, "served_html": False,
                "redirected": False, "error": res.kind, "truncated": False}
    out = {
        "probed_url": url, "status": res.status, "final_url": res.final_url,
        "served_html": _looks_html(res.content_type, res.text),
        "redirected": bool(res.redirect_chain),
        "error": None,
        "truncated": res.truncated,
    }
    if res.status == 429:
        out["retry_after"] = res.headers.get("retry-after")
    return out

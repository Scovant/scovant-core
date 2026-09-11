from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient


@register_gatherer("http")
def gather_http(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    res = client.try_fetch(ctx.input_url, kind="html")
    if isinstance(res, FetchError):
        ctx.set_final_url(ctx.input_url)
        return {"input_url": ctx.input_url, "final_url": None, "status": None, "headers": {},
                "redirect_chain": [], "html": "", "bytes": 0, "truncated": False,
                "error": {"kind": res.kind, "message": res.message}}
    ctx.set_final_url(res.final_url)
    return {"input_url": ctx.input_url, "final_url": res.final_url, "status": res.status,
            "headers": res.headers, "redirect_chain": res.redirect_chain, "html": res.text,
            "bytes": res.bytes_len, "truncated": res.truncated, "error": None}

"""Representation-parity gatherer (CORE-MACHINE-013). Gated on
`ScanOptions.experimental` like `reference_integrity`: a non-experimental scan
issues zero requests here."""
from __future__ import annotations

import time

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.representations.fetch import (
    REPR_BODY_CAP,
    VARIANTS,
    fetch_representations,
    public_fetch_meta,
    variant_verdict,
)
from scovant_core.security.client import FetchError, SecureClient


def _fetcher(client: SecureClient):
    def fetch(url: str, headers: dict) -> dict:
        t0 = time.monotonic()
        try:
            res = client.fetch(url, kind="text", headers=headers or None)
        except FetchError as exc:
            return {"error": exc.kind}
        body = res.text or ""
        return {
            "status": res.status, "content_type": res.content_type or res.headers.get("content-type", ""),
            "vary": res.headers.get("vary"), "preference_applied": res.headers.get("preference-applied"),
            "bytes": res.bytes_len, "latency_ms": res.elapsed_ms or int((time.monotonic() - t0) * 1000),
            "truncated": bool(res.truncated) or len(body.encode("utf-8", "replace")) > REPR_BODY_CAP,
            "final_url": res.final_url, "body": body[:REPR_BODY_CAP], "error": None,
        }
    return fetch


@register_gatherer("representations")
def gather_representations(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    if not ctx.options.experimental:
        return {"attempted": False, "reason": "experimental_off", "pages": []}
    home = (ctx.origin or ctx.final_url or ctx.input_url).rstrip("/") + "/"
    urls = [home, *[u for u in ctx.options.representation_pages if u.rstrip("/") + "/" != home]]
    pages = []
    for url in urls:
        got = fetch_representations(_fetcher(client), url)
        pages.append({"url": url, "variants": {
            v: {**variant_verdict(got["html"], got[v], variant=v, page_url=url),
                "fetch": public_fetch_meta(got[v])} for v in VARIANTS}})
    return {"attempted": True, "reason": None, "pages": pages}

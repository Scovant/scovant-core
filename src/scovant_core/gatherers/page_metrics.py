"""Derived view over `pages` evidence: no network — just re-shapes each
sampled page's `parsed.page_cost` (already computed by `parse_page`)."""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import SecureClient


@register_gatherer("page_metrics")
def gather_page_metrics(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    pages = store.get("pages")["pages"]
    entries = [
        {"url": pg["url"], **pg["parsed"]["page_cost"]}
        for pg in pages
        if pg.get("parsed") is not None
    ]
    entry = pages[0]["parsed"]["page_cost"] if pages and pages[0].get("parsed") is not None else None
    return {"pages": entries, "entry": entry}

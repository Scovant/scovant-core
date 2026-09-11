"""Derived view over `pages` evidence: no network — just re-shapes each
sampled page's `parsed.forms` (already computed by `parse_page`) and rolls
up a scan-wide total."""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import SecureClient

_TOTAL_KEYS = ("forms", "inputs", "unlabeled_inputs", "unnamed_buttons", "unlabeled_selects")


@register_gatherer("forms")
def gather_forms(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    pages = store.get("pages")["pages"]
    entries = []
    totals = dict.fromkeys(_TOTAL_KEYS, 0)
    pages_parsed = 0
    for pg in pages:
        parsed = pg.get("parsed")
        if parsed is None:
            continue
        pages_parsed += 1
        f = parsed["forms"]
        entries.append({"url": pg["url"], **f})
        for key in _TOTAL_KEYS:
            totals[key] += f[key]
    return {
        "pages": entries,
        "totals": totals,
        "pages_parsed": pages_parsed,
        "pages_total": len(pages),
    }

from __future__ import annotations

from typing import Any

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_IDENTIFIER_KEYS = ("sku", "gtin", "gtin8", "gtin12", "gtin13", "gtin14", "mpn", "brand", "productID")


def _product_nodes(schema_org: list[dict[str, Any]]):
    for node in schema_org:
        t = node.get("@type", "")
        types = t if isinstance(t, list) else [t]
        if "Product" in types:
            yield node


def _has_identifiers(schema_org: list[dict[str, Any]]) -> bool:
    # A present-but-empty value (e.g. `"sku": ""`) is not an identifier —
    # require the value itself to be truthy, not merely the key to exist.
    return any(node.get(key) for node in _product_nodes(schema_org) for key in _IDENTIFIER_KEYS)


class ProductStructuredData(CoreCheck):
    id = "CORE-MACHINE-004"
    title = "Product structured data"
    category = Category.MACHINE
    profiles = frozenset({"commerce"})
    weight = 4
    severity_on_fail = Severity.HIGH
    references = ("https://schema.org/Product",)
    why_it_matters = "An agent completing a purchase needs a machine-readable Product entity with stable identifiers, not just human-facing catalog copy."
    limitations = "Only the sampled pages are checked; a product catalog not represented in the sample is not evaluated."
    cloud_extension = "Scovant Cloud crawls the full product catalog rather than a bounded sample."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        product_pages = [p for p in parsed_pages if p["parsed"]["product_data"]]
        pages_unread = len(pages) - len(parsed_pages)
        ev = {"pages_parsed": len(parsed_pages), "product_pages": [p["url"] for p in product_pages]}
        # A Product node is read out of each sampled page's JSON-LD; a page
        # cut off at the fetch cap may be missing a node (or an identifier
        # field of one) that sat past it, so every verdict below — including
        # "no product page exposes a Product entity" — cannot claim full
        # confidence when any contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)
        if not product_pages:
            if pages_unread > 0:
                ev["unread"] = pages_unread
            return self.result(CheckStatus.FAIL, "No product page in the sampled set exposes a Product entity." + note, evidence=ev,
                               confidence=conf, remediation='Add JSON-LD with "@type": "Product" to product pages.')
        has_identifiers = any(_has_identifiers(p["parsed"]["schema_org"]) for p in product_pages)
        ev["has_identifiers"] = has_identifiers
        if has_identifiers:
            return self.result(CheckStatus.PASS, "A sampled product page exposes a Product entity with an identifier." + note,
                               evidence=ev, confidence=conf)
        if pages_unread > 0:
            ev["unread"] = pages_unread
        return self.result(CheckStatus.WARN, "A Product entity exists but carries no identifiers." + note, evidence=ev,
                           confidence=conf, remediation="Add a stable identifier (sku, gtin, mpn, or brand) to the Product entity.")

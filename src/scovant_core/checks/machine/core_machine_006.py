from __future__ import annotations

from typing import Any

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.checks.machine.core_machine_004 import _IDENTIFIER_KEYS, _product_nodes
from scovant_core.models import Category, CheckStatus, Severity


class ProductIdentifierCount(CoreCheck):
    id = "CORE-MACHINE-006"
    title = "Product identifier count"
    category = Category.MACHINE
    profiles = frozenset({"commerce"})
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://schema.org/Product",)
    why_it_matters = "Two or more stable identifiers (sku, gtin, mpn, brand, ...) let an agent match the same product across catalogs and marketplaces with confidence; a single identifier is a weak, ambiguous match."
    limitations = "Only the sampled pages are checked; a product catalog not represented in the sample is not evaluated."
    cloud_extension = "Scovant Cloud checks identifier coverage across the full sampled catalog, not just the pages in this scan."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        product_nodes = [n for p in parsed_pages for n in _product_nodes(p["parsed"]["schema_org"])]
        if not product_nodes:
            # Same absence-from-a-body class as CORE-MACHINE-005's N/A: the
            # Product nodes are read out of each sampled page's JSON-LD, so a
            # page read only in part cannot support "no Product entity was
            # found" at full confidence.
            na_ev: dict[str, Any] = {}
            na_note, na_truncated = record_truncation(
                {"truncated": any(p.get("truncated") for p in parsed_pages)}, na_ev)
            return self.na("No Product entity was found; evaluated by CORE-MACHINE-004." + na_note,
                           na_ev, confidence=truncated_confidence(na_truncated))
        present_keys = sorted({key for node in product_nodes for key in _IDENTIFIER_KEYS if node.get(key)})
        ev: dict[str, Any] = {"pages_parsed": len(parsed_pages), "identifier_keys": present_keys, "count": len(present_keys)}
        # The identifier fields are read out of each sampled page's JSON-LD;
        # a page cut off at the fetch cap may be missing an identifier that
        # sat past it, so the count below cannot claim full confidence when
        # any contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)
        if len(present_keys) >= 2:
            return self.result(CheckStatus.PASS, "Product entities declare two or more stable identifiers." + note,
                               evidence=ev, confidence=conf)
        pages_unread = len(pages) - len(parsed_pages)
        if pages_unread > 0:
            ev["unread"] = pages_unread
        if len(present_keys) == 1:
            return self.result(CheckStatus.WARN, "Product entities declare only one stable identifier (weak identity)." + note,
                               evidence=ev, confidence=conf,
                               remediation="Add a second stable identifier (sku, gtin, mpn, or brand) to the Product entity.")
        return self.result(CheckStatus.WARN, "Product entities declare no stable identifiers." + note, evidence=ev,
                           confidence=conf, remediation="Add a stable identifier (sku, gtin, mpn, or brand) to the Product entity.")

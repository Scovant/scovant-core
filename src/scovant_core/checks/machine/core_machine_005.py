from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_FIELDS = (("price", "price"), ("currency", "priceCurrency"), ("availability", "availability"))


class OfferCompleteness(CoreCheck):
    id = "CORE-MACHINE-005"
    title = "Offer price, currency, and availability"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    profiles = frozenset({"commerce"})
    weight = 4
    severity_on_fail = Severity.HIGH
    references = ("https://schema.org/Offer",)
    why_it_matters = "An agent cannot decide whether to buy without knowing the price, currency, and stock status up front."
    limitations = "Only the first sampled page that exposes a Product entity is checked."
    cloud_extension = "Scovant Cloud checks Offer completeness across the full sampled catalog, not just the first product page."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        product_pages = [p for p in parsed_pages if p["parsed"]["product_data"]]
        if not product_pages:
            # "No page exposes a Product entity" is an absence claim read out
            # of the sampled page BODIES — a page cut off at the fetch cap may
            # have carried the Product entity past the cut — so this branch
            # declares the partial read exactly as CORE-MACHINE-004 does on
            # the identical predicate. Delegating the verdict to another
            # check does not make silence here honest: this finding is
            # published on its own, with its own confidence.
            na_ev: dict = {}
            na_note, na_truncated = record_truncation(
                {"truncated": any(p.get("truncated") for p in parsed_pages)}, na_ev)
            return self.na("No page exposes a Product entity; evaluated by CORE-MACHINE-004." + na_note,
                           na_ev, confidence=truncated_confidence(na_truncated))
        page = product_pages[0]
        pd = page["parsed"]["product_data"]
        # A numeric `0` (e.g. a free item's price) is a real declared value,
        # not a missing one — `not pd.get(field)` would wrongly treat it as
        # absent. `extract_product_data` (parsers/html.py, shared with
        # Cloud) may itself collapse an explicit `0` via `or`-chaining
        # against a fallback field; that upstream behavior is out of scope
        # here and is left unchanged.
        missing = [schema_prop for field, schema_prop in _FIELDS
                   if pd.get(field) is None or pd.get(field) == ""]
        ev = {"url": page["url"], "price": pd.get("price"), "currency": pd.get("currency"),
              "availability": pd.get("availability"), "missing": missing}
        # The Offer fields are read out of THIS page's JSON-LD — a page cut
        # off at the fetch cap may be missing a field that sat past it.
        note, truncated = record_truncation(page, ev)
        conf = truncated_confidence(truncated)
        if not missing:
            return self.result(CheckStatus.PASS, "The product's Offer declares price, currency, and availability." + note,
                               evidence=ev, confidence=conf)
        if len(missing) == len(_FIELDS):
            return self.result(CheckStatus.FAIL, "The Product entity has no Offer with price, currency, or availability." + note,
                               evidence=ev, confidence=conf,
                               remediation="Add an Offer with price, priceCurrency, and availability to the Product entity.")
        return self.result(CheckStatus.WARN, "The Offer is missing " + ", ".join(missing) + "." + note, evidence=ev,
                           confidence=conf, remediation="Add " + ", ".join(missing) + " to the product's Offer.")

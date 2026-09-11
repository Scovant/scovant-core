"""CORE-TRUST-007: Pricing discoverability. Two independent signals feed
this, checked in order: a discovered `pricing` policy page (`gatherers/
policy_pages.py`, visible or structured price text on it) first; then, when
no pricing page was found, a commerce product page's own structured price
(`pages[*].parsed.product_data.price`, the same field CORE-MACHINE-005/012
read) — this fallback is entry-page-independent by construction (it reads
`store.get("pages")` directly, never `policy_pages`'s own entry-parse
gate), so an unparsed entry page never hides a real structured price found
on a non-entry sampled page. Only when NEITHER signal is available does an
unparsed entry page finally matter, and even then it demotes to ERROR
(unmeasured), never N/A."""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus


class PricingDiscoverability(CoreCheck):
    id = "CORE-TRUST-007"
    title = "Pricing discoverability"
    category = Category.TRUST
    profiles = frozenset({"saas", "commerce"})
    weight = 3
    references = ("https://schema.org/Offer",)
    why_it_matters = (
        "An agent comparing options or completing a purchase on a user's behalf needs a readable price — "
        "one it can extract as text or structured data, not one rendered only by client-side script."
    )
    limitations = "Pricing-page discovery follows only a same-origin link from the entry page; the structured-price fallback checks only the sampled pages."
    cloud_extension = "Scovant Cloud checks pricing across the full sampled page set and renders client-side pricing widgets to verify agent-visibility."

    def evaluate(self, store, ctx):
        policy = store.get("policy_pages")
        pricing_page = None if policy.get("entry_unparsed") else policy["pages"].get("pricing")
        entry_pages = store.get("pages")["pages"]
        entry_page = entry_pages[0] if entry_pages else None

        if pricing_page is not None:
            ev = {
                "url": pricing_page["url"], "status": pricing_page["status"],
                "has_price_text": pricing_page["has_price_text"],
                "has_structured_price": pricing_page["has_structured_price"],
            }
            if pricing_page["status"] is None:
                return self.error("the pricing page could not be read.", ev)
            # `pricing_page` is exactly one document (not `policy_pages`'
            # own folded record, which ORs shipping/returns/privacy/terms/
            # pricing together) — the label is honest here.
            note, truncated = record_truncation(pricing_page, ev, document="pricing page")
            conf = truncated_confidence(truncated)
            if pricing_page["has_price_text"] or pricing_page["has_structured_price"]:
                return self.result(CheckStatus.PASS, "A pricing page was found with a readable price." + note,
                                   evidence=ev, confidence=conf)
            return self.result(
                CheckStatus.WARN,
                "A pricing page was found but no readable price (visible text or structured data) was found on it." + note,
                evidence=ev, confidence=conf,
                remediation="Expose price as visible text or structured data (schema.org Offer/PriceSpecification) on the pricing page.",
            )

        if ctx.profile == "commerce":
            pages = store.get("pages")["pages"]
            parsed_pages = [p for p in pages if p.get("parsed")]
            priced = next(
                (p for p in parsed_pages if p["parsed"]["product_data"] and p["parsed"]["product_data"].get("price")),
                None,
            )
            if priced is not None:
                ev = {"url": priced["url"], "structured_price": priced["parsed"]["product_data"]["price"]}
                note, truncated = record_truncation(priced, ev, document="product page")
                conf = truncated_confidence(truncated)
                return self.result(CheckStatus.PASS, "Prices are exposed as structured product data." + note,
                                   evidence=ev, confidence=conf)

        if policy.get("entry_unparsed"):
            return self.error("the entry page could not be read, so a pricing page could not be discovered.")

        # Every input this absence claim rests on is a document body that
        # could have been cut off at the fetch cap: the entry page (whose
        # links are the only route to a pricing page), each fetched policy
        # page (a pricing page read only in part may not show its price
        # markup), and — on commerce — the sampled product pages searched
        # for a structured price. So the claim is declared as a partial read
        # whenever ANY of them was truncated. No `document=` label: the
        # verdict aggregates over several distinctly-named documents, so no
        # single name would be honest.
        contributing = [bool(entry_page.get("truncated")) if entry_page else False,
                        bool(policy.get("truncated"))]
        if ctx.profile == "commerce":
            contributing.append(any(p.get("truncated") for p in entry_pages if p.get("parsed")))
        na_ev: dict = {}
        na_note, na_truncated = record_truncation({"truncated": any(contributing)}, na_ev)
        return self.na("No pricing signal (a pricing page or a structured product price) was found." + na_note,
                       na_ev, confidence=truncated_confidence(na_truncated))

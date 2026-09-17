from __future__ import annotations

from typing import Any

from scovant_core.analysis.prices import parse_price_value
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_AMBIGUOUS_DISTINCT_VALUES = 3


class VisibleVsStructuredPrice(CoreCheck):
    id = "CORE-MACHINE-012"
    title = "Visible vs. structured price"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    profiles = frozenset({"commerce"})
    weight = 3
    severity_on_fail = Severity.MEDIUM
    experimental = True
    references = ("https://schema.org/price",)
    why_it_matters = "An agent that reads the structured price but a human-visible price disagrees will either quote the wrong number or abandon the page as untrustworthy."
    limitations = "This is a fragile heuristic: the visible-price regex only matches a narrow set of currency-marked formats, and it compares only the first product page found."
    promotion_criteria = (
        "≥ 300 canonical scans of commerce product pages, sampling more than the first product page "
        "found; a false-positive review of the visible-price regex across non-Latin digits and "
        "currency formats it does not yet match; a measured visible-versus-structured disagreement "
        "rate stable across two consecutive corpus snapshots; then a scored weight and a "
        "RULESET_VERSION bump."
    )
    cloud_extension = "Scovant Cloud checks visible-vs-structured price agreement across the full sampled catalog and a broader set of currency formats."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        page = next((p for p in parsed_pages if p["parsed"]["product_data"] and p["parsed"]["product_data"].get("price")), None)
        if page is None:
            # The structured price is read out of each sampled page's JSON-LD,
            # so "no sampled page exposes one" is an absence claim drawn from
            # those bodies — a page cut off at the fetch cap may have carried
            # the price past the cut.
            na_ev: dict[str, Any] = {}
            na_note, na_truncated = record_truncation(
                {"truncated": any(p.get("truncated") for p in parsed_pages)}, na_ev)
            return self.na("No sampled page exposes a structured product price; "
                           "evaluated by CORE-MACHINE-004/005." + na_note,
                           na_ev, confidence=truncated_confidence(na_truncated))
        pd = page["parsed"]["product_data"]
        structured_price = pd["price"]
        visible_prices = page["parsed"]["visible_prices"]
        pages_unread = len(pages) - len(parsed_pages)
        ev: dict[str, Any] = {
            "pages_parsed": len(parsed_pages), "url": page["url"],
            "structured_price": structured_price, "visible_prices": visible_prices,
        }
        # Both the structured price and the visible-text prices are read out
        # of THIS page's HTML; a page cut off at the fetch cap may be
        # missing a visible price (or the structured price itself) that sat
        # past it, so every verdict below cannot claim full confidence.
        note, truncated = record_truncation(page, ev)
        conf = truncated_confidence(truncated)
        if not visible_prices:
            if pages_unread > 0:
                ev["unread"] = pages_unread
            return self.result(CheckStatus.NA,
                               "No visible-text prices were found on the page to compare against the structured price." + note,
                               evidence=ev, confidence=conf, severity=Severity.INFO)
        parsed_visible = {v for v in (parse_price_value(s) for s in visible_prices) if v is not None}
        structured_value = parse_price_value(str(structured_price))
        ev.update(parsed_visible_values=sorted(parsed_visible), structured_value=structured_value,
                  distinct_visible_values=len(parsed_visible))
        if structured_value is not None and structured_value in parsed_visible:
            if len(parsed_visible) > _AMBIGUOUS_DISTINCT_VALUES:
                if pages_unread > 0:
                    ev["unread"] = pages_unread
                return self.result(CheckStatus.WARN,
                                   "The structured price matches a visible price, but many distinct visible prices "
                                   "make the match ambiguous." + note, evidence=ev, confidence=conf,
                                   remediation="Reduce the number of distinct visible prices on the page, or make the "
                                               "structured price's context unambiguous.")
            return self.result(CheckStatus.PASS, "The structured price matches a visible price on the page." + note,
                               evidence=ev, confidence=conf)
        if pages_unread > 0:
            ev["unread"] = pages_unread
        if structured_value is None:
            return self.result(CheckStatus.FAIL, "The structured price could not be parsed as a number." + note, evidence=ev,
                               confidence=conf, remediation="Make the structured Offer price a plain numeric value.")
        return self.result(CheckStatus.FAIL, "The structured price does not match any visible price on the page." + note, evidence=ev,
                           confidence=conf, remediation="Make the structured Offer price agree with the price shown to a human visitor.")

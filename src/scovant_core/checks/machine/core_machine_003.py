from __future__ import annotations

from typing import Any

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


def _has_site_or_page_node(schema_org: list[dict[str, Any]]) -> bool:
    for node in schema_org:
        t = node.get("@type", "")
        types = t if isinstance(t, list) else [t]
        if "WebSite" in types or "WebPage" in types:
            return True
    return False


class WebSiteOrPageEntity(CoreCheck):
    id = "CORE-MACHINE-003"
    title = "WebSite/WebPage entity"
    category = Category.MACHINE
    weight = 1
    severity_on_fail = Severity.LOW
    references = ("https://schema.org/WebSite", "https://schema.org/WebPage")
    why_it_matters = "A WebSite or WebPage entity anchors the rest of a site's structured data to a concrete machine-readable resource."
    limitations = "Only the schema_org nodes on the sampled pages are checked."
    cloud_extension = "Scovant Cloud checks WebSite/WebPage declarations across the full crawl, not just the sampled pages."
    standards = ("AR-READ-08",)

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        found = any(_has_site_or_page_node(p["parsed"]["schema_org"]) for p in parsed_pages)
        ev: dict[str, Any] = {"pages_parsed": len(parsed_pages), "found": found}
        # A WebSite/WebPage node is read out of each sampled page's JSON-LD;
        # a page cut off at the fetch cap may be missing a node that sat
        # past it, so this verdict cannot claim full confidence when any
        # contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)
        if found:
            return self.result(CheckStatus.PASS, "A WebSite or WebPage entity was found on the sampled pages." + note,
                               evidence=ev, confidence=conf)
        pages_unread = len(pages) - len(parsed_pages)
        if pages_unread > 0:
            ev["unread"] = pages_unread
        return self.result(CheckStatus.WARN, "No WebSite or WebPage entity was found on the sampled pages." + note, evidence=ev,
                           confidence=conf, remediation='Add JSON-LD with "@type": "WebSite" or "WebPage".')

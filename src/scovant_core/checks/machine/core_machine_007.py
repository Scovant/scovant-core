from __future__ import annotations

from typing import Any

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class Breadcrumbs(CoreCheck):
    id = "CORE-MACHINE-007"
    title = "Breadcrumbs"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    profiles = frozenset({"content", "commerce", "saas"})
    weight = 1
    severity_on_fail = Severity.LOW
    references = ("https://schema.org/BreadcrumbList",)
    why_it_matters = "A BreadcrumbList tells an agent where a page sits in a site's hierarchy without it having to infer structure from navigation markup."
    limitations = "Only the non-entry pages in the sampled set are checked."
    cloud_extension = "Scovant Cloud checks breadcrumb coverage across the full sampled catalog, not just the pages in this scan."

    def evaluate(self, store, ctx):
        data = store.get("pages")
        pages, selection = data["pages"], data["selection"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        non_entry = [p for p, s in zip(pages, selection, strict=True) if s["reason"] != "entry"]
        if not non_entry:
            return self.na("Only the entry page was sampled; there are no additional pages to check for breadcrumbs.")
        non_entry_parsed = [p for p in non_entry if p.get("parsed")]
        unread = len(non_entry) - len(non_entry_parsed)
        if not non_entry_parsed:
            # Every non-entry page we sampled failed to fetch/parse (a 5xx,
            # a network error, ...) — that is OUR read failing, never
            # evidence of a missing breadcrumb. Reporting WARN here would
            # blame the site for our own fetch failure.
            return self.error("no sampled non-entry page could be read.",
                              {"non_entry_sampled": len(non_entry), "non_entry_parsed": 0, "unread": unread})
        has_breadcrumb = any(p["parsed"]["breadcrumb"] for p in non_entry_parsed)
        ev: dict[str, Any] = {
            "non_entry_pages": [p["url"] for p in non_entry],
            "non_entry_parsed": len(non_entry_parsed),
            "has_breadcrumb": has_breadcrumb,
        }
        # A BreadcrumbList node is read out of each sampled non-entry page's
        # JSON-LD; a page cut off at the fetch cap may be missing a node
        # that sat past it, so this verdict cannot claim full confidence
        # when any contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in non_entry_parsed)}, ev)
        conf = truncated_confidence(truncated)
        if has_breadcrumb:
            return self.result(CheckStatus.PASS, "A sampled non-entry page declares a BreadcrumbList." + note,
                               evidence=ev, confidence=conf)
        # unread only surfaces on the WARN branch: a WARN is a real finding
        # about the site, and the reader should be able to see how much of
        # the sample it's actually based on (a PASS needed only one
        # breadcrumb to already be conclusive, so it's omitted there).
        return self.result(CheckStatus.WARN, "No sampled non-entry page declares a BreadcrumbList." + note,
                           evidence={**ev, "unread": unread}, confidence=conf,
                           remediation='Add JSON-LD with "@type": "BreadcrumbList" to non-homepage pages.')

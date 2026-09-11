from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class ContactDiscoverability(CoreCheck):
    id = "CORE-TRUST-001"
    title = "Contact/support discoverability"
    category = Category.TRUST
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://schema.org/ContactPoint",)
    why_it_matters = "An agent acting on a user's behalf needs a way to escalate to a human — a contact, support, or mailto link — when it hits a case it cannot resolve itself."
    limitations = "Only the entry page's anchors are scanned; a contact method reachable only from a deeper page is not found."
    cloud_extension = "Scovant Cloud checks contact reachability across the full sampled page set, not only the entry page."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be read.", {"entry_url": ctx.final_url})

        contact = store.get("contact")
        ev = {"contact_url": contact["contact_url"], "kind": contact["kind"]}
        # `contact` is scanned out of the entry page's own anchors
        # (`gatherers/contact.py` reads the same fetched HTML as `pages[0]`)
        # — a page cut off at the fetch cap may be hiding a contact/mailto
        # link that sat past it, so every verdict below must say so.
        note, truncated = record_truncation(entry, ev, document="entry page")
        conf = truncated_confidence(truncated)

        if contact["kind"] in ("page", "mailto"):
            return self.result(CheckStatus.PASS, "A contact or support link was found on the entry page." + note,
                               evidence=ev, confidence=conf)

        if contact["kind"] == "social":
            return self.result(
                CheckStatus.WARN,
                "Only a social-profile link was found; no direct contact or support page." + note,
                evidence=ev, confidence=conf,
                remediation="Add a direct contact or support page (or a mailto link), not only a social profile.",
            )

        return self.result(
            CheckStatus.WARN, "No contact or support link found on the entry page." + note, evidence=ev, confidence=conf,
            remediation="Add a clearly labeled contact or support link (a page or a mailto link) to the entry page.",
        )

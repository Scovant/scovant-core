"""CORE-TRUST-003: Returns/refund policy discoverability, read from
`gatherers/policy_pages.py`'s `returns` record."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.checks.trust._policy import policy_verdict
from scovant_core.models import Category, CheckStatus


class ReturnsPolicyDiscoverability(CoreCheck):
    id = "CORE-TRUST-003"
    title = "Returns/refund policy discoverability"
    category = Category.TRUST
    profiles = frozenset({"commerce"})
    weight = 2
    references = ("https://schema.org/MerchantReturnPolicy",)
    why_it_matters = (
        "An agent purchasing on a user's behalf needs to know whether and how a purchase can be returned "
        "before it commits — a missing or unreadable returns policy is a real trust gap, not a cosmetic one."
    )
    limitations = "Only a same-origin link discovered from the entry page's nav/footer/anchors is followed; a returns policy reachable only from a deeper page is not found."
    cloud_extension = "Scovant Cloud crawls the full sampled page set for a returns-policy link, not only the entry page."

    def evaluate(self, store, ctx):
        policy = store.get("policy_pages")
        if policy.get("entry_unparsed"):
            return self.error("the entry page could not be read, so policy links could not be discovered.")

        page = policy["pages"].get("returns")
        status, summary, evidence, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="returns/refund policy page")
        remediation = (
            "" if status == CheckStatus.PASS
            else "Publish a returns/refund policy page and link it from the entry page's nav or footer."
        )
        return self.result(status, summary, evidence=evidence, confidence=confidence, remediation=remediation)

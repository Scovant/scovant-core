"""CORE-TRUST-002: Shipping policy discoverability, read from
`gatherers/policy_pages.py`'s `shipping` record."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.checks.trust._policy import policy_verdict
from scovant_core.models import Category, CheckStatus


class ShippingPolicyDiscoverability(CoreCheck):
    id = "CORE-TRUST-002"
    title = "Shipping policy discoverability"
    category = Category.TRUST
    verification_mode = "DECLARED"
    profiles = frozenset({"commerce"})
    weight = 2
    references = ("https://schema.org/DeliveryTimeSettings",)
    why_it_matters = (
        "An agent completing a purchase on a user's behalf needs to know shipping cost and timing "
        "before it commits to checkout — a missing or unreadable shipping policy forces it to guess or abandon the order."
    )
    limitations = "Only a same-origin link discovered from the entry page's nav/footer/anchors is followed; a shipping policy reachable only from a deeper page is not found."
    cloud_extension = "Scovant Cloud crawls the full sampled page set for a shipping-policy link, not only the entry page."

    def evaluate(self, store, ctx):
        policy = store.get("policy_pages")
        if policy.get("entry_unparsed"):
            return self.error("the entry page could not be read, so policy links could not be discovered.")

        page = policy["pages"].get("shipping")
        status, summary, evidence, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="shipping policy page")
        remediation = (
            "" if status == CheckStatus.PASS
            else "Publish a shipping policy page (cost, timing, carriers) and link it from the entry page's nav or footer."
        )
        return self.result(status, summary, evidence=evidence, confidence=confidence, remediation=remediation)

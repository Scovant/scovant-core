"""CORE-TRUST-005: Terms/conditions discoverability, read from
`gatherers/policy_pages.py`'s `terms` record."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.checks.trust._policy import policy_verdict
from scovant_core.models import Category, CheckStatus


class TermsDiscoverability(CoreCheck):
    id = "CORE-TRUST-005"
    title = "Terms/conditions discoverability"
    category = Category.TRUST
    verification_mode = "DECLARED"
    profiles = frozenset({"commerce", "saas", "api"})
    weight = 2
    references = ("https://schema.org/Legal",)
    why_it_matters = (
        "An agent transacting with a site — buying, subscribing, or calling an API — needs the terms it is "
        "agreeing to on behalf of a user to be readable, not buried behind a broken or missing link."
    )
    limitations = "Only a same-origin link discovered from the entry page's nav/footer/anchors is followed; terms reachable only from a deeper page are not found."
    cloud_extension = "Scovant Cloud crawls the full sampled page set for a terms/conditions link, not only the entry page."

    def evaluate(self, store, ctx):
        policy = store.get("policy_pages")
        if policy.get("entry_unparsed"):
            return self.error("the entry page could not be read, so policy links could not be discovered.")

        page = policy["pages"].get("terms")
        status, summary, evidence, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
        remediation = (
            "" if status == CheckStatus.PASS
            else "Publish a terms/conditions page and link it from the entry page's nav or footer."
        )
        return self.result(status, summary, evidence=evidence, confidence=confidence, remediation=remediation)

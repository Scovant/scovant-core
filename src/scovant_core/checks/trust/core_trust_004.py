"""CORE-TRUST-004: Privacy policy discoverability, read from
`gatherers/policy_pages.py`'s `privacy` record. Unlike its shipping/returns/
terms siblings, a public site with NO privacy page at all is a real,
high-severity defect — `missing_status=FAIL` (`severity_on_fail=HIGH`)."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.checks.trust._policy import policy_verdict
from scovant_core.models import Category, CheckStatus, Severity


class PrivacyPolicyDiscoverability(CoreCheck):
    id = "CORE-TRUST-004"
    title = "Privacy policy discoverability"
    category = Category.TRUST
    verification_mode = "DECLARED"
    weight = 2
    severity_on_fail = Severity.HIGH
    references = ("https://schema.org/PrivacyPolicy",)
    why_it_matters = (
        "An agent (and the human on whose behalf it acts) needs to know what data a site collects and how it is "
        "used before submitting any personal or payment information — a site with no privacy page at all is a real defect, not an omission."
    )
    limitations = "Only a same-origin link discovered from the entry page's nav/footer/anchors is followed; a privacy policy reachable only from a deeper page is not found."
    cloud_extension = "Scovant Cloud crawls the full sampled page set for a privacy-policy link, not only the entry page."

    def evaluate(self, store, ctx):
        policy = store.get("policy_pages")
        if policy.get("entry_unparsed"):
            return self.error("the entry page could not be read, so policy links could not be discovered.")

        page = policy["pages"].get("privacy")
        status, summary, evidence, confidence = policy_verdict(page, missing_status=CheckStatus.FAIL, label="privacy policy page")
        remediation = (
            "" if status == CheckStatus.PASS
            else "Publish a privacy policy page and link it from the entry page's nav or footer."
        )
        return self.result(status, summary, evidence=evidence, confidence=confidence, remediation=remediation)

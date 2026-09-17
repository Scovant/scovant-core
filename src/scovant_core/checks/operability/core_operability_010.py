"""CORE-OPERABILITY-010: a bot-challenge page must not be served with HTTP 200."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_MAX = 5


class ChallengeServedAs200(CoreCheck):
    id = "CORE-OPERABILITY-010"
    title = "Challenge pages are not served as 200"
    category = Category.OPERABILITY
    verification_mode = "PASSIVE_OBSERVED"
    weight = 3
    check_version = "1.1"
    severity_on_fail = Severity.HIGH
    references = ("https://www.rfc-editor.org/rfc/rfc9110#name-403-forbidden",)
    why_it_matters = "A human-verification page returned with HTTP 200 is read by an agent as the page's content: it will summarise, quote or cache the challenge as if it were the site."
    limitations = "Only the entry response and the sampled pages are inspected; a challenge served with an honest 403/429/503 is not a defect here (the access checks cover blocking)."
    cloud_extension = "Scovant Cloud classifies WAF and challenge behaviour across identities and over time."

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http["error"]:
            return self.error(f"the entry URL could not be fetched ({http['error']['kind']}).", {"error": http["error"]["kind"]})
        pages = (store.try_get("pages") or {}).get("pages", [])
        candidates = [{"url": http.get("final_url") or http["input_url"], "status": http["status"], "bot_protection": http.get("bot_protection")}]
        candidates += [{"url": p["url"], "status": p["status"], "bot_protection": p.get("bot_protection")} for p in pages]
        served_200 = [c for c in candidates if (c["bot_protection"] or {}).get("blocked") and c["status"] == 200]
        honest = [c for c in candidates if (c["bot_protection"] or {}).get("blocked") and c["status"] != 200]
        ev = {"pages": [{"url": c["url"], "status": c["status"], "provider": (c["bot_protection"] or {}).get("provider")} for c in served_200[:_MAX]],
              "honest_challenges": len(honest), "pages_checked": len(candidates)}
        if served_200:
            return self.result(CheckStatus.FAIL, f"{len(served_200)} page(s) serve a bot-challenge with HTTP 200 — an agent reads the challenge as content.",
                               evidence=ev, remediation="Serve challenge pages with 403 or 503 (and Retry-After where applicable) so agents can distinguish them from content.")
        if honest and len(honest) == sum(1 for c in candidates if c["status"] is not None):
            return self.na("Every fetched page was a challenge served with an honest non-200 status.", ev)
        return self.result(CheckStatus.PASS, "No challenge page is served with HTTP 200.", evidence=ev)

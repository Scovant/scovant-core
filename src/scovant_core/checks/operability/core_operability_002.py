"""CORE-OPERABILITY-002: redirect chain complexity. Reads the `http` entry
response record. Deliberately narrow in scope: `CORE-ACCESS-001` owns
reachability (any fetch failure there is FAIL) — this check reports only the
shape of the redirect chain itself, and only WARNs, never FAILs, because a
site that redirects a lot but still resolves is a friction cost for an agent,
not an access failure."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.security.url_safety import display_url, redact_message

_MAX_REDIRECTS_OK = 2


class RedirectComplexity(CoreCheck):
    id = "CORE-OPERABILITY-002"
    title = "Redirect chain complexity"
    category = Category.OPERABILITY
    verification_mode = "PASSIVE_OBSERVED"
    weight = 1
    severity_on_fail = Severity.LOW
    references = ("https://www.rfc-editor.org/rfc/rfc9110#name-redirection-3xx",)
    why_it_matters = "Every redirect hop is a round trip an agent pays for before it reaches real content; a long or looping chain wastes budget CORE-ACCESS-001 already spent getting there."
    limitations = "Only the entry URL's own redirect chain is inspected; redirects encountered while fetching other sampled pages are not counted here."
    cloud_extension = "Scovant Cloud tracks redirect chains across every sampled page and over time."

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http["error"]:
            err = {**http["error"], "message": redact_message(http["error"]["message"], http["input_url"])}
            if http["error"]["kind"] == "network" and "too many redirects" in http["error"]["message"].lower():
                ev = {"error": err}
                return self.result(
                    CheckStatus.WARN, "The entry URL's redirect chain loops or exceeds the hop limit before settling.",
                    evidence=ev, severity=Severity.MEDIUM,
                    remediation="Collapse the redirect chain to at most one hop and eliminate any redirect loop.",
                )
            return self.error(f"the entry URL could not be fetched ({http['error']['kind']}).", {"error": err})

        redirect_count = len(http["redirect_chain"])
        ev = {"redirect_chain": [display_url(u) for u in http["redirect_chain"]], "redirect_count": redirect_count}
        if redirect_count <= _MAX_REDIRECTS_OK:
            return self.result(CheckStatus.PASS, f"The entry URL redirects {redirect_count} time(s) before settling.", evidence=ev)
        return self.result(
            CheckStatus.WARN, f"The entry URL redirects {redirect_count} times before settling.", evidence=ev,
            remediation="Collapse the redirect chain to at most one hop.",
        )

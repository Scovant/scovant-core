from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_RANK = {"FAIL": 3, "WARN": 2, "PASS": 1}


class RepresentationParity(CoreCheck):
    id = "CORE-MACHINE-013"
    title = "Agent representations match the HTML page"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    severity_on_fail = Severity.MEDIUM
    experimental = True
    references = ("https://www.rfc-editor.org/rfc/rfc7240",)
    why_it_matters = ("An agent that reads a site's Markdown or consolidated representation trusts it; "
                      "a version that drops prices or links misleads the agent more than no version at all.")
    limitations = ("Compares the homepage (and pages given with --page) only. Prices are recognised only "
                   "with the symbols $ € £ ¥ or a short list of ISO codes; token figures are estimates.")
    promotion_criteria = ("≥ 300 canonical scans with at least one offered representation; a false-positive "
                          "review of link and entity extraction on Markdown; stable FAIL/WARN rates across two "
                          "consecutive corpus snapshots; then promotion out of experimental and a "
                          "RULESET_VERSION bump.")
    cloud_extension = "Scovant Cloud compares the homepage and the site's most important page on every scan."

    def evaluate(self, store, ctx):
        g = store.get("representations")
        if not g.get("attempted"):
            return self.na("Representation parity runs only with --experimental.", {"reason": g.get("reason")})
        statuses = [vv["status"] for p in g["pages"] for vv in p["variants"].values()]
        ev = {"pages": [{"url": p["url"], "variants": {k: {"status": vv["status"], "reason": vv["reason"],
                                                           "compare": vv["compare"]}
                                                       for k, vv in p["variants"].items()}}
                        for p in g["pages"]]}
        compared = [s for s in statuses if s in _RANK]
        if compared:
            worst = max(compared, key=_RANK.__getitem__)
            if worst == "PASS":
                return self.result(CheckStatus.PASS, "Every offered representation carries the HTML page's "
                                   "prices, links and entities.", evidence=ev)
            return self.result(CheckStatus(worst),
                               "An agent representation is missing content the HTML page shows.",
                               evidence=ev,
                               remediation="Generate the Markdown or consolidated version from the same "
                                           "source as the HTML page, including prices and in-content links.")
        if all(s == "NA" for s in statuses):
            return self.na("The site offers no Markdown or consolidated representation (Core has no "
                           "presence check for it; Scovant Cloud's MARKDOWN_FOR_AGENTS_ABSENT rule covers it).", ev)
        return self.error("No representation could be compared (fetch failures or truncated reads).", ev)

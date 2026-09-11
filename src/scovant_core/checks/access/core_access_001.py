from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class HttpsReachability(CoreCheck):
    id = "CORE-ACCESS-001"
    title = "HTTPS reachability"
    category = Category.ACCESS
    weight = 2
    severity_on_fail = Severity.CRITICAL
    references = ("https://www.rfc-editor.org/rfc/rfc9110",)
    why_it_matters = "An agent that cannot complete a request against the entry URL cannot use anything else the site declares."
    cloud_extension = "Scovant Cloud tests reachability from real agent network paths and multiple regions."
    MAX_REDIRECTS_OK = 2

    def evaluate(self, store, ctx):
        http = store.get("http")
        ev = {"input_url": http["input_url"], "final_url": http["final_url"], "status": http["status"],
              "redirect_chain": http["redirect_chain"], "redirect_count": len(http["redirect_chain"])}
        if http["error"]:
            ev["error"] = http["error"]
            return self.result(CheckStatus.FAIL, f"The entry URL could not be fetched ({http['error']['kind']}).", evidence=ev,
                               remediation="Make the HTTPS entry URL respond with a 2xx status.")
        if not (http["final_url"] or "").startswith("https://"):
            return self.result(CheckStatus.FAIL, "The final URL is not served over HTTPS.", evidence=ev,
                               remediation="Serve the site over HTTPS and redirect http:// to https://.")
        if http["status"] >= 400:
            return self.result(CheckStatus.FAIL, f"The entry URL answered HTTP {http['status']}.", evidence=ev,
                               remediation="Return 200 for the public entry page.")
        if ev["redirect_count"] > self.MAX_REDIRECTS_OK:
            return self.result(CheckStatus.WARN, f"The entry URL redirects {ev['redirect_count']} times before settling.",
                               evidence=ev, severity=Severity.LOW, remediation="Collapse the redirect chain to at most one hop.")
        return self.result(CheckStatus.PASS, f"HTTPS entry URL answered {http['status']}.", evidence=ev)

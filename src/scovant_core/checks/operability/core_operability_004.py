"""CORE-OPERABILITY-004: broken machine endpoints. Reads the machine_links
inventory (sitemap document, llms.txt references, an OpenAPI spec, the
declared MCP endpoint, policy links, the canonical URL).

Three outcomes per reference, and only one of them is a finding:

* `broken` — the server answered with a REAL status that says the reference
  is dead (404/410, or any non-2xx/3xx). This is evidence about the site.
* `unresolved` — OUR fetch failed (`status is None`: DNS, connect, timeout).
  A document we could not read is never a finding, whatever the source
  declaring it: reporting a transient failure of our own client as a dead
  link the site published is a false accusation, not a conservative one.
* `inconclusive` — the reference is not probeable by Core at all (`ok is
  None`), which today means a declared MCP endpoint: it speaks JSON-RPC over
  POST and Core never performs the handshake, so a GET's status carries no
  verdict either way.

When NOTHING was judged, WHY decides the status rather than the check passing
on an empty inspection: any reference our own client failed to fetch makes the
result unmeasured (ERROR, which lowers coverage); only when every reference
answered with a real status and none of them is probeable by Core is there
genuinely nothing to evaluate (N/A). The FAIL summary counts broken references
against the references actually RESOLVED, never against ones we never read.
"""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_DEAD_STATUSES = {404, 410}
_MAX_EXAMPLES = 5


class BrokenMachineEndpoints(CoreCheck):
    id = "CORE-OPERABILITY-004"
    title = "Broken machine-consumable endpoints"
    category = Category.OPERABILITY
    weight = 3
    severity_on_fail = Severity.HIGH
    references = ("https://llmstxt.org/", "https://www.sitemaps.org/protocol.html")
    why_it_matters = "A declared machine reference that 404s wastes an agent's time and budget following a dead link the site itself pointed it at."
    limitations = "Only the capped set of references collected by the machine_links gatherer are checked; endpoints not linked from any declared document are not found. A declared MCP endpoint is recorded but never judged — Core does not perform the MCP handshake."
    cloud_extension = "Scovant Cloud checks a much larger set of machine-consumable endpoints and revisits them on a schedule."
    standards = ("AR-READ-02",)

    def evaluate(self, store, ctx):
        refs = store.get("machine_links")["refs"]
        if not refs:
            return self.na("No machine-consumable references were discovered to check.")

        broken, unresolved, inconclusive = [], [], []
        for r in refs:
            if r["status"] is None:
                unresolved.append(r)
            elif r.get("ok") is None:
                inconclusive.append(r)
            elif r["status"] in _DEAD_STATUSES or not r["ok"]:
                broken.append(r)

        resolved_count = len(refs) - len(unresolved) - len(inconclusive)
        ev = {
            "refs_checked": len(refs),
            "refs_resolved": resolved_count,
            "broken_count": len(broken),
            "broken": [{"url": r["url"], "source": r["source"], "status": r["status"]} for r in broken[:_MAX_EXAMPLES]],
            "unresolved": [{"url": r["url"], "source": r["source"]} for r in unresolved],
            "inconclusive": [{"url": r["url"], "source": r["source"], "status": r["status"]} for r in inconclusive],
        }

        if broken:
            return self.result(
                CheckStatus.FAIL,
                f"{len(broken)} of {resolved_count} machine-consumable reference(s) do not resolve.",
                evidence=ev,
                remediation="Fix or remove the broken references (sitemap, llms.txt, OpenAPI spec, policy links) so agents don't hit dead links.",
            )
        if resolved_count == 0:
            # Nothing was judged. WHY decides the status: if any reference
            # failed OUR fetch, this is unmeasured evidence (ERROR, which
            # lowers coverage). Only when every reference carried a real
            # status and none of them was probeable by Core is there
            # genuinely nothing to evaluate (N/A).
            if unresolved:
                return self.error(
                    f"{len(unresolved)} of {len(refs)} machine-consumable reference(s) "
                    "could not be resolved by Core, and none of the rest could be judged.",
                    ev,
                )
            return self.na(
                f"None of the {len(refs)} discovered machine-consumable reference(s) is probeable "
                "by Core.",
                ev,
            )
        return self.result(
            CheckStatus.PASS, f"All {resolved_count} checked machine-consumable reference(s) resolve.", evidence=ev,
        )

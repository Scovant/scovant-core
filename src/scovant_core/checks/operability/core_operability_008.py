"""CORE-OPERABILITY-008: unknown paths answer with a real 404."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class UnknownPathsReturn404(CoreCheck):
    id = "CORE-OPERABILITY-008"
    title = "Unknown paths return 404"
    category = Category.OPERABILITY
    weight = 2
    severity_on_fail = Severity.MEDIUM
    standards = ("AR-READ-02",)
    references = ("https://www.rfc-editor.org/rfc/rfc9110#name-404-not-found",)
    why_it_matters = "An agent that receives HTTP 200 for a path that does not exist cannot tell a missing page from a real one; it may read an error template as content or cache a phantom URL."
    limitations = "One extra request to a path that cannot exist (the URL is in evidence); a site that deliberately serves a 200 landing page for every path fails this check by design."
    cloud_extension = "Scovant Cloud probes several unknown paths per host and per section, and re-checks over time."

    def evaluate(self, store, ctx):
        probe = store.get("soft_404")
        ev = {k: probe[k] for k in ("probed_url", "status", "final_url", "served_html", "redirected")}
        if probe["error"]:
            return self.error(f"the probe request failed ({probe['error']}).", {**ev, "error": probe["error"]})
        status = probe["status"]
        if status in (404, 410):
            return self.result(CheckStatus.PASS, "Unknown paths answer with a real 404.", evidence=ev)
        if probe["redirected"] and 200 <= status < 300:
            return self.result(CheckStatus.WARN, "Unknown paths redirect to an existing page instead of answering 404.",
                               evidence=ev, remediation="Return 404 for paths that do not exist; do not redirect unknown URLs to a landing page.")
        if 200 <= status < 300:
            return self.result(CheckStatus.FAIL, "Unknown paths answer 200 with an HTML page (a soft-404) — agents cannot tell a missing page from a real one.",
                               evidence=ev, remediation="Return HTTP 404 (or 410) for unknown paths, with the same headers your real error page would carry.")
        return self.na(f"The probe answered {status}; that status is neither a 404 nor a soft-404 signal.", ev)

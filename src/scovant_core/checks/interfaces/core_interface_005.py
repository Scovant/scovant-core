from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class OpenApiDiscovery(CoreCheck):
    id = "CORE-INTERFACE-005"
    title = "OpenAPI discovery"
    category = Category.INTERFACES
    profiles = frozenset({"api", "saas"})
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.openapis.org/",)
    why_it_matters = "A discoverable OpenAPI document lets an agent understand and call this API's surface directly instead of reverse-engineering it from prose docs."
    limitations = "Only a fixed set of conventional paths, plus same-origin entry-page links naming openapi/swagger, are probed."
    cloud_extension = "Scovant Cloud validates the full OpenAPI document against the spec, not just that one parses."

    def evaluate(self, store, ctx):
        openapi = store.get("openapi")
        ev = {
            "found_url": openapi["found_url"],
            "parseable": openapi["parseable"],
            "openapi_version": openapi["openapi_version"],
            "candidates_checked": len(openapi["candidates"]),
        }

        if openapi["found_url"] and openapi["parseable"]:
            # Only the candidate that actually became the found spec
            # contributes to `openapi["truncated"]` (see
            # `gatherers/openapi.py`) — a single, named document, not a
            # folded record — so the label is honest.
            note, truncated = record_truncation(openapi, ev, document="OpenAPI document")
            conf = truncated_confidence(truncated)
            return self.result(CheckStatus.PASS, "An OpenAPI/Swagger document was discovered and parses." + note,
                               evidence=ev, confidence=conf)

        if openapi["found_url"] and not openapi["parseable"]:
            note, truncated = record_truncation(openapi, ev, document="OpenAPI document")
            conf = truncated_confidence(truncated)
            return self.result(
                CheckStatus.WARN, "A candidate OpenAPI document was found but does not parse as a valid spec." + note,
                evidence=ev, confidence=conf,
                remediation="Publish a valid OpenAPI document with a top-level `openapi`/`swagger` version key.",
            )

        # not found — `openapi["truncated"]` is only ever set when a
        # candidate WAS found (see `gatherers/openapi.py`), so confirmed
        # absence across every candidate never draws from a truncated read;
        # no note is added below. Separately, a definitive read failure
        # across every candidate (a real 5xx/401/403, not a real 404/410
        # or a served-as-html catch-all) is ERROR, not "not discovered";
        # `document_status` reads
        # `status`/`served_as_html` AGGREGATED across every candidate this
        # gatherer examined (see `gatherers/openapi.py`), never merely
        # whichever candidate happened to be examined last. Confirmed
        # absence keeps the check's own profile-based verdict below
        # unchanged.
        v = document_status({"status": openapi["status"], "served_as_html": openapi.get("last_served_as_html", False)},
                            what="OpenAPI document")
        if v and v.status is CheckStatus.ERROR:
            return self.error(v.reason, ev)
        if ctx.profile == "api":
            return self.result(
                CheckStatus.WARN, "No OpenAPI document discovered at the conventional paths.", evidence=ev,
                remediation="Publish an OpenAPI document at a conventional path (e.g. /openapi.json), or link to it from the entry page.",
            )
        return self.na("No OpenAPI document discovered at the conventional paths.", ev)

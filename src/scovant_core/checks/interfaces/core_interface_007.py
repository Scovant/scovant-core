"""CORE-INTERFACE-007: RFC 9728 OAuth protected-resource metadata,
read UNAUTHENTICATED at the scan target's own origin (`gatherers/oauth_metadata.py`)."""
from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class OAuthProtectedResourceMetadata(CoreCheck):
    id = "CORE-INTERFACE-007"
    title = "OAuth protected-resource metadata"
    category = Category.INTERFACES
    profiles = frozenset({"api", "saas"})
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.rfc-editor.org/rfc/rfc9728",)
    why_it_matters = (
        "An agent that receives a 401 from a protected API needs RFC 9728 protected-resource "
        "metadata to discover which authorization server to talk to, instead of dead-ending."
    )
    limitations = "Only the conventional /.well-known/oauth-protected-resource path is probed."
    cloud_extension = "Scovant Cloud exercises the discovered authorization server against a live OAuth flow, not just that the metadata document parses."
    standards = ("AR-ACT-01",)

    def evaluate(self, store, ctx):
        oauth = store.get("oauth_metadata")
        pr = oauth["protected_resource"]
        ev = {
            "resource": f"{ctx.origin}/.well-known/oauth-protected-resource",
            "http_status": pr["status"],
            "parseable": pr["parseable"],
            "served_as_html": pr["served_as_html"],
        }

        v = document_status(pr, what="OAuth protected-resource metadata")
        if v:
            if v.status is CheckStatus.ERROR:
                if pr["status"] is None:
                    return self.error("the protected-resource metadata document could not be read.", ev)
                return self.error(
                    f"the protected-resource metadata document could not be read (HTTP {pr['status']}).", ev
                )
            if pr["served_as_html"]:
                return self.na(
                    "No OAuth protected-resource metadata is published — the path is served by an HTML catch-all.",
                    ev,
                )
            return self.na("No OAuth protected-resource metadata is published.", ev)

        # Past this point the verdict is drawn from the ONE
        # protected-resource metadata document that was actually found and
        # read — `pr["truncated"]` reflects that one read alone, not
        # `oauth_metadata`'s own record-level OR against the SEPARATE
        # authorization-server document (`oauth_metadata` is a FOLDED
        # record, `pr` is not), so the label is honest.
        note, truncated = record_truncation(pr, ev, document="OAuth protected-resource metadata")
        conf = truncated_confidence(truncated)

        if pr["parseable"] and pr["resource"] and pr["authorization_servers"]:
            ev["resource_value"] = pr["resource"]
            ev["authorization_servers"] = pr["authorization_servers"]
            return self.result(CheckStatus.PASS, "OAuth protected-resource metadata is published and complete." + note,
                               evidence=ev, confidence=conf)

        return self.result(
            CheckStatus.WARN,
            "A protected-resource metadata document was found but is incomplete or does not parse." + note,
            evidence=ev, confidence=conf,
            remediation=(
                "Publish RFC 9728 metadata with `resource` and a non-empty `authorization_servers` "
                "list at /.well-known/oauth-protected-resource."
            ),
        )

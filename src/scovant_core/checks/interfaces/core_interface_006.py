"""CORE-INTERFACE-006: RFC 8414 OAuth authorization-server metadata,
read UNAUTHENTICATED at the scan target's own origin (`gatherers/oauth_metadata.py`)."""
from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class OAuthAuthorizationServerMetadata(CoreCheck):
    id = "CORE-INTERFACE-006"
    title = "OAuth authorization-server metadata"
    category = Category.INTERFACES
    profiles = frozenset({"api", "saas"})
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.rfc-editor.org/rfc/rfc8414",)
    why_it_matters = (
        "An agent that must authenticate to call this API needs RFC 8414 authorization-server "
        "metadata to discover the endpoints itself, rather than a human copying them out of docs."
    )
    limitations = "Only the conventional /.well-known/oauth-authorization-server path is probed."
    cloud_extension = "Scovant Cloud exercises the discovered endpoints against a live OAuth flow, not just that the metadata document parses."
    standards = ("AR-ACT-01",)

    def evaluate(self, store, ctx):
        oauth = store.get("oauth_metadata")
        as_ = oauth["authorization_server"]
        ev = {
            "resource": f"{ctx.origin}/.well-known/oauth-authorization-server",
            "http_status": as_["status"],
            "parseable": as_["parseable"],
            "served_as_html": as_["served_as_html"],
            "has_endpoints": as_["has_endpoints"],
        }

        v = document_status(as_, what="OAuth authorization-server metadata")
        if v:
            if v.status is CheckStatus.ERROR:
                if as_["status"] is None:
                    return self.error("the authorization-server metadata document could not be read.", ev)
                return self.error(
                    f"the authorization-server metadata document could not be read (HTTP {as_['status']}).", ev
                )
            if as_["served_as_html"]:
                return self.na(
                    "No OAuth authorization-server metadata is published — the path is served by an HTML catch-all.",
                    ev,
                )
            return self.na("No OAuth authorization-server metadata is published.", ev)

        # Past this point the verdict is drawn from the ONE
        # authorization-server metadata document that was actually found
        # and read (the branches above already ruled out absence/error,
        # neither of which was ever parsed as this document's body) —
        # `as_["truncated"]` reflects that one read alone (not
        # `oauth_metadata`'s own record-level OR against the SEPARATE
        # protected-resource document — `oauth_metadata` is a FOLDED
        # record, `as_` is not), so the label is honest.
        note, truncated = record_truncation(as_, ev, document="OAuth authorization-server metadata")
        conf = truncated_confidence(truncated)

        if as_["parseable"] and as_["issuer"] and as_["has_endpoints"]:
            ev["issuer"] = as_["issuer"]
            return self.result(CheckStatus.PASS, "OAuth authorization-server metadata is published and complete." + note,
                               evidence=ev, confidence=conf)

        return self.result(
            CheckStatus.WARN,
            "An authorization-server metadata document was found but is incomplete or does not parse." + note,
            evidence=ev, confidence=conf,
            remediation=(
                "Publish RFC 8414 metadata with `issuer`, `authorization_endpoint`, and "
                "`token_endpoint` at /.well-known/oauth-authorization-server."
            ),
        )

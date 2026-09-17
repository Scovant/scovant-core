"""CORE-INTERFACE-008 (EXPERIMENTAL): UCP profile validity, read from the
`/.well-known/ucp` document (`gatherers/ucp.py` / `parsers/ucp.py`)."""
from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class UcpProfilePresence(CoreCheck):
    id = "CORE-INTERFACE-008"
    title = "UCP profile validity"
    category = Category.INTERFACES
    verification_mode = "DECLARED"
    profiles = frozenset({"commerce"})
    weight = 2
    experimental = True
    severity_on_fail = Severity.MEDIUM
    references = ("https://ucp.dev/",)
    why_it_matters = (
        "An agent completing a purchase needs a machine-readable Universal Commerce Protocol "
        "profile naming this site's own services and capabilities, not just checkout copy."
    )
    limitations = "Only /.well-known/ucp is probed; a profile published at a non-conventional path is not found."
    promotion_criteria = (
        "≥ 200 canonical scans of commerce sites publishing a UCP profile; a UCP specification "
        "at a stable, versioned schema with a settled well-known path; a false-positive review of the "
        "HTML-catch-all-versus-real-absence split, so a catch-all page never reads as a published "
        "profile; then a scored weight and a RULESET_VERSION bump."
    )
    cloud_extension = "Scovant Cloud exercises the UCP profile's declared services and capabilities against a live checkout flow."

    def evaluate(self, store, ctx):
        ucp = store.get("ucp")
        status = ucp["status"]
        ev = {
            "resource": f"{ctx.origin}/.well-known/ucp",
            "http_status": status,
            "exists": ucp["exists"],
            "valid": ucp["valid"],
            "served_as_html": ucp["served_as_html"],
        }

        v = document_status(ucp, what="UCP profile")
        if v:
            if v.status is CheckStatus.ERROR:
                if status is None:
                    return self.error("the UCP profile document could not be read.", ev)
                return self.error(f"the UCP profile document could not be read (HTTP {status}).", ev)
            if ucp["served_as_html"]:
                return self.na(
                    "No UCP profile is published — the path is served by an HTML catch-all.", ev
                )
            return self.na("No UCP profile is published.", ev)

        # Past this point the verdict is drawn from the ONE UCP profile
        # document that was actually found and read — `ucp` is a single,
        # named document (not in FOLDED_RECORD_NAMES), so the label is
        # honest.
        note, truncated = record_truncation(ucp, ev, document="UCP profile")
        conf = truncated_confidence(truncated)

        if ucp["valid"]:
            ev["services"] = ucp["services"]
            ev["capabilities"] = ucp["capabilities"]
            return self.result(CheckStatus.PASS, "A UCP profile is published and valid." + note, evidence=ev, confidence=conf)

        ev["validation_errors"] = ucp["validation_errors"]
        return self.result(
            CheckStatus.WARN,
            "A UCP profile is published but fails validation." + note,
            evidence=ev, confidence=conf,
            remediation="Publish a valid UCP profile at /.well-known/ucp per the UCP specification.",
        )

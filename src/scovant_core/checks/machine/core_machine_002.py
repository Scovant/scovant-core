from __future__ import annotations

from typing import Any

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


def _organization_nodes(schema_org: list[dict[str, Any]]):
    for node in schema_org:
        t = node.get("@type", "")
        types = t if isinstance(t, list) else [t]
        if "Organization" in types:
            yield node


class OrganizationEntity(CoreCheck):
    id = "CORE-MACHINE-002"
    title = "Organization entity"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://schema.org/Organization",)
    why_it_matters = "An agent trying to identify who operates a site (for trust, citation, or contact) needs a machine-readable Organization entity, not just a human-facing 'About' page."
    limitations = "Only the schema_org nodes on the sampled pages are checked; an Organization declared elsewhere on the site is not evaluated."
    cloud_extension = "Scovant Cloud validates Organization data against the full schema.org vocabulary, not just presence of name/url."
    standards = ("AR-READ-08",)

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        org_nodes = [n for p in parsed_pages for n in _organization_nodes(p["parsed"]["schema_org"])]
        pages_unread = len(pages) - len(parsed_pages)
        ev: dict[str, Any] = {"pages_parsed": len(parsed_pages), "found": len(org_nodes) > 0}
        # An Organization node is read out of each sampled page's JSON-LD; a
        # page cut off at the fetch cap may be missing a node (or fields of
        # one) that sat past it, so the verdict below cannot claim full
        # confidence when any contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)
        if not org_nodes:
            if pages_unread > 0:
                ev["unread"] = pages_unread
            return self.result(CheckStatus.WARN, "No Organization entity was found on the sampled pages." + note, evidence=ev,
                               confidence=conf, remediation='Add JSON-LD with "@type": "Organization" declaring at least name and url.')
        complete = next((n for n in org_nodes if n.get("name") and n.get("url")), None)
        if complete is not None:
            ev.update(name=complete.get("name"), url=complete.get("url"),
                      has_logo=bool(complete.get("logo")), has_sameAs=bool(complete.get("sameAs")),
                      has_description=bool(complete.get("description")))
            return self.result(CheckStatus.PASS, "An Organization entity declares name and url." + note, evidence=ev, confidence=conf)
        first = org_nodes[0]
        missing = [field for field in ("name", "url") if not first.get(field)]
        ev["missing"] = missing
        if pages_unread > 0:
            ev["unread"] = pages_unread
        return self.result(CheckStatus.WARN, "An Organization entity is missing " + ", ".join(missing) + "." + note, evidence=ev,
                           confidence=conf, remediation="Add the missing fields (" + ", ".join(missing) + ") to the Organization entity.")

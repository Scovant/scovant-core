"""CORE-OPERABILITY-011 (experimental): discovery linkage — can an agent reach the
site's machine surfaces by following links, not by guessing well-known paths?
Declared/link-based discoverability only; agent success is Scovant Cloud's."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


def linkage(surfaces_present: dict[str, str | None], sources: dict[str, set[str]]) -> dict:
    out: dict[str, dict] = {}
    for name, url in surfaces_present.items():
        if not url:
            out[name] = {"present": False, "url": None, "linked_from": []}
            continue
        out[name] = {"present": True, "url": url, "linked_from": sorted(sources.get(url, set()))}
    present = [n for n, v in out.items() if v["present"]]
    linked = [n for n in present if out[n]["linked_from"]]
    return {"surfaces": out, "present": len(present), "linked": len(linked), "unlinked": [n for n in present if n not in linked]}


class DiscoveryLinkage(CoreCheck):
    id = "CORE-OPERABILITY-011"
    title = "Discovery linkage"
    category = Category.OPERABILITY
    verification_mode = "PASSIVE_OBSERVED"
    weight = 2
    severity_on_fail = Severity.LOW
    experimental = True
    references = ("https://www.rfc-editor.org/rfc/rfc8288",)
    why_it_matters = "A machine surface an agent can only find by guessing a well-known path is discoverable in theory; one linked from the entry page or referenced by another already-gathered document is discoverable in practice. This measures declared, link-based discoverability — whether a real agent finds it is Scovant Cloud's measurement."
    limitations = (
        "Only llms.txt, OpenAPI, MCP and UCP are considered (a markdown-mirror surface and Link-header "
        "attribution are not yet wired into the Core evidence pipeline, so they cannot be checked). This check "
        "never fetches OpenAPI or UCP itself — it reads them only if another applicable check for this profile "
        "already gathered that evidence (OpenAPI: `CORE-INTERFACE-005`, profiles api/saas; UCP: "
        "`CORE-INTERFACE-008`, profile commerce). On any other profile, an unfetched OpenAPI/UCP surface is "
        "treated as not probed on this profile (counted as absent), never actively probed to find out — an "
        "unscored experimental check must never add its own network requests. Exactly two link sources are "
        "walked: the anchor links on the entry page itself, and the `machine_links` reference inventory — whose "
        "entries are sourced from the canonical URL, a policy-page link, the sitemap document URL itself, the "
        "declared OpenAPI spec, an MCP endpoint, or an llms.txt reference — matched only when one of those "
        "reference URLs equals a surface URL exactly. robots.txt directives and the URLs listed inside the "
        "sitemap are NOT scanned as a link source (the sitemap candidate above is the sitemap document URL "
        "itself, not a URL it lists). Experimental: never scored."
    )
    promotion_criteria = (
        "≥ 500 canonical scans with at least one machine surface present; the markdown-mirror "
        "surface and `Link`-header attribution wired into the Core evidence pipeline, so an "
        "‘unlinked’ verdict is a property of the site rather than of what Core happens to gather; "
        "a false-positive review of exact-URL matching against equivalent surface URLs spelled "
        "differently; then a scored weight and a RULESET_VERSION bump."
    )
    cloud_extension = "Scovant Cloud measures real agent discovery success across providers."

    def evaluate(self, store, ctx):
        llms = store.get("llms")
        # OpenAPI/UCP are read via `gathered()` — never fetched by this check
        # itself (see `limitations`): an unscored experimental check must not
        # add HTTP requests a profile wouldn't otherwise make.
        openapi = store.gathered("openapi") or {}
        mcp = store.get("mcp_discovery")
        ucp = store.gathered("ucp") or {}
        origin = ctx.origin or ""
        surfaces = {
            "llms_txt": f"{origin}/llms.txt" if llms["parsed"].get("exists") else None,
            "openapi": openapi.get("found_url"),
            "mcp": f"{origin}/.well-known/mcp.json" if mcp["discovery"].get("exists") else None,
            "ucp": f"{origin}/.well-known/ucp" if ucp.get("exists") else None,
        }
        # Exactly two link sources are walked — see `limitations` above.
        # robots.txt is NOT scanned here (its Sitemap:/comment lines are not
        # link sources this check follows).
        sources: dict[str, set[str]] = {}
        pages = (store.try_get("pages") or {}).get("pages", [])
        entry_links: set[str] = set()
        if pages and pages[0].get("parsed"):
            entry_links = set(pages[0]["parsed"]["internal_links"]["urls"])
        for url in filter(None, surfaces.values()):
            if url in entry_links:
                sources.setdefault(url, set()).add("entry_page")
        # `machine_links`' own `source` label (canonical/policy_link/sitemap/
        # openapi/mcp_endpoint/llms) names the DOCUMENT the reference URL was
        # found in — e.g. "sitemap" means the sitemap.xml document's own URL
        # matched a surface, never "a URL the sitemap lists".
        for r in (store.try_get("machine_links") or {}).get("refs", []):
            if r["url"] in surfaces.values():
                sources.setdefault(r["url"], set()).add(r["source"])
        out = linkage(surfaces, sources)
        if out["present"] == 0:
            return self.na("No machine surface is present to link to.", out)
        if out["unlinked"]:
            return self.result(CheckStatus.WARN, f"{len(out['unlinked'])} of {out['present']} machine surface(s) are not linked from anything an agent reads: {', '.join(out['unlinked'])}.",
                               evidence=out, remediation="Link llms.txt, OpenAPI, MCP and UCP documents from the entry page (e.g. a footer link), or reference them from the canonical URL, a policy page, or the OpenAPI spec.")
        return self.result(CheckStatus.PASS, f"All {out['present']} present machine surface(s) are linked from something an agent reads.", evidence=out)

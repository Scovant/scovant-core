"""CORE-OPERABILITY-009: throttling (429) is signalled with Retry-After. Core
never provokes a 429; this check only reports what the scan observed."""
from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.evidence import GATHERERS
from scovant_core.models import Category, CheckStatus, Severity

_MAX = 5


def _try_get(store, name: str) -> dict | None:
    """`store.try_get`, but never raises on a name that has no registered
    gatherer (e.g. `markdown`, whose probe is not currently wired into the
    `EvidenceStore` under that key) — `collect_429s` reads a fixed list of
    document names, and a name this scan never gathers simply contributes
    nothing, exactly like one it gathered and found absent."""
    if name not in GATHERERS:
        return None
    return store.try_get(name)


def collect_429s(store) -> list[dict]:
    """Every response with status 429 seen by this scan, with its Retry-After."""
    out: list[dict] = []

    def add(url, status, retry_after):
        if status == 429:
            out.append({"url": url, "retry_after": retry_after})

    http = store.get("http")
    add(http.get("final_url") or http.get("input_url"), http.get("status"), (http.get("headers") or {}).get("retry-after"))
    for p in (_try_get(store, "pages") or {}).get("pages", []):
        add(p.get("url"), p.get("status"), p.get("retry_after"))
    for r in (_try_get(store, "machine_links") or {}).get("refs", []):
        add(r.get("url"), r.get("status"), r.get("retry_after"))
    for name in ("llms", "sitemap_urls", "openapi", "ucp", "security_txt", "oauth_metadata", "mcp_discovery", "markdown", "soft_404"):
        rec = _try_get(store, name) or {}
        # `sitemap_urls` never sets a top-level `"status"` — its document
        # status lives under `"probe_status"` — so both are tried, `status`
        # first (the common shape every other document here uses).
        add(rec.get("url") or rec.get("found_url") or rec.get("probed_url") or name,
            rec.get("status") if rec.get("status") is not None else rec.get("probe_status"),
            rec.get("retry_after"))
        for ref in rec.get("references", []) or []:
            add(ref.get("url"), ref.get("status"), ref.get("retry_after"))
        # `oauth_metadata` carries no top-level status at all — its two
        # documents (authorization-server metadata, protected-resource
        # metadata) each have their own `status`/`retry_after` in a nested
        # sub-dict, so they're walked explicitly here rather than via the
        # generic top-level read above.
        if name == "oauth_metadata":
            for sub_name in ("authorization_server", "protected_resource"):
                sub = rec.get(sub_name) or {}
                add(sub.get("url") or f"{name}:{sub_name}", sub.get("status"), sub.get("retry_after"))
    return out


class RateLimitSignalled(CoreCheck):
    id = "CORE-OPERABILITY-009"
    title = "Rate limiting is signalled"
    category = Category.OPERABILITY
    verification_mode = "PASSIVE_OBSERVED"
    weight = 1
    severity_on_fail = Severity.LOW
    standards = ("AR-READ-02",)
    references = ("https://www.rfc-editor.org/rfc/rfc6585#section-4", "https://www.rfc-editor.org/rfc/rfc9110#name-retry-after")
    why_it_matters = "A 429 without Retry-After leaves an agent guessing when to come back; with it, a well-behaved agent backs off exactly as long as the server asks."
    limitations = "Core never induces throttling; only 429 responses that happened to occur during the scan are examined, so most scans report N/A."
    cloud_extension = "Scovant Cloud observes rate-limit behaviour across its crawl and agent runs over time."

    def evaluate(self, store, ctx):
        seen = collect_429s(store)
        if not seen:
            return self.na("No 429 response was observed during this scan.", {"observed": []})
        missing = [s for s in seen if not s["retry_after"]]
        ev = {"observed": seen[:_MAX], "without_retry_after": missing[:_MAX], "count": len(seen)}
        if missing:
            return self.result(CheckStatus.FAIL, f"{len(missing)} throttled response(s) (429) carry no Retry-After header.",
                               evidence=ev, remediation="Send a Retry-After header (seconds or HTTP-date) with every 429 so agents can back off correctly.")
        return self.result(CheckStatus.PASS, "Every observed 429 carried a Retry-After header.", evidence=ev)

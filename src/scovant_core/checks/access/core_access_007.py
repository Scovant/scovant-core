from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.parsers.html import normalize_internal_url


def _canon(url: str) -> str:
    """`normalize_internal_url` plus one thing it deliberately does not do:
    treat an EMPTY path as `/`. `https://example.com` and
    `https://example.com/` are the same resource to every server, but the
    shared normalizer preserves the path exactly as given (its own contract,
    used for internal-link graph joins) — so a canonical written bare-origin
    against an entry URL that resolved with a trailing slash compared unequal
    and was reported as a differing canonical. Local on purpose: the shared
    normalizer keeps its semantics for every other caller."""
    p = urlsplit(normalize_internal_url(url))
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


class CanonicalIntegrity(CoreCheck):
    id = "CORE-ACCESS-007"
    title = "Canonical URL integrity"
    category = Category.ACCESS
    weight = 3
    severity_on_fail = Severity.MEDIUM
    references = ("https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls",)
    why_it_matters = "A broken or off-host canonical tells agents the entry page's authoritative content lives somewhere else."
    limitations = "Only the entry page's declared canonical is evaluated."
    cloud_extension = "Scovant Cloud validates canonical tags across every sampled page, not only the entry page."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be parsed.", {"entry_url": ctx.final_url})
        canonical = entry["parsed"].get("metadata", {}).get("canonical_url")
        ev = {"entry_url": ctx.final_url, "canonical_url": canonical}
        # `canonical` was read out of the entry page's own HTML — a page cut
        # off at the fetch cap may have lost the <link rel="canonical"> tag
        # (or the truth about whether one is even declared), so every verdict
        # below, including "no canonical declared", must say so.
        note, truncated = record_truncation(entry, ev, document="entry page")
        conf = truncated_confidence(truncated)
        if not canonical:
            return self.result(CheckStatus.WARN, "The entry page declares no canonical URL." + note, evidence=ev,
                               confidence=conf, remediation='Add a <link rel="canonical"> pointing at the entry page\'s own URL.')
        norm_canonical, norm_entry = _canon(canonical), _canon(ctx.final_url)
        if norm_canonical == norm_entry:
            return self.result(CheckStatus.PASS, "The canonical URL matches the entry URL." + note, evidence=ev, confidence=conf)
        canonical_host, entry_host = urlsplit(canonical).netloc.lower(), urlsplit(ctx.final_url).netloc.lower()
        if canonical_host != entry_host:
            return self.result(CheckStatus.FAIL, "The canonical URL points off-host." + note, evidence=ev,
                               confidence=conf, remediation="Point the canonical tag at a URL on this site's own host.")
        refs = store.get("machine_links")["refs"]
        ref = next((r for r in refs if r["source"] == "canonical"), None)
        # `ref["status"]` is the FINAL status the shared client resolved after
        # following any redirects itself — it is never a bare 3xx, so this is
        # real observed data, not a fabricated "was it redirected" guess.
        ev["canonical_ref_status"] = ref["status"] if ref else None
        if ref and ref["status"] in (404, 410):
            return self.result(CheckStatus.FAIL, f"The canonical URL returns HTTP {ref['status']}." + note, evidence=ev,
                               confidence=conf, remediation="Point the canonical tag at a URL that actually resolves.")
        return self.result(CheckStatus.WARN, "The canonical URL differs from the entry URL." + note, evidence=ev,
                           confidence=conf, remediation="Confirm the canonical target is the intended authoritative URL.")

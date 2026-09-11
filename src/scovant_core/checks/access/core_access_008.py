from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class Indexability(CoreCheck):
    id = "CORE-ACCESS-008"
    title = "Indexability"
    category = Category.ACCESS
    weight = 3
    severity_on_fail = Severity.HIGH
    references = ("https://developers.google.com/search/docs/crawling-indexing/block-indexing",)
    why_it_matters = "A page that declares noindex tells every compliant crawler, agents included, to leave it out of any index."
    limitations = "Only the entry page's own robots meta tag and X-Robots-Tag header are checked."
    cloud_extension = "Scovant Cloud checks indexability across every sampled page."

    def evaluate(self, store, ctx):
        http = store.get("http")
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be parsed.", {"entry_url": ctx.final_url})
        robots_meta = entry["parsed"].get("metadata", {}).get("robots_meta") or ""
        header = (http["headers"] or {}).get("x-robots-tag") or ""
        ev = {"robots_meta": robots_meta or None, "x_robots_tag": header or None}
        # The X-Robots-Tag header is unaffected by a body cap, but the meta
        # robots tag is read out of the entry page's own HTML — a page cut
        # off before a <meta name="robots"> past the cap would silently
        # read as "no noindex declared" without this note.
        note, truncated = record_truncation(entry, ev, document="entry page")
        conf = truncated_confidence(truncated)
        if "noindex" in robots_meta.lower() or "noindex" in header.lower():
            return self.result(CheckStatus.FAIL, "The entry page declares noindex." + note, evidence=ev,
                               confidence=conf, remediation="Remove the noindex directive from the meta robots tag or X-Robots-Tag header.")
        return self.result(CheckStatus.PASS, "The entry page does not declare noindex." + note, evidence=ev, confidence=conf)

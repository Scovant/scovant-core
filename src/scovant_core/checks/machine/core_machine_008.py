from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.security.url_safety import display_url


class MetadataQuality(CoreCheck):
    id = "CORE-MACHINE-008"
    title = "Metadata quality"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://ogp.me/",)
    why_it_matters = "Title, description, and Open Graph tags are the first summary an agent (or a link preview) sees of a page."
    limitations = "Only the entry page's metadata is checked."
    cloud_extension = "Scovant Cloud checks metadata quality across every sampled page."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be parsed.", {"entry_url": display_url(ctx.final_url)})
        md, og = entry["parsed"]["metadata"], entry["parsed"]["og_meta"]
        missing = []
        if not md.get("title"):
            missing.append("title")
        if not md.get("meta_description"):
            missing.append("meta_description")
        if not og.get("og_title"):
            missing.append("og:title")
        if not og.get("og_description"):
            missing.append("og:description")
        issues = list(missing)
        if md.get("title") and md.get("meta_description") and md["title"] == md["meta_description"]:
            issues.append("title equals description")
        ev = {"entry_url": display_url(ctx.final_url), "title": md.get("title"), "meta_description": md.get("meta_description"),
              "missing": missing, "issues": issues}
        # title/description/OG tags are read out of the entry page's own
        # <head> — a page cut off at the fetch cap may be missing a tag
        # that sat past it.
        note, truncated = record_truncation(entry, ev)
        conf = truncated_confidence(truncated)
        if not issues:
            return self.result(CheckStatus.PASS, "The entry page declares title, description, and Open Graph tags." + note,
                               evidence=ev, confidence=conf)
        return self.result(CheckStatus.WARN, "The entry page's metadata has issues: " + ", ".join(issues) + "." + note, evidence=ev,
                           confidence=conf, remediation="Add the missing metadata tags and give title and description distinct content.")

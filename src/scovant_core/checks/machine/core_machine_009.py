from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.security.url_safety import display_url


class HeadingStructure(CoreCheck):
    id = "CORE-MACHINE-009"
    title = "Heading structure"
    category = Category.MACHINE
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://www.w3.org/WAI/tutorials/page-structure/headings/",)
    why_it_matters = "A single, well-nested heading outline is how an agent (or a screen reader) infers a page's structure without reading every word."
    limitations = "Only the entry page's heading outline is checked."
    cloud_extension = "Scovant Cloud checks heading structure across every sampled page."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be parsed.", {"entry_url": display_url(ctx.final_url)})
        headings = entry["parsed"]["headings"]
        h1_count = sum(1 for h in headings if h["level"] == "h1")
        issues = []
        if h1_count == 0:
            issues.append("no H1")
        elif h1_count > 1:
            issues.append("multiple H1")
        prev = None
        for h in headings:
            level = int(h["level"][1])
            if prev is not None and level - prev > 1:
                issues.append("skipped heading level")
                break
            prev = level
        ev = {"entry_url": display_url(ctx.final_url), "heading_count": len(headings), "h1_count": h1_count,
              "levels": [h["level"] for h in headings], "issues": issues}
        # The heading outline is read out of the entry page's own HTML — a
        # page cut off at the fetch cap may be missing a heading (or the H1)
        # that sat past it.
        note, truncated = record_truncation(entry, ev)
        conf = truncated_confidence(truncated)
        if not issues:
            return self.result(CheckStatus.PASS, "The entry page has a single H1 and no skipped heading levels." + note,
                               evidence=ev, confidence=conf)
        return self.result(CheckStatus.WARN, "The entry page's heading structure has issues: " + ", ".join(issues) + "." + note, evidence=ev,
                           confidence=conf, remediation="Use exactly one H1 per page and avoid skipping heading levels (e.g. h1 to h3).")

from __future__ import annotations

from typing import Any

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_ALT_COVERAGE_FLOOR = 0.9


class ImageAltCoverage(CoreCheck):
    id = "CORE-MACHINE-011"
    title = "Image alt coverage"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    profiles = frozenset({"content", "commerce"})
    weight = 1
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.w3.org/WAI/tutorials/images/decision-tree/",)
    why_it_matters = "Alt text (or a deliberate empty/decorative alt) is how an agent that cannot see an image learns what it shows."
    limitations = "Only the images on the sampled pages are counted."
    cloud_extension = "Scovant Cloud checks image alt coverage across the full sampled catalog, not just the pages in this scan."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        total = sum(p["parsed"]["images"]["total"] for p in parsed_pages)
        with_alt = sum(p["parsed"]["images"]["with_alt"] for p in parsed_pages)
        empty_alt = sum(p["parsed"]["images"]["empty_alt"] for p in parsed_pages)
        covered = with_alt + empty_alt
        ev: dict[str, Any] = {
            "pages_parsed": len(parsed_pages), "total": total, "with_alt": with_alt,
            "empty_alt": empty_alt, "covered": covered,
        }
        pages_unread = len(pages) - len(parsed_pages)
        # Images are counted from each sampled page's HTML; a page cut off
        # at the fetch cap may be missing images (and their alt attributes)
        # that sat past it, so every verdict below cannot claim full
        # confidence when any contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)
        if total == 0:
            if pages_unread > 0:
                ev["unread"] = pages_unread
            return self.result(CheckStatus.NA, "No images were found on the sampled pages." + note, evidence=ev,
                               confidence=conf, severity=Severity.INFO)
        ratio = covered / total
        ev["ratio"] = round(ratio, 4)
        if ratio >= _ALT_COVERAGE_FLOOR:
            return self.result(CheckStatus.PASS, f"{covered}/{total} images have an alt attribute (ratio {ratio:.0%})." + note,
                               evidence=ev, confidence=conf)
        if pages_unread > 0:
            ev["unread"] = pages_unread
        return self.result(CheckStatus.WARN, f"Only {covered}/{total} images have an alt attribute (ratio {ratio:.0%})." + note, evidence=ev,
                           confidence=conf, remediation="Add an alt attribute (or an explicit empty alt for decorative images) to every image.")

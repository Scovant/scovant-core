from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class SitemapAvailability(CoreCheck):
    id = "CORE-ACCESS-005"
    title = "Sitemap availability"
    category = Category.ACCESS
    weight = 3
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.sitemaps.org/protocol.html",)
    why_it_matters = "A sitemap is the most reliable way for a crawler to discover a site's full page inventory without following every link."
    limitations = "Only the first-declared sitemap (or its first child, for a sitemap index) is fetched and validated."
    cloud_extension = "Scovant Cloud validates every child sitemap in an index and samples the full URL count."
    standards = ("AR-FIND-03",)

    def evaluate(self, store, ctx):
        sitemap = store.get("sitemap_urls")
        ev = {"url": sitemap["url"], "exists": sitemap["exists"], "valid": sitemap["valid"], "kind": sitemap["kind"],
              "entry_count": len(sitemap["entries"]), "parse_error": sitemap["parse_error"],
              "probe_status": sitemap["probe_status"], "probe_error": sitemap["probe_error"],
              "served_as_html": sitemap.get("served_as_html", False)}
        # `sitemap["valid"]`/`entry_count`/`kind` are read out of the sitemap
        # BODY (not the entry-list cap tracked by this record's own
        # `"truncated"` key) — a body cut off at the fetch cap could parse as
        # valid from a truncated prefix, or fail to parse only because of the
        # cut. Use `body_truncated`, the signal that actually means "the
        # document we read was a partial read", not the entry-count cap.
        #
        # Confirmed absence (below) is a real finding the truncation of some
        # OTHER, unrelated read (e.g. a catch-all HTML page larger than the
        # cap, on the direct-probe path) has no bearing on — so the flag/
        # note/confidence are computed ONLY for the two branches actually
        # built from a document we read, never written into `ev` on the
        # absence path. Writing `evidence["truncated"]` unconditionally here
        # once caused a HIGH-confidence "No sitemap was found" finding to
        # carry `truncated: true` in its own evidence — confidence and
        # evidence telling the reader two different stories about the same
        # finding.
        #
        # No `document=` label on either call below: `body_truncated` is an
        # OR across the sitemap index, a followed child sitemap and the
        # direct probe (gatherers/sitemap_urls.py), so no single document
        # name could be honest — an index read in full pointing at an
        # oversized child would otherwise produce a note claiming "the
        # sitemap body" itself was cut. The generic wording is true
        # whichever of the three was truncated.
        if sitemap["valid"]:
            note, truncated = record_truncation({"truncated": sitemap.get("body_truncated", False)}, ev)
            conf = truncated_confidence(truncated)
            return self.result(CheckStatus.PASS, f"A valid {sitemap['kind']} sitemap was found at {sitemap['url']}." + note,
                               evidence=ev, confidence=conf)
        if sitemap["exists"]:
            note, truncated = record_truncation({"truncated": sitemap.get("body_truncated", False)}, ev)
            conf = truncated_confidence(truncated)
            return self.result(CheckStatus.WARN, f"A sitemap was found at {sitemap['url']} but did not parse as valid XML." + note,
                               evidence=ev, confidence=conf, remediation="Fix the sitemap XML so it validates against the sitemaps.org schema.")
        # A missing sitemap is itself a meaningful, profile-dependent
        # finding (FAIL for commerce/content, WARN otherwise) — not a
        # data-quality gap — so only `document_status`'s ERROR verdict is
        # adopted here (widened beyond the old ">= 500" check to every
        # genuinely unreadable non-200/non-404/410 status, e.g. 401/403).
        # A real 404/410 or a served-as-html catch-all falls through to the
        # profile-based verdict below unchanged.
        probe_record = {"status": sitemap["probe_status"], "served_as_html": sitemap.get("served_as_html", False)}
        v = document_status(probe_record, what="sitemap")
        if v and v.status is CheckStatus.ERROR:
            return self.error("the sitemap could not be read (the probe failed or the server errored).", ev)
        status = CheckStatus.FAIL if ctx.profile in ("commerce", "content") else CheckStatus.WARN
        return self.result(status, "No sitemap was found.", evidence=ev,
                           remediation="Publish /sitemap.xml and declare it in robots.txt.")

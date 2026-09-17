from __future__ import annotations

import datetime

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

# Module-level so golden/unit tests can freeze "now" via
# `monkeypatch.setattr(core_access_006, "today", lambda: ...)`.
today = datetime.date.today

MAX_AGE_DAYS = 730
MIN_ENTRIES_FOR_UNIFORM_CHECK = 5


def _parse_date(value: str) -> datetime.date | None:
    try:
        return datetime.date.fromisoformat(value[:10])
    except (TypeError, ValueError):
        return None


class SitemapFreshness(CoreCheck):
    id = "CORE-ACCESS-006"
    title = "Sitemap freshness"
    category = Category.ACCESS
    verification_mode = "DECLARED"
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://www.sitemaps.org/protocol.html",)
    why_it_matters = "A stale or suspiciously uniform lastmod signal gives a crawler no reliable way to prioritise re-crawling changed pages."
    limitations = "Only ISO 8601 date-formatted lastmod values are parsed; malformed dates are ignored, not penalised."
    cloud_extension = "Scovant Cloud cross-checks lastmod against observed page changes over time."
    standards = ("AR-FIND-03",)

    def evaluate(self, store, ctx):
        sitemap = store.get("sitemap_urls")
        # N/A here covers BOTH a genuinely absent sitemap and an unreadable
        # one — CORE-ACCESS-005 is the check that ERRORs on the latter, so
        # this one stays "nothing to evaluate" either way, never a duplicate
        # ERROR for the same underlying read failure.
        #
        # The two cases differ in one way that matters to a report reader,
        # though. When a sitemap body WAS read (`exists`) and simply did not
        # parse, "no valid sitemap" is a verdict drawn from that body — and
        # a body cut off at the fetch cap is a plausible cause of the parse
        # failure itself, so the partial read must be declared exactly as
        # CORE-ACCESS-005 declares it on the same record (before this, one
        # truncated sitemap produced ACCESS-005 WARN + note + MEDIUM beside
        # ACCESS-006 N/A + HIGH + no flag — two stories about one document).
        # When nothing exists, absence was established by a 404, a failed
        # probe or a soft-404 HTML catch-all — independently of any body we
        # only partly read — so this branch stays silent, matching
        # CORE-ACCESS-005's own "No sitemap was found" branch.
        if not sitemap["valid"]:
            na_ev = {"url": sitemap["url"]}
            read_a_body = bool(sitemap["exists"]) and bool(sitemap.get("body_truncated", False))
            na_note, na_truncated = record_truncation({"truncated": read_a_body}, na_ev)
            return self.na("No valid sitemap to evaluate freshness for." + na_note, na_ev,
                           confidence=truncated_confidence(na_truncated))
        entries = sitemap["entries"]
        dated = [_parse_date(e["lastmod"]) for e in entries if e.get("lastmod")]
        dated = [d for d in dated if d is not None]
        ev = {"url": sitemap["url"], "entry_count": len(entries), "dated_entry_count": len(dated)}
        # Every branch below reads lastmod values out of the sitemap BODY —
        # a body cut off at the fetch cap may be missing entries (and their
        # dates) that sat past it, so the freshness verdict cannot claim
        # full confidence when the body was only read in part. Same
        # `body_truncated` signal as CORE-ACCESS-005, not the entry-count cap.
        # No `document=` label: `body_truncated` is an OR across the sitemap
        # index, a followed child sitemap and the direct probe (see
        # gatherers/sitemap_urls.py), so no single document name would be
        # honest — the generic wording is true whichever of them was cut.
        note, truncated = record_truncation({"truncated": sitemap.get("body_truncated", False)}, ev)
        conf = truncated_confidence(truncated)
        if not dated:
            return self.result(CheckStatus.PASS, "No lastmod declared — no penalty." + note, evidence=ev, confidence=conf)
        now = today()
        ev["newest"], ev["oldest"] = max(dated).isoformat(), min(dated).isoformat()
        if any(d > now + datetime.timedelta(days=1) for d in dated):
            return self.result(CheckStatus.WARN, "One or more sitemap entries declare a future lastmod date." + note,
                               evidence=ev, confidence=conf, remediation="Correct lastmod values so they never fall in the future.")
        if len(dated) >= MIN_ENTRIES_FOR_UNIFORM_CHECK and len(set(dated)) == 1:
            return self.result(CheckStatus.WARN, "Every sampled page carries the same lastmod date." + note,
                               evidence=ev, confidence=conf, remediation="Only update lastmod for pages that actually changed.")
        if max(dated) < now - datetime.timedelta(days=MAX_AGE_DAYS):
            return self.result(CheckStatus.WARN, f"The newest lastmod in the sitemap is over {MAX_AGE_DAYS} days old." + note,
                               evidence=ev, confidence=conf, remediation="Regenerate the sitemap so lastmod reflects real content changes.")
        return self.result(CheckStatus.PASS, "Sitemap lastmod values look plausible." + note, evidence=ev, confidence=conf)

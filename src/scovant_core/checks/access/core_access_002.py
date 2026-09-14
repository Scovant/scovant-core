from __future__ import annotations

import hashlib

from scovant_core.checks._document import document_status
from scovant_core.checks.access._robots_readability import robots_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class RobotsTxtAvailability(CoreCheck):
    id = "CORE-ACCESS-002"
    title = "robots.txt availability and syntax"
    category = Category.ACCESS
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.rfc-editor.org/rfc/rfc9309",)
    why_it_matters = "robots.txt is the first document a crawler checks; a broken or unreachable one forces every crawler to guess."
    limitations = "Only reachability and syntax are checked; per-agent policy is evaluated by the other CORE-ACCESS checks."
    cloud_extension = "Scovant Cloud fetches robots.txt from multiple regions to catch geo-inconsistent policies."
    standards = ("AR-FIND-01",)

    def evaluate(self, store, ctx):
        robots = store.get("robots_txt")
        ev = {
            "resource": f"{ctx.origin}/robots.txt",
            "status": robots["status"],
            "sha256": hashlib.sha256(robots["text"].encode()).hexdigest() if robots["text"] else None,
            "unknown_directives": robots["unknown_directives"],
            "sitemap_count": len(robots["sitemaps"]),
            "served_as_html": robots["served_as_html"],
            "error": robots["error"],
        }
        # A robots.txt cut off at the client's body cap was parsed from a
        # prefix — whatever it declares past the cap is invisible to us, so
        # the finding must not read as fully-read, high-confidence evidence.
        # The note is appended to EVERY verdict below, not only the PASS one:
        # the verdict truncation is most likely to invert is a FAIL (an
        # `Allow:` past the cap), and a silent summary there is exactly the
        # over-claim this guard exists to prevent.
        note, truncated = robots_truncation(robots, ev, document="robots.txt")
        conf = truncated_confidence(truncated)
        # `document_status` widens ERROR coverage beyond the old "status is
        # None" check to every genuinely unreadable non-200/non-404/410
        # status (5xx, 401/403, an unexpected redirect target) — previously
        # those were mischaracterized as "No robots.txt is published". A
        # real 404/410 or a served-as-html catch-all is NOT intercepted here:
        # for robots.txt, confirmed absence is itself the finding (crawlers
        # assume allow-all with no sitemap hint), not a data-quality gap —
        # see the branches below.
        v = document_status(robots, what="robots.txt")
        if v and v.status is CheckStatus.ERROR:
            return self.error(v.reason, ev)
        if robots["served_as_html"]:
            return self.result(CheckStatus.WARN,
                               "robots.txt was served as an HTML page — treated as absent." + note, evidence=ev,
                               confidence=conf, remediation="Serve /robots.txt with a text/plain body, not an HTML error page.")
        if robots["status"] != 200:
            return self.result(CheckStatus.WARN,
                               f"No robots.txt is published (HTTP {robots['status']}); crawlers assume allow-all "
                               "and get no sitemap hint." + note,
                               evidence=ev, confidence=conf,
                               remediation="Publish a robots.txt, even a permissive one, with a Sitemap: directive.")
        if robots["general_disallow_all"]:
            return self.result(CheckStatus.FAIL, "robots.txt disallows all crawlers from the entire site." + note,
                               evidence=ev, confidence=conf, remediation="Scope Disallow rules to specific paths instead of blocking `/` for `*`.")
        if robots["unknown_directives"]:
            return self.result(CheckStatus.WARN,
                               "robots.txt contains directive(s) not recognised by the standard: "
                               + ", ".join(robots["unknown_directives"]) + note,
                               evidence=ev, confidence=conf, remediation="Remove or correct the unrecognised directives.")
        return self.result(CheckStatus.PASS,
                           f"robots.txt answered {robots['status']} with a well-formed policy." + note,
                           evidence=ev, confidence=conf)

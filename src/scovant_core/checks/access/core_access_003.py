from scovant_core.checks.access._identities import SEARCH_CRAWLERS, USER_FETCH_CRAWLERS
from scovant_core.checks.access._robots_readability import (
    classify_robots_readability,
    robots_truncation,
    truncated_confidence,
)
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Confidence, Severity
from scovant_core.parsers.robots import is_allowed


class AiSearchCrawlerPolicy(CoreCheck):
    id = "CORE-ACCESS-003"
    title = "AI search crawler policy"
    category = Category.ACCESS
    verification_mode = "DECLARED"
    weight = 4
    severity_on_fail = Severity.HIGH
    check_version = "1.1"
    references = ("https://www.rfc-editor.org/rfc/rfc9309",)
    why_it_matters = "Search and answer engines only surface pages their crawlers are declared allowed to fetch."
    limitations = "Only the declared robots.txt policy is evaluated; whether the crawler is actually served is not observed."
    cloud_extension = "Scovant Cloud observes whether these crawlers are actually admitted or challenged."
    standards = ("AR-FIND-01",)

    def evaluate(self, store, ctx):
        robots = store.get("robots_txt")
        ev = {"resource": f"{ctx.origin}/robots.txt", "http_status": robots["status"]}
        # This is the weight-4, HIGH-severity policy verdict: "all major
        # crawlers are allowed" drawn from a body we only partly read is the
        # single most consequential over-claim in the ruleset, so the same
        # truncation treatment as CORE-ACCESS-002 applies here too.
        note, truncated = robots_truncation(robots, ev, document="robots.txt")
        readability = classify_robots_readability(robots)
        if readability == "unreadable":
            return self.error("robots.txt could not be read (the fetch failed, or the response was not a "
                               "real robots.txt document).", ev)
        if readability == "absent":
            # Derived allow-all (RFC 9309 default) is not a parsed policy —
            # don't dress it up as one in the evidence.
            ev["declared_policy"], ev["robots_present"] = None, False
            return self.result(CheckStatus.PASS,
                               "No robots.txt is published; all crawlers, including search/retrieval crawlers, "
                               "are allowed by default.",
                               evidence=ev, confidence=Confidence.MEDIUM)
        verdicts = {ua: is_allowed(robots["text"], ua, f"{ctx.origin}/") for ua in SEARCH_CRAWLERS}
        disallowed = [ua for ua, ok in verdicts.items() if not ok]
        ev["declared_policy"], ev["robots_present"] = verdicts, True
        # The user-fetch class (a person's own agent fetching a page on
        # their behalf, e.g. ChatGPT-User) is reported alongside the search
        # verdict, never folded into it — a site can restrict one without
        # the other, and conflating them would misreport which class is
        # actually blocked.
        uf = {ua: is_allowed(robots["text"], ua, f"{ctx.origin}/") for ua in USER_FETCH_CRAWLERS}
        ev["user_fetch_policy"] = uf
        blocked_uf = [ua for ua, ok in uf.items() if not ok]
        uf_note = f" User-triggered fetch agents blocked: {', '.join(blocked_uf)}." if blocked_uf else ""
        conf = truncated_confidence(truncated)
        if not disallowed:
            return self.result(CheckStatus.PASS,
                               "robots.txt declares all major search and answer-engine crawlers as allowed." + note + uf_note,
                               evidence=ev, confidence=conf)
        if len(disallowed) == len(verdicts):
            return self.result(CheckStatus.FAIL,
                               "robots.txt declares every major search and answer-engine crawler as disallowed." + note + uf_note,
                               evidence=ev, confidence=conf,
                               remediation="Allow search/retrieval crawlers (" + ", ".join(SEARCH_CRAWLERS[:3]) + ", …) in robots.txt while keeping any training restrictions separate.")
        return self.result(CheckStatus.WARN, "robots.txt declares " + ", ".join(disallowed) + " as disallowed." + note + uf_note,
                           evidence=ev, confidence=conf,
                           remediation="Review whether blocking these retrieval crawlers is intended; they power answer-engine discovery, not model training.")

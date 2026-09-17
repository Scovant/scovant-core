from __future__ import annotations

from scovant_core.checks.access._identities import (
    CONTENT_USE_TOKENS,
    SEARCH_CRAWLERS,
    TRAINING_CRAWLERS,
)
from scovant_core.checks.access._robots_readability import (
    classify_robots_readability,
    robots_truncation,
    truncated_confidence,
)
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Confidence, Severity
from scovant_core.parsers.robots import is_allowed


class TrainingVsSearchSeparation(CoreCheck):
    id = "CORE-ACCESS-004"
    title = "Training vs. search crawler separation"
    category = Category.ACCESS
    verification_mode = "DECLARED"
    weight = 2
    severity_on_fail = Severity.LOW
    check_version = "1.1"
    references = ("https://www.rfc-editor.org/rfc/rfc9309",)
    why_it_matters = (
        "A site that wants to opt out of AI training without also losing answer-engine visibility needs "
        "the two crawler classes declared separately."
    )
    limitations = "Only the declared robots.txt policy is evaluated."
    cloud_extension = "Scovant Cloud observes whether training and search crawlers are actually treated differently in practice."

    def evaluate(self, store, ctx):
        robots = store.get("robots_txt")
        ev = {"resource": f"{ctx.origin}/robots.txt", "http_status": robots["status"]}
        # Same treatment as CORE-ACCESS-003: both the training and the search
        # verdict below are read out of the robots.txt body, so a body read
        # only in part cannot produce a full-confidence separation verdict.
        note, truncated = robots_truncation(robots, ev, document="robots.txt")
        readability = classify_robots_readability(robots)
        if readability == "unreadable":
            return self.error("robots.txt could not be read (the fetch failed, or the response was not a "
                               "real robots.txt document).", ev)
        url = f"{ctx.origin}/"
        conf = truncated_confidence(truncated)
        # Content-use-control tokens (e.g. an operator's AI-training/grounding
        # opt-out that carries no user-agent of its own — see
        # `identity_type="robots_token"` in the registry) are, from a site
        # owner's perspective, the same training-CLASS restriction as the
        # dedicated training crawlers: disallowing only one of them is still
        # an explicit training opt-out, not "no restriction declared".
        training_class = TRAINING_CRAWLERS + CONTENT_USE_TOKENS
        training_blocked = [ua for ua in training_class if not is_allowed(robots["text"], ua, url)]
        search_blocked = [ua for ua in SEARCH_CRAWLERS if not is_allowed(robots["text"], ua, url)]
        ev["training_blocked"], ev["search_blocked"] = training_blocked, search_blocked
        if readability == "absent":
            ev["explicit_separation"] = False
            return self.result(CheckStatus.PASS,
                               "No robots.txt is published; all crawlers, including training crawlers, are "
                               "allowed by default.",
                               evidence=ev, confidence=Confidence.MEDIUM)
        if search_blocked:
            ev["explicit_separation"] = False
            return self.result(CheckStatus.WARN,
                               "Search/retrieval crawlers are restricted together with training crawlers — intent unclear." + note,
                               evidence=ev, confidence=conf,
                               remediation="Restrict only the training-purpose crawler tokens; leave search/retrieval crawlers allowed.")
        if training_blocked:
            ev["explicit_separation"] = True
            return self.result(CheckStatus.PASS,
                               f"Training/content-use crawler(s) {', '.join(training_blocked)} are restricted while "
                               "search/retrieval crawlers remain allowed." + note,
                               evidence=ev, confidence=conf)
        ev["explicit_separation"] = False
        return self.result(CheckStatus.PASS,
                           "No training restriction is declared; search and retrieval remain allowed." + note,
                           evidence=ev, confidence=Confidence.MEDIUM)

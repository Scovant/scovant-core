from __future__ import annotations

from scovant_core.checks.access._robots_readability import (
    classify_robots_readability,
    robots_truncation,
    truncated_confidence,
)
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class ContentSignalDeclaration(CoreCheck):
    id = "CORE-ACCESS-010"
    title = "Content-Signal declaration"
    category = Category.ACCESS
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://contentsignals.org/",)
    why_it_matters = (
        "Content-Signal lets a site state search/AI-input/AI-training intent per dimension instead of leaving "
        "agents to guess from Disallow rules alone."
    )
    limitations = "Absence is not penalised; the convention is emerging."
    cloud_extension = "Scovant Cloud tracks Content-Signal adoption trends across the crawled corpus."

    def evaluate(self, store, ctx):
        robots = store.get("robots_txt")
        signals = robots["content_signals"]
        ev = {"declared": signals["declared"], "dimensions": signals["dimensions"], "syntax_errors": signals["syntax_errors"]}
        # Content-Signal is parsed out of the robots.txt body like every other
        # directive, so "no Content-Signal is declared" read off a truncated
        # body is a statement about our read, not about the site — the same
        # honesty rule as CORE-ACCESS-002/-003/-004.
        note, truncated = robots_truncation(robots, ev, document="robots.txt")
        conf = truncated_confidence(truncated)
        if classify_robots_readability(robots) == "unreadable":
            return self.error("Content-Signal could not be evaluated: robots.txt could not be read "
                               "(the fetch failed, or the response was not a real robots.txt document).", ev)
        if not signals["declared"]:
            return self.result(CheckStatus.NA, "No Content-Signal directive is declared." + note,
                               evidence=ev, confidence=conf, severity=Severity.INFO)
        if signals["syntax_errors"]:
            return self.result(CheckStatus.WARN, "Content-Signal is declared but has syntax error(s)." + note,
                               evidence=ev, confidence=conf,
                               remediation='Fix the Content-Signal directive, e.g. "Content-Signal: search=yes, ai-input=yes, ai-train=no".')
        dims = signals["dimensions"]
        if dims.get("search") == "no" and dims.get("ai-input") == "yes":
            return self.result(CheckStatus.WARN,
                               "Content-Signal conflicts: search is disallowed while ai-input is allowed." + note,
                               evidence=ev, confidence=conf, remediation="Reconcile the search and ai-input dimensions.")
        return self.result(CheckStatus.PASS, "Content-Signal is declared and internally consistent." + note,
                           evidence=ev, confidence=conf)

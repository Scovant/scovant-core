"""CORE-OPERABILITY-006: form/control labels. Reads the `forms` gatherer's
rolled-up `totals` across every sampled page that could be parsed."""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class FormControlLabels(CoreCheck):
    id = "CORE-OPERABILITY-006"
    title = "Form/control labels"
    category = Category.OPERABILITY
    profiles = frozenset({"commerce", "saas"})
    weight = 2
    severity_on_fail = Severity.MEDIUM
    references = ("https://www.w3.org/WAI/tutorials/forms/labels/",)
    why_it_matters = "An agent filling out a form has to guess an unlabeled input's purpose from placeholder text or surrounding prose alone — a labeled control is the difference between a reliable fill and a guess."
    limitations = "Only forms on the sampled page set are inspected; a form behind client-side rendering that never appears in the static HTML is not seen."
    cloud_extension = "Scovant Cloud inspects forms across the full crawled page set, including those reachable only after interaction."

    def evaluate(self, store, ctx):
        forms = store.get("forms")
        totals = forms["totals"]
        ev = {"totals": totals}

        if forms["pages_parsed"] == 0:
            return self.error("no page on this site could be parsed.", ev)

        pages_unread = forms["pages_total"] - forms["pages_parsed"]
        if pages_unread > 0:
            # Only recorded when non-zero, so a fully-readable fixture (the common
            # case) keeps a byte-identical evidence shape and its golden untouched.
            ev["pages_total"] = forms["pages_total"]
            ev["pages_unread"] = pages_unread

        # `forms["totals"]` is rolled up from `pages[*].parsed.forms` — a
        # page cut off at the fetch cap is never fully parsed for forms
        # past the cap, so "no forms found" here can be an absence claim
        # drawn from a partial read, not a real conclusion. `forms` itself
        # carries no `truncated` field (see `gatherers/forms.py`); the same
        # `pages` list it rolled up from does, on the same subset
        # (`p.get("parsed")` is not None) that fed `pages_parsed`.
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)

        if totals["forms"] == 0:
            return self.result(CheckStatus.NA, "No forms were found on any sampled page." + note, evidence=ev,
                               confidence=conf, severity=Severity.INFO)

        unlabeled = totals["unlabeled_inputs"] + totals["unnamed_buttons"] + totals["unlabeled_selects"]
        if unlabeled == 0:
            return self.result(CheckStatus.PASS, f"All controls across {totals['forms']} form(s) are labeled." + note,
                               evidence=ev, confidence=conf)
        return self.result(
            CheckStatus.WARN,
            f"{unlabeled} control(s) across {totals['forms']} form(s) lack a label or accessible name." + note,
            evidence=ev, confidence=conf,
            remediation="Add a <label> (or aria-label/aria-labelledby) to every input/select, and a name or accessible text to every button.",
        )

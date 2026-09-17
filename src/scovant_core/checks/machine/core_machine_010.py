from __future__ import annotations

import re

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.security.url_safety import display_url

_LANG_RE = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")


class LanguageDeclaration(CoreCheck):
    id = "CORE-MACHINE-010"
    title = "Language declaration"
    category = Category.MACHINE
    verification_mode = "PASSIVE_OBSERVED"
    weight = 1
    severity_on_fail = Severity.LOW
    references = ("https://www.w3.org/International/questions/qa-html-language-declarations",)
    why_it_matters = "A valid `lang` attribute lets an agent (or a translation/screen-reader tool) know what language a page's content is in without guessing."
    limitations = "Only the entry page's `<html lang>` attribute is checked."
    cloud_extension = "Scovant Cloud checks the language declaration across every sampled page."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be parsed.", {"entry_url": display_url(ctx.final_url)})
        lang = entry["parsed"]["html_lang"]
        ev = {"entry_url": display_url(ctx.final_url), "html_lang": lang}
        # `lang` is read out of the entry page's own `<html>` tag.
        note, truncated = record_truncation(entry, ev)
        conf = truncated_confidence(truncated)
        if lang and _LANG_RE.fullmatch(lang):
            return self.result(CheckStatus.PASS, "The entry page declares a valid `lang` attribute." + note, evidence=ev, confidence=conf)
        return self.result(CheckStatus.WARN, "The entry page's `lang` attribute is absent or invalid." + note, evidence=ev,
                           confidence=conf, remediation='Add a valid `lang` attribute to the `<html>` tag (e.g. `lang="en"`).')

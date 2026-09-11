from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class JsonLdParseability(CoreCheck):
    id = "CORE-MACHINE-001"
    title = "JSON-LD parseability"
    category = Category.MACHINE
    weight = 3
    severity_on_fail = Severity.MEDIUM
    references = ("https://json-ld.org/spec/latest/json-ld/",)
    why_it_matters = "A structured-data block an agent's parser cannot read is worse than no block: it promises machine-readable data and then withholds it."
    limitations = "Only well-formed-JSON parseability is checked; schema.org vocabulary correctness is not validated."
    cloud_extension = "Scovant Cloud validates JSON-LD against the schema.org vocabulary, not just JSON syntax."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")
        per_page = [
            {"url": p["url"], "raw": p["parsed"]["raw_jsonld_count"], "parsed": p["parsed"]["parsed_jsonld_count"]}
            for p in parsed_pages
        ]
        raw_total = sum(p["raw"] for p in per_page)
        parsed_total = sum(p["parsed"] for p in per_page)
        ev = {"pages": per_page, "raw_total": raw_total, "parsed_total": parsed_total}
        # JSON-LD blocks are counted from each sampled page's HTML; a page
        # cut off at the fetch cap may be missing a block that sat past it,
        # so a count drawn from these pages cannot claim full confidence
        # when any contributing page was only read in part.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)
        if raw_total == 0:
            return self.result(CheckStatus.NA, "No JSON-LD blocks were found on the sampled pages." + note,
                               evidence=ev, confidence=conf, severity=Severity.INFO)
        if parsed_total == raw_total:
            return self.result(CheckStatus.PASS, "Every JSON-LD block on the sampled pages parses as valid JSON." + note,
                               evidence=ev, confidence=conf)
        if parsed_total == 0:
            return self.result(CheckStatus.FAIL, "No JSON-LD block on the sampled pages parses as valid JSON." + note,
                               evidence=ev, confidence=conf,
                               remediation="Fix the malformed JSON-LD so it parses (validate with a JSON linter before publishing).")
        return self.result(CheckStatus.WARN, "Some JSON-LD blocks on the sampled pages fail to parse as valid JSON." + note,
                           evidence=ev, confidence=conf,
                           remediation="Fix the malformed JSON-LD blocks so every one parses (validate with a JSON linter before publishing).")

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity


class LlmsTxtIntegrity(CoreCheck):
    id = "CORE-ACCESS-009"
    title = "llms.txt presence and integrity"
    category = Category.ACCESS
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://llmstxt.org/",)
    why_it_matters = "A well-formed llms.txt gives agents a curated map of the pages worth reading; a broken one sends them to dead links."
    limitations = "Absence is not penalised; the convention is emerging. Reference checks are HTTP status only."
    cloud_extension = "Scovant Cloud checks the supply-chain integrity of packages and hosts referenced from llms.txt."
    standards = ("AR-READ-07",)

    def evaluate(self, store, ctx):
        llms = store.get("llms")
        parsed = llms["parsed"]
        resource_ev = {"resource": f"{ctx.origin}/llms.txt", "http_status": llms["status"]}
        # `llms.txt`/`llms-full.txt` were read under the fetch layer's body
        # cap like any other document; a cut-off read must not be published
        # at full confidence, on the "not published" verdict as much as on
        # the well-formed one — the note is appended below on every branch.
        #
        # No `document="llms.txt"` here: `llms["truncated"]` is an OR of TWO
        # reads (llms.txt itself AND the /llms-full.txt probe — see
        # `gatherers/llms.py`), so a fully-read llms.txt beside a truncated
        # llms-full.txt would otherwise produce a note naming llms.txt
        # specifically for a cut it was never subject to. The generic
        # "document body" wording is the honest one for a record that folds
        # two documents into one flag.
        note, truncated = record_truncation(llms, resource_ev)
        conf = truncated_confidence(truncated)
        # Widened beyond the old "None or >= 500" check to every genuinely
        # unreadable non-200/non-404/410 status (401/403, an unexpected
        # redirect target) — those used to fall through to "not published"
        # below, mischaracterizing a read failure as confirmed absence.
        v = document_status(llms, what="llms.txt")
        if v and v.status is CheckStatus.ERROR:
            # No note/confidence here: `self.error()` is already LOW
            # confidence and its summary claims nothing about the document's
            # content (only that it could not be read at all), so there is
            # no over-claim for the truncation note to guard against.
            return self.error(v.reason, resource_ev)
        if not parsed["exists"]:
            return self.result(CheckStatus.NA, "No llms.txt is published." + note, evidence=resource_ev,
                               confidence=conf, severity=Severity.INFO)
        refs = llms["references"]
        # A reference whose status is None is one OUR fetch failed on (DNS,
        # connect, timeout) — that is a gap in our evidence, not a dead link
        # the site published, so it is reported separately and never counted
        # as broken. Only a real HTTP status >= 400 is the site's problem.
        broken = [r["url"] for r in refs if r["status"] is not None and r["status"] >= 400]
        unresolved = [r["url"] for r in refs if r["status"] is None]
        ev = {"resource": f"{ctx.origin}/llms.txt", "valid": parsed["valid"], "errors": parsed["errors"],
              "references_checked": len(refs), "references_broken": broken,
              "references_unresolved": unresolved}
        if truncated:
            ev["truncated"] = True
        if not parsed["valid"]:
            return self.result(CheckStatus.WARN, "llms.txt is present but not well-formed." + note, evidence=ev,
                               confidence=conf,
                               remediation="Follow the llms.txt format: an H1 title, an optional blockquote summary, and H2 sections of Markdown links.")
        if refs and len(unresolved) == len(refs):
            # No note/confidence here either, same reasoning as the ERROR
            # branch above: self.error() is already LOW confidence and
            # claims nothing about the references' content, only that none
            # of them could be fetched.
            return self.error("none of the llms.txt references could be fetched.", ev)
        if broken:
            return self.result(CheckStatus.WARN, f"llms.txt references {len(broken)} link(s) that do not resolve." + note,
                               evidence=ev, confidence=conf,
                               remediation="Remove or fix the broken references in llms.txt.")
        return self.result(CheckStatus.PASS,
                           f"llms.txt is well-formed and its {len(refs) - len(unresolved)} checked references resolve." + note,
                           evidence=ev, confidence=conf)

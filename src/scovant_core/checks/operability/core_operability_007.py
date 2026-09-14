"""CORE-OPERABILITY-007 (EXPERIMENTAL): machine reference integrity. Reads
the `reference_integrity` gatherer — the shared `check_instruction_integrity`
over llms.txt + declared MCP server descriptions (allow-listed npm/PyPI
metadata GETs + DNS only, hard-budgeted; see
`gatherers/reference_integrity.py` and `analysis/integrity_probe.py`).

The asymmetry that gatherer documents is the one this check must preserve:
a definitive negative (`BROKEN`/`UNCLAIMED`) is evidence about the site, a
timeout or exhausted budget (`UNCHECKED`) is not — `UNCHECKED` alone can
never surface as a finding, only as ERROR (unmeasured) when it is the
entirety of what could be judged.
"""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_MAX_EXAMPLES = 5


class MachineReferenceIntegrity(CoreCheck):
    id = "CORE-OPERABILITY-007"
    title = "Machine reference integrity"
    category = Category.OPERABILITY
    weight = 2
    experimental = True
    severity_on_fail = Severity.HIGH
    references = ("https://llmstxt.org/",)
    why_it_matters = "A package name or domain named in agent-facing instructions that doesn't exist is a dependency-confusion / typosquat slot waiting to be claimed by someone else — an agent that follows the instruction inherits whatever fills it."
    limitations = "Only references extracted from llms.txt and declared MCP server descriptions are resolved, under a hard per-scan lookup budget; a resolution that times out or exhausts the budget is recorded as unchecked, never as broken."
    cloud_extension = "Scovant Cloud resolves a larger reference surface on a recurring schedule and tracks resolution drift over time."
    standards = ("AR-READ-06",)

    def evaluate(self, store, ctx):
        gathered = store.get("reference_integrity")
        if not gathered.get("attempted"):
            if gathered.get("reason") == "experimental_off":
                return self.na("Machine reference integrity was not evaluated (experimental off).")
            return self.error(
                "the integrity probe failed internally.",
                {k: v for k, v in gathered.items() if k != "attempted"},
            )

        refs = gathered.get("references", [])
        remote_exec = gathered.get("remote_exec", [])
        if not refs and not remote_exec:
            # Genuinely nothing was extracted from the read documents — but
            # that read could itself have been cut off (llms.txt/MCP server
            # descriptions), so this NA still carries the note.
            na_ev: dict = {}
            note, truncated = record_truncation(gathered, na_ev)
            conf = truncated_confidence(truncated)
            return self.result(CheckStatus.NA, "No machine-consumable references were discovered to check." + note,
                               evidence=na_ev, confidence=conf, severity=Severity.INFO)

        broken = [r for r in refs if r["status"] == "BROKEN"]
        unclaimed = [r for r in refs if r["status"] == "UNCLAIMED"]
        checked = [r for r in refs if r["status"] != "UNCHECKED"]

        ev = {
            "refs_total": len(refs),
            "broken": [{"kind": r["kind"], "name": r["name"]} for r in broken[:_MAX_EXAMPLES]],
            "unclaimed": [{"kind": r["kind"], "name": r["name"]} for r in unclaimed[:_MAX_EXAMPLES]],
            "remote_exec": remote_exec[:_MAX_EXAMPLES],
            "budget_exhausted": gathered.get("budget_exhausted", False),
        }
        # Every reference/description judged here is read out of llms.txt
        # and declared MCP server descriptions, plus the registry lookups
        # that resolve them (see `gatherers/reference_integrity.py`) — a
        # FOLDED record (many distinctly-named documents), so the generic
        # wording is used rather than naming any one of them.
        note, truncated = record_truncation(gathered, ev)
        conf = truncated_confidence(truncated)

        if broken:
            return self.result(
                CheckStatus.FAIL, f"{len(broken)} referenced package/domain(s) do not exist." + note, evidence=ev,
                confidence=conf,
                remediation="Remove or fix the dead reference before an agent (or anyone else) can register the empty slot.",
            )
        if unclaimed or remote_exec:
            severity = Severity.HIGH if remote_exec else Severity.MEDIUM
            summary = (
                f"{len(unclaimed)} referenced package name(s) are unclaimed and {len(remote_exec)} "
                "remote-execution instruction(s) were found in agent-facing documentation."
            )
            return self.result(
                CheckStatus.WARN, summary + note, evidence=ev, severity=severity, confidence=conf,
                remediation="Claim referenced unclaimed package names (dependency-confusion risk) and avoid instructing agents to pipe a remote script into a shell.",
            )
        if checked:
            return self.result(CheckStatus.PASS, f"All {len(checked)} checked reference(s) resolve." + note,
                               evidence=ev, confidence=conf)
        return self.error("every reference exhausted the lookup budget or timed out before it could be resolved.", ev)

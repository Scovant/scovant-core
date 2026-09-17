"""CoreCheck: the base class every check implements. `run()` is the only
entry point the engine calls — it guarantees a check bug or a gathering
failure never aborts the scan, only degrades that one check to ERROR.

ERROR vs. N/A (product spec §6): a document or page that SHOULD have been
readable but could not be (a fetch failed, a 5xx, an unparseable body) is
`self.error(...)` — it stays out of the score itself but counts toward a
category's *applicable* weight, so a site that is genuinely unreachable
drops the scan's evidence coverage below the floor in `scoring.py` and the
report is honestly reported as `INSUFFICIENT_EVIDENCE` rather than scored
on whatever the two or three checks that happened to still evaluate found.
`self.na(...)` is reserved for "nothing to evaluate here" — the check does
not apply to this site's resolved profile, or the thing being checked is
genuinely absent by a real, meaningful HTTP response (a real 404 where
absence is not itself a defect, e.g. an optional MCP discovery file) rather
than a read failure. Getting this wrong in either direction either hides a
broken/unreachable site behind a false score, or drags an evidence floor
down over sites that simply don't have the optional thing being checked."""
from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, EvidenceUnavailable
from scovant_core.models import Category, CheckResult, CheckStatus, Confidence, Severity


class CoreCheck(ABC):
    id: str
    title: str
    category: Category
    profiles: frozenset[str] | None = None
    weight: int = 1
    severity_on_fail: Severity = Severity.MEDIUM
    check_version: str = "1.0"
    experimental: bool = False
    references: tuple[str, ...] = ()
    standards: tuple[str, ...] = ()
    why_it_matters: str = ""
    # Experimental checks only (and required there — `tests/test_registry.py`):
    # what it would take to make this check scored. Without it "experimental"
    # is an indefinite parking space rather than a stage with an exit.
    promotion_criteria: str = ""
    limitations: str = (
        "Scovant Core evaluates declared and static evidence only; it does not observe real agent traffic."
    )
    cloud_extension: str = ""
    # SECURITY-category checks only (enforced by `registry.validate_registry`):
    # `family_id` groups checks into one identity/attack surface, and the
    # other four describe HOW the evidence was obtained and where it points.
    family_id: str = ""
    verification_mode: str = "PASSIVE_OBSERVED"
    security_domain: str = ""
    fix_owner: str = ""
    security_tags: tuple[str, ...] = ()

    def applicable(self, ctx: ScanContext) -> bool:
        return self.profiles is None or ctx.profile in self.profiles

    @abstractmethod
    def evaluate(self, store: EvidenceStore, ctx: ScanContext) -> CheckResult: ...

    def result(
        self, status: CheckStatus, summary: str, *, evidence: dict | None = None,
        confidence: Confidence = Confidence.HIGH, severity: Severity | None = None,
        remediation: str = "",
    ) -> CheckResult:
        sev = severity or (self.severity_on_fail if status in (CheckStatus.FAIL, CheckStatus.WARN) else Severity.INFO)
        return CheckResult(
            id=self.id, title=self.title, category=self.category, status=status, severity=sev,
            confidence=confidence, weight=self.weight, summary=summary, evidence=evidence or {},
            why_it_matters=self.why_it_matters, limitations=self.limitations,
            cloud_extension=self.cloud_extension, remediation=remediation,
            experimental=self.experimental, check_version=self.check_version,
            family_id=self.family_id, verification_mode=self.verification_mode,
            security_domain=self.security_domain, fix_owner=self.fix_owner,
            security_tags=list(self.security_tags),
        )

    def na(self, summary: str, evidence: dict | None = None, *,
           confidence: Confidence = Confidence.HIGH) -> CheckResult:
        """`confidence` is here for the same reason it exists on `result()`:
        an N/A that says "nothing was found to evaluate" is still a verdict
        drawn from a document, and a document read only in part cannot
        support that claim at full confidence. Branches whose absence is
        established independently of any partial read (a 404, a probe that
        found nothing to read) keep the HIGH default."""
        return self.result(CheckStatus.NA, summary, evidence=evidence, severity=Severity.INFO,
                           confidence=confidence)

    def error(self, reason: str, evidence: dict | None = None) -> CheckResult:
        return self.result(
            CheckStatus.ERROR, f"Could not evaluate: {reason}", evidence=evidence,
            confidence=Confidence.LOW, severity=Severity.INFO,
        )

    def run(self, store: EvidenceStore, ctx: ScanContext) -> CheckResult:
        if not self.applicable(ctx):
            return self.na(f"Not applicable to the {ctx.profile} profile.")
        try:
            return self.evaluate(store, ctx)
        except EvidenceUnavailable as exc:
            return self.error(str(exc), {"gather_error": dataclasses.asdict(exc.err)})
        except Exception as exc:  # noqa: BLE001 — a check bug must never abort the scan
            return self.error(f"{type(exc).__name__}: {exc}"[:200])

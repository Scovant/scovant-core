"""The report's `security` block: counts over SECURITY-category findings
only. Never a score — see docs/security.md and the spec's D3."""

from __future__ import annotations

from scovant_core.models import Category, CheckResult, CheckStatus, SecuritySummary, Severity

SECURITY_NOT_TESTED = [
    "Observed authorization",
    "Verified agent identity",
    "Prompt-injection resilience",
    "Tool invocation safety",
]
_STATUSES = (
    CheckStatus.PASS,
    CheckStatus.WARN,
    CheckStatus.FAIL,
    CheckStatus.NA,
    CheckStatus.ERROR,
)


def _has_redaction(evidence: object) -> bool:
    if isinstance(evidence, dict):
        return "redacted" in evidence or any(_has_redaction(v) for v in evidence.values())
    if isinstance(evidence, list):
        return any(_has_redaction(v) for v in evidence)
    return False


def build_security_summary(findings: list[CheckResult]) -> SecuritySummary:
    sec = [f for f in findings if f.category == Category.SECURITY]
    if not sec:
        # No SECURITY check ran at all (`--exclude security`, or a
        # `--include` selection that chose none). The bare defaults —
        # `findings_by_severity` and `by_domain` both `{}` — are what
        # `report._common.security_rows` renders as "not measured". A
        # zero-filled severity dict would instead render "Critical 0 …",
        # claiming a measurement that never happened.
        return SecuritySummary(not_tested=list(SECURITY_NOT_TESTED))
    by_sev = {s.value: 0 for s in Severity}
    by_domain: dict[str, dict[str, int]] = {}
    redacted = False
    for f in sec:
        if f.status in (CheckStatus.FAIL, CheckStatus.WARN):
            by_sev[f.severity.value] += 1
        dom = by_domain.setdefault(
            f.security_domain or "unclassified", {s.value: 0 for s in _STATUSES}
        )
        dom[f.status.value] += 1
        redacted = redacted or _has_redaction(f.evidence)
    return SecuritySummary(
        findings_by_severity=by_sev,
        by_domain=by_domain,
        not_tested=list(SECURITY_NOT_TESTED),
        redaction_applied=redacted,
    )

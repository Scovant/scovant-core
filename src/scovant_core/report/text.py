"""Human-readable CLI report — product spec §18 layout. The CTA is always the
last line: the target URL, once printed near the top, is never repeated
after it, so the report never reads as "one more mention of your URL" at the
exact point it's trying to sell a follow-up scan."""
from __future__ import annotations

from scovant_core.models import CATEGORY_TITLES, Category, CheckStatus, Report
from scovant_core.report._common import (
    capabilities_lines,
    evaluated_experimental,
    na_experimental,
    profile_note,
    status_counts,
    top_findings,
)
from scovant_core.report._common import scored_experimental as _scored_experimental
from scovant_core.report._cta import CTA_TEXT, cta_url

RULE = "─" * 46
CTA_URL = cta_url("cli")
_LABEL_WIDTH = 26
_STATUS_COLOR = {
    CheckStatus.PASS: "\033[32m",
    CheckStatus.WARN: "\033[33m",
    CheckStatus.FAIL: "\033[31m",
    CheckStatus.NA: "\033[2m",
    CheckStatus.ERROR: "\033[2m",
}
_RESET = "\033[0m"
_COUNT_ORDER = (
    CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.NA, CheckStatus.ERROR,
)
_COUNT_LABEL = {
    CheckStatus.PASS: "PASS", CheckStatus.WARN: "WARN", CheckStatus.FAIL: "FAIL",
    CheckStatus.NA: "N/A", CheckStatus.ERROR: "ERROR",
}


def _colorize(text: str, status: CheckStatus, color: bool) -> str:
    return f"{_STATUS_COLOR[status]}{text}{_RESET}" if color else text


def _profile_line(target) -> str:
    if target.requested_profile == "auto":
        return (
            f"Profile: {target.resolved_profile} "
            f"(auto → {target.resolved_profile}, confidence {target.profile_confidence:.2f})"
        )
    return f"Profile: {target.resolved_profile}"


def _total_checks() -> int:
    # Imported lazily to avoid a module-load cycle (checks import report
    # helpers transitively; report.text must not import checks at module scope).
    from scovant_core.checks.registry import CHECKS

    return len(CHECKS)


def score_line(report: Report) -> str:
    """The single summary line — `Static Signal Score NN / 100  GRADE`, or a
    status-specific fallback for DEGRADED/NOT_CANONICAL/INSUFFICIENT_EVIDENCE
    scans. Public so the CLI's `--quiet` mode can print exactly this line
    without pulling in the rest of `render_text`."""
    score = report.score
    if score.status == "INSUFFICIENT_EVIDENCE" or score.value is None:
        return f"Core Score: INSUFFICIENT EVIDENCE (coverage {score.coverage:.2f})"
    if score.status == "NOT_CANONICAL":
        selected = len(report.findings)
        excluded = report.provenance.get("excluded_checks")
        total = len(report.findings) + len(excluded) if excluded else _total_checks()
        return (
            f"{score.name} {score.value} / 100 — Canonical Core Score: NOT CALCULATED "
            f"({selected} of {total} checks selected)"
        )
    if score.status == "DEGRADED":
        n = int(report.metrics.get("error_count", 0))
        return (
            f"{'Static Signal Score'.ljust(_LABEL_WIDTH)}{score.value} / 100   "
            f"(no grade — score DEGRADED, coverage {score.coverage:.2f}, {n} checks errored)"
        )
    return f"{'Static Signal Score'.ljust(_LABEL_WIDTH)}{score.value} / 100   {score.grade}"


def _category_counts(findings: list, scored_experimental: bool) -> dict[str, tuple[int, int]]:
    """Per category: (evaluated, applicable) CHECK counts, on the same
    population the score itself uses — `N/A` is not applicable, `ERROR` is
    applicable but not evaluated, and an experimental check counts only when
    this scan actually scored experimental checks."""
    counts: dict[str, tuple[int, int]] = {}
    for f in findings:
        if f.experimental and not scored_experimental:
            continue
        if f.status == CheckStatus.NA:
            continue
        ev, ap = counts.get(f.category.value, (0, 0))
        counts[f.category.value] = (
            ev + (1 if f.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL) else 0),
            ap + 1,
        )
    return counts


def _category_lines(categories: dict, counts: dict[str, tuple[int, int]]) -> list[str]:
    """`(n/N)` = checks evaluated / checks applicable in that category — the
    coverage behind the number, so a category scored on one of four checks
    never reads like a category scored on all four. With only 1-10 checks per
    category in v0.1, a single check can move a whole category by a lot; see
    docs/methodology.md."""
    lines = []
    for cat in Category:
        cs = categories.get(cat.value)
        if cs is None:
            continue
        score_str = f"{cs.score:.0f}" if cs.score is not None else "n/a"
        evaluated, applicable = counts.get(cat.value, (0, 0))
        lines.append(
            f"{CATEGORY_TITLES[cat].ljust(_LABEL_WIDTH)}{score_str.ljust(6)}({evaluated}/{applicable})"
        )
    return lines


def _counts(findings: list) -> list[str]:
    counts = status_counts(findings)
    return [f"{counts[s]} {_COUNT_LABEL[s]}" for s in _COUNT_ORDER]


def _findings_block(findings: list, color: bool) -> list[str]:
    """Render a list of findings as alternating (status+id, summary, blank)
    lines — the shared rendering shape for both Top findings and the
    Experimental block."""
    lines: list[str] = []
    for f in findings:
        lines.append(f"{_colorize(f.status.value, f.status, color)}  {f.id}")
        lines.append(f"      {f.summary}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _top_findings(findings: list, color: bool, scored_experimental: bool) -> list[str]:
    return _findings_block(top_findings(findings, scored=scored_experimental), color)


def _experimental_lines(findings: list, color: bool) -> list[str]:
    """Experimental findings that are NOT `N/A`, in id order — shown on
    their own so a reader never mistakes an unscored experimental WARN/FAIL
    for something that moved the Static Signal Score. `N/A` experimental
    findings carry nothing to show (nothing was evaluated) and are left out
    of THIS list — a page of five "not applicable" full entries would be
    noise, not signal — but they are not left out of the rendered document:
    `render_text` names them on a separate compact "N/A: ..." line right
    after this block (or after the one-line notice, when every experimental
    finding is `N/A`), since the header's N/A count already includes them.
    Only called when the scan did NOT score experimental checks
    (`--experimental` off); when scoring is on, these
    findings already appear in the normal category counts and Top findings
    list."""
    return _findings_block(evaluated_experimental(findings), color)


def render_text(report: Report, *, color: bool = False) -> str:
    scored_experimental = _scored_experimental(report)
    lines = [
        "SCOVANT CORE", RULE, "",
        f"Target: {report.target.input_url}",
        _profile_line(report.target),
        f"Core version: {report.core_version}",
    ]
    if report.provenance.get("allow_private_networks"):
        lines.append("Note: private-network targets allowed (--allow-private-networks)")
    if scored_experimental:
        lines.append("Experimental checks: scored")
    s = report.score
    error_count = report.metrics.get("error_count", 0)
    lines.extend([
        "",
        score_line(report),
    ])
    note = profile_note(report)
    if note:
        lines.append(note)
    lines.extend([
        f"Scope: {s.scope} · Status: {s.status} · Coverage: {s.coverage:.0%} · Errors: {error_count}",
        "",
    ])
    lines += ["Capabilities detected (descriptive, not scored)", *("  " + line for line in capabilities_lines(report)), ""]
    counts = _category_counts(report.findings, scored_experimental)
    lines.extend(_category_lines(report.categories, counts))
    lines.append("")
    lines.append(f"{len(report.findings)} checks")
    lines.extend(_counts(report.findings))
    lines.append("")
    lines.append("Top findings")
    lines.append("")
    top = _top_findings(report.findings, color, scored_experimental)
    lines.extend(top if top else ["(none)"])
    lines.append("")
    if not scored_experimental:
        experimental_lines = _experimental_lines(report.findings, color)
        na = na_experimental(report.findings)
        if experimental_lines:
            lines.append("Experimental (not scored)")
            lines.append(RULE)
            lines.extend(experimental_lines)
            lines.append("")
        elif any(f.experimental for f in report.findings):
            # Every experimental finding is N/A on this scan — a five-line
            # "N/A" block would be noise, not signal; say so in one line.
            lines.append("Experimental checks: not scored (run with --experimental)")
            lines.append("")
        if na:
            # The header count above counts every check, N/A experimental
            # ones included; `_experimental_lines`/the notice above only
            # account for evaluated experimental findings, so name the N/A
            # ones here too or the header's own arithmetic does not
            # reconcile (mirrors markdown.py/html.py).
            lines.append("N/A: " + ", ".join(f.id for f in na))
            lines.append("")
    lines.append("Not tested by Scovant Core")
    lines.append(RULE)
    lines.extend(f"{name.ljust(_LABEL_WIDTH)}NOT TESTED" for name in report.not_tested)
    lines.append("")
    lines.append(CTA_TEXT)
    lines.append(CTA_URL)
    return "\n".join(lines) + "\n"

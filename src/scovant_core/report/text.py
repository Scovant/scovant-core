"""Human-readable CLI report — product spec §18 layout. The CTA is always the
last line: the target URL, once printed near the top, is never repeated
after it, so the report never reads as "one more mention of your URL" at the
exact point it's trying to sell a follow-up scan."""
from __future__ import annotations

from scovant_core.models import CATEGORY_TITLES, Category, CheckStatus, Report
from scovant_core.report._common import (
    SECURITY_DISCLAIMER,
    STANDARDS_FOOTER,
    TECHNICAL_LABEL,
    capabilities_lines,
    diagnostics_parts,
    evaluated_experimental,
    legacy_headline,
    na_experimental,
    not_measured_text,
    profile_note,
    security_rows,
    standards_line,
    status_counts,
    status_note,
    technical_headline,
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


def score_line(report: Report, *, legacy_score: bool = False) -> str:
    """The single summary line: the Technical Readiness headline
    (`Technical Readiness  NN / 100  G · coverage NN% · model …`, or its
    no-number / not-computed form), or — with `legacy_score` — the
    deprecated five-domain line. Public so the CLI's `--quiet` mode can
    print exactly this line without the rest of `render_text`."""
    if legacy_score:
        return legacy_headline(report)
    return f"{TECHNICAL_LABEL}  {technical_headline(report)}"


def _technical_lines(report: Report) -> list[str]:
    """Headline, the not-measured line when non-empty, then Diagnostics."""
    lines = [score_line(report)]
    missing = not_measured_text(report)
    if missing:
        lines.append(f"Not measured by Core: {missing}")
    lines.append(": ".join(diagnostics_parts(report)))
    return lines


def _legacy_lines(report: Report, scored_experimental: bool) -> list[str]:
    """The deprecated five-domain block — printed only with
    `--legacy-score` (removed in 0.19.0)."""
    s = report.score
    error_count = report.metrics.get("error_count", 0)
    lines = [
        legacy_headline(report),
        f"Scope: {s.scope} · Status: {s.status} · Coverage: {s.coverage:.0%} · Errors: {error_count}",
    ]
    note = status_note(report)
    if note:
        lines.append("".join(note))
    if scored_experimental:
        lines.append("Experimental checks: scored")
    counts = _category_counts(report.findings, scored_experimental)
    lines.extend(_category_lines(report.categories, counts))
    return lines


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
        tag = "[security] " if f.category == Category.SECURITY else ""
        lines.append(f"{_colorize(f.status.value, f.status, color)}  {tag}{f.id}")
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


def render_text(report: Report, *, color: bool = False, legacy_score: bool = False) -> str:
    scored_experimental = _scored_experimental(report)
    lines = [
        "SCOVANT CORE", RULE, "",
        f"Target: {report.target.input_url}",
        _profile_line(report.target),
        f"Core version: {report.core_version}",
    ]
    if report.provenance.get("allow_private_networks"):
        lines.append("Note: private-network targets allowed (--allow-private-networks)")
    lines.append("")
    lines.extend(_technical_lines(report))
    note = profile_note(report)
    if note:
        lines.append(note)
    lines.append("")
    lines += ["Capabilities detected (descriptive, not scored)", *("  " + line for line in capabilities_lines(report)), ""]
    lines += [standards_line(report), "  " + STANDARDS_FOOTER, ""]
    if legacy_score:
        lines.extend(_legacy_lines(report, scored_experimental))
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
    lines.append("AGENTIC SECURITY & TRUST".ljust(_LABEL_WIDTH) + report.security.label)
    lines.append(RULE)
    for label, value in security_rows(report):
        lines.append(f"{label.ljust(_LABEL_WIDTH)}{value}")
    # `(name + " ").ljust(_LABEL_WIDTH)` (not `name.ljust(_LABEL_WIDTH)`)
    # guarantees at least one separating space even for a label at or past
    # `_LABEL_WIDTH` chars ("Prompt-injection resilience" is 28) — plain
    # `ljust` is a no-op once the string already exceeds the width, which
    # glued the label straight onto "NOT TESTED" with no space at all.
    lines.extend(f"{(name + ' ').ljust(_LABEL_WIDTH)}NOT TESTED" for name in report.security.not_tested)
    lines.append(SECURITY_DISCLAIMER)
    lines.append("")
    lines.append("Not tested by Scovant Core")
    lines.append(RULE)
    lines.extend(f"{(name + ' ').ljust(_LABEL_WIDTH)}NOT TESTED" for name in report.not_tested)
    lines.append("")
    lines.append(CTA_TEXT)
    lines.append(CTA_URL)
    return "\n".join(lines) + "\n"

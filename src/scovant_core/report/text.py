"""Human-readable CLI report — product spec §18 layout. The CTA is always the
last line: the target URL, once printed near the top, is never repeated
after it, so the report never reads as "one more mention of your URL" at the
exact point it's trying to sell a follow-up scan."""
from __future__ import annotations

from scovant_core.models import Category, CheckStatus, Report
from scovant_core.report._common import (
    SECURITY_DISCLAIMER,
    STANDARDS_FOOTER,
    TECHNICAL_LABEL,
    capabilities_lines,
    diagnostics_parts,
    evaluated_experimental,
    na_experimental,
    not_measured_text,
    profile_note,
    scope_note,
    security_rows,
    standards_line,
    status_counts,
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


def score_line(report: Report) -> str:
    """The single summary line: the Technical Readiness headline
    (`Technical Readiness  NN / 100  G · coverage NN% · model …`, or its
    no-number / not-computed form). Public so the CLI's `--quiet` mode can
    print exactly this line without the rest of `render_text`."""
    return f"{TECHNICAL_LABEL}  {technical_headline(report)}"


def _technical_lines(report: Report) -> list[str]:
    """Headline, the not-measured line when non-empty, then Diagnostics."""
    lines = [score_line(report)]
    missing = not_measured_text(report)
    if missing:
        lines.append(f"Not measured by Core: {missing}")
    lines.append(": ".join(diagnostics_parts(report)))
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
    their own so a reader never mistakes an experimental WARN/FAIL for an
    established check. `N/A` experimental
    findings carry nothing to show (nothing was evaluated) and are left out
    of THIS list — a page of five "not applicable" full entries would be
    noise, not signal — but they are not left out of the rendered document:
    `render_text` names them on a separate compact "N/A: ..." line right
    after this block (or after the one-line notice, when every experimental
    finding is `N/A`), since the header's N/A count already includes them.
    Only called when `--experimental` is off; with it on, these findings
    already appear in the Top findings list."""
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
    lines.append("")
    lines.extend(_technical_lines(report))
    scope = scope_note(report)
    if scope:
        lines.append(scope)
    note = profile_note(report)
    if note:
        lines.append(note)
    lines.append("")
    lines += ["Capabilities detected (descriptive, not scored)", *("  " + line for line in capabilities_lines(report)), ""]
    lines += [standards_line(report), "  " + STANDARDS_FOOTER, ""]
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

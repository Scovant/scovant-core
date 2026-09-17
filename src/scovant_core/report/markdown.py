"""Markdown report — for pull requests, issues and chat. Derived from `Report` only."""
from __future__ import annotations

import json

from scovant_core.models import Category, CheckStatus, Report
from scovant_core.report._common import (
    SECURITY_DISCLAIMER,
    STANDARDS_FOOTER,
    capabilities_lines,
    evaluated_experimental,
    grouped_by_status,
    has_experimental,
    na_experimental,
    profile_note,
    scored_experimental,
    security_findings,
    security_rows,
    standards_line,
    status_counts,
    status_note,
    top_findings,
)
from scovant_core.report._cta import CTA_TEXT, cta_url

_STATUS_HEADING = {
    CheckStatus.FAIL: "FAIL", CheckStatus.WARN: "WARN", CheckStatus.ERROR: "ERROR",
    CheckStatus.PASS: "PASS", CheckStatus.NA: "N/A",
}


def _score_block(r: Report) -> list[str]:
    s = r.score
    value = "—" if s.value is None else str(s.value)
    grade = s.grade or "—"
    error_count = r.metrics.get("error_count", 0)
    lines = [f"**{s.name}:** {value} / 100 · grade {grade} · coverage {s.coverage:.0%}"]
    lines.append(f"**Scope:** {s.scope} · **Status:** {s.status} · **Errors:** {error_count}")
    note = status_note(r)
    if note:
        strong, rest = note
        lines.append(f"**{strong}**{rest}")
    p_note = profile_note(r)
    if p_note:
        lines.append(p_note)
    t = r.target
    lines.append(
        f"**Profile:** {t.resolved_profile} (requested {t.requested_profile}, "
        f"confidence {t.profile_confidence:.0%})"
    )
    if scored_experimental(r):
        lines.append("**Experimental checks:** scored")
    if r.provenance.get("allow_private_networks"):
        lines.append(
            "**Note:** private-network targets were allowed for this scan "
            "(`--allow-private-networks`)."
        )
    lines.append("")
    lines.append("**Capabilities detected** (descriptive, not scored): " + " · ".join(capabilities_lines(r)))
    lines.append(f"**Standards:** {standards_line(r)} — {STANDARDS_FOOTER}")
    return lines


def _categories(r: Report) -> list[str]:
    out = ["| Category | Weight | Score | Evaluated / applicable |", "|---|---:|---:|---:|"]
    for c in r.categories.values():
        score = "n/a" if c.score is None else f"{c.score:.0f}"
        out.append(f"| {c.title} | {c.weight} | {score} | {c.evaluated_weight:g} / {c.applicable_weight:g} |")
    return out


def _finding(f) -> list[str]:
    lines = [f"- **{f.id}** — {f.title} ({f.severity.value}): {f.summary}"]
    if f.remediation:
        lines.append(f"  - Remediation: {f.remediation}")
    if f.evidence:
        ev = json.dumps(f.evidence, indent=2, sort_keys=True, ensure_ascii=False)
        lines += ["", "  <details><summary>evidence</summary>", "", "  ```json"]
        lines += ["  " + line for line in ev.splitlines()]
        lines += ["  ```", "", "  </details>", ""]
    return lines


def render_markdown(report: Report, *, utm_medium: str = "cli") -> str:
    scored = scored_experimental(report)
    counts = status_counts(report.findings)
    out = [f"# Scovant Core — {report.target.final_url or report.target.input_url}", "", "## Score", ""]
    out += _score_block(report) + ["", "## Categories", ""] + _categories(report)
    out += [
        "",
        f"{len(report.findings)} checks: "
        + ", ".join(
            f"{counts[s]} {_STATUS_HEADING[s]}"
            for s in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.NA, CheckStatus.ERROR)
        ),
        "",
    ]
    out += ["## Top findings", ""]
    top = top_findings(report.findings, scored)
    out += [
        f"- {'**[security]** ' if f.category == Category.SECURITY else ''}**{f.id}** — {f.summary}"
        for f in top
    ] or ["(none)"]
    out += ["", "## Findings", ""]
    for status, fs in grouped_by_status(report.findings).items():
        fs = [f for f in fs if scored or not f.experimental]
        if not fs:
            continue
        out += [f"### {_STATUS_HEADING[status]} ({len(fs)})", ""]
        if status == CheckStatus.NA:
            out += [", ".join(f"`{f.id}`" for f in fs), ""]
            continue
        for f in fs:
            out += _finding(f)
    if not scored and has_experimental(report.findings):
        # The count line above counts every check in the report, experimental
        # ones included, while the status sections above list only the scored
        # ones — so every experimental finding has to be accounted for HERE or
        # the document's own arithmetic does not add up. Evaluated ones get a
        # full entry; `N/A` ones (nothing was evaluated, nothing to show) get
        # the same compact bare-id line the `N/A` section uses, rather than a
        # page of "not applicable" entries.
        ex = evaluated_experimental(report.findings)
        na = na_experimental(report.findings)
        out += ["## Experimental (not scored)", ""]
        if ex:
            out += [f"- **{f.id}** ({f.status.value}) — {f.summary}" for f in ex]
            out += [""]
        else:
            out += ["_Experimental checks: not scored (run with --experimental)_", ""]
        if na:
            out += ["N/A: " + ", ".join(f"`{f.id}`" for f in na), ""]
    out += ["## Agentic Security & Trust", "", f"_{report.security.label}_", "", "| | |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in security_rows(report)]
    out += [""]
    if report.security.not_tested:
        out += [f"- {n}: NOT TESTED" for n in report.security.not_tested] + [""]
    for f in security_findings(report):
        out += [
            f"### {f.id} ({f.family_id}) — {f.title}", "",
            f"- Status: {f.status.value} · Severity: {f.severity.value} · Confidence: {f.confidence.value} · Verification: {f.verification_mode}",
            f"- Fix owner: {f.fix_owner} · Domain: {f.security_domain}", f"- {f.summary}",
        ]
        if f.remediation:
            out.append(f"- Remediation: {f.remediation}")
        if f.limitations:
            out.append(f"- Limitations: {f.limitations}")
        out += _finding(f)[1:] if f.evidence else [""]
    out += [SECURITY_DISCLAIMER, ""]
    out += ["## Not tested by Scovant Core", ""] + [f"- {n}" for n in report.not_tested] + [""]
    p = report.provenance
    out += [
        "## Provenance", "",
        f"Core {report.core_version} · ruleset {report.ruleset_version} "
        f"(digest `{p.get('ruleset_digest', '')}`) · scan `{report.scan_id}` · {report.completed_at}",
        "",
    ]
    out += [f"{CTA_TEXT} [scovant.com/scan]({cta_url(utm_medium)})", ""]
    return "\n".join(out)

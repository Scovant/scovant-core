"""GitHub Action glue for `scovant_core`.

`action.yml` is deliberately thin bash — every decision it needs (what the
six outputs are, what the `$GITHUB_STEP_SUMMARY` block looks like, which
report format to render, how the gate maps to an exit code) lives here so it
is unit-tested like any other module, not hidden inside inline YAML.

Contract: `python -m scovant_core.action <command> core.json [options]`.
`main(argv, env=None)` never reads `os.environ` directly — the Action's own
steps pass no `env` and get the real environment; tests inject a small dict
so `$GITHUB_OUTPUT`/`$GITHUB_STEP_SUMMARY` never touch the real filesystem
location a CI runner would use.

Four subcommands:
- `outputs core.json --report-path PATH` — appends the action outputs to
  `$GITHUB_OUTPUT`. Since 0.18.0 `score`/`grade`/`score_status`/`coverage`
  are Technical Readiness (`readiness.technical`); the deprecated
  five-domain value is `legacy_score`. Empty strings stand for "no number"
  / "no block", never 0.
- `summary core.json [--legacy-score]` — appends the Markdown block to
  `$GITHUB_STEP_SUMMARY`, led by Technical Readiness; the legacy line only
  with `--legacy-score`.
- `report core.json --format html|markdown --out PATH [--legacy-score]` —
  renders the chosen format via the same renderers the CLI uses, with
  `utm_medium="github"`.
- `gate core.json --min-score N --fail-on never|warn|fail [--legacy-score]`
  — re-applies `cli._threshold_exit_code` over the JSON re-parsed into a
  `Report`, so a red check always reflects the site, never a rendering
  difference. `--legacy-score` gates on the deprecated five-domain score.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from scovant_core.cli import _threshold_exit_code
from scovant_core.models import Category, CheckStatus, Report, Severity, TechnicalReadiness
from scovant_core.report._common import (
    TECHNICAL_LABEL,
    diagnostics_parts,
    legacy_headline,
    scored_experimental,
    status_counts,
    status_note,
    top_findings,
)
from scovant_core.report._cta import cta_url
from scovant_core.report.html import render_html
from scovant_core.report.markdown import render_markdown

__all__ = ["main", "INPUT_KEYS", "OUTPUT_KEYS"]

# `action.yml`'s `inputs:` keys, in the order they appear there. A test
# parses `action.yml` and asserts its input names equal this set and the
# README's inputs table, so the three can never quietly drift apart.
INPUT_KEYS = (
    "url",
    "profile",
    "min-core-score",
    "fail-on",
    "experimental",
    "timeout",
    "report-format",
    "allow-private-networks",
    "trusted-target",
    "require-canonical",
    "fail-on-security",
    "legacy-score",
)

# `action.yml`'s `outputs:` keys, in the order §25 defines them, plus the
# four security counts, plus (0.18.0) `legacy_score`/`model_id`. `score`/
# `grade`/`coverage`/`score_status` are Technical Readiness
# (`readiness.technical`); `scan_scope` stays the five-domain selection
# scope, and `legacy_score` the deprecated five-domain value (removed with
# it in 0.19.0). `pass_count`/`warn_count`/`fail_count` are
# READINESS-ONLY (SECURITY-category findings excluded) — `Report.security`
# is never scored, so folding a security FAIL into the readiness `fail_count`
# would silently change what that number means; `security_critical`/
# `security_high` (from `Report.security.findings_by_severity`, FAIL+WARN)
# and `security_fail_count`/`security_warn_count` (readiness-gate-shaped
# counts, over SECURITY findings only) make the security population visible
# on its own instead.
OUTPUT_KEYS = (
    "score",
    "grade",
    "pass_count",
    "warn_count",
    "fail_count",
    "report_path",
    "coverage",
    "score_status",
    "scan_scope",
    "error_count",
    "security_critical",
    "security_high",
    "security_fail_count",
    "security_warn_count",
    "legacy_score",
    "model_id",
)

_FAIL_ON = ("fail", "warn", "never")
_FAIL_ON_SECURITY = ("critical", "high", "medium", "never")
_REPORT_FORMATS = ("html", "markdown")


def _load_report(path: str) -> Report:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Report.model_validate(data)


def _append(path: str | None, text: str) -> None:
    """Append `text` to the file at `path` — a no-op when `path` is unset
    (e.g. a local dry run with no `$GITHUB_OUTPUT`/`$GITHUB_STEP_SUMMARY` in
    the environment), never an error."""
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def _min_score_type(value: str) -> int | None:
    """`--min-score` accepts the empty string (the Action's `min-core-score`
    input defaults to `''`, meaning "no gate") in addition to `0..100`."""
    if value == "":
        return None
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if not 0 <= n <= 100:
        raise argparse.ArgumentTypeError("--min-score must be between 0 and 100")
    return n


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scovant-core-action")
    sub = parser.add_subparsers(dest="command", required=True)

    outputs_p = sub.add_parser("outputs", help="write the action outputs to $GITHUB_OUTPUT")
    outputs_p.add_argument("report_json")
    outputs_p.add_argument("--report-path", required=True, dest="report_path")

    summary_p = sub.add_parser("summary", help="write the step summary to $GITHUB_STEP_SUMMARY")
    summary_p.add_argument("report_json")
    summary_p.add_argument("--legacy-score", action="store_true", dest="legacy_score",
                           help="add the deprecated five-domain score line")

    report_p = sub.add_parser("report", help="render the chosen report format to --out")
    report_p.add_argument("report_json")
    report_p.add_argument("--format", choices=_REPORT_FORMATS, required=True)
    report_p.add_argument("--out", required=True)
    report_p.add_argument("--legacy-score", action="store_true", dest="legacy_score",
                          help="render the deprecated five-domain score block")

    gate_p = sub.add_parser("gate", help="re-apply the CLI's threshold exit code")
    gate_p.add_argument("report_json")
    gate_p.add_argument("--min-score", type=_min_score_type, default=None, dest="min_score")
    gate_p.add_argument("--fail-on", choices=_FAIL_ON, default="never", dest="fail_on")
    gate_p.add_argument(
        "--require-canonical", action="store_true", dest="require_canonical",
        help="fail unless Technical Readiness status is OK (with --legacy-score: "
             "the five-domain scan is CANONICAL with score status OK)",
    )
    gate_p.add_argument(
        "--fail-on-security", choices=_FAIL_ON_SECURITY, default="never", dest="fail_on_security",
        help="exit 6 when a security finding FAILs at or above this severity (WARN never gates)",
    )
    gate_p.add_argument(
        "--legacy-score", action="store_true", dest="legacy_score",
        help="gate on the deprecated five-domain Static Signal Score; removed in 0.19.0",
    )

    return parser


_NOT_MEASURED_CAP = 10


def summary_headline(report: Report) -> str:
    """The summary's first line: `## Scovant Core — Technical Readiness NN
    / 100 (G) · coverage NN%`. No grade token without a grade (DEGRADED), a
    status token when it is not OK, `— · STATUS` with no number, `not
    computed` when the engine recorded no `readiness` block."""
    head = f"## Scovant Core — {TECHNICAL_LABEL}"
    if report.readiness is None:
        return f"{head} not computed"
    t = report.readiness.technical
    coverage = f"coverage {t.coverage:.0%}"
    if t.rating is None:
        return f"{head} — · {t.status} · {coverage}"
    grade = "" if t.grade is None else f" ({t.grade})"
    status = "" if t.status == "OK" else f" · {t.status}"
    return f"{head} {t.rating} / 100{grade}{status} · {coverage}"


def _not_measured_line(technical: TechnicalReadiness) -> str:
    """`RULE (reason), …` sorted by rule, at most ten, then `and N more`."""
    items = sorted(technical.not_measured, key=lambda n: (n.rule, n.reason))
    if not items:
        return "**Not measured by Core:** none"
    text = ", ".join(f"{n.rule} ({n.reason})" for n in items[:_NOT_MEASURED_CAP])
    if len(items) > _NOT_MEASURED_CAP:
        text += f" and {len(items) - _NOT_MEASURED_CAP} more"
    return f"**Not measured by Core:** {text}"


def render_summary(report: Report, *, legacy_score: bool = False) -> str:
    """The Markdown block written verbatim to `$GITHUB_STEP_SUMMARY`:
    Technical Readiness first, then its model id and not-measured list, the
    readiness diagnostics, and — only with `legacy_score` — the deprecated
    five-domain score line."""
    # Readiness-only, matching the `pass_count`/`warn_count`/`fail_count`
    # outputs this Action publishes (see the OUTPUT_KEYS comment): one
    # summary block must not count a population the outputs exclude.
    # SECURITY findings get their own line below instead.
    security = [f for f in report.findings if f.category == Category.SECURITY]
    security_counts = status_counts(security)
    scored = scored_experimental(report)

    critical = [
        f
        for f in report.findings
        if f.status == CheckStatus.FAIL
        and f.severity in (Severity.HIGH, Severity.CRITICAL)
        and (scored or not f.experimental)
    ]
    # SECURITY-category items are never scored (see `Report.security.scored`)
    # but a high/critical-severity FAIL there is still worth a reviewer's
    # eye — tagged, not silently folded into the readiness "Critical" count.
    critical_line = " | ".join(
        f"`{f.id}` — {'[security] ' if f.category == Category.SECURITY else ''}{f.summary}" for f in critical
    ) or "none"

    top = top_findings(report.findings, scored)
    top_line = f"`{top[0].id}` — {top[0].summary}" if top else "none"

    lines = [summary_headline(report), ""]
    if report.readiness is not None:
        t = report.readiness.technical
        lines.append(f"**Model:** `{t.model_id}` · status {t.status} · passive evidence only")
        lines.append(_not_measured_line(t))
    else:
        lines.append(f"{TECHNICAL_LABEL} was not computed for this scan.")
    label, diag = diagnostics_parts(report)
    lines += ["", f"**{label}:** {diag}"]
    if legacy_score:
        lines += ["", f"**{legacy_headline(report)}**"]
        note = status_note(report)
        if note:
            strong, rest = note
            lines.append(f"**{strong}**{rest}")
    lines += [
        "",
        # Never folded into the line above: security findings are never
        # scored, and "not measured" is not the same statement as "0 fail".
        "**Security (never scored):** " + (
            f"{security_counts[CheckStatus.PASS]} pass · {security_counts[CheckStatus.WARN]} warn · "
            f"{security_counts[CheckStatus.FAIL]} fail · {security_counts[CheckStatus.NA]} n/a · "
            f"{security_counts[CheckStatus.ERROR]} error"
            if security else "not measured (no security check ran)"
        ),
        "",
        f"**Critical:** {critical_line}",
        f"**Top issue:** {top_line}",
        "",
        f"Verify with real agents: {cta_url('github')}",
        "Track this score over time and verify real agents with Scovant Monitor.",
        "",
    ]
    return "\n".join(lines)


def _cmd_outputs(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    report = _load_report(args.report_json)
    s = report.score
    # Readiness-only: `Report.security` is never scored, so pass_count/
    # warn_count/fail_count must never mix a security finding into a
    # readiness population — see the OUTPUT_KEYS comment above.
    readiness = [f for f in report.findings if f.category != Category.SECURITY]
    counts = status_counts(readiness)
    security = [f for f in report.findings if f.category == Category.SECURITY]
    security_counts = status_counts(security)
    sec_sev = report.security.findings_by_severity
    # Technical Readiness: empty strings when the block is absent (Technical
    # raised) and, for score/grade, when it carries no number — never 0.
    t = report.readiness.technical if report.readiness is not None else None
    lines = [
        f"score={'' if t is None or t.rating is None else t.rating}",
        f"grade={'' if t is None else (t.grade or '')}",
        f"pass_count={counts[CheckStatus.PASS]}",
        f"warn_count={counts[CheckStatus.WARN]}",
        f"fail_count={counts[CheckStatus.FAIL]}",
        f"report_path={args.report_path}",
        f"coverage={'' if t is None else t.coverage}",
        f"score_status={'' if t is None else t.status}",
        f"scan_scope={s.scope}",
        f"error_count={report.metrics.get('error_count', 0)}",
        f"security_critical={sec_sev.get('critical', 0)}",
        f"security_high={sec_sev.get('high', 0)}",
        f"security_fail_count={security_counts[CheckStatus.FAIL]}",
        f"security_warn_count={security_counts[CheckStatus.WARN]}",
        f"legacy_score={'' if s.value is None else s.value}",
        f"model_id={'' if t is None else t.model_id}",
    ]
    _append(env.get("GITHUB_OUTPUT"), "".join(f"{line}\n" for line in lines))
    return 0


def _cmd_summary(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    report = _load_report(args.report_json)
    _append(env.get("GITHUB_STEP_SUMMARY"), render_summary(report, legacy_score=args.legacy_score) + "\n")
    return 0


def _cmd_report(args: argparse.Namespace, env: Mapping[str, str]) -> int:  # noqa: ARG001 — env unused, kept for the shared call shape
    report = _load_report(args.report_json)
    render = render_html if args.format == "html" else render_markdown
    rendered = render(report, utm_medium="github", legacy_score=args.legacy_score)
    if not rendered.endswith("\n"):
        rendered += "\n"
    Path(args.out).write_text(rendered, encoding="utf-8")
    return 0


def _cmd_gate(args: argparse.Namespace, env: Mapping[str, str]) -> int:  # noqa: ARG001 — env unused, kept for the shared call shape
    report = _load_report(args.report_json)
    return _threshold_exit_code(
        report, min_score=args.min_score, fail_on=args.fail_on,
        require_canonical=args.require_canonical, fail_on_security=args.fail_on_security,
        legacy_score=args.legacy_score,
    )


_COMMANDS = {
    "outputs": _cmd_outputs,
    "summary": _cmd_summary,
    "report": _cmd_report,
    "gate": _cmd_gate,
}


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    import os

    resolved_env: Mapping[str, str] = dict(os.environ if env is None else env)
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _COMMANDS[args.command](args, resolved_env)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

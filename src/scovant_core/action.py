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
- `outputs core.json --report-path PATH` — appends the six action outputs
  to `$GITHUB_OUTPUT` (`score`/`grade` as the empty string when unmeasured).
- `summary core.json` — appends the product-spec §25.1 Markdown block to
  `$GITHUB_STEP_SUMMARY`.
- `report core.json --format html|markdown --out PATH` — renders the chosen
  format via the same renderers the CLI uses, with `utm_medium="github"`.
- `gate core.json --min-score N --fail-on never|warn|fail` — re-applies
  `cli._threshold_exit_code` over the JSON re-parsed into a `Report`, so a
  red check always reflects the site, never a rendering difference.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from scovant_core.cli import _threshold_exit_code
from scovant_core.models import CheckStatus, Report, Severity
from scovant_core.report._common import (
    scored_experimental,
    status_counts,
    status_note,
    top_findings,
)
from scovant_core.report._cta import cta_url
from scovant_core.report.html import render_html
from scovant_core.report.markdown import render_markdown

__all__ = ["main", "INPUT_KEYS", "OUTPUT_KEYS"]

# `action.yml`'s `inputs:` keys, in the order they appear there — the
# monorepo sync test (`test_action_manifest_matches_readme_and_code`) parses
# `action.yml` and asserts its input names equal this set, and equal the
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
)

# `action.yml`'s `outputs:` keys, in the order §25 defines them.
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
)

_FAIL_ON = ("fail", "warn", "never")
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

    report_p = sub.add_parser("report", help="render the chosen report format to --out")
    report_p.add_argument("report_json")
    report_p.add_argument("--format", choices=_REPORT_FORMATS, required=True)
    report_p.add_argument("--out", required=True)

    gate_p = sub.add_parser("gate", help="re-apply the CLI's threshold exit code")
    gate_p.add_argument("report_json")
    gate_p.add_argument("--min-score", type=_min_score_type, default=None, dest="min_score")
    gate_p.add_argument("--fail-on", choices=_FAIL_ON, default="never", dest="fail_on")
    gate_p.add_argument(
        "--require-canonical", action="store_true", dest="require_canonical",
        help="fail unless the scan is CANONICAL with score status OK",
    )

    return parser


def render_summary(report: Report) -> str:
    """The product-spec §25.1 Markdown block, written verbatim to
    `$GITHUB_STEP_SUMMARY`."""
    s = report.score
    value = "—" if s.value is None else str(s.value)
    grade = s.grade or "—"
    counts = status_counts(report.findings)
    scored = scored_experimental(report)

    critical = [
        f
        for f in report.findings
        if f.status == CheckStatus.FAIL
        and f.severity in (Severity.HIGH, Severity.CRITICAL)
        and (scored or not f.experimental)
    ]
    critical_line = " | ".join(f"`{f.id}` — {f.summary}" for f in critical) or "none"

    top = top_findings(report.findings, scored)
    top_line = f"`{top[0].id}` — {top[0].summary}" if top else "none"

    note = status_note(report)

    lines = [
        f"## Scovant Core — scope {s.scope} · status {s.status}",
        "",
        f"**{s.name}:** {value} / 100 · grade {grade} · scope {s.scope} · status {s.status} · "
        f"coverage {s.coverage:.0%}",
    ]
    if note:
        strong, rest = note
        lines.append(f"**{strong}**{rest}")
    lines += [
        "",
        f"{counts[CheckStatus.PASS]} pass · {counts[CheckStatus.WARN]} warn · "
        f"{counts[CheckStatus.FAIL]} fail · {counts[CheckStatus.NA]} n/a · "
        f"{counts[CheckStatus.ERROR]} error",
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
    counts = status_counts(report.findings)
    lines = [
        f"score={'' if s.value is None else s.value}",
        f"grade={s.grade or ''}",
        f"pass_count={counts[CheckStatus.PASS]}",
        f"warn_count={counts[CheckStatus.WARN]}",
        f"fail_count={counts[CheckStatus.FAIL]}",
        f"report_path={args.report_path}",
        f"coverage={s.coverage}",
        f"score_status={s.status}",
        f"scan_scope={s.scope}",
        f"error_count={report.metrics.get('error_count', 0)}",
    ]
    _append(env.get("GITHUB_OUTPUT"), "".join(f"{line}\n" for line in lines))
    return 0


def _cmd_summary(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    report = _load_report(args.report_json)
    _append(env.get("GITHUB_STEP_SUMMARY"), render_summary(report) + "\n")
    return 0


def _cmd_report(args: argparse.Namespace, env: Mapping[str, str]) -> int:  # noqa: ARG001 — env unused, kept for the shared call shape
    report = _load_report(args.report_json)
    rendered = render_html(report, utm_medium="github") if args.format == "html" \
        else render_markdown(report, utm_medium="github")
    if not rendered.endswith("\n"):
        rendered += "\n"
    Path(args.out).write_text(rendered, encoding="utf-8")
    return 0


def _cmd_gate(args: argparse.Namespace, env: Mapping[str, str]) -> int:  # noqa: ARG001 — env unused, kept for the shared call shape
    report = _load_report(args.report_json)
    return _threshold_exit_code(
        report, min_score=args.min_score, fail_on=args.fail_on,
        require_canonical=args.require_canonical,
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

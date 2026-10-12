import pytest

from scovant_core import action
from scovant_core.report.json import render_json
from tests.test_cli import _real_report
from tests.test_report_markdown import _report


def _core_json(tmp_path):
    p = tmp_path / "core.json"
    p.write_text(render_json(_report("commerce-bad")))
    return p


@pytest.fixture
def report_json(tmp_path):
    """A CANONICAL/OK report — no --include/--exclude selection."""
    return _core_json(tmp_path)


@pytest.fixture
def custom_report_json(tmp_path):
    """A CUSTOM/NOT_CANONICAL report, produced with `--include CORE-ACCESS-003`."""
    from scovant_core.context import ScanOptions
    from scovant_core.engine import scan
    from tests.conftest import FIXTURES, FixtureTransport

    report = scan(
        "https://example.com/",
        ScanOptions(include=("CORE-ACCESS-003",)),
        transport=FixtureTransport(FIXTURES / "sites" / "commerce-bad"),
        clock=lambda: "2026-09-04T00:00:00Z",
        scan_id="md-custom",
    )
    p = tmp_path / "custom.json"
    p.write_text(render_json(report))
    return p


def _outputs(tmp_path, report_json) -> dict[str, str]:
    out = tmp_path / "out.txt"
    out.unlink(missing_ok=True)  # $GITHUB_OUTPUT is appended to
    action.main(["outputs", str(report_json), "--report-path", "core.html"], env={"GITHUB_OUTPUT": str(out)})
    lines = out.read_text().splitlines()
    pairs = dict(line.split("=", 1) for line in lines)
    assert len(pairs) == len(lines) == len(action.OUTPUT_KEYS)
    assert tuple(pairs) == action.OUTPUT_KEYS
    return pairs


def _write(tmp_path, report, name="core.json"):
    p = tmp_path / name
    p.write_text(render_json(report))
    return p


def test_outputs_written_to_github_output(tmp_path):
    for key, value in _outputs(tmp_path, _core_json(tmp_path)).items():
        assert key in action.OUTPUT_KEYS and isinstance(value, str)
    assert _outputs(tmp_path, _core_json(tmp_path))["report_path"] == "core.html"


def test_outputs_carry_technical_readiness_on_commerce_good(tmp_path):
    """`score`/`grade`/`score_status`/`coverage` are Technical Readiness."""
    report = _report("commerce-good")
    t = report.readiness.technical
    assert (t.rating, t.grade, t.status) == (82, "B", "OK")
    out = _outputs(tmp_path, _write(tmp_path, report))
    assert out["score"] == "82"
    assert out["grade"] == "B"
    assert out["score_status"] == "OK"
    assert out["coverage"] == str(t.coverage)
    assert out["model_id"] == "R2.1@67df90af85b0"
    assert "legacy_score" not in out
    assert out["scan_scope"] == "CANONICAL"


def test_outputs_on_a_custom_selection_with_ok_technical(tmp_path, custom_report_json):
    """A narrowed selection is scope CUSTOM; Technical stays OK and is what
    `score` carries."""
    out = _outputs(tmp_path, custom_report_json)
    assert (out["score"], out["grade"], out["score_status"]) == ("57", "D", "OK")
    assert out["scan_scope"] == "CUSTOM"


def test_outputs_without_a_technical_number(tmp_path):
    """INSUFFICIENT_EVIDENCE Technical: no number, no grade — empty
    strings — while status, coverage and model id still say why."""
    report = _real_report("commerce-good", keep={"/"})
    t = report.readiness.technical
    assert (t.rating, t.status) == (None, "INSUFFICIENT_EVIDENCE")
    out = _outputs(tmp_path, _write(tmp_path, report))
    assert (out["score"], out["grade"]) == ("", "")
    assert out["score_status"] == "INSUFFICIENT_EVIDENCE"
    assert out["coverage"] == str(t.coverage)
    assert out["model_id"] == t.model_id


def test_outputs_without_a_readiness_block(tmp_path):
    """Technical raised, `readiness` is None. Every Technical output is
    empty; the selection scope is still written."""
    report = _report("commerce-good").model_copy(update={"readiness": None})
    out = _outputs(tmp_path, _write(tmp_path, report))
    for key in ("score", "grade", "score_status", "coverage", "model_id"):
        assert out[key] == "", key
    assert out["scan_scope"] == "CANONICAL"


def test_summary_has_spec_shape(tmp_path):
    summ = tmp_path / "summary.md"
    action.main(["summary", str(_core_json(tmp_path))], env={"GITHUB_STEP_SUMMARY": str(summ)})
    md = summ.read_text()
    assert md.startswith("## Scovant Core — Technical Readiness") and "Critical:" in md and "Top issue:" in md
    assert "Static Signal Score" not in md
    assert "utm_medium=github" in md


def test_report_renders_requested_format(tmp_path):
    action.main(["report", str(_core_json(tmp_path)), "--format", "html", "--out", str(tmp_path / "r.html")])
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")


def test_report_renders_markdown_format(tmp_path):
    action.main(["report", str(_core_json(tmp_path)), "--format", "markdown", "--out", str(tmp_path / "r.md")])
    assert (tmp_path / "r.md").read_text().startswith("#")


def test_gate_exit_code(tmp_path):
    # commerce-bad: Technical 57 — the gate reads Technical.
    assert action.main(["gate", str(_core_json(tmp_path)), "--min-score", "58"]) == 1
    assert action.main(["gate", str(_core_json(tmp_path)), "--min-score", "57", "--fail-on", "never"]) == 0
    assert action.main(["gate", str(_core_json(tmp_path)), "--min-score", "0", "--fail-on", "never"]) == 0


def test_gate_min_score_fails_without_a_technical_number(tmp_path, capsys):
    report = _real_report("commerce-good", keep={"/"})
    p = _write(tmp_path, report)
    assert action.main(["gate", str(p), "--min-score", "0"]) == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness has no number (status INSUFFICIENT_EVIDENCE); --min-score fails",
    ]


def test_gate_accepts_empty_min_score_default(tmp_path):
    # `min-core-score`'s Action default is the empty string ('' = no gate);
    # `--fail-on`'s default is `never` — together this must never fail the step.
    assert action.main(["gate", str(_core_json(tmp_path)), "--min-score", ""]) == 0


def test_empty_env_override_never_touches_the_real_process_environment(tmp_path, monkeypatch):
    # `env={}` is a deliberate "write nowhere" override, distinct from
    # `env=None` ("use the real process environment"). `dict(env or os.environ)`
    # collapses the two (an empty dict is falsy), so a caller passing `{}`
    # would silently fall through to the real `$GITHUB_OUTPUT` — exactly the
    # file this test points at a real path to prove untouched.
    real_output = tmp_path / "real_github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(real_output))
    action.main(["outputs", str(_core_json(tmp_path)), "--report-path", "core.html"], env={})
    assert not real_output.exists()


def test_outputs_include_scope_status_coverage_errors(tmp_path, report_json):
    out = _outputs(tmp_path, report_json)
    assert out["scan_scope"] == "CANONICAL" and out["score_status"] == "OK"
    assert out["error_count"] == "0"


def test_gate_require_canonical(tmp_path, custom_report_json):
    # The gate reads Technical Readiness: a narrowed `--include` selection
    # does not change Technical, which is OK on commerce-bad, so the CUSTOM
    # scope does not fail it.
    assert action.main(
        ["gate", str(custom_report_json), "--min-score", "", "--fail-on", "never", "--require-canonical"], env={},
    ) == 0


def test_gate_require_canonical_fails_on_degraded_technical(tmp_path, capsys):
    """saas-mixed with only `/` and robots.txt answering: Technical DEGRADED
    (with a number). Only OK passes `--require-canonical`."""
    report = _real_report("saas-mixed", keep={"/", "/robots.txt"})
    assert report.readiness.technical.status == "DEGRADED"
    assert action.main(["gate", str(_write(tmp_path, report)), "--require-canonical"], env={}) == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness status DEGRADED is not OK; --require-canonical fails",
    ]


def test_gate_require_canonical_fails_without_a_readiness_block(tmp_path):
    report = _report("commerce-good").model_copy(update={"readiness": None})
    p = _write(tmp_path, report)
    assert action.main(["gate", str(p), "--require-canonical"], env={}) == 1
    assert action.main(["gate", str(p), "--min-score", "0"], env={}) == 1


def _summary(report, **kw) -> str:
    from scovant_core.action import render_summary

    return render_summary(report, **kw)


def test_summary_first_line_leads_with_technical_readiness():
    md = _summary(_report("commerce-good"))
    assert md.splitlines()[0] == "## Scovant Core — Technical Readiness 82 / 100 (B) · coverage 97%"
    assert "R2.1@67df90af85b0" in md.splitlines()[2]
    assert "**Not measured by Core:** MCP_DISCOVERY_INVALID (handshake_not_performed)" in md


def test_summary_without_a_technical_number():
    md = _summary(_real_report("commerce-good", keep={"/"}))
    assert md.splitlines()[0] == "## Scovant Core — Technical Readiness — · INSUFFICIENT_EVIDENCE · coverage 55%"


def test_summary_degraded_technical_has_no_grade():
    md = _summary(_real_report("saas-mixed", keep={"/", "/robots.txt"}))
    assert md.splitlines()[0] == "## Scovant Core — Technical Readiness 70 / 100 · DEGRADED · coverage " + \
        md.splitlines()[0].rsplit("coverage ", 1)[1]
    assert "(" not in md.splitlines()[0]


def test_summary_without_a_readiness_block_never_crashes():
    md = _summary(_report("commerce-good").model_copy(update={"readiness": None}))
    assert md.splitlines()[0] == "## Scovant Core — Technical Readiness not computed"
    assert "Legacy" not in md


def test_summary_not_measured_list_is_capped_at_ten():
    from scovant_core.models import NotMeasured

    report = _report("commerce-good")
    many = [NotMeasured(rule=f"RULE_{i:02d}", reason="r") for i in range(13)]
    tech = report.readiness.technical.model_copy(update={"not_measured": many})
    report = report.model_copy(update={"readiness": report.readiness.model_copy(update={"technical": tech})})
    line = next(row for row in _summary(report).splitlines() if row.startswith("**Not measured by Core:**"))
    assert line.endswith("RULE_09 (r) and 3 more")
    assert "RULE_10" not in line


def test_summary_on_a_custom_selection_leads_with_technical(custom_report_json):
    """A CUSTOM selection with an OK Technical block leads with Technical
    and carries no other rating."""
    from scovant_core.action import _load_report

    report = _load_report(str(custom_report_json))
    md = _summary(report)
    assert md.splitlines()[0] == "## Scovant Core — Technical Readiness 57 / 100 (D) · coverage 100%"
    assert "Legacy" not in md and "NOT CALCULATED" not in md and "NOT_CANONICAL" not in md


@pytest.mark.parametrize(
    "argv",
    [
        ["summary", "{p}", "--legacy-score"],
        ["report", "{p}", "--format", "markdown", "--out", "{out}", "--legacy-score"],
        ["gate", "{p}", "--legacy-score"],
    ],
)
def test_legacy_score_flag_is_rejected_by_every_command(tmp_path, argv):
    p = str(_core_json(tmp_path))
    with pytest.raises(SystemExit) as exc:
        action.main([a.format(p=p, out=str(tmp_path / "r.md")) for a in argv], env={})
    assert exc.value.code == 2


def test_summary_counts_are_readiness_only_with_security_on_its_own_line(report_json):
    """The summary block's diagnostics line must describe the same
    population as the `pass_count`/`warn_count`/`fail_count` outputs —
    readiness only. Security is stated separately, never folded in."""
    from scovant_core.action import _load_report
    from scovant_core.models import Category, CheckStatus
    from scovant_core.report._common import status_counts

    report = _load_report(str(report_json))
    readiness = [f for f in report.findings if f.category != Category.SECURITY]
    security = [f for f in report.findings if f.category == Category.SECURITY]
    assert security, "fixture must contain security findings for this test to mean anything"
    counts = status_counts(readiness)
    md = _summary(report)
    assert f"{counts[CheckStatus.PASS]} pass · {counts[CheckStatus.WARN]} warn" in md
    assert "**Security (never scored):**" in md
    all_counts = status_counts(report.findings)
    assert all_counts[CheckStatus.PASS] != counts[CheckStatus.PASS]
    assert f" {all_counts[CheckStatus.PASS]} pass · " not in md


def test_action_yml_has_no_legacy_score_input_or_wiring():
    """0.19.0: the `legacy-score` input and the `legacy_score` output are
    gone, and no step passes `--legacy-score`."""
    from pathlib import Path

    import yaml

    text = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
    doc = yaml.safe_load(text)
    assert "legacy-score" not in doc["inputs"]
    assert "legacy_score" not in doc["outputs"]
    assert "legacy" not in text.lower()

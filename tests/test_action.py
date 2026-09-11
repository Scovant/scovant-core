from scovant_core import action
from scovant_core.report.json import render_json
from tests.test_report_markdown import _report


def _core_json(tmp_path):
    p = tmp_path / "core.json"
    p.write_text(render_json(_report("commerce-bad")))
    return p


def test_outputs_written_to_github_output(tmp_path):
    out = tmp_path / "out.txt"
    action.main(["outputs", str(_core_json(tmp_path)), "--report-path", "core.html"], env={"GITHUB_OUTPUT": str(out)})
    text = out.read_text()
    for key in ("score=", "grade=", "pass_count=", "warn_count=", "fail_count=", "report_path=core.html"):
        assert key in text


def test_summary_has_spec_shape(tmp_path):
    summ = tmp_path / "summary.md"
    action.main(["summary", str(_core_json(tmp_path))], env={"GITHUB_STEP_SUMMARY": str(summ)})
    md = summ.read_text()
    assert md.startswith("## Scovant Core") and "Static Signal Score:" in md and "Critical:" in md and "Top issue:" in md
    assert "utm_medium=github" in md


def test_report_renders_requested_format(tmp_path):
    action.main(["report", str(_core_json(tmp_path)), "--format", "html", "--out", str(tmp_path / "r.html")])
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")


def test_report_renders_markdown_format(tmp_path):
    action.main(["report", str(_core_json(tmp_path)), "--format", "markdown", "--out", str(tmp_path / "r.md")])
    assert (tmp_path / "r.md").read_text().startswith("#")


def test_gate_exit_code(tmp_path):
    assert action.main(["gate", str(_core_json(tmp_path)), "--min-score", "100"]) == 1
    assert action.main(["gate", str(_core_json(tmp_path)), "--min-score", "0", "--fail-on", "never"]) == 0


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

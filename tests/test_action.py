import pytest

from scovant_core import action
from scovant_core.report.json import render_json
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


def test_outputs_include_scope_status_coverage_errors(tmp_path, report_json):
    out = tmp_path / "out.txt"
    action.main(["outputs", str(report_json), "--report-path", "r.html"], env={"GITHUB_OUTPUT": str(out)})
    text = out.read_text()
    for key in ("coverage=", "score_status=", "scan_scope=", "error_count="):
        assert key in text
    assert "scan_scope=CANONICAL" in text and "score_status=OK" in text


def test_gate_require_canonical(tmp_path, custom_report_json):
    assert action.main(
        ["gate", str(custom_report_json), "--min-score", "", "--fail-on", "never", "--require-canonical"], env={},
    ) == 1


def test_summary_first_line_names_scope_and_status(report_json):
    from scovant_core.action import _load_report, render_summary

    first = render_summary(_load_report(str(report_json))).splitlines()[0]
    assert "CANONICAL" in first and "OK" in first


def test_summary_shows_not_calculated_for_not_canonical(custom_report_json):
    from scovant_core.action import _load_report, render_summary

    md = render_summary(_load_report(str(custom_report_json)))
    assert "Canonical Core Score: NOT CALCULATED" in md


def test_summary_shows_no_grade_for_degraded(report_json):
    from scovant_core.action import _load_report, render_summary
    from scovant_core.models import Score

    report = _load_report(str(report_json))
    degraded = report.model_copy(update={
        "score": Score(value=71, grade=None, coverage=0.78, status="DEGRADED", scope="PARTIAL"),
        "metrics": {**report.metrics, "error_count": 2},
    })
    md = render_summary(degraded)
    assert "No grade" in md

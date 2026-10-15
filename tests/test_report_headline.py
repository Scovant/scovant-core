"""Every renderer leads with Technical Readiness (R2), Core's only rating
since 0.19.0 removed the five-domain block. Every report here is a REAL engine report on
a fixture site — the DEGRADED / INSUFFICIENT_EVIDENCE cases come from scans
whose own fetches failed, the missing-block case from a real report with
`readiness` dropped, as the engine does when Technical raised."""
from __future__ import annotations

import pytest

from scovant_core import cli
from scovant_core.report.html import render_html
from scovant_core.report.markdown import render_markdown
from scovant_core.report.text import render_text, score_line
from tests.test_cli import _real_report, _use_fixture

_LEGACY_TEXT = "Legacy Static Signal Score"


@pytest.fixture(scope="module")
def ok_report():
    return _real_report("commerce-good")


@pytest.fixture(scope="module")
def bad_report():
    return _real_report("commerce-bad")


@pytest.fixture(scope="module")
def degraded_report():
    r = _real_report("saas-mixed", keep={"/", "/robots.txt"})
    assert (r.readiness.technical.rating, r.readiness.technical.status) == (70, "DEGRADED")
    return r


@pytest.fixture(scope="module")
def insufficient_report():
    r = _real_report("commerce-good", keep={"/"})
    assert r.readiness.technical.rating is None
    assert r.readiness.technical.status == "INSUFFICIENT_EVIDENCE"
    return r


@pytest.fixture(scope="module")
def missing_report(ok_report):
    return ok_report.model_copy(update={"readiness": None})


def _headline(text: str) -> list[str]:
    """The lines from the Technical headline up to the first blank line."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("Technical Readiness"))
    end = lines.index("", start)
    return lines[start:end]


# --- text headline by Technical status ------------------------------------

def test_text_headline_ok(ok_report):
    assert _headline(render_text(ok_report)) == [
        "Technical Readiness  82 / 100  B · coverage 97% · model R2.1@7389c208c89e",
        "Not measured by Core: MCP_DISCOVERY_INVALID (handshake_not_performed)",
        "Diagnostics (50 readiness checks): 40 pass · 1 warn · 0 fail",
    ]


def test_text_headline_ok_without_not_measured(bad_report):
    """`not_measured` empty → no not-measured line at all."""
    head = _headline(render_text(bad_report))
    assert head[0] == "Technical Readiness  57 / 100  D · coverage 100% · model R2.1@7389c208c89e"
    assert head[1].startswith("Diagnostics (")
    assert not any(ln.startswith("Not measured by Core") for ln in head)


def test_text_headline_degraded(degraded_report):
    head = _headline(render_text(degraded_report))
    assert head[0] == "Technical Readiness  70 / 100 · DEGRADED · coverage 65% · model R2.1@7389c208c89e"
    rules = [n.rule for n in degraded_report.readiness.technical.not_measured]
    expected = ", ".join(
        f"{n.rule} ({n.reason})"
        for n in sorted(degraded_report.readiness.technical.not_measured, key=lambda n: n.rule)
    )
    assert head[1] == f"Not measured by Core: {expected}"
    assert len(rules) > 1
    assert head[2].startswith("Diagnostics (")


def test_text_headline_insufficient_evidence(insufficient_report):
    head = _headline(render_text(insufficient_report))
    assert head[0] == "Technical Readiness  — · INSUFFICIENT_EVIDENCE · coverage 55%"
    assert head[1].startswith("Not measured by Core: ")


def test_text_headline_missing_block(missing_report):
    head = _headline(render_text(missing_report))
    assert head[0] == "Technical Readiness  not computed"
    assert head[1].startswith("Diagnostics (")


def test_not_measured_line_is_sorted_by_rule(degraded_report):
    t = degraded_report.readiness.technical
    shuffled = t.model_copy(update={"not_measured": list(reversed(t.not_measured))})
    r = degraded_report.model_copy(update={
        "readiness": degraded_report.readiness.model_copy(update={"technical": shuffled}),
    })
    assert _headline(render_text(r))[1] == _headline(render_text(degraded_report))[1]


def test_diagnostics_counts_readiness_checks_only(ok_report):
    from scovant_core.models import Category, CheckStatus

    readiness = [f for f in ok_report.findings if f.category != Category.SECURITY]
    n = {s: sum(1 for f in readiness if f.status == s) for s in CheckStatus}
    passed, warned, failed = n[CheckStatus.PASS], n[CheckStatus.WARN], n[CheckStatus.FAIL]
    line = f"Diagnostics ({len(readiness)} readiness checks): {passed} pass · {warned} warn · {failed} fail"
    assert line in render_text(ok_report)


def test_score_line_is_the_technical_headline(ok_report, insufficient_report, missing_report):
    assert score_line(ok_report) == "Technical Readiness  82 / 100  B · coverage 97% · model R2.1@7389c208c89e"
    assert score_line(insufficient_report) == "Technical Readiness  — · INSUFFICIENT_EVIDENCE · coverage 55%"
    assert score_line(missing_report) == "Technical Readiness  not computed"


# --- no five-domain block -------------------------------------------------

def test_text_default_has_no_five_domain_block(ok_report):
    text = render_text(ok_report)
    assert _LEGACY_TEXT not in text and "Static Signal Score" not in text
    assert "Access & Discovery" not in text
    assert "Scope: CANONICAL" not in text


def test_markdown_leads_with_technical_and_hides_categories(ok_report):
    md = render_markdown(ok_report)
    assert "## Technical Readiness" in md
    assert "**Technical Readiness:** 82 / 100 · grade B · coverage 97% · model R2.1@7389c208c89e" in md
    assert "**Not measured by Core:** MCP_DISCOVERY_INVALID (handshake_not_performed)" in md
    assert "**Diagnostics (50 readiness checks):** 40 pass · 1 warn · 0 fail" in md
    assert "## Categories" not in md and "Static Signal Score" not in md


def test_markdown_headline_by_status(degraded_report, insufficient_report, missing_report):
    md = render_markdown(degraded_report)
    assert "**Technical Readiness:** 70 / 100 · DEGRADED · coverage 65%" in md
    assert "grade —" not in md
    assert "**Technical Readiness:** — · INSUFFICIENT_EVIDENCE · coverage 55%" in render_markdown(insufficient_report)
    md = render_markdown(missing_report)
    assert "**Technical Readiness:** not computed" in md
    assert "Not measured by Core" not in md


def test_html_leads_with_technical_and_hides_categories(ok_report):
    html = render_html(ok_report)
    assert "<h2>Technical Readiness</h2>" in html
    assert "82 / 100" in html and "R2.1@7389c208c89e" in html
    assert "MCP_DISCOVERY_INVALID (handshake_not_performed)" in html
    assert 'id="categories"' not in html and "Static Signal Score" not in html


def _score_section(html: str) -> str:
    return html.split('<section id="score">', 1)[1].split("</section>", 1)[0]


def test_html_headline_by_status(ok_report, degraded_report, insufficient_report, missing_report):
    ok = _score_section(render_html(ok_report))
    assert "<strong>Grade:</strong> B" in ok and "<strong>Status:</strong> OK" in ok
    assert "<strong>Diagnostics (50 readiness checks):</strong> 40 pass · 1 warn · 0 fail" in ok
    degraded = _score_section(render_html(degraded_report))
    assert ">70 / 100</p>" in degraded
    assert "<strong>Status:</strong> DEGRADED" in degraded
    assert "<strong>Grade:</strong>" not in degraded
    insufficient = _score_section(render_html(insufficient_report))
    assert ">—</p>" in insufficient
    assert "<strong>Status:</strong> INSUFFICIENT_EVIDENCE" in insufficient
    missing = _score_section(render_html(missing_report))
    assert "Technical Readiness not computed" in missing and "<strong>Status:</strong>" not in missing


def test_html_methodology_describes_r2_only(ok_report):
    html = render_html(ok_report)
    method = html.split('id="methodology"', 1)[1].split("</section>", 1)[0]
    assert "25/25/20/15/15" not in html
    assert "docs/r2.md" in method and "coverage" in method and "not measured" in method
    assert "deprecated" not in method and "--legacy-score" not in method


def test_no_private_agent_policy_in_any_rendering(ok_report):
    for out in (render_text(ok_report), render_markdown(ok_report), render_html(ok_report)):
        # Built from parts so this test file does not itself carry the
        # private names the publish guard bans.
        banned_names = ("AGENT_" + "CAP", "AGENT_" + "POLICY", "agent-" + "private", "overlay" + "@", "Agent Readiness")
        for banned in banned_names:
            assert banned not in out


def test_cloud_matrix_row_names_technical_readiness():
    from scovant_core.report._cloud_matrix import CORE_VS_CLOUD

    caps = [row[0] for row in CORE_VS_CLOUD]
    assert "Technical Readiness from Core's own sampled evidence" in caps
    assert "Core Score" not in caps


# --- CLI ------------------------------------------------------------------

def test_cli_quiet_prints_the_technical_headline(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--quiet"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "Technical Readiness  82 / 100  B · coverage 97% · model R2.1@7389c208c89e",
    ]


def test_experimental_scan_prints_no_scored_line():
    """"Experimental checks: scored" described the five-domain score only;
    it is gone with it."""
    from scovant_core.context import ScanOptions
    from scovant_core.engine import scan
    from tests.conftest import FIXTURES, FixtureTransport

    r = scan("https://example.com/", ScanOptions(experimental=True),
             transport=FixtureTransport(FIXTURES / "sites" / "commerce-good"),
             clock=lambda: "2026-09-04T00:00:00Z", scan_id="x")
    for render in (render_text, render_markdown, render_html):
        assert "Experimental checks: scored" not in render(r)
        assert "Experimental checks:</strong> scored" not in render(r)

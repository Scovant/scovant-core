"""0.19.0 (report schema 2.0): the five-domain score is gone. Technical
Readiness (`readiness.technical`) is Core's only rating; scan scope comes
from the check selection; top findings rank by severity, then status, then id.
"""
from __future__ import annotations

import importlib
import json

import pytest

from scovant_core import cli
from scovant_core.checks.base import CoreCheck
from scovant_core.checks.registry import CHECKS, ruleset_digest
from scovant_core.context import ScanOptions
from scovant_core.engine import scan
from scovant_core.models import (
    REPORT_SCHEMA_VERSION,
    Category,
    CheckResult,
    CheckStatus,
    Confidence,
    Report,
    Severity,
)
from scovant_core.report._common import top_findings
from scovant_core.report.html import render_html
from scovant_core.report.json import render_json
from scovant_core.report.markdown import render_markdown
from scovant_core.report.text import render_text
from tests.conftest import FIXTURES, FixtureTransport

CLOCK = lambda: "2026-09-04T00:00:00Z"  # noqa: E731 — deterministic test clock
URL = "https://example.com/"
SITES = ("commerce-good", "commerce-bad", "api-good", "saas-mixed", "security-good", "security-bad",
         "oauth-good", "oauth-bad")
# The one value this release mints: the digest no longer folds in the
# five-domain scoring constants. 0.18.0 published 7f440d6205c3.
RULESET_DIGEST_0_19 = "e7426fb13abe"
BANNED = ("Static Signal", "Legacy", "five-domain", "Core Score", "weight", "25/25/20/15/15")


def _scan(site: str = "commerce-good", **opts) -> Report:
    return scan(URL, ScanOptions(**opts), transport=FixtureTransport(FIXTURES / "sites" / site),
                clock=CLOCK, scan_id="scan-fixed")


def test_schema_is_2_0():
    assert REPORT_SCHEMA_VERSION == "2.1"


def test_the_scoring_module_is_gone():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("scovant_core.scoring")


def test_json_report_has_no_score_or_categories():
    data = json.loads(render_json(_scan()))
    assert "score" not in data and "categories" not in data
    assert data["schema_version"] == "2.1"
    assert data["readiness"]["technical"]["rating"] is not None
    assert all("weight" not in f for f in data["findings"])
    assert "evidence_min_coverage" not in data["provenance"]
    assert "canonical_min_coverage" not in data["provenance"]


def test_checks_carry_no_weight():
    assert "weight" not in CheckResult.model_fields
    assert not hasattr(CoreCheck, "weight")
    assert all("weight" not in vars(type(c)) for c in CHECKS)


def test_ruleset_digest_is_pinned():
    assert ruleset_digest() == RULESET_DIGEST_0_19


def test_full_scan_is_canonical():
    assert _scan().provenance["scan_scope"] == "CANONICAL"


def test_include_makes_the_scan_custom():
    assert _scan(include=("CORE-ACCESS-001",)).provenance["scan_scope"] == "CUSTOM"


def test_exclude_makes_the_scan_custom():
    assert _scan(exclude=("security",)).provenance["scan_scope"] == "CUSTOM"


def test_errors_never_change_the_scope():
    """PARTIAL was a property of the five-domain coverage; the scope is now
    the selection alone. An erroring full scan is CANONICAL — Technical
    Readiness carries its own DEGRADED/INSUFFICIENT_EVIDENCE status."""
    import httpx

    def only_entry(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>hi</body></html>")
        return httpx.Response(503)

    report = scan(URL, ScanOptions(), transport=httpx.MockTransport(only_entry), clock=CLOCK, scan_id="s")
    assert report.metrics["error_count"] > 0
    assert report.provenance["scan_scope"] == "CANONICAL"


def test_experimental_is_custom_and_runs_the_experimental_checks():
    report = _scan(experimental=True)
    assert report.provenance["scan_scope"] == "CUSTOM"
    assert report.provenance["experimental"] is True
    assert any(f.experimental for f in report.findings)
    assert not hasattr(report, "score")


def _use_fixture(monkeypatch, name: str = "commerce-good") -> None:
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / name))
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)


def test_legacy_score_flag_is_an_argparse_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", URL, "--legacy-score"])
    assert exc.value.code == 2
    assert "--legacy-score" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], 0),
        (["--min-score", "57"], 0),
        (["--min-score", "58"], 1),
        (["--require-canonical"], 0),
        (["--fail-on", "fail"], 1),
    ],
)
def test_technical_gate_exit_codes_are_unchanged(capsys, monkeypatch, argv, expected):
    """commerce-bad: Technical Readiness 57, status OK — the same numbers the
    0.18.0 gate tests pinned."""
    _use_fixture(monkeypatch, "commerce-bad")
    assert cli.main(["scan", URL, "--quiet", *argv]) == expected
    err = capsys.readouterr().err
    assert "legacy" not in err.lower() and "five-domain" not in err


@pytest.mark.parametrize("extra", [["--include", "access"], ["--experimental"]])
def test_custom_and_experimental_scans_are_never_contributed(capsys, monkeypatch, extra):
    _use_fixture(monkeypatch)
    sent: list[dict] = []
    monkeypatch.setattr(cli, "send", lambda payload: sent.append(payload))
    assert cli.main(["scan", URL, "--quiet", "--contribute", *extra]) == 0
    assert sent == []
    assert "contributed: skipped (scan is CUSTOM" in capsys.readouterr().err


def _r(id_: str, status: CheckStatus, severity: Severity, category: Category = Category.ACCESS) -> CheckResult:
    return CheckResult(id=id_, title=id_, category=category, status=status, severity=severity,
                       confidence=Confidence.HIGH, summary="")


def test_top_findings_rank_by_severity_then_status_then_id():
    findings = [
        _r("CORE-ACCESS-009", CheckStatus.FAIL, Severity.MEDIUM),
        _r("CORE-ACCESS-002", CheckStatus.WARN, Severity.HIGH),
        _r("CORE-ACCESS-003", CheckStatus.FAIL, Severity.HIGH),
        _r("CORE-ACCESS-001", CheckStatus.WARN, Severity.MEDIUM),
        _r("CORE-ACCESS-008", CheckStatus.FAIL, Severity.LOW),
        _r("CORE-ACCESS-007", CheckStatus.FAIL, Severity.CRITICAL),
        _r("CORE-ACCESS-004", CheckStatus.WARN, Severity.INFO),
        _r("CORE-ACCESS-005", CheckStatus.FAIL, Severity.HIGH),
        _r("CORE-ACCESS-006", CheckStatus.PASS, Severity.CRITICAL),
    ]
    assert [f.id for f in top_findings(findings, True)] == [
        "CORE-ACCESS-007",  # critical FAIL
        "CORE-ACCESS-003", "CORE-ACCESS-005",  # high FAIL, by id
        "CORE-ACCESS-002",  # high WARN
        "CORE-ACCESS-009",  # medium FAIL
        "CORE-ACCESS-001",  # medium WARN
        "CORE-ACCESS-008",  # low FAIL
        "CORE-ACCESS-004",  # info WARN
    ]


@pytest.mark.parametrize("site", SITES)
def test_no_renderer_mentions_the_removed_score(site):
    report = _scan(site)
    html = render_html(report)
    # The page's own CSS (`font-weight`) is markup, not report output.
    html_body = html.split("</style>", 1)[1].replace("font-weight", "")
    outputs = {
        "text": render_text(report), "markdown": render_markdown(report),
        "html": html_body, "json": render_json(report),
    }
    for fmt, out in outputs.items():
        for banned in BANNED:
            assert banned not in out, (site, fmt, banned)
    data = json.loads(outputs["json"])
    assert "score" not in data and "categories" not in data


# --- fix round 1: contribute only Technical-OK scans; label CUSTOM scope ----

@pytest.mark.parametrize(
    ("site", "keep", "status"),
    [
        ("saas-mixed", {"/", "/robots.txt"}, "DEGRADED"),
        ("commerce-good", {"/"}, "INSUFFICIENT_EVIDENCE"),
    ],
)
def test_a_full_scan_without_ok_technical_is_never_contributed(capsys, monkeypatch, site, keep, status):
    """A full (CANONICAL) scan whose own fetches failed: Technical is not OK,
    so `--contribute` sends nothing and says why."""
    from tests.test_cli import _real_report, _use_own_fetch_failures

    report = _real_report(site, keep=keep)
    assert report.provenance["scan_scope"] == "CANONICAL"
    assert report.readiness.technical.status == status
    _use_own_fetch_failures(monkeypatch, site, keep)
    sent: list[dict] = []
    monkeypatch.setattr(cli, "send", lambda payload: sent.append(payload))
    cli.main(["scan", URL, "--quiet", "--contribute"])
    assert sent == []
    assert (f"contributed: skipped (Technical Readiness is {status}; "
            "only Technical-OK scans are accepted)") in capsys.readouterr().err


def test_a_scan_without_a_readiness_block_is_never_contributed(capsys, monkeypatch):
    def boom(store, ctx):
        raise RuntimeError("boom")
    monkeypatch.setattr("scovant_core.r2.readiness.technical_report", boom)
    _use_fixture(monkeypatch)
    sent: list[dict] = []
    monkeypatch.setattr(cli, "send", lambda payload: sent.append(payload))
    cli.main(["scan", URL, "--quiet", "--contribute"])
    assert sent == []
    assert ("contributed: skipped (Technical Readiness not computed; "
            "only Technical-OK scans are accepted)") in capsys.readouterr().err


_SCOPE_LINE = "Scope: CUSTOM (subset of checks)"


@pytest.mark.parametrize("render", [render_text, render_markdown, render_html])
def test_custom_scope_is_labelled_near_the_headline(render):
    custom = render(_scan(include=("CORE-ACCESS-001",)))
    assert custom.count(_SCOPE_LINE) == 1
    # near the headline: before the findings
    assert custom.index(_SCOPE_LINE) < custom.index("Top findings" if render is not render_html else 'id="findings"')
    assert _SCOPE_LINE not in render(_scan())


def test_experimental_scope_is_labelled_too():
    assert _SCOPE_LINE in render_text(_scan(experimental=True))

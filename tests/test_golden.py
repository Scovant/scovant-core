"""Golden-report regression tests for the four canonical fixture sites.

Each fixture site's scan output is deterministic given a frozen clock, a
frozen `scan_id`, and a frozen "today" for CORE-ACCESS-006 (the only check
that reads real wall-clock time) — so `render_json(scan(...))` can be
byte-compared against a committed expected file. `provenance.python`,
`provenance.platform`, `provenance.dependencies`, and
`provenance.environment_digest` are the only genuinely non-deterministic
fields (they vary with the interpreter/OS/installed-package-versions running
the test); all four are replaced with the literal string "<runtime>" before
comparison.

To regenerate the expected files after a deliberate ruleset change:

    SCOVANT_CORE_UPDATE_GOLDENS=1 pytest tests/test_golden.py

Always review the diff by eye before committing regenerated goldens — see
CONTRIBUTING.md.
"""
from __future__ import annotations

import datetime
import json
import os

import pytest

from scovant_core.checks.access import core_access_006
from scovant_core.engine import scan
from scovant_core.report.html import render_html
from scovant_core.report.json import render_json
from scovant_core.report.markdown import render_markdown
from tests.conftest import FIXTURES, FixtureTransport

pytestmark = pytest.mark.golden

CLOCK = lambda: "2026-09-04T00:00:00Z"  # noqa: E731 — deterministic test clock
FROZEN_TODAY = datetime.date(2026, 9, 4)
URL = "https://example.com/"
SITES = ("commerce-good", "commerce-bad", "api-good", "saas-mixed")
EXPECTED_DIR = FIXTURES / "sites" / "expected"


def _normalize(data: dict) -> dict:
    """Replace the four genuinely-nondeterministic provenance fields with a
    stable placeholder. Nothing else in a `render_json` payload should ever
    vary run-to-run for a fixed clock/scan_id/frozen-today — that invariant
    is exactly what `test_render_json_is_byte_stable_across_two_runs` in
    test_report.py already pins."""
    data["provenance"]["python"] = "<runtime>"
    data["provenance"]["platform"] = "<runtime>"
    data["provenance"]["dependencies"] = "<runtime>"
    data["provenance"]["environment_digest"] = "<runtime>"
    return data


def _run(site: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(core_access_006, "today", lambda: FROZEN_TODAY)
    transport = FixtureTransport(FIXTURES / "sites" / site)
    report = scan(URL, transport=transport, clock=CLOCK, scan_id="local-golden")
    data = _normalize(json.loads(render_json(report)))
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)


@pytest.mark.parametrize("site", SITES)
def test_golden_report_matches_expected(site, monkeypatch):
    rendered = _run(site, monkeypatch)
    expected_path = EXPECTED_DIR / f"{site}.json"

    if os.environ.get("SCOVANT_CORE_UPDATE_GOLDENS") == "1":
        expected_path.write_text(rendered + "\n", encoding="utf-8")
        pytest.skip(f"regenerated {expected_path} — re-run without SCOVANT_CORE_UPDATE_GOLDENS to verify")

    assert expected_path.exists(), (
        f"missing golden file {expected_path} — run "
        "`SCOVANT_CORE_UPDATE_GOLDENS=1 pytest tests/test_golden.py` once to generate it, "
        "then review the diff by eye before committing."
    )
    expected = expected_path.read_text(encoding="utf-8")
    assert rendered + "\n" == expected


@pytest.mark.parametrize("site", SITES)
def test_golden_report_is_stable_across_two_runs(site, monkeypatch):
    """The scan itself (not just the comparison) must be deterministic —
    running it twice against the same fixture must produce byte-identical
    output, independent of whether a committed golden file exists yet."""
    a = _run(site, monkeypatch)
    b = _run(site, monkeypatch)
    assert a == b


def _run_markdown(site: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(core_access_006, "today", lambda: FROZEN_TODAY)
    transport = FixtureTransport(FIXTURES / "sites" / site)
    report = scan(URL, transport=transport, clock=CLOCK, scan_id="local-golden")
    return render_markdown(report)


@pytest.mark.parametrize("site", SITES)
def test_golden_markdown_matches_expected(site, monkeypatch):
    rendered = _run_markdown(site, monkeypatch)
    expected_path = EXPECTED_DIR / f"{site}.md"

    if os.environ.get("SCOVANT_CORE_UPDATE_GOLDENS") == "1":
        expected_path.write_text(rendered + "\n", encoding="utf-8")
        pytest.skip(f"regenerated {expected_path} — re-run without SCOVANT_CORE_UPDATE_GOLDENS to verify")

    assert expected_path.exists(), (
        f"missing golden file {expected_path} — run "
        "`SCOVANT_CORE_UPDATE_GOLDENS=1 pytest tests/test_golden.py` once to generate it, "
        "then review the diff by eye before committing."
    )
    expected = expected_path.read_text(encoding="utf-8")
    assert rendered + "\n" == expected


@pytest.mark.parametrize("site", SITES)
def test_golden_markdown_is_stable_across_two_runs(site, monkeypatch):
    a = _run_markdown(site, monkeypatch)
    b = _run_markdown(site, monkeypatch)
    assert a == b


def _run_html(site: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Same non-determinism as `_run` above (`provenance.python`/`.platform`/
    `.dependencies`/`.environment_digest` vary with the interpreter/OS/
    installed-package-versions running the test — the CI matrix runs both
    3.12 and 3.13) — normalized the same way before rendering, since HTML has
    no JSON structure to post-process after the fact."""
    monkeypatch.setattr(core_access_006, "today", lambda: FROZEN_TODAY)
    transport = FixtureTransport(FIXTURES / "sites" / site)
    report = scan(URL, transport=transport, clock=CLOCK, scan_id="local-golden")
    report.provenance["python"] = "<runtime>"
    report.provenance["platform"] = "<runtime>"
    report.provenance["dependencies"] = "<runtime>"
    report.provenance["environment_digest"] = "<runtime>"
    return render_html(report)


@pytest.mark.parametrize("site", SITES)
def test_golden_html_matches_expected(site, monkeypatch):
    rendered = _run_html(site, monkeypatch)
    expected_path = EXPECTED_DIR / f"{site}.html"

    if os.environ.get("SCOVANT_CORE_UPDATE_GOLDENS") == "1":
        expected_path.write_text(rendered + "\n", encoding="utf-8")
        pytest.skip(f"regenerated {expected_path} — re-run without SCOVANT_CORE_UPDATE_GOLDENS to verify")

    assert expected_path.exists(), (
        f"missing golden file {expected_path} — run "
        "`SCOVANT_CORE_UPDATE_GOLDENS=1 pytest tests/test_golden.py` once to generate it, "
        "then review the diff by eye before committing."
    )
    expected = expected_path.read_text(encoding="utf-8")
    assert rendered + "\n" == expected


@pytest.mark.parametrize("site", SITES)
def test_golden_html_is_stable_across_two_runs(site, monkeypatch):
    a = _run_html(site, monkeypatch)
    b = _run_html(site, monkeypatch)
    assert a == b

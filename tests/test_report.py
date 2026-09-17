from __future__ import annotations

import json

import httpx
import pytest

from scovant_core.checks.registry import CHECKS
from scovant_core.context import ScanOptions
from scovant_core.engine import NOT_TESTED, scan
from scovant_core.models import CheckStatus
from scovant_core.report.json import render_json
from scovant_core.report.text import render_text
from tests.conftest import FIXTURES, FixtureTransport

CLOCK = lambda: "2026-09-04T00:00:00Z"  # noqa: E731 — deterministic test clock
URL = "https://example.com/"


def _scan(fixture: str = "commerce-good", **kwargs):
    transport = FixtureTransport(FIXTURES / "sites" / fixture)
    return scan(URL, transport=transport, clock=CLOCK, scan_id="local-test", **kwargs)


def test_scan_returns_a_report_with_every_check_run():
    report = _scan()
    assert isinstance(report.score.value, int)
    assert len(report.findings) == len(CHECKS)
    assert [f.id for f in report.findings] == sorted(f.id for f in report.findings)


def test_provenance_carries_the_expected_keys():
    report = _scan()
    prov = report.provenance
    for key in (
        "core_version", "profile_detector_version", "ruleset_version", "ruleset_digest",
        "python", "platform", "user_agent", "timeout", "max_pages", "network_mode",
        "experimental", "dependencies", "environment_digest",
    ):
        assert key in prov, key
    # `_scan()` always passes an explicit transport (a fixture site), so this
    # is never a real network scan — `network_mode` says so honestly.
    assert prov["network_mode"] == "fixture"
    assert prov["profile_detector_version"] == "1.0"
    assert report.metrics["requests"] > 0
    assert report.metrics["gather_errors"] == []
    assert report.metrics["gather_error_details"] == []


def test_render_json_is_byte_stable_across_two_runs():
    a = render_json(_scan())
    b = render_json(_scan())
    assert a == b
    data = json.loads(a)
    assert [f["id"] for f in data["findings"]] == sorted(f["id"] for f in data["findings"])


def test_render_text_layout():
    report = _scan()
    text = render_text(report)
    assert "Static Signal Score" in text or "Core Score: INSUFFICIENT EVIDENCE" in text
    assert "Not tested by Scovant Core" in text
    cta = "https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss"
    assert cta in text
    after_cta = text[text.index(cta) + len(cta):]
    assert "example.com" not in after_cta
    for name in NOT_TESTED:
        assert f"{name.ljust(26)}NOT TESTED" in text


def test_unreachable_host_yields_insufficient_evidence_and_never_raises():
    """A host that refuses every connection must never crash the scan. Per
    product spec §6 (checks/base.py's ERROR-vs-N/A rule), every
    content-dependent check now degrades to ERROR — not N/A — when its
    document genuinely could not be read, so ERROR counts toward applicable
    weight and the resulting near-zero coverage trips the
    `INSUFFICIENT_EVIDENCE` floor in `scoring.py`."""
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    report = scan(URL, transport=httpx.MockTransport(_boom), clock=CLOCK, scan_id="local-test")
    assert report.score.status == "INSUFFICIENT_EVIDENCE"
    assert report.score.value is None
    assert any(f.status == CheckStatus.FAIL and f.id == "CORE-ACCESS-001" for f in report.findings)
    # No shipped gatherer ever raises (each catches its own fetch failures
    # and returns a "soft" error dict — see `gatherers/http.py`/`pages.py`),
    # so `gather_errors`/`gather_error_details` (the EvidenceStore-level
    # gatherer-crashed signal) stay empty even on a fully unreachable host;
    # the per-check ERROR statuses above are the real signal here.
    assert report.metrics["gather_errors"] == []
    assert report.metrics["gather_error_details"] == []


def test_gather_error_details_shape_when_a_gatherer_raises():
    from scovant_core.evidence import GATHERERS

    original = dict(GATHERERS)

    def _boom(client, ctx, store):
        raise RuntimeError("simulated gatherer bug")

    GATHERERS["pages"] = _boom
    try:
        report = _scan()
    finally:
        GATHERERS.clear()
        GATHERERS.update(original)

    # "policy_pages" (read by CORE-TRUST-002/003/004/005/007) and "page_metrics"
    # (read by CORE-OPERABILITY-005) both call `store.get("pages")` from
    # within their own gatherer bodies, so a "pages" failure cascades into a
    # distinct gather-error entry for each — not a duplicate of the first,
    # a different gatherer whose own fetch never ran because its one
    # dependency was already broken. Sorted alphabetically by the engine.
    assert report.metrics["gather_errors"] == ["page_metrics", "pages", "policy_pages"]
    assert report.metrics["gather_error_details"] == [
        {"name": "page_metrics", "kind": "EvidenceUnavailable", "message": "pages: RuntimeError: simulated gatherer bug"},
        {"name": "pages", "kind": "RuntimeError", "message": "simulated gatherer bug"},
        {"name": "policy_pages", "kind": "EvidenceUnavailable", "message": "pages: RuntimeError: simulated gatherer bug"},
    ]


def test_include_filters_to_a_single_check_id():
    report = _scan(options=ScanOptions(include=("core-access-001",)))
    assert [f.id for f in report.findings] == ["CORE-ACCESS-001"]


def test_exclude_filters_out_a_whole_category():
    report = _scan(options=ScanOptions(exclude=("access",)))
    assert all(f.category.value != "access" for f in report.findings)
    access_count = sum(1 for c in CHECKS if c.category.value == "access")
    assert len(report.findings) == len(CHECKS) - access_count


def test_unknown_include_selector_raises_value_error():
    with pytest.raises(ValueError, match="unknown check or category: not-a-real-check"):
        _scan(options=ScanOptions(include=("not-a-real-check",)))


def test_unknown_exclude_selector_raises_value_error():
    with pytest.raises(ValueError, match="unknown check or category: bogus"):
        _scan(options=ScanOptions(exclude=("bogus",)))


def test_render_text_shows_evaluated_over_applicable_check_counts_per_category():
    """Each category line carries `(n/N)` — checks evaluated / applicable —
    so a category resting on one check never reads like a broad measurement.
    See docs/methodology.md's v0.1 category coverage section."""
    report = _scan()
    text = render_text(report)
    line = next(ln for ln in text.splitlines() if ln.startswith("Operability & Efficiency"))
    assert line.endswith("(7/7)")
    for ln in text.splitlines():
        if ln.startswith("Access & Discovery"):
            assert "(10/10)" in ln


def test_final_url_is_null_when_the_entry_fetch_failed():
    """A scan whose entry URL never answered has no final URL. Reporting the
    input URL as `final_url` would claim we reached a page we never reached."""
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    report = scan(URL, transport=httpx.MockTransport(_boom), clock=CLOCK, scan_id="local-test")
    assert report.metrics["entry_error"] is not None
    assert report.target.final_url is None
    assert report.target.input_url == URL


def test_experimental_block_appears_when_off_and_excluded_from_top_findings():
    """A WARN/FAIL experimental finding, with `--experimental` off, must
    appear ONLY in the dedicated 'Experimental (not scored)' block — never
    mixed into 'Top findings' (which is reserved for findings that actually
    moved the score) and never counted in the category (n/N) totals."""
    from scovant_core.evidence import GATHERERS

    original = dict(GATHERERS)

    def _fake_reference_integrity(client, ctx, store):
        return {
            "attempted": True, "checked": 1,
            "references": [
                {"kind": "package_npm", "name": "totally-unclaimed-pkg", "status": "UNCLAIMED",
                 "resolution": {"checked": True, "exists": False}},
            ],
            "remote_exec": [], "budget_exhausted": False,
        }

    GATHERERS["reference_integrity"] = _fake_reference_integrity
    try:
        report = _scan("commerce-good")
    finally:
        GATHERERS.clear()
        GATHERERS.update(original)

    assert report.provenance["experimental"] is False
    finding = next(f for f in report.findings if f.id == "CORE-OPERABILITY-007")
    assert finding.status == CheckStatus.WARN
    assert finding.experimental is True

    text = render_text(report)
    assert "Experimental checks: scored" not in text
    assert "Experimental (not scored)" in text
    exp_block = text[text.index("Experimental (not scored)"):]
    assert "CORE-OPERABILITY-007" in exp_block

    top_block = text[text.index("Top findings"):text.index("Experimental (not scored)")]
    assert "CORE-OPERABILITY-007" not in top_block


def test_experimental_findings_scored_and_no_block_when_on():
    """With `--experimental` on, experimental findings are scored like any
    other — they show up in the normal Top findings list, the header notes
    scoring is on, and the dedicated unscored block disappears entirely."""
    from scovant_core.evidence import GATHERERS

    original = dict(GATHERERS)

    def _fake_reference_integrity(client, ctx, store):
        return {
            "attempted": True, "checked": 1,
            "references": [
                {"kind": "package_npm", "name": "totally-unclaimed-pkg", "status": "UNCLAIMED",
                 "resolution": {"checked": True, "exists": False}},
            ],
            "remote_exec": [], "budget_exhausted": False,
        }

    GATHERERS["reference_integrity"] = _fake_reference_integrity
    try:
        report = _scan("commerce-good", options=ScanOptions(experimental=True))
    finally:
        GATHERERS.clear()
        GATHERERS.update(original)

    assert report.provenance["experimental"] is True
    text = render_text(report)
    assert "Experimental checks: scored" in text
    assert "Experimental (not scored)" not in text
    top_block = text[text.index("Top findings"):text.index("Not tested by Scovant Core")]
    assert "CORE-OPERABILITY-007" in top_block


def test_experimental_notice_is_a_single_line_when_all_experimental_are_na():
    """saas-mixed's five legacy experimental checks are all N/A on that
    fixture (none of INTERFACE-004/008/009, MACHINE-012, or OPERABILITY-007
    has anything to evaluate for a saas site with no MCP/UCP/agent-
    discovery/reference-integrity signal) — the report must say so in ONE
    line, never a five-line block of "N/A" entries that carries no
    information. The header's N/A count still includes these five, though,
    so they must each be named somewhere — as a single compact bare-id
    line, not full entries, the same shape the Markdown and HTML renderers
    already use for this.

    `exclude=("security",)`: AS-1's PROMPT-SURFACE-* experimental checks
    (CORE-SECURITY-011..014) evaluate benign `llms.txt`/MCP content on this
    fixture and PASS rather than N/A — a real signal, not a bug, but
    unrelated to what this test is pinning (the readiness-only single-line
    notice), so it isolates the readiness experimental set the same way
    `test_security_is_score_neutral.py` proves security never changes a
    readiness verdict."""
    report = _scan("saas-mixed", options=ScanOptions(exclude=("security",)))
    assert report.provenance["experimental"] is False
    assert all(f.status == CheckStatus.NA for f in report.findings if f.experimental)

    text = render_text(report)
    assert "Experimental checks: not scored (run with --experimental)" in text
    assert "Experimental (not scored)" not in text
    assert "N/A: " in text
    for check_id in (
        "CORE-INTERFACE-004", "CORE-INTERFACE-008", "CORE-INTERFACE-009",
        "CORE-MACHINE-012", "CORE-OPERABILITY-007",
    ):
        assert check_id in text


def test_experimental_block_omits_na_findings_but_keeps_non_na_ones():
    """When SOME experimental findings are N/A and others are not, only the
    non-N/A ones get a full entry — commerce-good has CORE-MACHINE-012 PASS
    and the other four experimental checks N/A. The N/A ones are still named,
    but only as bare ids on the compact "N/A: ..." line, never as a full
    status+summary entry — the same shape the Markdown and HTML renderers
    already use for this."""
    report = _scan("commerce-good")
    assert report.provenance["experimental"] is False
    experimental = [f for f in report.findings if f.experimental]
    non_na = [f for f in experimental if f.status != CheckStatus.NA]
    na = [f for f in experimental if f.status == CheckStatus.NA]
    assert non_na and na  # exactly the mixed case this test is about

    text = render_text(report)
    assert "Experimental (not scored)" in text
    assert "Experimental checks: not scored" not in text
    exp_block = text[text.index("Experimental (not scored)"):]
    na_marker = next(line for line in exp_block.splitlines() if "N/A:" in line)
    full_entries_block = exp_block[: exp_block.index(na_marker)]
    for f in non_na:
        assert f.id in full_entries_block
    for f in na:
        assert f.id not in full_entries_block  # no full entry — bare id only
        assert f.id in na_marker

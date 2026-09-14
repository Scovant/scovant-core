"""AgentReady v1.0 mapping is data, complete, and two-way consistent with the checks."""
from collections import Counter

from scovant_core.checks.registry import CHECKS
from scovant_core.models import Category, CheckResult, CheckStatus, Confidence, Severity
from scovant_core.standards.agentready import (
    AGENTREADY_URL,
    AGENTREADY_VERSION,
    MAPPING,
    RELATIONSHIPS,
    REQUIREMENTS,
    TIERS,
    checks_for,
    mapping_summary,
    standards_for,
)

EXPECTED_IDS = (
    [f"AR-FIND-{i:02d}" for i in (1, 2, 3)]
    + [f"AR-READ-{i:02d}" for i in range(1, 10)]
    + [f"AR-ACT-{i:02d}" for i in range(1, 7)]
)


def test_requirements_are_the_18_of_v1_in_spec_order():
    # AGENTREADY_URL is the single source of truth (defined in
    # scovant_core.standards.agentready) — asserted here by shape only,
    # never re-embedded as a literal, so this test can't itself become a
    # second hand-typed copy of the URL for the publish guard to trip on.
    assert AGENTREADY_VERSION == "1.0"
    assert AGENTREADY_URL.startswith("https://") and AGENTREADY_URL.endswith("/")
    assert [r.id for r in REQUIREMENTS] == EXPECTED_IDS
    assert all(r.tier in TIERS for r in REQUIREMENTS)
    assert {r.id: r.tier for r in REQUIREMENTS if r.tier == "MUST"} == {
        "AR-FIND-01": "MUST", "AR-READ-01": "MUST", "AR-READ-02": "MUST"}
    assert [r.id for r in REQUIREMENTS if r.tier == "MAY"] == ["AR-READ-09", "AR-ACT-04", "AR-ACT-05"]


def test_exactly_one_mapping_per_requirement_and_every_check_exists():
    assert [m.requirement_id for m in MAPPING] == EXPECTED_IDS
    known = {c.id for c in CHECKS}
    for m in MAPPING:
        assert m.relationship in RELATIONSHIPS
        assert set(m.core_checks) <= known, (m.requirement_id, set(m.core_checks) - known)
        if m.relationship in ("AGENTREADY_ONLY", "NOT_APPLICABLE"):
            assert m.core_checks == (), m.requirement_id
        else:
            assert m.core_checks, m.requirement_id
        assert m.notes


def test_check_standards_attribute_is_the_inverse_of_mapping():
    inverse: dict[str, list[str]] = {}
    for m in MAPPING:
        for cid in m.core_checks:
            inverse.setdefault(cid, []).append(m.requirement_id)
    for c in CHECKS:
        assert tuple(c.standards) == tuple(inverse.get(c.id, ())), c.id
        assert tuple(c.standards) == standards_for(c.id)
    assert checks_for("AR-ACT-02") == ("CORE-INTERFACE-005",)
    assert checks_for("AR-ACT-06") == ()


def test_summary_counts_recount_from_mapping():
    s = mapping_summary()
    rel = Counter(m.relationship for m in MAPPING)
    assert s == {
        "version": "1.0", "url": AGENTREADY_URL, "requirements": 18,
        "with_checks": sum(1 for m in MAPPING if m.core_checks),
        "exact": rel["EXACT"], "partial": rel["PARTIAL"], "superset": rel["SCOVANT_SUPERSET"],
        "agentready_only": rel["AGENTREADY_ONLY"], "not_applicable": rel["NOT_APPLICABLE"],
    }
    assert s["with_checks"] == s["exact"] + s["partial"] + s["superset"]
    must = [m for m in MAPPING if next(r for r in REQUIREMENTS if r.id == m.requirement_id).tier == "MUST"]
    assert all(m.core_checks for m in must), "every MUST requirement has at least one Core check"


def _f(cid, status):
    return CheckResult(id=cid, title=cid, category=Category.ACCESS, status=status,
                       severity=Severity.INFO, confidence=Confidence.HIGH, weight=1,
                       summary="", evidence={})


def test_coverage_reduces_to_worst_evaluated_status_and_counts_tiers():
    from scovant_core.standards.agentready import agentready_coverage
    findings = [
        _f("CORE-ACCESS-002", CheckStatus.PASS), _f("CORE-ACCESS-003", CheckStatus.WARN),   # AR-FIND-01 → warn
        _f("CORE-ACCESS-008", CheckStatus.NA),
        _f("CORE-OPERABILITY-001", CheckStatus.PASS),                                       # AR-READ-01 → pass
        _f("CORE-OPERABILITY-004", CheckStatus.ERROR),                                      # AR-READ-02 → not_measured
        _f("CORE-INTERFACE-005", CheckStatus.FAIL),                                         # AR-ACT-02 → fail
    ]
    cov = agentready_coverage(findings)
    r = cov["requirements"]
    assert r["AR-FIND-01"] == "warn" and r["AR-READ-01"] == "pass" and r["AR-READ-02"] == "not_measured"
    assert r["AR-ACT-02"] == "fail" and r["AR-ACT-06"] == "not_measured" and r["AR-ACT-05"] == "not_measured"
    assert set(r) == {m.requirement_id for m in MAPPING}
    assert cov["by_tier"]["MUST"] == {"requirements": 3, "measured": 2, "pass": 1, "warn": 1, "fail": 0}
    # AR-READ-03 (SHOULD) also maps to CORE-OPERABILITY-001, so it is measured
    # (pass) alongside AR-ACT-02 (fail) from CORE-INTERFACE-005.
    assert cov["by_tier"]["SHOULD"]["measured"] == 2 and cov["by_tier"]["SHOULD"]["fail"] == 1
    assert cov["by_tier"]["MAY"] == {"requirements": 3, "measured": 0, "pass": 0, "warn": 0, "fail": 0}


def test_coverage_from_statuses_matches_the_checkresult_reduction():
    from scovant_core.standards.agentready import agentready_coverage_from_statuses

    statuses = {
        "CORE-ACCESS-002": "PASS", "CORE-ACCESS-003": "WARN",   # AR-FIND-01 -> warn
        "CORE-ACCESS-008": "N/A",
        "CORE-OPERABILITY-001": "PASS",                          # AR-READ-01 -> pass
        "CORE-OPERABILITY-004": "ERROR",                         # AR-READ-02 -> not_measured (only evaluated statuses count)
        "CORE-INTERFACE-005": "FAIL",                            # AR-ACT-02 -> fail
    }
    cov = agentready_coverage_from_statuses(statuses)
    r = cov["requirements"]
    assert r["AR-FIND-01"] == "warn" and r["AR-READ-01"] == "pass" and r["AR-READ-02"] == "not_measured"
    assert r["AR-ACT-02"] == "fail" and r["AR-ACT-06"] == "not_measured" and r["AR-ACT-05"] == "not_measured"
    assert set(r) == {m.requirement_id for m in MAPPING}
    assert cov["by_tier"]["MUST"] == {"requirements": 3, "measured": 2, "pass": 1, "warn": 1, "fail": 0}


def test_coverage_is_in_report_metrics_and_rendered(load_expected):
    from scovant_core.report._common import standards_line
    from scovant_core.report.html import render_html
    from scovant_core.report.markdown import render_markdown
    from scovant_core.report.text import render_text
    r = load_expected("commerce-good")
    assert r.metrics["standards"]["agentready_v1"]["version"] == "1.0"
    line = standards_line(r)
    assert line.startswith("AgentReady v1.0 (descriptive, not scored): MUST ")
    for out in (render_text(r), render_markdown(r), render_html(r)):
        assert "AgentReady v1.0 (descriptive, not scored)" in out and "docs/standards/agentready.md" in out


def test_read_02_is_exact_with_three_operability_checks():
    m = next(m for m in MAPPING if m.requirement_id == "AR-READ-02")
    assert m.relationship == "EXACT" and m.core_checks == ("CORE-OPERABILITY-004", "CORE-OPERABILITY-008", "CORE-OPERABILITY-009")
    assert mapping_summary()["exact"] == 3 and mapping_summary()["partial"] == 6

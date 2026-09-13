"""v0.1.1 (audit P0 §3/§4): scan scope + score status. A subset scan is a
Subset Diagnostic Score, never a Core Score; a full scan below the canonical
coverage floor or with any ERROR is DEGRADED and carries no grade."""
from __future__ import annotations

from scovant_core import scoring
from scovant_core.models import (
    SCORE_NAME,
    SCORE_SUBSET_NAME,
    Category,
    CheckResult,
    CheckStatus,
    Confidence,
    Severity,
)


def _r(id_: str, cat: Category, status: CheckStatus, weight: int = 2, experimental: bool = False) -> CheckResult:
    return CheckResult(id=id_, title=id_, category=cat, status=status, severity=Severity.MEDIUM,
                       confidence=Confidence.HIGH, weight=weight, summary="", experimental=experimental)


def _full(pass_all: bool = True, errors: int = 0) -> list[CheckResult]:
    out = []
    i = 0
    for cat in Category:
        for _ in range(4):
            i += 1
            st = CheckStatus.ERROR if errors > 0 else (CheckStatus.PASS if pass_all else CheckStatus.WARN)
            errors -= 1 if st == CheckStatus.ERROR else 0
            out.append(_r(f"C-{i:03d}", cat, st))
    return out


def test_thresholds_are_public_and_in_the_digest():
    assert scoring.EVIDENCE_MIN_COVERAGE == 0.60
    assert scoring.CANONICAL_MIN_COVERAGE == 0.85
    assert "0.85" in repr(scoring._DIGEST_INPUT) and "0.6" in repr(scoring._DIGEST_INPUT)


def test_canonical_full_scan_is_ok_with_grade():
    score, _ = scoring.score_results(_full())
    assert (score.scope, score.status, score.name) == ("CANONICAL", "OK", SCORE_NAME)
    assert score.value == 100 and score.grade == "A" and score.coverage == 1.0


def test_custom_selection_is_subset_diagnostic_without_grade():
    score, _ = scoring.score_results(_full(), selection_is_custom=True)
    assert (score.scope, score.status, score.name) == ("CUSTOM", "NOT_CANONICAL", SCORE_SUBSET_NAME)
    assert score.value == 100 and score.grade is None


def test_one_error_makes_a_full_scan_partial_degraded():
    results = _full(errors=1)
    score, _ = scoring.score_results(results, error_count=1)
    assert (score.scope, score.status) == ("PARTIAL", "DEGRADED")
    assert score.value is not None and score.grade is None and score.name == SCORE_NAME


def test_coverage_between_floors_is_degraded():
    # 20 checks × weight 2 = 40 applicable; 7 errors → evaluated 26/40 = 0.65
    results = _full(errors=7)
    score, _ = scoring.score_results(results, error_count=7)
    assert 0.60 <= score.coverage < 0.85
    assert (score.scope, score.status, score.grade) == ("PARTIAL", "DEGRADED", None)
    assert score.value is not None


def test_below_evidence_floor_is_insufficient_and_keeps_scope():
    results = _full(errors=17)          # evaluated 6/40 = 0.15
    score, _ = scoring.score_results(results, error_count=17)
    assert (score.scope, score.status, score.value, score.grade) == ("PARTIAL", "INSUFFICIENT_EVIDENCE", None, None)
    score_c, _ = scoring.score_results(results, selection_is_custom=True, error_count=17)
    assert (score_c.scope, score_c.status, score_c.name) == ("CUSTOM", "INSUFFICIENT_EVIDENCE", SCORE_SUBSET_NAME)


def test_boundary_0_85_is_canonical_but_error_free_only():
    # 40 applicable; need evaluated ≥ 34 → 3 ERRORs give 34/40 = 0.85 exactly, but ERROR>0 ⇒ PARTIAL
    results = _full(errors=3)
    score, _ = scoring.score_results(results, error_count=3)
    assert score.coverage == 0.85 and score.scope == "PARTIAL"
    # the same coverage with error_count=0 (N/A instead of ERROR) is CANONICAL
    results_na = _full()
    for r in results_na[:3]:
        results_na[results_na.index(r)] = _r(r.id, r.category, CheckStatus.NA)
    score2, _ = scoring.score_results(results_na)
    assert score2.scope == "CANONICAL" and score2.status == "OK" and score2.coverage == 1.0


def test_experimental_makes_the_scan_custom():
    results = _full() + [_r("X-1", Category.ACCESS, CheckStatus.PASS, experimental=True)]
    score, _ = scoring.score_results(results, include_experimental=True, selection_is_custom=True)
    assert score.scope == "CUSTOM"

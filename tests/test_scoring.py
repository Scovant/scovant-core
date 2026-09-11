from scovant_core.models import Category, CheckResult, CheckStatus, Confidence, Severity
from scovant_core.scoring import CATEGORY_WEIGHTS, grade_for, score_results


def _r(id, cat, status, weight, experimental=False):
    return CheckResult(id=id, title=id, category=cat, status=status, severity=Severity.LOW,
                       confidence=Confidence.HIGH, weight=weight, summary="", experimental=experimental)


def test_weights_sum_to_100():
    assert sum(CATEGORY_WEIGHTS.values()) == 100


def test_category_score_is_weighted_status_ratio():
    rs = [_r("A1", Category.ACCESS, CheckStatus.PASS, 3), _r("A2", Category.ACCESS, CheckStatus.WARN, 1),
          _r("A3", Category.ACCESS, CheckStatus.NA, 5), _r("A4", Category.ACCESS, CheckStatus.ERROR, 5)]
    score, cats = score_results(rs)
    assert cats["access"].score == 87.5            # (3*1 + 1*0.5) / 4
    assert cats["access"].applicable_weight == 9 and cats["access"].evaluated_weight == 4


def test_overall_renormalises_over_categories_with_evidence():
    rs = [_r("A1", Category.ACCESS, CheckStatus.PASS, 2), _r("M1", Category.MACHINE, CheckStatus.FAIL, 2)]
    score, _ = score_results(rs)
    assert score.value == 50 and score.grade == "F" and score.status == "OK"


def test_insufficient_evidence_when_coverage_below_floor():
    rs = [_r("A1", Category.ACCESS, CheckStatus.PASS, 1), _r("A2", Category.ACCESS, CheckStatus.ERROR, 9)]
    score, _ = score_results(rs)
    assert score.value is None and score.grade is None and score.status == "INSUFFICIENT_EVIDENCE"
    assert score.coverage == 0.1


def test_experimental_excluded_unless_opted_in():
    rs = [_r("A1", Category.ACCESS, CheckStatus.PASS, 1), _r("X1", Category.ACCESS, CheckStatus.FAIL, 9, True)]
    assert score_results(rs)[0].value == 100
    assert score_results(rs, include_experimental=True)[0].value == 10


def test_grade_ladder():
    assert [grade_for(v) for v in (100, 90, 89, 80, 79, 70, 69, 60, 59, 0)] == list("AABBCCDDFF")


def test_overall_weighting_uses_unrounded_category_ratios():
    # Category raw ratios: access 56.25 (9/16), machine 80.0 (4/5),
    # interfaces 45.0 (9/20), trust 27.78 (5/18), operability 81.82 (9/11).
    # Rounding each to 0.1 before weighting shifts the weighted sum enough
    # to flip the integer overall's grade band (D -> F) on this input; the
    # unrounded weighted sum is ~59.50, which half-up-rounds to 60 (D).
    rs = [
        _r("A1", Category.ACCESS, CheckStatus.PASS, 9), _r("A2", Category.ACCESS, CheckStatus.FAIL, 7),
        _r("M1", Category.MACHINE, CheckStatus.PASS, 4), _r("M2", Category.MACHINE, CheckStatus.FAIL, 1),
        _r("I1", Category.INTERFACES, CheckStatus.PASS, 9), _r("I2", Category.INTERFACES, CheckStatus.FAIL, 11),
        _r("T1", Category.TRUST, CheckStatus.PASS, 5), _r("T2", Category.TRUST, CheckStatus.FAIL, 13),
        _r("O1", Category.OPERABILITY, CheckStatus.PASS, 9), _r("O2", Category.OPERABILITY, CheckStatus.FAIL, 2),
    ]
    score, cats = score_results(rs)
    assert cats["access"].score == 56.2  # display rounding only — the weighted sum below uses the raw 56.25
    assert score.value == 60
    assert score.grade == "D"


def test_coverage_floor_uses_raw_ratio_not_rounded():
    # 1499/2500 = 0.5996, which is below MIN_COVERAGE=0.60 — but round(0.5996, 3)
    # == 0.6, so comparing the ROUNDED coverage to the floor would wrongly pass.
    rs = [_r("A1", Category.ACCESS, CheckStatus.PASS, 1499), _r("A2", Category.ACCESS, CheckStatus.ERROR, 1001)]
    score, _ = score_results(rs)
    assert score.status == "INSUFFICIENT_EVIDENCE"
    assert score.value is None and score.grade is None
    assert score.coverage == 0.6

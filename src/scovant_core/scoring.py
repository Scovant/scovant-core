"""Public scoring model: category weights, PASS/WARN/FAIL to a 0-100 score,
coverage-gated grading. Kept intentionally simple and transparent — every
constant here is public, unlike Scovant Cloud's proprietary weighting.

The weighted overall is computed from the UNROUNDED per-category ratio —
`CategoryScore.score` is rounded to 0.1 only for display. Rounding each
category to 0.1 before weighting can flip the overall's grade band on
reachable inputs (a category near a 0.05 boundary rounds one way, and the
weighted sum of several such roundings can cross a grade threshold that the
unrounded sum does not), so the two must stay separate. The coverage floor
check is likewise compared against the raw ratio; `Score.coverage` is only
rounded for the report."""
from __future__ import annotations

import hashlib
import math

from scovant_core.models import (
    CATEGORY_TITLES,
    Category,
    CategoryScore,
    CheckResult,
    CheckStatus,
    Score,
)

CATEGORY_WEIGHTS = {"access": 25, "machine": 25, "interfaces": 20, "trust": 15, "operability": 15}
STATUS_VALUE = {CheckStatus.PASS: 1.0, CheckStatus.WARN: 0.5, CheckStatus.FAIL: 0.0}
MIN_COVERAGE = 0.60
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))
SCORING_DIGEST = hashlib.sha256(
    repr((CATEGORY_WEIGHTS, {k.value: v for k, v in STATUS_VALUE.items()}, MIN_COVERAGE, GRADES)).encode()
).hexdigest()[:12]


def grade_for(value: int) -> str:
    return next(g for floor, g in GRADES if value >= floor)


def score_results(
    results: list[CheckResult], *, include_experimental: bool = False
) -> tuple[Score, dict[str, CategoryScore]]:
    cats: dict[str, CategoryScore] = {}
    raw_scores: dict[str, float] = {}
    for cat in Category:
        rs = [r for r in results if r.category == cat and (include_experimental or not r.experimental)]
        applicable = [r for r in rs if r.status != CheckStatus.NA]
        evaluated = [r for r in applicable if r.status in STATUS_VALUE]
        aw = float(sum(r.weight for r in applicable))
        ew = float(sum(r.weight for r in evaluated))
        raw = 100 * sum(r.weight * STATUS_VALUE[r.status] for r in evaluated) / ew if ew else None
        cats[cat.value] = CategoryScore(
            title=CATEGORY_TITLES[cat], score=(round(raw, 1) if raw is not None else None),
            weight=CATEGORY_WEIGHTS[cat.value], applicable_weight=aw, evaluated_weight=ew,
        )
        if raw is not None:
            raw_scores[cat.value] = raw

    total_applicable = sum(c.applicable_weight for c in cats.values())
    total_evaluated = sum(c.evaluated_weight for c in cats.values())
    raw_coverage = total_evaluated / total_applicable if total_applicable else 0.0
    coverage = round(raw_coverage, 3)

    if raw_coverage < MIN_COVERAGE or not raw_scores:
        return Score(value=None, grade=None, coverage=coverage, status="INSUFFICIENT_EVIDENCE"), cats

    wsum = sum(CATEGORY_WEIGHTS[k] for k in raw_scores)
    weighted = sum(raw_scores[k] * CATEGORY_WEIGHTS[k] for k in raw_scores) / wsum
    value = math.floor(weighted + 0.5)  # half-up, never Python's banker's round()
    return Score(value=value, grade=grade_for(value), coverage=coverage, status="OK"), cats

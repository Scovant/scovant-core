"""`score_r2` — the R2 readiness formula (see docs/r2.md).

category  = 100 · Σ wᵢ·vᵢ / Σ wᵢ over measured, counted WEIGHTED outcomes
            vᵢ = 1 − fᵢ·(1 − STATE_VALUE[state]); fᵢ = pages_failed/pages_measured
            for a page-scope rule, 1 for a domain-scope rule
overall   = Σ category·W / Σ W over categories that have a score
rating    = half-up integer, then at most one effect per fired gate
coverage  = Σ w (measured) / Σ w (applicable) over WEIGHTED + GATE outcomes
"""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from scovant_core.r2.manifest import Manifest, RuleScope, RuleSpec, ScoreEffect
from scovant_core.r2.outcome import MEASURED_STATES, STATE_VALUE, Outcome, OutcomeState, R2Category
from scovant_core.r2.policy import ScoringPolicy

FORMULA_VERSION = "R2.0"


class CategoryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    score: float | None
    weight: float
    applicable: bool
    applicable_weight: float
    measured_weight: float


class GateHit(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_cause_group: str
    effect: str
    cap: int | None
    rule_id: str


class R2Result(BaseModel):
    model_config = ConfigDict(frozen=True)

    model_id: str
    policy_name: str
    profile: str
    rating_raw: float | None
    rating: int | None
    grade: str | None
    badge: str | None
    status: str          # OK | DEGRADED | INSUFFICIENT_EVIDENCE
    confidence: str      # high | medium | low
    coverage: float
    categories: dict[str, CategoryResult]
    gates_applied: list[GateHit]
    deduplicated: list[str]
    unknown_rules: list[str]
    result_hash: str


def model_id(manifest: Manifest, policy: ScoringPolicy) -> str:
    blob = f"{FORMULA_VERSION}|{manifest.digest()}|{policy.digest()}"
    return f"{FORMULA_VERSION}@{hashlib.sha256(blob.encode()).hexdigest()[:12]}"


def _check_counts(spec: RuleSpec, o: Outcome) -> None:
    """Every outcome's page counts must agree with its rule's scope — for
    weighted, gate and merged rules alike."""
    if spec.scope == RuleScope.DOMAIN:
        if o.pages_measured is not None:
            raise ValueError(f"{spec.rule_id}: a domain-scope outcome carries no page counts")
        return
    if o.state not in MEASURED_STATES:
        return
    if not o.pages_measured:
        raise ValueError(f"{spec.rule_id}: a measured page-scope outcome needs pages_measured > 0")
    if (o.state == OutcomeState.PASS) != (o.pages_failed == 0):
        raise ValueError(f"{spec.rule_id}: PASS needs pages_failed == 0, WARN/FAIL need pages_failed > 0")


def _value(spec: RuleSpec, o: Outcome) -> float:
    base = STATE_VALUE[o.state]
    if spec.scope == RuleScope.PAGE and o.pages_measured:
        assert o.pages_failed is not None
        return 1.0 - (o.pages_failed / o.pages_measured) * (1.0 - base)
    return base


def _floor_label(value: int, ladder: tuple[tuple[int, str], ...]) -> str | None:
    return next((label for floor, label in ladder if value >= floor), None)


def score_r2(
    outcomes: Iterable[Outcome], *, profile: str, manifest: Manifest, policy: ScoringPolicy,
) -> R2Result:
    profile = profile.strip().lower()
    by_id: dict[str, Outcome] = {}
    for o in outcomes:
        if o.rule_id not in manifest:
            raise ValueError(f"outcome for {o.rule_id}, which is not in the manifest")
        if o.rule_id in by_id:
            raise ValueError(f"two outcomes for {o.rule_id}")
        by_id[o.rule_id] = o

    rows: list[tuple[RuleSpec, Outcome]] = []
    unknown: list[str] = []
    for spec in manifest.specs:
        if spec.maturity != "required" or spec.score_effect == ScoreEffect.DIAGNOSTIC:
            continue
        found = by_id.get(spec.rule_id)
        if found is not None:
            _check_counts(spec, found)
        if found is None:
            unknown.append(spec.rule_id)
            found = Outcome(rule_id=spec.rule_id, state=OutcomeState.UNKNOWN)
        applies = policy.category_applies(spec.category, profile) and (
            not spec.profiles or profile in spec.profiles)
        if not applies:
            found = Outcome(rule_id=spec.rule_id, state=OutcomeState.NA)
        rows.append((spec, found))

    # Fired gates: a FAILing gate rule whose group the policy defines. A gate
    # acts only on the badge or as a cap; it never removes a weighted outcome,
    # so fixing (or losing the measurement of) a gate can only raise a score.
    hits: list[GateHit] = []
    for spec, o in rows:
        if spec.score_effect == ScoreEffect.GATE and o.state == OutcomeState.FAIL:
            gate = policy.gate_for(spec.root_cause_group)
            if gate is not None and all(h.root_cause_group != gate.root_cause_group for h in hits):
                hits.append(GateHit(root_cause_group=gate.root_cause_group, effect=gate.effect,
                                    cap=gate.cap, rule_id=spec.rule_id))

    def weight(spec: RuleSpec) -> int:
        return policy.severity_weights[spec.severity.value]

    # One numeric effect per root cause: measured WEIGHTED outcomes sharing
    # (root_cause_group, scope, evidence_key) — the manifest keeps a group
    # inside one category — form ONE element with the heaviest member's weight
    # and the WORST member's value. Membership never depends on pass/fail, so
    # fixing any member can only raise the element's value. Empty group or
    # empty key = never merged.
    clusters: dict[tuple[str, str, str], list[tuple[RuleSpec, Outcome]]] = {}
    for s_, o in rows:
        if (s_.score_effect == ScoreEffect.WEIGHTED and o.state in MEASURED_STATES
                and s_.root_cause_group and o.evidence_key):
            clusters.setdefault((s_.root_cause_group, s_.scope.value, o.evidence_key), []).append((s_, o))
    merged_value: dict[str, float] = {}
    deduped: set[str] = set()
    for members in clusters.values():
        members.sort(key=lambda so: (-weight(so[0]), so[0].rule_id))
        head = members[0][0]
        merged_value[head.rule_id] = min(_value(sp, oc) for sp, oc in members)
        deduped.update(sp.rule_id for sp, _ in members[1:])

    applicable_w = 0.0
    measured_w = 0.0
    any_error = False
    cat_num: dict[R2Category, float] = {c: 0.0 for c in R2Category}
    cat_den: dict[R2Category, float] = {c: 0.0 for c in R2Category}
    cat_app: dict[R2Category, float] = {c: 0.0 for c in R2Category}
    for spec, o in rows:
        if o.state == OutcomeState.NA or spec.rule_id in deduped:
            continue
        w = float(weight(spec))
        applicable_w += w
        cat_app[spec.category] += w
        if o.state == OutcomeState.ERROR:
            any_error = True
        if o.state not in MEASURED_STATES:
            continue
        measured_w += w
        if spec.score_effect == ScoreEffect.WEIGHTED:
            cat_num[spec.category] += w * merged_value.get(spec.rule_id, _value(spec, o))
            cat_den[spec.category] += w

    categories: dict[str, CategoryResult] = {}
    raw_scores: dict[R2Category, float] = {}
    for c in R2Category:
        applicable = policy.category_applies(c, profile)
        score = 100.0 * cat_num[c] / cat_den[c] if applicable and cat_den[c] else None
        if score is not None:
            raw_scores[c] = score
        categories[c.value] = CategoryResult(
            score=round(score, 1) if score is not None else None,
            weight=policy.category_weights[c], applicable=applicable,
            applicable_weight=cat_app[c], measured_weight=cat_den[c],
        )

    raw_coverage = measured_w / applicable_w if applicable_w else 0.0
    coverage = round(raw_coverage, 3)
    mid = model_id(manifest, policy)

    rating_raw: float | None = None
    rating: int | None = None
    grade = badge = None
    if raw_coverage < policy.evidence_min_coverage or not raw_scores:
        status, confidence = "INSUFFICIENT_EVIDENCE", "low"
    else:
        wsum = sum(policy.category_weights[c] for c in raw_scores)
        weighted = sum(raw_scores[c] * policy.category_weights[c] for c in raw_scores) / wsum
        # A weighted mean of 100s can land a float ulp above 100; clamp.
        rating_raw = min(100.0, max(0.0, weighted))
        rating = math.floor(rating_raw + 0.5)  # half-up, never banker's rounding
        for h in hits:
            if h.effect == "cap" and h.cap is not None:
                rating = min(rating, h.cap)
        if raw_coverage < policy.canonical_min_coverage or any_error:
            status, confidence = "DEGRADED", "medium"
        else:
            status, confidence = "OK", "high"
            grade = _floor_label(rating, policy.grades)
            if not any(h.effect == "badge_block" for h in hits):
                badge = _floor_label(rating, policy.badges)

    body = {
        "model_id": mid, "policy_name": policy.name, "profile": profile,
        "rating_raw": rating_raw, "rating": rating, "grade": grade, "badge": badge,
        "status": status, "confidence": confidence, "coverage": coverage,
        "categories": {k: v.model_dump(mode="json") for k, v in categories.items()},
        "gates_applied": [h.model_dump(mode="json") for h in hits],
        "deduplicated": sorted(deduped), "unknown_rules": sorted(unknown),
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return R2Result(
        model_id=mid, policy_name=policy.name, profile=profile, rating_raw=rating_raw,
        rating=rating, grade=grade, badge=badge, status=status, confidence=confidence,
        coverage=coverage, categories=categories, gates_applied=hits,
        deduplicated=sorted(deduped), unknown_rules=sorted(unknown), result_hash=digest,
    )

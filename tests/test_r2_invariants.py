"""R2 invariants as seeded randomized properties (stdlib `random`; no new
dependency). Each property runs over 800 generated manifests/outcome sets:
400 of any structure and 400 dense ones where merging and gates happen."""
import random

import pytest

from scovant_core.models import Severity
from scovant_core.r2.manifest import Manifest, RuleScope, RuleSpec, ScoreEffect
from scovant_core.r2.outcome import MEASURED_STATES, Outcome, R2Category
from scovant_core.r2.outcome import OutcomeState as S
from scovant_core.r2.policy import PUBLIC_POLICY
from scovant_core.r2.score import score_r2

PROFILES = ("blog", "commerce", "saas", "other")
NON_MEASURED = (S.NA, S.NOT_MEASURED, S.ERROR, S.BLOCKED_BY_POLICY, S.UNKNOWN)
KEYS = ("", "k1", "k2")


def _case(rng, dense=False):
    """dense=False: any structure. dense=True: few categories, shared root
    causes and evidence keys, mostly measured outcomes — the family where
    merging and gates actually happen and a rating exists."""
    specs, outs = [], []
    cats = list(R2Category)[:3] if dense else list(R2Category)
    for i in range(rng.randint(3, 12) if dense else rng.randint(1, 12)):
        scope = rng.choice(list(RuleScope))
        effect = rng.choice([ScoreEffect.WEIGHTED] * 4 + [ScoreEffect.GATE])
        cat = rng.choice(cats)
        # a weighted group lives inside one category (manifest rule)
        group = (rng.choice(["", f"{cat.value}-g"]) if not dense else f"{cat.value}-g")
        if effect == ScoreEffect.GATE:
            group = "agent_access_blocked" if rng.random() < 0.5 else f"gate-{i % 2}"
        rid = f"R{i}"
        specs.append(RuleSpec(rule_id=rid, signal=f"s{i}", category=cat,
                              severity=rng.choice(list(Severity)), scope=scope,
                              score_effect=effect, root_cause_group=group))
        states = [S.PASS, S.WARN, S.FAIL] * 6 + list(S) if dense else list(S)
        state = rng.choice(states)
        if state == S.UNKNOWN or rng.random() < 0.05:
            continue  # no outcome at all -> UNKNOWN
        pages = {}
        if scope == RuleScope.PAGE:
            pm = rng.randint(1, 20)
            pf = 0 if state == S.PASS else rng.randint(1, pm)
            pages = dict(pages_measured=pm, pages_failed=pf)
        key = rng.choice(KEYS[1:]) if dense else rng.choice(KEYS)
        outs.append(Outcome(rule_id=rid, state=state, evidence_key=key, **pages))
    return specs, outs, rng.choice(PROFILES) if not dense else "blog"


def _score(specs, outs, profile):
    return score_r2(outs, profile=profile, manifest=Manifest(specs), policy=PUBLIC_POLICY)


def _with_state(outs, rule_id, state):
    new = []
    for o in outs:
        if o.rule_id == rule_id:
            pages = {}
            if o.pages_measured is not None:
                failed = o.pages_failed if o.state in (S.FAIL, S.WARN) else 1
                pages = dict(pages_measured=o.pages_measured,
                             pages_failed=0 if state == S.PASS else failed)
            if state not in MEASURED_STATES:
                pages = {} if o.pages_measured is None else pages
            o = Outcome(rule_id=rule_id, state=state, evidence_key=o.evidence_key, **pages)
        new.append(o)
    return new


CASES = ([_case(random.Random(seed)) for seed in range(400)]
         + [_case(random.Random(10_000 + seed), dense=True) for seed in range(400)])


def test_the_generator_exercises_merging_and_gates():
    # A property over cases that never merge or never rate proves nothing.
    rated = [c for c in CASES if _score(*c).rating is not None]
    merged = [c for c in rated if _score(*c).deduplicated]
    gated = [c for c in rated if _score(*c).gates_applied]
    assert len(rated) >= 300 and len(merged) >= 100 and len(gated) >= 50, (
        len(rated), len(merged), len(gated))


@pytest.mark.parametrize("specs,outs,profile", CASES)
def test_deterministic_and_order_independent(specs, outs, profile):
    a = _score(specs, outs, profile)
    b = _score(list(reversed(specs)), list(reversed(outs)), profile)
    assert a.result_hash == b.result_hash and a == b


@pytest.mark.parametrize("specs,outs,profile", CASES)
def test_rating_bounded(specs, outs, profile):
    r = _score(specs, outs, profile)
    if r.rating is not None:
        assert 0 <= r.rating <= 100 and 0.0 <= r.rating_raw <= 100.0
    assert 0.0 <= r.coverage <= 1.0


@pytest.mark.parametrize("specs,outs,profile", CASES)
def test_non_measured_states_never_act_as_fail(specs, outs, profile):
    # Any non-measured state leaves every category score exactly as N/A does:
    # it may lower coverage, never a category.
    for o in outs:
        base = _score(specs, _with_state(outs, o.rule_id, S.NA), profile)
        for st in NON_MEASURED[1:]:
            other = _score(specs, _with_state(outs, o.rule_id, st), profile)
            assert {k: c.score for k, c in other.categories.items()} == {
                k: c.score for k, c in base.categories.items()}


@pytest.mark.parametrize("specs,outs,profile", CASES)
def test_fixing_a_failure_never_lowers_the_rating(specs, outs, profile):
    before = _score(specs, outs, profile)
    for o in outs:
        if o.state not in (S.FAIL, S.WARN):
            continue
        after = _score(specs, _with_state(outs, o.rule_id, S.PASS), profile)
        if before.rating_raw is not None and after.rating_raw is not None:
            assert after.rating_raw >= before.rating_raw - 1e-9
            assert after.rating >= before.rating


@pytest.mark.parametrize("specs,outs,profile", CASES)
def test_adding_a_not_applicable_rule_changes_nothing_but_the_model(specs, outs, profile):
    extra = RuleSpec(rule_id="ZEXTRA", signal="s-extra", category=R2Category.TRUST,
                     severity=Severity.CRITICAL, scope=RuleScope.DOMAIN)
    a = _score(specs, outs, profile)
    b = _score(specs + [extra], outs + [Outcome(rule_id="ZEXTRA", state=S.NA)], profile)
    assert (a.rating_raw, a.rating, a.coverage, a.status, a.grade, a.badge) == (
        b.rating_raw, b.rating, b.coverage, b.status, b.grade, b.badge)

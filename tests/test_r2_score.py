import pytest

from scovant_core.models import Severity
from scovant_core.r2.manifest import Manifest, RuleScope, RuleSpec, ScoreEffect
from scovant_core.r2.outcome import Outcome
from scovant_core.r2.outcome import OutcomeState as S
from scovant_core.r2.outcome import R2Category as C
from scovant_core.r2.policy import PUBLIC_POLICY, Gate, ScoringPolicy
from scovant_core.r2.score import FORMULA_VERSION, model_id, score_r2


def spec(rule_id, category, severity, scope=RuleScope.DOMAIN, **kw):
    return RuleSpec(rule_id=rule_id, signal=f"sig.{rule_id}", category=category,
                    severity=severity, scope=scope, **kw)


BASE = [
    spec("A", C.DISCOVERABILITY, Severity.HIGH),
    spec("B", C.DISCOVERABILITY, Severity.MEDIUM, RuleScope.PAGE),
    spec("C", C.STRUCTURED, Severity.LOW),
]
BASE_OUT = [
    Outcome(rule_id="A", state=S.PASS),
    Outcome(rule_id="B", state=S.FAIL, pages_measured=10, pages_failed=2),
    Outcome(rule_id="C", state=S.WARN),
]


def run(specs=BASE, outs=BASE_OUT, profile="blog", policy=PUBLIC_POLICY):
    return score_r2(outs, profile=profile, manifest=Manifest(specs), policy=policy)


def test_worked_example():
    r = run()
    # discoverability = 100·(25·1 + 14·(1 − 0.2)) / 39 ; structured = 50
    assert r.categories["discoverability"].score == 92.8
    assert r.categories["structured"].score == 50.0
    assert r.rating_raw == pytest.approx(70.7985347985348, abs=1e-12)
    assert r.rating == 71
    assert (r.status, r.confidence, r.coverage) == ("OK", "high", 1.0)
    assert (r.grade, r.badge) == ("C", "agent_compatible")
    assert r.categories["ucp"].applicable is False and r.categories["ucp"].score is None
    assert r.categories["citability"].applicable is True and r.categories["citability"].score is None
    assert r.model_id.startswith(f"{FORMULA_VERSION}@")
    assert r.model_id == model_id(Manifest(BASE), PUBLIC_POLICY)


def test_error_degrades_and_withholds_grade():
    specs = BASE + [spec("E", C.TRUST, Severity.MEDIUM)]
    r = run(specs, BASE_OUT + [Outcome(rule_id="E", state=S.ERROR)])
    assert r.status == "DEGRADED" and r.confidence == "medium"
    assert r.coverage == 0.763          # 45 / 59
    assert r.rating == 71               # ERROR never enters the ratio
    assert r.grade is None and r.badge is None


def test_missing_outcome_is_unknown_not_pass():
    r = run(outs=BASE_OUT[:2])
    assert r.unknown_rules == ["C"]
    assert r.categories["structured"].score is None
    assert r.coverage == round(39 / 45, 3)


def test_low_coverage_is_insufficient_evidence():
    outs = [Outcome(rule_id="A", state=S.NOT_MEASURED),
            Outcome(rule_id="B", state=S.BLOCKED_BY_POLICY), Outcome(rule_id="C", state=S.WARN)]
    r = run(outs=outs)
    assert (r.status, r.rating, r.rating_raw, r.grade, r.badge) == (
        "INSUFFICIENT_EVIDENCE", None, None, None, None)
    assert r.confidence == "low"


@pytest.mark.parametrize("outs", [[], [Outcome(rule_id=x, state=S.NA) for x in "ABC"]])
def test_nothing_measured_never_divides_by_zero(outs):
    r = run(outs=outs)
    assert r.status == "INSUFFICIENT_EVIDENCE" and r.coverage == 0.0


def test_profile_excludes_category():
    specs = BASE + [spec("U", C.UCP, Severity.CRITICAL)]
    blog = run(specs, BASE_OUT + [Outcome(rule_id="U", state=S.FAIL)], profile="blog")
    assert blog.rating_raw == run().rating_raw
    shop = run(specs, BASE_OUT + [Outcome(rule_id="U", state=S.FAIL)], profile="commerce")
    assert shop.categories["ucp"].score == 0.0 and shop.rating < blog.rating


def test_rule_profiles_restrict_the_rule():
    specs = BASE + [spec("P", C.TRUST, Severity.HIGH, profiles=("commerce",))]
    r = run(specs, BASE_OUT + [Outcome(rule_id="P", state=S.FAIL)], profile="blog")
    assert r.categories["trust"].score is None and r.rating == 71


def test_unknown_or_duplicate_outcomes_fail_closed():
    with pytest.raises(ValueError, match="not in the manifest"):
        run(outs=BASE_OUT + [Outcome(rule_id="ZZ", state=S.PASS)])
    with pytest.raises(ValueError, match="two outcomes"):
        run(outs=BASE_OUT + [Outcome(rule_id="A", state=S.FAIL)])


def test_page_counts_must_match_scope():
    with pytest.raises(ValueError, match="pages_measured > 0"):
        run(outs=[BASE_OUT[0], Outcome(rule_id="B", state=S.FAIL, pages_measured=0, pages_failed=0),
                  BASE_OUT[2]])
    with pytest.raises(ValueError, match="carries no page counts"):
        run(outs=[Outcome(rule_id="A", state=S.PASS, pages_measured=3, pages_failed=0),
                  *BASE_OUT[1:]])


def test_experimental_and_diagnostic_rules_never_count():
    specs = BASE + [spec("X", C.TRUST, Severity.CRITICAL, maturity="experimental"),
                    spec("D", C.TRUST, Severity.CRITICAL, score_effect=ScoreEffect.DIAGNOSTIC)]
    r = run(specs, BASE_OUT + [Outcome(rule_id="X", state=S.FAIL), Outcome(rule_id="D", state=S.FAIL)])
    assert r.categories["trust"].score is None and r.rating == 71 and r.coverage == 1.0


GATE = spec("G", C.DISCOVERABILITY, Severity.CRITICAL, score_effect=ScoreEffect.GATE,
            root_cause_group="agent_access_blocked")


def test_public_gate_blocks_badge_but_not_number():
    r = run(BASE + [GATE], BASE_OUT + [Outcome(rule_id="G", state=S.FAIL, evidence_key="robots:/")])
    assert r.rating == 71 and r.grade == "C" and r.badge is None
    assert [h.root_cause_group for h in r.gates_applied] == ["agent_access_blocked"]


def test_host_policy_cap_gate():
    data = PUBLIC_POLICY.model_dump()
    data["name"] = "host"
    data["gates"] = (Gate(root_cause_group="agent_access_blocked", effect="cap", cap=50),)
    host = ScoringPolicy(**data)
    r = run(BASE + [GATE], BASE_OUT + [Outcome(rule_id="G", state=S.FAIL)], policy=host)
    assert r.rating == 50 and r.badge is None  # 50 is below every badge floor
    assert r.model_id != run(BASE + [GATE], BASE_OUT + [Outcome(rule_id="G", state=S.PASS)]).model_id


def test_gate_never_removes_a_weighted_failure():
    # A gate is a badge/cap effect; it must not hide the weighted failure of
    # the same evidence, or fixing the gate would bring that failure back.
    w = spec("W", C.DISCOVERABILITY, Severity.HIGH, root_cause_group="agent_access_blocked")
    outs = BASE_OUT + [Outcome(rule_id="G", state=S.FAIL, evidence_key="robots:/"),
                       Outcome(rule_id="W", state=S.FAIL, evidence_key="robots:/")]
    r = run(BASE + [GATE, w], outs)
    # discoverability = 100·(25 + 14·0.8 + 25·0) / 64 = 56.5625
    assert r.deduplicated == [] and r.categories["discoverability"].score == 56.6
    assert r.rating == 53 and r.grade == "D" and r.badge is None
    fixed = run(BASE + [GATE, w], BASE_OUT + [Outcome(rule_id="G", state=S.PASS),
                                              Outcome(rule_id="W", state=S.FAIL, evidence_key="robots:/")])
    assert fixed.rating >= r.rating


def test_gate_without_a_policy_gate_changes_nothing():
    g2 = spec("G2", C.STRUCTURED, Severity.HIGH, score_effect=ScoreEffect.GATE, root_cause_group="schema")
    w2 = spec("W2", C.STRUCTURED, Severity.HIGH, root_cause_group="schema")
    outs = BASE_OUT + [Outcome(rule_id="G2", state=S.FAIL, evidence_key="x"),
                       Outcome(rule_id="W2", state=S.FAIL, evidence_key="x")]
    r = run(BASE + [g2, w2], outs)
    assert r.gates_applied == [] and r.deduplicated == []
    assert r.categories["structured"].score == round(300 / 31, 1)


def test_a_missing_gate_measurement_moves_no_category():
    w = spec("W", C.DISCOVERABILITY, Severity.HIGH, root_cause_group="agent_access_blocked")
    def cats(gstate):
        outs = BASE_OUT + [Outcome(rule_id="G", state=gstate, evidence_key="robots:/"),
                           Outcome(rule_id="W", state=S.FAIL, evidence_key="robots:/")]
        return {k: c.score for k, c in run(BASE + [GATE, w], outs).categories.items()}
    assert cats(S.FAIL) == cats(S.NOT_MEASURED) == cats(S.PASS)


def test_fixing_the_kept_duplicate_never_lowers_the_rating():
    w1 = spec("W1", C.STRUCTURED, Severity.HIGH, root_cause_group="g")
    w2 = spec("W2", C.STRUCTURED, Severity.MEDIUM, root_cause_group="g")
    before = run(BASE + [w1, w2], BASE_OUT + [Outcome(rule_id="W1", state=S.FAIL, evidence_key="k"),
                                              Outcome(rule_id="W2", state=S.FAIL, evidence_key="k")])
    after = run(BASE + [w1, w2], BASE_OUT + [Outcome(rule_id="W1", state=S.PASS),
                                             Outcome(rule_id="W2", state=S.FAIL, evidence_key="k")])
    assert after.rating_raw >= before.rating_raw


def test_page_counts_are_checked_for_gate_rules_too():
    pg = spec("PG", C.DISCOVERABILITY, Severity.HIGH, RuleScope.PAGE, score_effect=ScoreEffect.GATE,
              root_cause_group="agent_access_blocked")
    with pytest.raises(ValueError, match="PASS needs pages_failed"):
        run(BASE + [pg], BASE_OUT + [Outcome(rule_id="PG", state=S.FAIL, pages_measured=5, pages_failed=0)])
    with pytest.raises(ValueError, match="pages_measured > 0"):
        run(BASE + [pg], BASE_OUT + [Outcome(rule_id="PG", state=S.FAIL)])
    with pytest.raises(ValueError, match="carries no page counts"):
        run(BASE + [GATE], BASE_OUT + [Outcome(rule_id="G", state=S.FAIL, pages_measured=2, pages_failed=1)])


def test_rule_profiles_are_normalised():
    p = spec("P", C.TRUST, Severity.HIGH, profiles=(" Commerce",))
    assert p.profiles == ("commerce",)
    r = run(BASE + [p], BASE_OUT + [Outcome(rule_id="P", state=S.FAIL)], profile="commerce")
    assert r.categories["trust"].score == 0.0


def test_same_group_different_evidence_both_count():
    w1 = spec("W1", C.STRUCTURED, Severity.HIGH, root_cause_group="schema_broken")
    w2 = spec("W2", C.STRUCTURED, Severity.MEDIUM, root_cause_group="schema_broken")
    outs = BASE_OUT + [Outcome(rule_id="W1", state=S.FAIL, evidence_key="page:/a"),
                       Outcome(rule_id="W2", state=S.FAIL, evidence_key="page:/b")]
    r = run(BASE + [w1, w2], outs)
    assert r.deduplicated == []
    # structured = 100·(6·0.5) / (6+25+14)
    assert r.categories["structured"].score == round(300 / 45, 1)


def test_same_group_same_evidence_keeps_the_heavier():
    w1 = spec("W1", C.STRUCTURED, Severity.HIGH, root_cause_group="schema_broken")
    w2 = spec("W2", C.STRUCTURED, Severity.MEDIUM, root_cause_group="schema_broken")
    outs = BASE_OUT + [Outcome(rule_id="W1", state=S.FAIL, evidence_key="page:/a"),
                       Outcome(rule_id="W2", state=S.FAIL, evidence_key="page:/a")]
    r = run(BASE + [w1, w2], outs)
    assert r.deduplicated == ["W2"]
    assert r.categories["structured"].score == round(300 / 31, 1)


def test_empty_evidence_key_is_never_merged():
    w1 = spec("W1", C.STRUCTURED, Severity.HIGH, root_cause_group="schema_broken")
    w2 = spec("W2", C.STRUCTURED, Severity.MEDIUM, root_cause_group="schema_broken")
    outs = BASE_OUT + [Outcome(rule_id="W1", state=S.FAIL), Outcome(rule_id="W2", state=S.FAIL)]
    assert run(BASE + [w1, w2], outs).deduplicated == []


def test_half_up_rounding():
    # 1 - 3/8 = 0.625 -> raw 62.5: half-up gives 63, banker's round() would give 62
    specs = [spec("Q", C.STRUCTURED, Severity.LOW, RuleScope.PAGE)]
    r = run(specs, [Outcome(rule_id="Q", state=S.FAIL, pages_measured=8, pages_failed=3)], profile="commerce")
    assert r.rating_raw == 62.5 and r.rating == 63
    # a WARN page rule loses half: 1 - (1/2)*(1-0.5) = 0.75
    r = run(specs, [Outcome(rule_id="Q", state=S.WARN, pages_measured=2, pages_failed=1)], profile="commerce")
    assert r.rating_raw == 75.0 and r.rating == 75


def test_profile_is_case_and_space_insensitive():
    assert run(profile=" Blog ").result_hash == run(profile="blog").result_hash


@pytest.mark.parametrize("state,failed", [(S.PASS, 1), (S.FAIL, 0), (S.WARN, 0)])
def test_page_state_must_agree_with_failed_pages(state, failed):
    with pytest.raises(ValueError, match="PASS needs pages_failed"):
        run(outs=[BASE_OUT[0], Outcome(rule_id="B", state=state, pages_measured=5, pages_failed=failed),
                  BASE_OUT[2]])


def test_empty_manifest_is_insufficient_evidence():
    r = run(specs=[], outs=[])
    assert r.status == "INSUFFICIENT_EVIDENCE" and r.rating is None and r.coverage == 0.0


def test_only_a_failing_gate_fires():
    r = run(BASE + [GATE], BASE_OUT + [Outcome(rule_id="G", state=S.WARN)])
    assert r.gates_applied == [] and r.badge == "agent_compatible"

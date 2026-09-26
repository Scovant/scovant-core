import pytest
from pydantic import ValidationError

from scovant_core.r2.outcome import R2Category
from scovant_core.r2.policy import PUBLIC_POLICY, Gate, ScoringPolicy


def test_public_policy_values_are_the_published_ones():
    # These are the values on scovant.com/scoring. The host pins its own
    # constants to this object; a change here is a new model version.
    p = PUBLIC_POLICY
    assert {c.value: w for c, w in p.category_weights.items()} == {
        "discoverability": 0.17, "structured": 0.18, "consistency": 0.15, "actionability": 0.12,
        "trust": 0.08, "ucp": 0.12, "citability": 0.18}
    assert abs(sum(p.category_weights.values()) - 1.0) < 1e-9
    assert p.severity_weights == {"critical": 40, "high": 25, "medium": 14, "low": 6, "info": 2}
    assert p.evidence_min_coverage == 0.60 and p.canonical_min_coverage == 0.85
    assert p.grades == ((90, "A"), (80, "B"), (60, "C"), (0, "D"))
    assert p.badges == ((80, "agent_ready"), (60, "agent_compatible"))
    assert p.gates == (Gate(root_cause_group="agent_access_blocked", effect="badge_block"),)


def test_public_policy_has_no_numeric_cap():
    # Technical Readiness gates are public and badge-only; numeric caps are a
    # host policy decision and never ship in this package.
    assert all(g.effect == "badge_block" and g.cap is None for g in PUBLIC_POLICY.gates)


def test_category_profiles():
    assert PUBLIC_POLICY.category_applies(R2Category.UCP, "commerce")
    assert not PUBLIC_POLICY.category_applies(R2Category.UCP, "blog")
    assert PUBLIC_POLICY.category_applies(R2Category.CITABILITY, "blog")
    assert not PUBLIC_POLICY.category_applies(R2Category.CITABILITY, "commerce")
    assert PUBLIC_POLICY.category_applies(R2Category.TRUST, "anything")


@pytest.mark.parametrize("kw", [
    dict(effect="cap"), dict(effect="cap", cap=101), dict(effect="badge_block", cap=50)])
def test_gate_validation(kw):
    with pytest.raises(ValidationError):
        Gate(root_cause_group="g", **kw)


def test_policy_must_be_complete():
    data = PUBLIC_POLICY.model_dump()
    data["category_weights"].pop(R2Category.UCP)
    with pytest.raises(ValidationError):
        ScoringPolicy(**data)
    data = PUBLIC_POLICY.model_dump()
    data["gates"] = (Gate(root_cause_group="g", effect="badge_block"),) * 2
    with pytest.raises(ValidationError):
        ScoringPolicy(**data)


def test_digest_changes_with_any_value():
    data = PUBLIC_POLICY.model_dump()
    data["severity_weights"] = {**data["severity_weights"], "info": 3}
    assert ScoringPolicy(**data).digest() != PUBLIC_POLICY.digest()


def test_category_profiles_are_normalised_and_sorted():
    data = PUBLIC_POLICY.model_dump()
    data["category_profiles"] = {R2Category.UCP: ("Saas ", "commerce", "booking", "restaurant")}
    p = ScoringPolicy(**data)
    assert p.category_profiles[R2Category.UCP] == ("booking", "commerce", "restaurant", "saas")
    assert p.category_applies(R2Category.UCP, "saas")

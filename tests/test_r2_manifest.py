import pytest
from pydantic import ValidationError

from scovant_core.models import Severity
from scovant_core.r2.manifest import Manifest, RuleScope, RuleSpec, ScoreEffect
from scovant_core.r2.outcome import R2Category


def spec(rule_id="A-1", signal="sig.a", **kw):
    base = dict(rule_id=rule_id, signal=signal, category=R2Category.DISCOVERABILITY,
                severity=Severity.HIGH, scope=RuleScope.DOMAIN)
    base.update(kw)
    return RuleSpec(**base)


def test_duplicate_rule_id_rejected():
    with pytest.raises(ValueError, match="duplicate rule_id"):
        Manifest([spec(), spec(signal="sig.b")])


def test_one_owner_per_signal():
    with pytest.raises(ValueError, match="owned by both"):
        Manifest([spec("A-1", "robots.agents"), spec("B-1", "robots.agents")])


def test_gate_requires_root_cause_group():
    with pytest.raises(ValidationError):
        spec(score_effect=ScoreEffect.GATE)


@pytest.mark.parametrize("bad", ["", "a-1", "A 1", "-A"])
def test_rule_id_shape(bad):
    with pytest.raises(ValidationError):
        spec(rule_id=bad)


def test_empty_signal_rejected():
    with pytest.raises(ValidationError):
        spec(signal="  ")


def test_digest_is_order_independent_and_content_sensitive():
    a, b = spec("A-1", "s1", profiles=("news", "blog")), spec("B-1", "s2")
    m1, m2 = Manifest([a, b]), Manifest([b, a])
    assert m1.digest() == m2.digest()
    assert spec("A-1", "s1", profiles=("blog", "news", "blog")).profiles == ("blog", "news")
    m3 = Manifest([spec("A-1", "s1", profiles=("news", "blog"), severity=Severity.LOW), b])
    assert m3.digest() != m1.digest()


def test_lookup():
    m = Manifest([spec()])
    assert "A-1" in m and "Z-9" not in m
    assert m.get("A-1").signal == "sig.a"


def test_a_root_cause_group_stays_inside_one_category():
    with pytest.raises(ValueError, match="spans categories"):
        Manifest([spec("A-1", "s1", root_cause_group="g"),
                  spec("B-1", "s2", root_cause_group="g", category=R2Category.TRUST)])
    # gate rules may sit anywhere; only weighted rules are merged
    Manifest([spec("A-1", "s1", root_cause_group="g"),
              spec("B-1", "s2", root_cause_group="g", category=R2Category.TRUST,
                   score_effect=ScoreEffect.GATE)])

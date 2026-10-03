"""Wave-2 rules published in Core: the consolidated machine representation."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())
NM = OutcomeState.NOT_MEASURED
MR = {"attempted": True, "status": 200, "content_type": "text/html; charset=utf-8",
      "preference_applied": True, "vary": "Accept", "alternates": []}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["MACHINE-REP-004"] == ("discoverability", "low", "experimental", "domain")
    assert got["MACHINE-REP-005"] == ("discoverability", "low", "experimental", "domain")


def test_findings():
    f, = _rule("MACHINE-REP-004").evaluate({}, {"machine_rep": MR})
    assert f.metadata == {"content_type": "text/html; charset=utf-8", "preference_applied": True}
    assert _rule("MACHINE-REP-004").evaluate({}, {"machine_rep": {**MR, "content_type": "text/markdown"}}) == []
    f, = _rule("MACHINE-REP-005").evaluate({}, {"machine_rep": MR})
    assert f.metadata == {"vary": "Accept"}
    assert _rule("MACHINE-REP-005").evaluate({}, {"machine_rep": {**MR, "vary": "Prefer"}}) == []
    for code in ("MACHINE-REP-004", "MACHINE-REP-005"):
        assert _rule(code).evaluate({}, None) == [] and _rule(code).evaluate({}, {}) == []


def test_measure():
    for code in ("MACHINE-REP-004", "MACHINE-REP-005"):
        r = _rule(code)
        assert r.measure({}, {"machine_rep": MR}, CTX) is None
        assert r.measure({}, {"machine_rep": {**MR, "attempted": False}}, CTX) is NM
        assert r.measure({}, {"machine_rep": {**MR, "status": None}}, CTX) is NM
        assert r.measure({}, {"machine_rep": {**MR, "preference_applied": False}}, CTX) is OutcomeState.NA
        assert r.measure({}, {"machine_rep": {**MR, "status": 500}}, CTX) is OutcomeState.NA
        failed = MeasureCtx(site_category=None, defaulted=frozenset({"machine_rep"}))
        assert r.measure({}, {"machine_rep": MR}, failed) is NM

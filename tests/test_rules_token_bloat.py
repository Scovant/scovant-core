"""Rule published in Core: the page token cost an agent pays (page-scoped)."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.token_bloat import LOW_TOKENS_DEFAULT, MEDIUM_TOKENS_DEFAULT

CTX = MeasureCtx(site_category="commerce", defaulted=frozenset())
ON = {"enabled": True, "low": 8000, "medium": 20000}


def _rule():
    return next(r for r in RULES if r.code == "PAGE_TOKEN_BLOAT")


def _page(total):
    return {"token_cost": {"total": total, "text": total, "skeleton": 0}}


def test_contract_and_public_defaults():
    r = _rule()
    assert (r.category, r.severity, r.maturity, r.scope) == ("structured", "low", "required", "page")
    assert (LOW_TOKENS_DEFAULT, MEDIUM_TOKENS_DEFAULT) == (8000, 20000)


def test_bands_and_page_share():
    r = _rule()
    assert r.evaluate(_page(7999), {"token_bloat_settings": ON}) == []
    f, = r.evaluate(_page(8000), {"token_bloat_settings": ON, "pages_scored": 4})
    assert (f.severity, f.weight_multiplier, f.metadata) == ("low", 0.25, {"token_cost": 8000})
    assert f.description.startswith("This page costs ~8,000 tokens")
    f, = r.evaluate(_page(20000), {"token_bloat_settings": ON})
    assert (f.severity, f.weight_multiplier) == ("medium", 1.0)


def test_host_thresholds_and_their_defaults():
    r = _rule()
    tight = {"token_bloat_settings": {"enabled": True, "low": 10, "medium": 40}}
    f, = r.evaluate(_page(14), tight)
    assert f.severity == "low"
    # an enabled block that omits a threshold takes the public default
    assert r.evaluate(_page(7999), {"token_bloat_settings": {"enabled": True}}) == []
    f, = r.evaluate(_page(20000), {"token_bloat_settings": {"enabled": True}})
    assert f.severity == "medium"


def test_switched_off_or_unconfigured_reports_nothing():
    r = _rule()
    for domain in (None, {}, {"pages_scored": 3}, {"token_bloat_settings": {**ON, "enabled": False}}):
        assert r.evaluate(_page(999_999), domain) == []
    assert r.evaluate({}, {"token_bloat_settings": ON}) == []


def test_measure():
    r = _rule()
    assert r.measure(_page(5), None, CTX) is OutcomeState.NOT_MEASURED
    assert r.measure(_page(5), {"pages_scored": 3}, CTX) is OutcomeState.NA
    assert r.measure(_page(5), {"token_bloat_settings": {**ON, "enabled": False}}, CTX) is OutcomeState.NA
    assert r.measure(_page(5), {"token_bloat_settings": ON}, CTX) is None
    assert r.measure({}, {"token_bloat_settings": ON}, CTX) is OutcomeState.NOT_MEASURED

"""Wave-2 rule published in Core: page crawlability (a page-scoped rule)."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())


def _rule():
    return next(r for r in RULES if r.code == "BLOCKED_CRAWLABILITY")


def test_contract():
    r = _rule()
    assert (r.category, r.severity, r.maturity, r.scope) == ("discoverability", "high", "required", "page")


def test_findings():
    f, = _rule().evaluate({"metadata": {"robots_meta": "NOINDEX, nofollow"}}, None)
    assert f.description == "Page is not accessible to crawlers: noindex directive in robots meta."
    assert f.metadata == {"robots_meta": "NOINDEX, nofollow", "http_status": None}
    f, = _rule().evaluate({"metadata": {}, "http_status": 403}, None)
    assert f.description == "Page is not accessible to crawlers: HTTP status 403."
    assert _rule().evaluate({"metadata": {"robots_meta": "index, follow"}, "http_status": 200}, None) == []
    assert _rule().evaluate({"metadata": None}, None) == []


def test_measure():
    r = _rule()
    assert r.measure({}, None, CTX) is OutcomeState.NOT_MEASURED                       # no page metadata
    assert r.measure({"metadata": {}, "_http_status": 404}, None, CTX) is OutcomeState.NOT_MEASURED
    assert r.measure({"metadata": {}, "_http_status": 200}, None, CTX) is None
    assert r.measure({"metadata": {}}, None, CTX) is None

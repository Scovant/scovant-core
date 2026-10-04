"""Rules published in Core: Content-Signal and sitemap."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())
CS_MALFORMED = {"content_signals": {"present": False, "declared": True, "dimensions": {"ai-train": "maybe"},
                                    "syntax_errors": ["ai-train=maybe", "garbage"]}}
SM_MISSING = {"sitemap": {"exists": False, "valid": False, "url": None}}
SM_INVALID = {"sitemap": {"exists": True, "valid": False, "url": "https://example.com/sitemap.xml"}}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_the_three_rules_are_registered_with_their_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["CONTENT_SIGNALS_ABSENT"] == ("discoverability", "info", "required", "domain")
    assert got["CONTENT-SIGNAL-001"] == ("discoverability", "low", "experimental", "domain")
    assert got["SITEMAP_MISSING_OR_INVALID"] == ("discoverability", "low", "required", "domain")


def test_findings():
    f, = _rule("CONTENT-SIGNAL-001").evaluate({}, CS_MALFORMED)
    assert f.title == "Content-Signal directives are malformed"
    assert list(f.metadata) == ["syntax_errors", "dimensions"]
    assert _rule("CONTENT_SIGNALS_ABSENT").evaluate({}, CS_MALFORMED)[0].title == \
        "No Content-Signal directives in robots.txt"
    missing, = _rule("SITEMAP_MISSING_OR_INVALID").evaluate({}, SM_MISSING)
    invalid, = _rule("SITEMAP_MISSING_OR_INVALID").evaluate({}, SM_INVALID)
    assert missing.description != invalid.description and missing.metadata == {"exists": False, "url": None}
    for code in ("CONTENT_SIGNALS_ABSENT", "CONTENT-SIGNAL-001", "SITEMAP_MISSING_OR_INVALID"):
        assert _rule(code).evaluate({}, None) == [] and _rule(code).evaluate({}, {}) == []


def test_measure():
    for code, key in (("CONTENT_SIGNALS_ABSENT", "content_signals"), ("SITEMAP_MISSING_OR_INVALID", "sitemap"),
                      ("CONTENT-SIGNAL-001", "content_signals")):
        assert _rule(code).measure({}, None, CTX) is OutcomeState.NOT_MEASURED
        failed = MeasureCtx(site_category=None, defaulted=frozenset({key}))
        assert _rule(code).measure({}, {key: {"declared": True}}, failed) is OutcomeState.NOT_MEASURED
    assert _rule("CONTENT-SIGNAL-001").measure({}, {"content_signals": {"declared": False}}, CTX) is OutcomeState.NA
    assert _rule("CONTENT-SIGNAL-001").measure({}, CS_MALFORMED, CTX) is None
    assert _rule("SITEMAP_MISSING_OR_INVALID").measure({}, SM_MISSING, CTX) is None

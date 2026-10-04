"""Rules published in Core: llms.txt, Markdown for agents, Link headers,
content negotiation."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())
NM = OutcomeState.NOT_MEASURED
MD_OK = {"negotiation": True, "mirror": False, "status": 200, "content_type": "text/markdown",
         "vary": "Accept", "looks_markdown": True, "body_looks_markdown": True}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["LLMS_TXT_MISSING_OR_INVALID"] == ("discoverability", "info", "required", "domain")
    assert got["MARKDOWN_FOR_AGENTS_ABSENT"] == ("discoverability", "low", "required", "domain")
    assert got["LINK_HEADERS_ABSENT"] == ("discoverability", "info", "required", "domain")
    assert got["CONTENT-NEG-002"] == ("discoverability", "medium", "experimental", "domain")
    assert got["CONTENT-NEG-004"] == ("discoverability", "low", "experimental", "domain")


def test_llms_txt_fires_on_a_missing_or_invalid_file():
    r = _rule("LLMS_TXT_MISSING_OR_INVALID")
    f, = r.evaluate({}, {"llms_txt": {"exists": True, "valid": False}})
    assert f.title == "llms.txt missing or invalid" and f.metadata == {}
    assert r.evaluate({}, {"llms_txt": {"exists": True, "valid": True}}) == []
    assert r.evaluate({}, None) == []
    # domain evidence without the block still reports (the rule's long-standing reading) ...
    assert len(r.evaluate({}, {"sitemap": {}})) == 1
    # ... but measures nothing
    assert r.measure({}, {"sitemap": {}}, CTX) is NM


def test_markdown_absent_and_link_headers():
    md = _rule("MARKDOWN_FOR_AGENTS_ABSENT")
    assert md.evaluate({}, {"markdown_agents": MD_OK}) == []
    f, = md.evaluate({}, {"markdown_agents": {**MD_OK, "negotiation": False, "status": 404}})
    assert f.title == "No Markdown representation for agents"
    lh = _rule("LINK_HEADERS_ABSENT")
    f, = lh.evaluate({}, {"link_headers": {"present": True, "rels": ["preload"], "agent_relevant": False}})
    assert f.metadata == {"present": True, "rels": ["preload"]}
    assert lh.evaluate({}, {"robots": {}}) == []


def test_content_negotiation_pair():
    neg2, neg4 = _rule("CONTENT-NEG-002"), _rule("CONTENT-NEG-004")
    f, = neg2.evaluate({}, {"markdown_agents": {**MD_OK, "content_type": "text/html"}})
    assert f.metadata == {"content_type": "text/html", "body_looks_markdown": True}
    assert neg2.evaluate({}, {"markdown_agents": MD_OK}) == []
    f, = neg4.evaluate({}, {"markdown_agents": {**MD_OK, "vary": "Origin"}})   # "Accept-Encoding" would contain "accept"
    assert f.metadata == {"vary": "Origin"}
    assert neg4.evaluate({}, {"markdown_agents": MD_OK}) == []


def test_measure():
    md, lh = _rule("MARKDOWN_FOR_AGENTS_ABSENT"), _rule("LINK_HEADERS_ABSENT")
    neg2, neg4 = _rule("CONTENT-NEG-002"), _rule("CONTENT-NEG-004")
    assert md.measure({}, {"markdown_agents": {**MD_OK, "status": None}}, CTX) is NM   # our GET failed
    assert md.measure({}, {"markdown_agents": MD_OK}, CTX) is None
    none_found = {"present": False, "rels": [], "agent_relevant": False}
    assert lh.measure({}, {"link_headers": {**none_found, "fetch_status": "error", "error": "x"}}, CTX) is NM
    assert lh.measure({}, {"link_headers": none_found}, CTX) is None
    assert neg2.measure({}, {"markdown_agents": {**MD_OK, "status": 404}}, CTX) is OutcomeState.NA
    assert neg2.measure({}, {"markdown_agents": {**MD_OK, "body_looks_markdown": None}}, CTX) is NM
    assert neg4.measure({}, {"markdown_agents": {**MD_OK, "content_type": "text/plain"}}, CTX) is OutcomeState.NA
    assert neg4.measure({}, {"markdown_agents": MD_OK}, CTX) is None
    failed = MeasureCtx(site_category=None, defaulted=frozenset({"markdown_agents"}))
    assert neg4.measure({}, {"markdown_agents": MD_OK}, failed) is NM

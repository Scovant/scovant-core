"""Wave-2 rules published in Core: the crawl graph of the sampled pages."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())
GRAPH = {"root": "https://example.com/", "sampled": 6, "root_fallback": False, "pages": {
    "https://example.com/": {"inlinks": 0, "outlinks_in_sample": 3, "outlinks_raw": 3, "depth": 0},
    "https://example.com/a": {"inlinks": 1, "outlinks_in_sample": 1, "outlinks_raw": 1, "depth": 1},
    "https://example.com/a/b/c/d": {"inlinks": 1, "outlinks_in_sample": 0, "outlinks_raw": 0, "depth": 4},
    "https://example.com/a/b/c/d/e": {"inlinks": 1, "outlinks_in_sample": 1, "outlinks_raw": 2, "depth": 5},
    "https://example.com/orphan": {"inlinks": 0, "outlinks_in_sample": 0, "outlinks_raw": 0, "depth": None},
    "https://example.com/z": {"inlinks": 2, "outlinks_in_sample": 2, "outlinks_raw": 4, "depth": 2},
}}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["CRAWL-GRAPH-001"] == ("discoverability", "low", "experimental", "domain")
    assert got["CRAWL-GRAPH-002"] == ("discoverability", "low", "experimental", "domain")
    assert got["CRAWL-GRAPH-005"] == ("discoverability", "info", "experimental", "domain")


def test_findings():
    dd = {"crawl_graph": GRAPH}
    f, = _rule("CRAWL-GRAPH-001").evaluate({}, dd)
    assert f.title == "Orphaned pages within the 6 scanned pages"
    assert f.metadata == {"count": 1, "examples": ["https://example.com/orphan"], "sampled": 6}
    f, = _rule("CRAWL-GRAPH-002").evaluate({}, dd)
    assert f.metadata == {"count": 2, "examples": ["https://example.com/a/b/c/d", "https://example.com/a/b/c/d/e"],
                          "sampled": 6, "max_depth": 5}
    f, = _rule("CRAWL-GRAPH-005").evaluate({}, dd)
    assert f.metadata == {"count": 2, "examples": ["https://example.com/a/b/c/d", "https://example.com/orphan"],
                          "sampled": 6}


def test_examples_are_capped_and_absence_is_silent():
    pages = {"https://example.com/": {"inlinks": 0, "outlinks_raw": 0, "depth": 0}}
    pages.update({f"https://example.com/o{i}": {"inlinks": 0, "outlinks_raw": 1, "depth": None} for i in range(8)})
    f, = _rule("CRAWL-GRAPH-001").evaluate({}, {"crawl_graph": {"root": "https://example.com/", "sampled": 9,
                                                                 "pages": pages}})
    assert f.metadata["count"] == 8 and len(f.metadata["examples"]) == 5
    for code in ("CRAWL-GRAPH-001", "CRAWL-GRAPH-002", "CRAWL-GRAPH-005"):
        assert _rule(code).evaluate({}, None) == [] and _rule(code).evaluate({}, {}) == []


def test_measure():
    for code in ("CRAWL-GRAPH-001", "CRAWL-GRAPH-002", "CRAWL-GRAPH-005"):
        assert _rule(code).measure({}, {"crawl_graph": GRAPH}, CTX) is None
        assert _rule(code).measure({}, {}, CTX) is OutcomeState.NOT_MEASURED
        assert _rule(code).measure({}, None, CTX) is OutcomeState.NOT_MEASURED

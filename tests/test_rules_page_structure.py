"""Rules published in Core: the heading outline and HTML5 landmarks of a
content-bearing page (page-scoped)."""
import pytest

from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.page_structure import MIN_CONTENT_CHARS, page_share

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())
NA, NM = OutcomeState.NA, OutcomeState.NOT_MEASURED
TEXT = "x" * MIN_CONTENT_CHARS
LANDMARKS_NONE = {t: 0 for t in ("main", "article", "nav", "section", "header", "footer", "aside")}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def _h(*levels):
    return [{"level": lv, "text": "t"} for lv in levels]


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["HEADING_HIERARCHY_POOR"] == ("structured", "low", "required", "page")
    assert got["SEMANTIC_HTML_ABSENT"] == ("structured", "info", "required", "page")
    assert MIN_CONTENT_CHARS == 300


@pytest.mark.parametrize(("pages_scored", "share"), [(None, 1.0), (0, 1.0), (4, 0.25), ("4", 0.25)])
def test_page_share(pages_scored, share):
    assert page_share({"pages_scored": pages_scored}) == share
    assert page_share(None) == 1.0


def test_heading_hierarchy():
    r = _rule("HEADING_HIERARCHY_POOR")
    assert r.evaluate({"visible_text": TEXT, "headings": _h("h1", "h2", "h3", "h2")}, None) == []
    f, = r.evaluate({"visible_text": TEXT, "headings": _h("h2", "h4")}, {"pages_scored": 4})
    assert f.metadata == {"defects": ["no <h1> heading", "heading level skip (h2 → h4)"]}
    assert f.weight_multiplier == 0.25 and f.severity is None
    f, = r.evaluate({"visible_text": TEXT, "headings": _h("h1", "h1")}, None)
    assert f.metadata == {"defects": ["multiple <h1> headings (2)"]} and f.weight_multiplier == 1.0
    # only lower-case "hN" levels are read: "H1" and a missing level are skipped
    f, = r.evaluate({"visible_text": TEXT, "headings": [{"level": "H1"}, {"text": "t"}]}, None)
    assert f.metadata == {"defects": ["no <h1> heading"]}
    assert r.evaluate({"visible_text": "short", "headings": _h("h3")}, None) == []


def test_heading_measure():
    r = _rule("HEADING_HIERARCHY_POOR")
    assert r.measure({"visible_text": TEXT, "headings": []}, None, CTX) is None
    assert r.measure({"visible_text": "short", "headings": []}, None, CTX) is NA
    assert r.measure({"visible_text": TEXT}, None, CTX) is NM
    assert r.measure({}, None, CTX) is NM


def test_semantic_html():
    r = _rule("SEMANTIC_HTML_ABSENT")
    f, = r.evaluate({"visible_text": TEXT, "landmark_tags": LANDMARKS_NONE}, {"pages_scored": 2})
    assert f.title == "No semantic HTML5 landmarks" and f.metadata == {} and f.weight_multiplier == 0.5
    assert len(r.evaluate({"visible_text": TEXT, "landmark_tags": {}}, None)) == 1   # empty counts: none found
    assert r.evaluate({"visible_text": TEXT, "landmark_tags": {**LANDMARKS_NONE, "nav": 1}}, None) == []
    assert r.evaluate({"visible_text": TEXT, "landmark_tags": None}, None) == []
    assert r.evaluate({"visible_text": TEXT}, None) == []
    assert r.measure({"visible_text": TEXT, "landmark_tags": {}}, None, CTX) is None
    assert r.measure({"visible_text": TEXT}, None, CTX) is NM
    assert r.measure({"visible_text": "short", "landmark_tags": {}}, None, CTX) is NA

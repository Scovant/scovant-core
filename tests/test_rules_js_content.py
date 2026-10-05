"""Rule published in Core: JS-only critical content."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.js_content import MIN_LABELED_SHARE, MIN_VISIBLE_TEXT_CHARS

CTX = MeasureCtx(site_category="commerce", defaulted=frozenset())
TEXT = "w" * MIN_VISIBLE_TEXT_CHARS


def _rule():
    return next(r for r in RULES if r.code == "JS_ONLY_CRITICAL_CONTENT")


def _page(text=TEXT, product=None, labeled=1, interactive=1, cart=True):
    return {"visible_text": text, "product_data": product,
            "semantic_signals": {"labeled_elements_count": labeled, "interactive_elements_count": interactive,
                                 "add_to_cart_found": cart}}


def test_public_thresholds():
    assert (MIN_VISIBLE_TEXT_CHARS, MIN_LABELED_SHARE) == (100, 0.3)


def test_an_spa_shell():
    finding, = _rule().evaluate(_page(text="w" * 99), None)
    assert "less than 100 characters" in finding.description and finding.metadata == {}
    assert _rule().evaluate(_page(), None) == []
    finding, = _rule().evaluate({}, None)            # nothing extracted at all
    assert "SPA shell" in finding.description


def test_a_product_page_without_add_to_cart_in_static_html():
    finding, = _rule().evaluate(_page(product={"product_name": "W"}, cart=False, labeled=0, interactive=9), None)
    assert "add-to-cart" in finding.description           # the product condition wins over the label share
    assert _rule().evaluate(_page(product=None, cart=False), None) == []


def test_unlabelled_controls():
    finding, = _rule().evaluate(_page(labeled=2, interactive=10), None)
    assert finding.metadata == {"labeled_elements_count": 2, "interactive_elements_count": 10}
    assert _rule().evaluate(_page(labeled=3, interactive=10), None) == []       # exactly the share
    assert _rule().evaluate(_page(labeled=0, interactive=0), None) == []


def test_measure_needs_text_and_signals():
    assert _rule().measure(_page(), None, CTX) is None
    assert _rule().measure({"visible_text": TEXT}, None, CTX) is OutcomeState.NOT_MEASURED
    assert _rule().measure({"semantic_signals": {}}, None, CTX) is OutcomeState.NOT_MEASURED

"""Rule published in Core: how readily AI answer engines can quote a content
page (page-scoped), with its block scorer and term packs."""
import pytest

from scovant_core.r2 import PUBLIC_POLICY, OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.citability import (
    CITABILITY_TYPES,
    MEDIUM_BELOW,
    PASS_MIN,
    POOR_BELOW,
    POOR_CODE,
    WEAK_CODE,
    citability_band,
)
from scovant_core.rules.citability_scorer import page_citability, score_block
from scovant_core.rules.citability_terms import get_pack

BLOG = MeasureCtx(site_category="blog", defaulted=frozenset())
SHOP = MeasureCtx(site_category="commerce", defaulted=frozenset())
WEAK = "Click here now for more. See the page below for all the details you may need today."
FILL = ("Garden beds need steady care in every season. Fresh mulch keeps roots cool in dry summer weeks. "
        "Good soil drains well and holds air for roots. Small tools make light work of weeds in spring.")


def _rule():
    return next(r for r in RULES if r.code == WEAK_CODE)


def _page(text, lang="en", heading=None, canonical=None):
    return {"content_blocks": [{"heading": heading, "text": text, "word_count": len(text.split())}],
            "page_language": lang, "metadata": {"canonical_url": canonical}}


def test_contract_public_bands_and_the_alias():
    r = _rule()
    assert (r.category, r.severity, r.maturity, r.scope, r.aliases) == (
        "citability", "low", "required", "page", (POOR_CODE,))
    assert (PASS_MIN, MEDIUM_BELOW, POOR_BELOW) == (65, 50, 35)
    assert citability_band(65.0) is None and citability_band(100.0) is None
    assert citability_band(64.9) == (WEAK_CODE, "low") and citability_band(50.0) == (WEAK_CODE, "low")
    assert citability_band(49.9) == (WEAK_CODE, "medium") and citability_band(35.0) == (WEAK_CODE, "medium")
    assert citability_band(34.9) == (POOR_CODE, "high") and citability_band(0.0) == (POOR_CODE, "high")


def test_the_site_types_are_the_public_policy_profile():
    profile, = (set(p) for c, p in PUBLIC_POLICY.category_profiles.items() if c.value == "citability")
    assert profile == CITABILITY_TYPES


def test_a_weak_page_is_poor_with_its_share_and_canonical_url():
    f, = _rule().evaluate(_page(WEAK + " " + FILL, canonical="https://example.com/a"),
                          {"site_type": "blog", "content_pages_scored": 4})
    assert (f.code, f.severity, f.weight_multiplier, f.url) == (POOR_CODE, "high", 0.25, "https://example.com/a")
    assert f.metadata == {"page_citability": page_citability(_page(WEAK + " " + FILL)["content_blocks"], "en")}
    assert f.description.startswith(f"Page citability score {f.metadata['page_citability']}/100.")


def test_silent_off_content_sites_without_blocks_or_without_domain():
    r = _rule()
    for site_type in ("commerce", "saas", None, "Blog"):
        assert r.evaluate(_page(WEAK), {"site_type": site_type}) == []
    assert r.evaluate(_page(WEAK), None) == [] and r.evaluate(_page(WEAK), {}) == []
    assert r.evaluate({"content_blocks": []}, {"site_type": "blog"}) == []
    assert r.evaluate({}, {"site_type": "blog"}) == []


def test_the_page_count_defaults_to_one_and_must_be_a_count():
    r = _rule()
    for count in (None, 0):
        f, = r.evaluate(_page(WEAK), {"site_type": "news", "content_pages_scored": count})
        assert f.weight_multiplier == 1.0
    f, = r.evaluate(_page(WEAK), {"site_type": "news", "content_pages_scored": 3})
    assert f.weight_multiplier == 1.0 / 3
    for bad in (-1, 0.5):  # not a page count: a finding cannot carry more than the whole penalty
        with pytest.raises(ValueError):
            r.evaluate(_page(WEAK), {"site_type": "news", "content_pages_scored": bad})


def test_measure():
    r = _rule()
    assert r.measure(_page(WEAK), {"site_type": "blog"}, SHOP) is OutcomeState.NA
    assert r.measure(_page(WEAK), None, BLOG) is OutcomeState.NOT_MEASURED
    assert r.measure(_page(WEAK), {}, BLOG) is OutcomeState.NOT_MEASURED
    assert r.measure({"content_blocks": []}, {"site_type": "blog"}, BLOG) is OutcomeState.NOT_MEASURED
    assert r.measure({}, {"site_type": "blog"}, BLOG) is OutcomeState.NOT_MEASURED
    assert r.measure(_page(WEAK), {"site_type": "blog"}, BLOG) is None


def test_packs_and_language_normalisation():
    assert get_pack("en") is get_pack(" EN ") and get_pack("ru") is get_pack("Ru")
    for lang in (None, "", "de", "en-us", "ja"):
        assert get_pack(lang) is None
    assert get_pack("en")["flesch_coefficients"] == (206.835, 1.015, 84.6)
    assert get_pack("ru")["flesch_coefficients"] == (206.835, 1.3, 60.1)


def test_a_pack_term_moves_the_block_score():
    base = score_block(FILL + " Notes loam loam soil.", None, "en")["total"]
    assert score_block(FILL + " Notes is a soil.", None, "en")["total"] == base + 12.0   # definition
    assert score_block(FILL + " Notes it loam soil.", None, "en")["total"] == base - 4.0  # pronoun
    # without a pack the term is plain text and the pack points leave the maximum
    assert score_block(FILL + " Notes is a soil.", None, None) == score_block(FILL + " Notes loam loam soil.", None, None)


def test_page_score_is_the_mean_of_the_five_best_blocks():
    blocks = [{"heading": None, "text": t} for t in (WEAK, FILL, FILL + " 12% in 2024.", WEAK, WEAK, WEAK)]
    totals = sorted((score_block(b["text"], None, "en")["total"] for b in blocks), reverse=True)[:5]
    assert page_citability(blocks, "en") == round(sum(totals) / 5, 1)
    assert page_citability([], "en") == 0.0

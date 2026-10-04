"""Rules published in Core: product and offer structured data (page-scoped)."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

SHOP = MeasureCtx(site_category="commerce", defaulted=frozenset())
BLOG = MeasureCtx(site_category="blog", defaulted=frozenset())
NA, NM = OutcomeState.NA, OutcomeState.NOT_MEASURED
OFFER = {"@type": "Offer", "price": "29.99", "priceCurrency": "USD",
         "availability": "https://schema.org/InStock"}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def _page(*entities, **extra):
    return {"schema_org": list(entities), **extra}


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["MISSING_PRODUCT_SCHEMA"] == ("structured", "high", "required", "page")
    assert got["MISSING_OFFER_DATA"] == ("structured", "high", "required", "page")
    assert got["PRICE_MISSING_INVALID"] == ("structured", "critical", "required", "page")
    assert got["MISSING_AVAILABILITY"] == ("structured", "critical", "required", "page")


def test_missing_product_schema():
    r = _rule("MISSING_PRODUCT_SCHEMA")
    f, = r.evaluate({}, None)                       # no extraction at all still reports
    assert f.title == "Missing Product schema" and f.metadata == {} and f.example.startswith("<script")
    assert r.evaluate(_page({"@type": "Product", "name": "Widget"}), None) == []
    assert r.evaluate(_page({"@graph": [{"@type": "Product"}]}), None) == []


def test_missing_product_schema_is_measured_on_product_pages_only():
    r = _rule("MISSING_PRODUCT_SCHEMA")
    listing = _page(semantic_signals={"add_to_cart_found": False}, visible_text="Our story")
    assert r.measure(listing, None, SHOP) is NA
    assert r.measure({**listing, "semantic_signals": {"add_to_cart_found": True}}, None, SHOP) is None
    assert r.measure({**listing, "visible_text": "Produkt. In den Warenkorb"}, None, SHOP) is None
    assert r.measure(_page({"@type": "Product"}), None, SHOP) is None
    assert r.measure(_page(), None, SHOP) is NM          # no semantic signals recorded
    assert r.measure({}, None, SHOP) is NM               # no schema extraction
    assert r.measure(listing, None, BLOG) is NA          # a site that never transacts


def test_missing_offer_data():
    r = _rule("MISSING_OFFER_DATA")
    f, = r.evaluate(_page({"@type": "Product", "name": "Widget"}), None)
    assert f.description == "Product entity found but no Offer data is present."
    assert r.evaluate(_page({"@type": "Product", "offers": OFFER}), None) == []
    assert r.evaluate(_page(), None) == []
    assert r.measure(_page(), None, SHOP) is NA
    assert r.measure(_page({"@type": "Product"}), None, SHOP) is None
    assert r.measure({}, None, SHOP) is NM


def test_price_missing_or_invalid():
    r = _rule("PRICE_MISSING_INVALID")
    f, = r.evaluate(_page({"@type": "Product", "offers": [OFFER, {**OFFER, "price": "$5"}]}), None)
    assert f.metadata == {"price": "$5"}
    f, = r.evaluate(_page({"@type": "Product", "offers": {"@type": "Offer"}}), None)
    assert f.metadata == {"price": "None"}
    assert r.evaluate(_page({"@type": "Product", "offers": {**OFFER, "price": 12}}), None) == []
    assert r.evaluate(_page({"@type": "Product"}), None) == []        # no offers: another rule's finding
    assert r.measure(_page({"@type": "Product"}), None, SHOP) is NA
    assert r.measure(_page({"@type": "Product", "offers": OFFER}), None, SHOP) is None


def test_missing_availability():
    r = _rule("MISSING_AVAILABILITY")
    no_stock = {k: v for k, v in OFFER.items() if k != "availability"}
    f, = r.evaluate(_page({"@type": "Product", "offers": no_stock}), None)
    assert f.title == "Availability missing from Offer" and f.metadata == {}
    assert r.evaluate(_page({"@type": "Product", "offers": OFFER}), None) == []
    assert r.measure(_page({"@type": "Product", "offers": OFFER}), None, BLOG) is NA


def test_the_commerce_gate_is_measure_only():
    """The site type never changes a finding — only whether the rule measured."""
    page = _page({"@type": "Product", "offers": {"@type": "Offer", "price": "0"}})
    for code in ("PRICE_MISSING_INVALID", "MISSING_AVAILABILITY"):
        r = _rule(code)
        assert len(r.evaluate(page, None)) == 1
        assert r.measure(page, None, BLOG) is NA
        for site_type in ("commerce", "other", None):
            assert r.measure(page, None, MeasureCtx(site_category=site_type, defaulted=None)) is None


def test_variant_info_missing():
    r = _rule("VARIANT_INFO_MISSING")
    assert (r.category, r.severity, r.maturity, r.scope) == ("structured", "medium", "required", "page")
    two_offers = {"@type": "Product", "offers": [OFFER, {**OFFER, "price": "31.99"}]}
    f, = r.evaluate(_page(two_offers, visible_text="Widget"), None)
    assert f.title == "Variant information missing from structured data" and f.metadata == {}
    one_offer = {"@type": "Product", "offers": OFFER}
    assert len(r.evaluate(_page(one_offer, visible_text="Pick a Colour"), None)) == 1
    assert r.evaluate(_page(one_offer, visible_text="Widget"), None) == []
    assert r.evaluate(_page({**two_offers, "hasVariant": [{"@type": "Product"}]}), None) == []
    assert r.evaluate(_page({**two_offers, "additionalProperty": [{"name": "size"}]}), None) == []
    assert r.measure(_page(one_offer, visible_text=""), None, SHOP) is None
    assert r.measure(_page(visible_text="Size M"), None, SHOP) is NA      # no product
    assert r.measure(_page(one_offer), None, SHOP) is NM                   # no visible text recorded
    assert r.measure(_page(one_offer, visible_text=""), None, BLOG) is NA

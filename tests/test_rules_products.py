"""Product and Offer helpers, the commerce gate and the product-page
vocabulary shared by the structured-data and consistency rules."""
from scovant_core.rules.product_terms import (
    ADD_TO_CART_TERMS,
    PRODUCT_PAGE_TERMS,
    mentions_add_to_cart,
)
from scovant_core.rules.products import (
    COMMERCE_GATED_CODES,
    NON_TRANSACTING_SITE_TYPES,
    PROFILE_POLICY_ID,
    UNKNOWN_SITE_TYPE,
    commerce_gated,
    extract_visible_price,
    find_products,
    get_offers,
    is_valid_price,
    mentions_variant_keywords,
    normalize_price,
    schema_offer_price,
)

PRODUCT = {"@type": "Product", "name": "Widget", "offers": {"@type": "Offer", "price": "29.99"}}


def test_find_products_reads_top_level_and_graph_entities():
    graph = {"@graph": [PRODUCT, "not-an-entity", {"@type": "Organization"}]}
    assert find_products([PRODUCT, {"@type": "WebPage"}]) == [PRODUCT]
    assert find_products([graph]) == [PRODUCT]
    assert find_products([]) == []


def test_only_the_exact_product_type_is_a_product():
    # A list-valued or namespaced @type is not read as a Product.
    assert find_products([{"@type": ["Product", "Thing"]}]) == []
    assert find_products([{"@type": "schema:Product"}]) == []


def test_get_offers_accepts_a_dict_or_a_list_and_nothing_else():
    assert get_offers({"offers": {"price": "1"}}) == [{"price": "1"}]
    assert get_offers({"offers": [{"price": "1"}, {"price": "2"}]}) == [{"price": "1"}, {"price": "2"}]
    assert get_offers({}) == []
    assert get_offers({"offers": "29.99"}) == []


def test_is_valid_price():
    assert is_valid_price("29.99") and is_valid_price(5) and is_valid_price(0.5)
    for bad in (None, "0", 0, -1, "$29.99", "free", "", [], {}):
        assert not is_valid_price(bad), bad


def test_visible_and_structured_prices():
    assert extract_visible_price("Was $45, now $39.00") == "45"
    assert extract_visible_price("Price: €39.00") is None
    # a thousands separator ends the match: "$1,299.00" reads as "1"
    assert extract_visible_price("Only $1,299.00") == "1"
    assert schema_offer_price([PRODUCT]) == "29.99"
    assert schema_offer_price([{"@type": "Product", "offers": {"price": 19}}]) == "19"
    assert schema_offer_price([{"@type": "Product"}]) is None
    assert schema_offer_price([]) is None
    assert normalize_price("39.00") == 39.0
    assert normalize_price("abc") is None


def test_variant_keywords():
    assert mentions_variant_keywords("Choose a SIZE")
    assert not mentions_variant_keywords("One widget")


def test_commerce_gate():
    gated = {"MISSING_PRODUCT_SCHEMA", "MISSING_OFFER_DATA", "PRICE_MISSING_INVALID",
             "MISSING_AVAILABILITY", "VARIANT_INFO_MISSING", "PRICE_MISMATCH",
             "MISSING_RETURNS_POLICY", "SHIPPING_INFO_UNAVAILABLE"}
    assert gated == COMMERCE_GATED_CODES
    assert commerce_gated("PRICE_MISMATCH", "blog")
    assert commerce_gated("MISSING_PRODUCT_SCHEMA", "saas")
    for site_type in ("commerce", "restaurant", "booking", "other", None, "unheard-of"):
        assert not commerce_gated("PRICE_MISMATCH", site_type), site_type
    # applicability-2026.10.1: an UNESTABLISHED profile measures nothing for the
    # commerce-gated rules — "unknown" is not "may transact" (an unlisted type is)
    for code in COMMERCE_GATED_CODES:
        assert commerce_gated(code, UNKNOWN_SITE_TYPE), code
    assert not commerce_gated("HEADING_HIERARCHY_POOR", UNKNOWN_SITE_TYPE)
    assert UNKNOWN_SITE_TYPE not in NON_TRANSACTING_SITE_TYPES   # a separate outcome, not "never transacts"


def test_profile_policy_id_is_pinned():
    assert PROFILE_POLICY_ID == "applicability-2026.10.1"


def test_unknown_profile_measures_gated_rules_as_not_applicable():
    from scovant_core.r2 import OutcomeState
    from scovant_core.rules import RULES, MeasureCtx

    page = {"schema_org": [{"@type": "Product", "name": "Mug",
                            "offers": {"@type": "Offer", "price": "12.00", "priceCurrency": "USD"}}],
            "visible_text": "Price $12.00 Size M", "policy_links": {}, "product_data": {}}
    ctx = MeasureCtx(site_category=UNKNOWN_SITE_TYPE, defaulted=frozenset())
    gated = [r for r in RULES if r.code in COMMERCE_GATED_CODES]
    assert len(gated) == len(COMMERCE_GATED_CODES)
    for rule in gated:
        assert rule.measure(page, {}, ctx) == OutcomeState.NA, rule.code
    assert not commerce_gated("HEADING_HIERARCHY_POOR", "blog")
    assert "blog" in NON_TRANSACTING_SITE_TYPES and "commerce" not in NON_TRANSACTING_SITE_TYPES


def test_product_page_vocabulary():
    assert len(ADD_TO_CART_TERMS) == 30 and next(iter(ADD_TO_CART_TERMS)) == "en"
    assert list(PRODUCT_PAGE_TERMS) == sorted(PRODUCT_PAGE_TERMS)
    assert all(t == t.lower() and len(t) >= 3 for t in PRODUCT_PAGE_TERMS)
    assert "购买" not in PRODUCT_PAGE_TERMS            # two characters: too short to match on
    for text in ("Товар. В корзину", "Produkt In den Warenkorb", "Ajouter au panier", "ADD TO BAG"):
        assert mentions_add_to_cart(text), text
    assert not mentions_add_to_cart("A short story about bicycles")


def test_find_products_and_get_offers_read_malformed_schema_as_nothing():
    # `schema_org: None` is what a producer writes for "not extracted"; a
    # non-object entity or offer entry is page-published JSON-LD.
    assert find_products(None) == []
    assert find_products("Product") == []
    assert find_products([None, "Product", 7, PRODUCT]) == [PRODUCT]
    assert find_products([{"@graph": 5}, {"@graph": {"@type": "Product"}}]) == []
    assert get_offers({"offers": [{"price": "1"}, "2", None]}) == [{"price": "1"}]
    assert get_offers({"offers": None}) == []

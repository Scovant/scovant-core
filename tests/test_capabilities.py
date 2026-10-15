# backend/scovant-core/tests/test_capabilities.py
from scovant_core.capabilities import CODE_FLAG, FLAGS, TYPE_DEFAULTS, derive_capabilities, gate
from scovant_core.parsers.html import (
    extract_product_data,
    extract_schema_org,
    extract_semantic_signals,
)
from scovant_core.r2 import OutcomeState
from scovant_core.rules.products import COMMERCE_GATED_CODES

PRODUCT_HTML = ('<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product",'
                '"name":"Mug","offers":{"@type":"Offer","price":"9.00","priceCurrency":"USD"}}</script>')
MENTION_HTML = '<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Mug"}</script>'
SHIP_HTML = ('<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Mug",'
             '"offers":{"@type":"Offer","price":"9","shippingDetails":{"@type":"OfferShippingDetails"}}}</script>')
CART_HTML = '<button>Add to cart</button>'

def page(html, **extra):
    schema = extract_schema_org(html)
    return {"schema_org": schema, "product_data": extract_product_data(schema),
            "semantic_signals": extract_semantic_signals(html), **extra}

def test_map_covers_exactly_the_gated_codes():
    assert set(CODE_FLAG) == set(COMMERCE_GATED_CODES) | {"UCP_CHECKOUT_MISSING", "AGENT_PAYMENTS_ABSENT"}
    assert set(CODE_FLAG.values()) == set(FLAGS)

def test_booking_defaults_and_gate_reason():
    caps = derive_capabilities("booking", [page("<p>rooms</p>")], {})
    assert caps.physical_goods.value is False and caps.physical_goods.source == "type_default"
    assert gate("SHIPPING_INFO_UNAVAILABLE", caps) == (OutcomeState.NA, "capability_absent:physical_goods")
    assert gate("UCP_CHECKOUT_MISSING", caps) is None  # booking checks out

def test_other_is_not_established():
    caps = derive_capabilities("other", [page("<p>hi</p>")], {})
    assert gate("MISSING_PRODUCT_SCHEMA", caps) == (OutcomeState.NA, "capability_not_established:product_catalog")
    assert caps.product_catalog.source == "unknown"

def test_saas_seller_evidence_overrides_default():
    caps = derive_capabilities("saas", [page(PRODUCT_HTML)], {})
    assert caps.product_catalog.value is True and caps.product_catalog.source == "evidence"
    assert gate("MISSING_PRODUCT_SCHEMA", caps) is None
    assert caps.physical_goods.value is False  # no shipping evidence

def test_add_to_cart_is_catalog_evidence():
    assert derive_capabilities("media", [page(CART_HTML)], {}).product_catalog.value is True

BUY_NOW_HTML = '<a href="/pricing">Buy now</a>'


def test_a_saas_call_to_action_alone_is_not_catalog_evidence():
    # 0.20.1: on a SaaS site "Buy now" / "Add to cart" sells a licence or a
    # subscription (SoftwareApplication, not Product); 57 SaaS homepages failed
    # MISSING_PRODUCT_SCHEMA on that button alone after 0.20.0.
    for html in (BUY_NOW_HTML, CART_HTML):
        caps = derive_capabilities("saas", [page(html)], {})
        assert caps.product_catalog.value is False and caps.product_catalog.source == "type_default"
        assert gate("MISSING_PRODUCT_SCHEMA", caps) == (OutcomeState.NA, "capability_absent:product_catalog")
    # real Product/Offer data still establishes it, button or not
    caps = derive_capabilities("saas", [page(BUY_NOW_HTML + PRODUCT_HTML)], {})
    assert caps.product_catalog.value is True and caps.product_catalog.evidence[0].startswith("product_offer:")


def test_other_types_keep_the_call_to_action_as_catalog_evidence():
    for t in ("media", "booking", "restaurant", "other", None):
        assert derive_capabilities(t, [page(BUY_NOW_HTML)], {}).product_catalog.value is True, t


def test_product_mention_without_offer_is_not_evidence():
    assert derive_capabilities("blog", [page(MENTION_HTML)], {}).product_catalog.value is False

def test_shipping_schema_is_physical_evidence():
    caps = derive_capabilities("saas", [page(SHIP_HTML)], {})
    assert caps.physical_goods.value is True and caps.physical_goods.source == "evidence"

def test_walled_page_gives_no_evidence():
    caps = derive_capabilities("saas", [page(PRODUCT_HTML, content_blocked=True)], {})
    assert caps.product_catalog.value is False and caps.product_catalog.source == "type_default"

def test_no_pages_keeps_defaults():
    caps = derive_capabilities("commerce", [], None)
    assert all(getattr(caps, f).source == "type_default" for f in FLAGS)
    caps = derive_capabilities("unknown", [], None)
    assert all(getattr(caps, f).value is None and getattr(caps, f).source == "unknown" for f in FLAGS)

def test_absence_never_sets_false_on_unknown():
    caps = derive_capabilities("unknown", [page("<p>nothing to sell</p>")] * 5, {})
    assert caps.physical_goods.value is None

def test_checkout_evidence_from_domain():
    caps = derive_capabilities("saas", [], {"ucp": {"exists": True, "valid": True, "has_checkout": True}})
    assert caps.transactional_checkout.value is True
    caps = derive_capabilities("saas", [], {"agent_payments": {"any_non_ucp": True, "protocols": {}}})
    assert caps.transactional_checkout.value is True

def test_unlisted_type_and_none_are_unknown():
    for st in ("spaceship", None):
        assert derive_capabilities(st, [], {}).product_catalog.source == "unknown"

def test_round_trip_and_evidence_cap():
    caps = derive_capabilities("saas", [page(PRODUCT_HTML)] * 6, {})
    d = caps.to_dict()
    assert len(d["product_catalog"]["evidence"]) <= 3
    assert type(caps).from_dict(d) == caps
    assert type(caps).from_dict(None) is None

def test_defaults_table_is_the_spec_table():
    assert TYPE_DEFAULTS["commerce"] == (True, True, True)
    assert TYPE_DEFAULTS["booking"] == TYPE_DEFAULTS["restaurant"] == (False, False, True)
    assert TYPE_DEFAULTS["saas"] == (False, False, None)
    for t in ("blog", "news", "docs", "documentation", "media", "portfolio", "education", "real_estate"):
        assert TYPE_DEFAULTS[t] == (False, False, False)
    assert "other" not in TYPE_DEFAULTS and "unknown" not in TYPE_DEFAULTS

"""Rules published in Core: returns policy, shipping information and OpenGraph meta."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.products import COMMERCE_GATED_CODES, NON_TRANSACTING_SITE_TYPES
from scovant_core.rules.trust import has_structured_shipping

NM, NA = OutcomeState.NOT_MEASURED, OutcomeState.NA
CTX = MeasureCtx(site_category="commerce", defaulted=frozenset())
LINKS = {"returns_policy_url": "https://example.com/returns", "shipping_policy_url": "https://example.com/shipping",
         "privacy_policy_url": None, "terms_url": None}
NO_LINKS = dict.fromkeys(LINKS)
SHIPPING = {"@type": "OfferShippingDetails"}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_the_three_rules():
    for code in ("MISSING_RETURNS_POLICY", "SHIPPING_INFO_UNAVAILABLE", "MISSING_OG_META_FOR_CITATION"):
        rule = _rule(code)
        assert (rule.scope, rule.category, rule.severity, rule.maturity, rule.rule_version) == \
            ("page", "trust", "medium", "required", "1.0"), code


def test_returns_policy():
    rule = _rule("MISSING_RETURNS_POLICY")
    finding, = rule.evaluate({"policy_links": NO_LINKS}, None)
    assert finding.title == "Return policy unavailable" and finding.metadata == {}
    assert finding.description == "No returns or refund policy page was found or linked."
    assert finding.example.startswith("// Attach a MerchantReturnPolicy")
    assert rule.evaluate({"policy_links": LINKS}, None) == []
    # a link was found: the rule does not judge an empty href
    assert rule.evaluate({"policy_links": {**NO_LINKS, "returns_policy_url": ""}}, None) == []
    assert len(rule.evaluate({}, None)) == 1 and len(rule.evaluate({"policy_links": None}, None)) == 1


def test_shipping_information():
    rule = _rule("SHIPPING_INFO_UNAVAILABLE")
    finding, = rule.evaluate({"policy_links": NO_LINKS, "schema_org": []}, None)
    assert finding.description == "No shipping policy page link and no structured shipping data found."
    assert finding.metadata == {}
    assert rule.evaluate({"policy_links": LINKS, "schema_org": []}, None) == []
    offer = {"@type": "Product", "offers": {"@type": "Offer", "shippingDetails": SHIPPING}}
    assert rule.evaluate({"policy_links": NO_LINKS, "schema_org": [offer]}, None) == []
    assert len(rule.evaluate({"policy_links": NO_LINKS, "schema_org": None}, None)) == 1


def test_structured_shipping():
    assert has_structured_shipping([{"offers": {"shippingDetails": SHIPPING}}])
    assert has_structured_shipping([{"offers": [{"price": "1"}, {"shippingDetails": SHIPPING}]}])
    assert has_structured_shipping([{"@type": "Product"}, {"@type": "Service", "offers": {"shippingDetails": SHIPPING}}])
    assert has_structured_shipping([{"offers": ["free", {"shippingDetails": SHIPPING}]}])
    assert not has_structured_shipping([{"offers": {"shippingDetails": {}}}])        # empty details
    assert not has_structured_shipping([{"offers": "29.99"}, {"name": "no offers"}])
    assert not has_structured_shipping([])


def test_opengraph_meta():
    rule = _rule("MISSING_OG_META_FOR_CITATION")
    both = {"og_title": None, "og_description": None, "og_image": None, "og_url": None}
    finding, = rule.evaluate({"og_meta": both}, None)
    assert finding.metadata == {"missing_fields": ["og:title", "og:description"]}
    assert finding.description == "Required OpenGraph fields are missing: og:title, og:description."
    finding, = rule.evaluate({"og_meta": {**both, "og_title": "Widget"}}, None)
    assert finding.metadata == {"missing_fields": ["og:description"]}
    # an empty content attribute is present
    assert rule.evaluate({"og_meta": {**both, "og_title": "", "og_description": " "}}, None) == []
    assert rule.evaluate({}, None) == [] and rule.evaluate({"og_meta": None}, None) == []
    assert len(rule.evaluate({"og_meta": {}}, None)) == 1


def test_measure_asks_for_presence_not_truthiness():
    returns, shipping, og = (_rule(c) for c in ("MISSING_RETURNS_POLICY", "SHIPPING_INFO_UNAVAILABLE",
                                                 "MISSING_OG_META_FOR_CITATION"))
    assert returns.measure({}, None, CTX) is NM                       # recorded before the field existed
    assert returns.measure({"policy_links": None}, None, CTX) is None
    assert returns.measure({"policy_links": {}}, None, CTX) is None
    assert shipping.measure({"policy_links": NO_LINKS}, None, CTX) is NM   # schema never extracted
    assert shipping.measure({"policy_links": NO_LINKS, "schema_org": []}, None, CTX) is None
    assert og.measure({}, None, CTX) is NM and og.measure({"og_meta": None}, None, CTX) is NM
    assert og.measure({"og_meta": {}}, None, CTX) is None


def test_the_commerce_gate():
    page = {"policy_links": NO_LINKS, "schema_org": [], "og_meta": {"og_title": None}}
    assert {"MISSING_RETURNS_POLICY", "SHIPPING_INFO_UNAVAILABLE"} <= COMMERCE_GATED_CODES
    for site_type in NON_TRANSACTING_SITE_TYPES:
        ctx = MeasureCtx(site_category=site_type, defaulted=frozenset())
        assert _rule("MISSING_RETURNS_POLICY").measure(page, None, ctx) is NA
        assert _rule("SHIPPING_INFO_UNAVAILABLE").measure(page, None, ctx) is NA
        assert _rule("MISSING_OG_META_FOR_CITATION").measure(page, None, ctx) is None   # not gated
    for site_type in ("commerce", "booking", "other", None):
        ctx = MeasureCtx(site_category=site_type, defaulted=frozenset())
        assert _rule("MISSING_RETURNS_POLICY").measure(page, None, ctx) is None
    # the findings do not depend on the site type: a host decides whether to keep them
    assert len(_rule("MISSING_RETURNS_POLICY").evaluate(page, {"site_type": "blog"})) == 1

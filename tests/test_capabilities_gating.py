from scovant_core.capabilities import CODE_FLAG
from scovant_core.models import Severity
from scovant_core.parsers.html import (
    extract_policy_links,
    extract_product_data,
    extract_schema_org,
    extract_semantic_signals,
)
from scovant_core.r2 import PUBLIC_POLICY, OutcomeState, RuleScope, model_id
from scovant_core.r2.evaluate import technical_readiness
from scovant_core.r2.manifest import Manifest, RuleSpec
from scovant_core.r2.outcome import R2Category
from scovant_core.r2.technical import technical_manifest
from scovant_core.rules import RULES, MeasureCtx

PRODUCT_HTML = ('<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product",'
                '"name":"Mug","offers":{"@type":"Offer","price":"9.00","priceCurrency":"USD"}}</script>')
PLAIN_HTML = "<html><body><p>Rooms and rates</p><a href='/about'>About</a></body></html>"
S = OutcomeState


def page(html):
    schema = extract_schema_org(html)
    return {"_http_status": 200, "schema_org": schema, "product_data": extract_product_data(schema),
            "semantic_signals": extract_semantic_signals(html), "visible_text": "Rooms and rates",
            "policy_links": extract_policy_links(html, "https://example.com/"), "headings": []}


def outcomes(site_type, html):
    run = technical_readiness([page(html)], {}, site_type=site_type, defaulted=None)
    return {o.rule_id: o for o in run.outcomes}


def test_booking_gates_shipping_and_returns():
    o = outcomes("booking", PLAIN_HTML)
    for code in ("SHIPPING_INFO_UNAVAILABLE", "MISSING_RETURNS_POLICY"):
        assert (o[code].state, o[code].reason) == (S.NA, "capability_absent:physical_goods")


def test_commerce_same_page_fails():
    o = outcomes("commerce", PLAIN_HTML)
    assert o["SHIPPING_INFO_UNAVAILABLE"].state == S.FAIL
    assert o["MISSING_RETURNS_POLICY"].state == S.FAIL


def test_saas_with_product_evidence_is_measured():
    o = outcomes("saas", PRODUCT_HTML)
    assert o["MISSING_OFFER_DATA"].state in (S.PASS, S.FAIL)


def test_unknown_gates_every_commerce_code_with_flag_reason():
    o = outcomes("unknown", PLAIN_HTML)
    for code, flag in CODE_FLAG.items():
        if code in o:
            assert o[code].state == S.NA and o[code].reason == f"capability_not_established:{flag}", code


def test_technical_run_carries_capabilities():
    run = technical_readiness([page(PLAIN_HTML)], {}, site_type="booking", defaulted=None)
    assert run.capabilities.physical_goods.value is False


def _two():
    a = RuleSpec(rule_id="A-1", signal="s:a", category=R2Category.DISCOVERABILITY,
                 severity=Severity.HIGH, scope=RuleScope.DOMAIN)
    b = RuleSpec(rule_id="B-1", signal="s:b", category=R2Category.DISCOVERABILITY,
                 severity=Severity.LOW, scope=RuleScope.PAGE)
    return [a, b]


def test_manifest_digest_without_applicability_is_unchanged():
    assert Manifest(_two()).digest() == "0189d1b89271"  # computed on BASE ac090a67


def test_applicability_changes_the_digest():
    assert Manifest(_two(), applicability="x").digest() != Manifest(_two()).digest()


def test_technical_model_id_moved():
    assert model_id(technical_manifest(), PUBLIC_POLICY) != "R2.1@67df90af85b0"


def test_legacy_measure_without_capabilities_still_gates_by_type():
    ctx = MeasureCtx(site_category="saas", defaulted=None)
    assert ctx.capabilities is None
    for code in ("MISSING_RETURNS_POLICY", "SHIPPING_INFO_UNAVAILABLE", "MISSING_OFFER_DATA"):
        rule = next(r for r in RULES if r.code == code)
        assert rule.measure(page(PRODUCT_HTML), {}, ctx) == S.NA, code
    for code in ("UCP_CHECKOUT_MISSING", "AGENT_PAYMENTS_ABSENT"):
        rule = next(r for r in RULES if r.code == code)
        assert rule.measure({}, {"ucp": {"exists": True, "valid": True}}, ctx) == S.NA, code

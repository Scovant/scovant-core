"""Rules published in Core: the UCP profile and agent payments."""
from scovant_core.r2 import PUBLIC_POLICY, OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.ucp import UCP_APPLICABLE_SITE_TYPES, UCP_CHECKOUT_SITE_TYPES

NM, NA = OutcomeState.NOT_MEASURED, OutcomeState.NA
CTX = MeasureCtx(site_category="commerce", defaulted=frozenset())
VALID = {"exists": True, "valid": True, "validation_errors": [], "capabilities": ["dev.ucp.commerce.order"],
         "has_checkout": False, "signing_keys_valid": False}
ABSENT = {"exists": False, "valid": False, "validation_errors": []}
NO_PAYMENTS = {"any_non_ucp": False, "protocols": {"l402": {}, "x402": {}}, "fetch_status": "ok"}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_the_ucp_site_types_are_the_published_ucp_profile():
    ucp_profile, = (set(p) for c, p in PUBLIC_POLICY.category_profiles.items() if c.value == "ucp")
    assert ucp_profile == UCP_APPLICABLE_SITE_TYPES
    assert UCP_CHECKOUT_SITE_TYPES < UCP_APPLICABLE_SITE_TYPES
    assert "saas" not in UCP_CHECKOUT_SITE_TYPES


def test_profile_absent():
    rule = _rule("UCP_PROFILE_ABSENT")
    finding, = rule.evaluate({}, {"site_type": "saas", "ucp": ABSENT})
    assert finding.metadata == {"site_type": "saas"}
    assert rule.evaluate({}, {"site_type": "blog", "ucp": ABSENT}) == []
    assert rule.evaluate({}, {"site_type": "saas", "ucp": {**ABSENT, "exists": True}}) == []
    assert rule.measure({}, {"ucp": ABSENT}, MeasureCtx("blog", frozenset())) is NA
    assert rule.measure({}, {"ucp": ABSENT}, MeasureCtx("commerce", frozenset({"ucp"}))) is NM


def test_profile_invalid():
    rule = _rule("UCP_PROFILE_INVALID")
    errors = [f"e{i}" for i in range(7)]
    finding, = rule.evaluate({}, {"ucp": {"exists": True, "valid": False, "validation_errors": errors}})
    assert "First errors: e0; e1; e2; e3; e4." in finding.description
    assert finding.metadata == {"validation_errors": errors}
    finding, = rule.evaluate({}, {"ucp": {"exists": True, "valid": False}})
    assert "none reported" in finding.description
    assert rule.measure({}, {"ucp": ABSENT}, CTX) is NA


def test_checkout_and_signing_keys_need_a_valid_profile():
    checkout, keys = _rule("UCP_CHECKOUT_MISSING"), _rule("UCP_SIGNING_KEYS_INVALID")
    finding, = checkout.evaluate({}, {"site_type": "booking", "ucp": VALID})
    assert finding.metadata == {"site_type": "booking", "declared_capabilities": ["dev.ucp.commerce.order"]}
    assert checkout.evaluate({}, {"site_type": "saas", "ucp": VALID}) == []
    finding, = keys.evaluate({}, {"ucp": VALID})
    assert finding.metadata == {}
    broken = {**VALID, "valid": False}
    assert checkout.evaluate({}, {"site_type": "commerce", "ucp": broken}) == []
    assert keys.evaluate({}, {"ucp": broken}) == []
    assert checkout.measure({}, {"ucp": broken}, CTX) is NA and keys.measure({}, {"ucp": broken}, CTX) is NA
    assert checkout.measure({}, {"ucp": VALID}, MeasureCtx("saas", frozenset())) is NA
    assert keys.measure({}, {"ucp": VALID}, MeasureCtx("saas", frozenset())) is None


def test_agent_payments_only_beside_a_published_profile():
    rule = _rule("AGENT_PAYMENTS_ABSENT")
    finding, = rule.evaluate({}, {"site_type": "restaurant", "ucp": VALID, "agent_payments": NO_PAYMENTS})
    assert finding.metadata == {"probed": ["l402", "x402"]}
    assert rule.evaluate({}, {"site_type": "restaurant", "ucp": ABSENT, "agent_payments": NO_PAYMENTS}) == []
    assert rule.evaluate({}, {"site_type": "saas", "ucp": VALID, "agent_payments": NO_PAYMENTS}) == []
    found = {**NO_PAYMENTS, "any_non_ucp": True}
    assert rule.evaluate({}, {"site_type": "commerce", "ucp": VALID, "agent_payments": found}) == []
    dd = {"ucp": VALID, "agent_payments": NO_PAYMENTS}
    assert rule.measure({}, dd, CTX) is None
    assert rule.measure({}, {**dd, "ucp": ABSENT}, CTX) is NA
    assert rule.measure({}, dd, MeasureCtx("commerce", frozenset({"agent_payments"}))) is NM


def test_a_payment_probe_that_never_got_an_answer_is_not_measured():
    """Core's own scan records no `defaulted` list: `fetch_status` says absence
    was not established."""
    failed = {**NO_PAYMENTS, "fetch_status": "error", "error": "ConnectError"}
    rule = _rule("AGENT_PAYMENTS_ABSENT")
    assert rule.measure({}, {"ucp": VALID, "agent_payments": failed}, MeasureCtx("commerce", None)) is NM

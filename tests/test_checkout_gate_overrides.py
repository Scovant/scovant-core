"""M-5: the checkout gate honours owner capability overrides carried in the
domain evidence (`capability_overrides`) when the host passed no derived
capabilities. Profiles come from the real parser over vendored fixtures."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from scovant_core.capabilities import FLAGS, apply_capability_overrides, derive_capabilities
from scovant_core.parsers.ucp import check_ucp_profile
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

FIXTURES = Path(__file__).parent / "fixtures" / "ucp"
NO_PAYMENTS = {"any_non_ucp": False, "protocols": {"l402": {}, "x402": {}}, "fetch_status": "ok"}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def _domain(site_type: str, **extra) -> dict:
    # current_a2a: a usable v2026 profile that declares no checkout capability
    ucp = check_ucp_profile((FIXTURES / "current_a2a.json").read_text(), 200, "application/json")
    return {"site_type": site_type, "ucp": ucp, "agent_payments": NO_PAYMENTS, **extra}


def test_rule_versions():
    assert _rule("UCP_CHECKOUT_MISSING").rule_version == "2.1"
    assert _rule("AGENT_PAYMENTS_ABSENT").rule_version == "2.1"


def test_owner_true_override_fires_checkout_missing_in_evaluate():
    d = _domain("saas", capability_overrides={"transactional_checkout": True})
    assert [f.code or "UCP_CHECKOUT_MISSING" for f in _rule("UCP_CHECKOUT_MISSING").evaluate({}, d)] \
        == ["UCP_CHECKOUT_MISSING"]
    assert _rule("UCP_CHECKOUT_MISSING").measure({}, d, MeasureCtx("saas", frozenset())) is None
    assert len(_rule("AGENT_PAYMENTS_ABSENT").evaluate({}, d)) == 1


def test_no_overrides_unchanged():
    d = _domain("saas")
    assert _rule("UCP_CHECKOUT_MISSING").evaluate({}, d) == []
    assert _rule("AGENT_PAYMENTS_ABSENT").evaluate({}, d) == []
    assert _rule("UCP_CHECKOUT_MISSING").measure({}, d, MeasureCtx("saas", frozenset())) \
        is OutcomeState.NA


def test_override_false_suppresses():
    assert len(_rule("UCP_CHECKOUT_MISSING").evaluate({}, _domain("commerce"))) == 1
    d = _domain("commerce", capability_overrides={"transactional_checkout": False})
    assert _rule("UCP_CHECKOUT_MISSING").evaluate({}, d) == []
    assert _rule("AGENT_PAYMENTS_ABSENT").evaluate({}, d) == []
    assert _rule("UCP_CHECKOUT_MISSING").measure({}, d, MeasureCtx("commerce", frozenset())) \
        is OutcomeState.NA


def test_host_capabilities_win_over_the_domain_key():
    # a ctx that carries derived capabilities is used as given (Cloud applies
    # its overrides before handing them in)
    d = _domain("saas", capability_overrides={"transactional_checkout": True})
    caps = derive_capabilities("saas", [], _domain("saas"))
    assert _rule("UCP_CHECKOUT_MISSING").measure({}, d, MeasureCtx("saas", frozenset(), capabilities=caps)) \
        is OutcomeState.NA


def test_apply_capability_overrides():
    caps = derive_capabilities("saas", [], _domain("saas"))
    assert apply_capability_overrides(caps, None) is caps
    assert apply_capability_overrides(caps, {}) is caps
    out = apply_capability_overrides(caps, {"transactional_checkout": True, "bogus": True,
                                            "physical_goods": "yes"})
    assert out.transactional_checkout == replace(caps.transactional_checkout, value=True, source="owner")
    for flag in FLAGS:
        if flag != "transactional_checkout":
            assert getattr(out, flag) == getattr(caps, flag)

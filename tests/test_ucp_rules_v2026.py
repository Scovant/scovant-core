"""The five UCP rules read the profile as a UCP v2026-08-25 business profile.

Every evidence block here comes from the real parser (`check_ucp_profile`)
over the vendored fixture texts in `fixtures/ucp/` (provenance in that
directory's PROVENANCE.md) — never a hand-shaped dict.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scovant_core.capabilities import derive_capabilities
from scovant_core.parsers.ucp import UCP_MAX_BODY_BYTES, check_ucp_profile
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

FIXTURES = Path(__file__).parent / "fixtures" / "ucp"
NM, NA = OutcomeState.NOT_MEASURED, OutcomeState.NA
UCP_CODES = ("UCP_PROFILE_ABSENT", "UCP_PROFILE_INVALID", "UCP_CHECKOUT_MISSING",
             "UCP_SIGNING_KEYS_INVALID", "AGENT_PAYMENTS_ABSENT")
NO_PAYMENTS = {"any_non_ucp": False, "protocols": {"l402": {}, "x402": {}}, "fetch_status": "ok"}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def _ucp(name: str | None, *, content_type: str = "application/json") -> dict:
    if name is None:
        return check_ucp_profile(None, 404)
    path, = FIXTURES.glob(f"{name}.*")
    return check_ucp_profile(path.read_text(), 200, content_type)


def _domain(name: str | None, site_type: str = "commerce", **extra) -> dict:
    return {"site_type": site_type, "ucp": _ucp(name), "agent_payments": NO_PAYMENTS, **extra}


def _fires(code: str, domain: dict) -> list:
    return [f.code or code for f in _rule(code).evaluate({}, domain)]


def _measure(code: str, domain: dict, site_type: str = "commerce", defaulted=frozenset(), caps=False):
    """`caps=True` derives the capability flags the way a host does (`derive_capabilities`)."""
    capabilities = derive_capabilities(site_type, [], domain) if caps else None
    return _rule(code).measure({}, domain, MeasureCtx(site_type, defaulted, capabilities=capabilities))


def test_every_ucp_rule_is_version_two():
    assert {_rule(c).rule_version for c in UCP_CODES} == {"2.0"}


# ── UCP_PROFILE_ABSENT ──────────────────────────────────────────────────

def test_absent_fires_when_nothing_was_published():
    d = _domain(None)
    assert _fires("UCP_PROFILE_ABSENT", d) == ["UCP_PROFILE_ABSENT"]
    assert _measure("UCP_PROFILE_ABSENT", d) is None


def test_absent_fires_when_the_well_known_path_serves_html():
    d = _domain("html_catchall")
    finding, = _rule("UCP_PROFILE_ABSENT").evaluate({}, d)
    assert finding.metadata == {"site_type": "commerce", "served_html": True}
    assert _measure("UCP_PROFILE_ABSENT", d) is None
    # an HTML page is no profile: nothing else reports it
    for code in UCP_CODES[1:]:
        assert _fires(code, d) == [], code
        assert _measure(code, d) is NA, code


@pytest.mark.parametrize("fixture", ["current_rest", "version_0_1", "future_version", "json_array_root"])
def test_absent_is_silent_when_a_non_html_body_was_served(fixture):
    d = _domain(fixture)
    assert _fires("UCP_PROFILE_ABSENT", d) == []
    assert _measure("UCP_PROFILE_ABSENT", d) is None


def test_absent_is_not_applicable_outside_the_ucp_site_types():
    assert _fires("UCP_PROFILE_ABSENT", _domain(None, "blog")) == []
    assert _measure("UCP_PROFILE_ABSENT", _domain(None, "blog"), "blog") is NA


# ── UCP_PROFILE_INVALID ─────────────────────────────────────────────────

@pytest.mark.parametrize("fixture", ["current_rest", "current_mcp", "current_a2a", "current_embedded",
                                     "checkout_and_cart", "legacy_signing_keys", "protocol_version_2026_01_23"])
def test_invalid_is_silent_on_a_usable_profile(fixture):
    d = _domain(fixture)
    assert d["ucp"]["v2026"]["version_state"] in ("CURRENT", "SUPPORTED_LEGACY")
    assert _fires("UCP_PROFILE_INVALID", d) == []
    assert _measure("UCP_PROFILE_INVALID", d) is None


@pytest.mark.parametrize("fixture", ["uppercase_rest", "missing_endpoint", "missing_schema", "version_0_1",
                                     "private_jwk", "json_array_root"])
def test_invalid_fires_on_a_profile_that_is_not_usable(fixture):
    d = _domain(fixture)
    finding, = _rule("UCP_PROFILE_INVALID").evaluate({}, d)
    assert finding.metadata == {"validation_errors": d["ucp"]["v2026"]["validation_errors"],
                                "version_state": d["ucp"]["v2026"]["version_state"]}
    assert _measure("UCP_PROFILE_INVALID", d) is None


def test_invalid_reports_the_first_five_errors():
    profile = json.loads((FIXTURES / "current_rest.json").read_text())
    for i in range(6):  # six bindings without a transport: one error each
        profile["ucp"]["services"][f"com.example.svc{i}"] = [{"version": "2026-08-25"}]
    d = {"site_type": "commerce", "ucp": check_ucp_profile(json.dumps(profile), 200, "application/json")}
    errors = d["ucp"]["v2026"]["validation_errors"]
    assert len(errors) > 5
    finding, = _rule("UCP_PROFILE_INVALID").evaluate({}, d)
    assert f"First errors: {'; '.join(errors[:5])}." in finding.description


def test_future_version_is_not_measured_not_failed():
    d = _domain("future_version")
    assert d["ucp"]["v2026"]["version_state"] == "FUTURE_UNSUPPORTED"
    for code in UCP_CODES[1:]:
        assert _fires(code, d) == [], code
        assert _measure(code, d) is NM, code


def test_invalid_is_not_applicable_without_a_profile():
    assert _measure("UCP_PROFILE_INVALID", _domain(None)) is NA


# ── UCP_CHECKOUT_MISSING ────────────────────────────────────────────────

def test_checkout_missing_fires_on_a_usable_profile_without_shopping_checkout():
    d = _domain("current_a2a")
    assert d["ucp"]["v2026"]["valid"] and not d["ucp"]["v2026"]["has_checkout"]
    finding, = _rule("UCP_CHECKOUT_MISSING").evaluate({}, d)
    v = d["ucp"]["v2026"]
    assert finding.metadata == {"site_type": "commerce",
                                "declared_capabilities": v["capabilities_standard"] + v["capabilities_custom"]}
    assert "dev.ucp.shopping.checkout" in finding.description
    assert _measure("UCP_CHECKOUT_MISSING", d) is None


def test_the_old_commerce_checkout_name_is_not_a_checkout():
    d = _domain("legacy_commerce_checkout")
    assert _fires("UCP_CHECKOUT_MISSING", d) == ["UCP_CHECKOUT_MISSING"]


def test_checkout_missing_is_silent_when_shopping_checkout_is_declared():
    for fixture in ("current_rest", "checkout_and_cart"):
        d = _domain(fixture)
        assert _fires("UCP_CHECKOUT_MISSING", d) == [], fixture
        assert _measure("UCP_CHECKOUT_MISSING", d) is None, fixture


def test_checkout_missing_needs_a_usable_profile():
    d = _domain("uppercase_rest")
    assert _fires("UCP_CHECKOUT_MISSING", d) == []
    assert _measure("UCP_CHECKOUT_MISSING", d) is NA


def test_checkout_missing_is_not_applicable_to_saas():
    d = _domain("current_a2a", "saas")
    assert _fires("UCP_CHECKOUT_MISSING", d) == []
    assert _measure("UCP_CHECKOUT_MISSING", d, "saas") is NA


# ── UCP_SIGNING_KEYS_INVALID ────────────────────────────────────────────

def test_keys_are_optional_a_profile_without_keys_passes():
    d = _domain("current_rest")
    assert d["ucp"]["v2026"]["keys_state"] == "MISSING"
    assert _fires("UCP_SIGNING_KEYS_INVALID", d) == []
    assert _measure("UCP_SIGNING_KEYS_INVALID", d) is None


def test_the_legacy_signing_keys_field_alone_is_no_finding():
    d = _domain("legacy_signing_keys")
    assert d["ucp"]["v2026"]["keys_state"] == "LEGACY_FIELD"
    assert "legacy_field:signing_keys" in d["ucp"]["v2026"]["validation_warnings"]
    assert _fires("UCP_SIGNING_KEYS_INVALID", d) == []
    assert _measure("UCP_SIGNING_KEYS_INVALID", d) is None


def test_keys_invalid_fires_on_a_private_key_member():
    d = _domain("private_jwk")
    assert d["ucp"]["v2026"]["keys_state"] == "INVALID"
    finding, = _rule("UCP_SIGNING_KEYS_INVALID").evaluate({}, d)
    assert finding.metadata == {"key_errors": ["keys[0]: private key member present"]}
    assert _measure("UCP_SIGNING_KEYS_INVALID", d) is None


def test_keys_invalid_needs_a_readable_version():
    d = _domain("version_0_1")
    assert _fires("UCP_SIGNING_KEYS_INVALID", d) == []
    assert _measure("UCP_SIGNING_KEYS_INVALID", d) is NA


# ── AGENT_PAYMENTS_ABSENT ───────────────────────────────────────────────

def test_payments_absent_beside_a_usable_profile():
    d = _domain("current_rest", "restaurant")
    finding, = _rule("AGENT_PAYMENTS_ABSENT").evaluate({}, d)
    assert finding.metadata == {"probed": ["l402", "x402"]}
    assert _measure("AGENT_PAYMENTS_ABSENT", d, "restaurant") is None
    found = {**d, "agent_payments": {**NO_PAYMENTS, "any_non_ucp": True}}
    assert _fires("AGENT_PAYMENTS_ABSENT", found) == []


def test_payments_absent_needs_a_usable_profile():
    for fixture in (None, "uppercase_rest", "html_catchall"):
        d = _domain(fixture)
        assert _fires("AGENT_PAYMENTS_ABSENT", d) == [], fixture
        assert _measure("AGENT_PAYMENTS_ABSENT", d) is NA, fixture


# ── failures on our side and snapshots from before the v2026 reading ─────

def test_a_failed_fetch_is_not_measured():
    for code in UCP_CODES:
        assert _measure(code, _domain("current_rest"), defaulted=frozenset({"ucp"})) is NM, code


def test_a_profile_read_before_the_v2026_reading_is_not_measured():
    """A snapshot stored before the parser carried `v2026` says a profile was
    served but not what it is: the rules that read its content are silent and
    NOT_MEASURED, never a verdict reconstructed from the old model."""
    ucp = {k: v for k, v in _ucp("current_rest").items() if k != "v2026"}
    d = {"site_type": "commerce", "ucp": ucp, "agent_payments": NO_PAYMENTS}
    assert _fires("UCP_PROFILE_ABSENT", d) == []
    assert _measure("UCP_PROFILE_ABSENT", d) is None
    for code in UCP_CODES[1:]:
        assert _fires(code, d) == [], code
        assert _measure(code, d) is NM, code


def test_every_firing_rule_is_measured():
    """A finding is only ever reported where `measure` says the rule was measured."""
    for path in sorted(FIXTURES.iterdir()):
        if path.suffix not in (".json", ".html") or path.stem == "legacy_expected":
            continue  # legacy_expected.json is recorded parser output, not a profile
        for site_type in ("commerce", "saas", "blog"):
            d = _domain(path.stem, site_type)
            for code in UCP_CODES:
                for caps in (False, True):
                    if _fires(code, d):
                        assert _measure(code, d, site_type, caps=caps) is None, (path.name, site_type, code, caps)


def test_the_checkout_rules_evaluate_where_they_are_measured():
    """No false PASS: wherever measure says a checkout rule applies, evaluate
    judges it (one shared predicate: the transactional_checkout flag)."""
    for path in sorted(FIXTURES.iterdir()):
        if path.suffix not in (".json", ".html") or path.stem == "legacy_expected":
            continue
        for site_type in ("commerce", "booking", "saas", "blog", "other", "unknown"):
            d = _domain(path.stem, site_type)
            usable = d["ucp"]["v2026"] and d["ucp"]["v2026"]["valid"] \
                and d["ucp"]["v2026"]["version_state"] in ("CURRENT", "SUPPORTED_LEGACY")
            for caps in (False, True):
                if _measure("AGENT_PAYMENTS_ABSENT", d, site_type, caps=caps) is None and usable:
                    assert _fires("AGENT_PAYMENTS_ABSENT", d), (path.name, site_type, caps)
                if _measure("UCP_CHECKOUT_MISSING", d, site_type, caps=caps) is None and usable \
                        and not d["ucp"]["v2026"]["has_checkout"]:
                    assert _fires("UCP_CHECKOUT_MISSING", d), (path.name, site_type, caps)


def test_a_saas_profile_declaring_checkout_is_judged_for_other_rails():
    d = _domain("current_rest", "saas")      # usable, dev.ucp.shopping.checkout, no other rail
    assert _fires("AGENT_PAYMENTS_ABSENT", d) == ["AGENT_PAYMENTS_ABSENT"]
    assert _measure("AGENT_PAYMENTS_ABSENT", d, "saas", caps=True) is None
    assert _measure("AGENT_PAYMENTS_ABSENT", d, "saas") is None
    # a SaaS profile without checkout and no other rail: checkout is not established
    d = _domain("current_a2a", "saas")
    assert _fires("AGENT_PAYMENTS_ABSENT", d) == [] and _fires("UCP_CHECKOUT_MISSING", d) == []
    assert _measure("UCP_CHECKOUT_MISSING", d, "saas", caps=True) is NA
    # commerce unchanged
    assert _fires("AGENT_PAYMENTS_ABSENT", _domain("current_rest")) == ["AGENT_PAYMENTS_ABSENT"]
    assert _fires("UCP_CHECKOUT_MISSING", _domain("current_a2a")) == ["UCP_CHECKOUT_MISSING"]


def test_an_unreleased_version_names_the_cause():
    profile = json.loads((FIXTURES / "current_rest.json").read_text())
    for version in ("2026-02-15", "2026-13-45"):
        text = json.dumps(profile).replace("2026-08-25", version)
        d = {"site_type": "commerce", "ucp": check_ucp_profile(text, 200, "application/json")}
        assert d["ucp"]["v2026"]["version_state"] == "INVALID"
        finding, = _rule("UCP_PROFILE_INVALID").evaluate({}, d)
        assert f"declares version {version}, which is not a released UCP version" in finding.description
        assert "none reported" not in finding.description
    long = json.dumps(profile).replace("2026-08-25", "2026-02-15" + "x" * 200)
    finding, = _rule("UCP_PROFILE_INVALID").evaluate({}, {"site_type": "commerce",
                                                          "ucp": check_ucp_profile(long, 200)})
    assert "x" * 100 not in finding.description


def test_a_profile_over_our_read_bound_is_not_measured():
    """FACTS (f): the size bound is our deployment guard, not a site defect."""
    body = (FIXTURES / "current_rest.json").read_text()
    body = body.rstrip()[:-1] + ', "pad": "' + "a" * UCP_MAX_BODY_BYTES + '"}\n'
    d = {"site_type": "commerce", "ucp": check_ucp_profile(body, 200, "application/json"),
         "agent_payments": NO_PAYMENTS}
    assert "body_too_large" in d["ucp"]["v2026"]["validation_errors"]
    for code in UCP_CODES[1:]:
        assert _fires(code, d) == [], code
        assert _measure(code, d) is NM, code
    assert _fires("UCP_PROFILE_ABSENT", d) == []


def test_examples_show_the_current_profile_shape():
    for code in ("UCP_PROFILE_ABSENT", "UCP_PROFILE_INVALID", "UCP_CHECKOUT_MISSING"):
        rule = _rule(code)
        d = {"UCP_PROFILE_ABSENT": _domain(None), "UCP_PROFILE_INVALID": _domain("uppercase_rest"),
             "UCP_CHECKOUT_MISSING": _domain("current_a2a")}[code]
        finding, = rule.evaluate({}, d)
        assert "0.1" not in finding.example and "signing_keys" not in finding.example
        assert "commerce.checkout" not in finding.example + finding.remediation_hint
    # the full example is itself a usable profile
    finding, = _rule("UCP_PROFILE_ABSENT").evaluate({}, _domain(None))
    body = finding.example.split("\n", 1)[1]
    v = check_ucp_profile(body, 200, "application/json")["v2026"]
    assert v["valid"] and v["version_state"] == "CURRENT" and v["has_checkout"], v["validation_errors"]
    json.loads(body)

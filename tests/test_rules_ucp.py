"""Rules published in Core: the UCP profile and agent payments."""
from pathlib import Path

from scovant_core.parsers.ucp import check_ucp_profile
from scovant_core.r2 import PUBLIC_POLICY, OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.ucp import UCP_APPLICABLE_SITE_TYPES, UCP_CHECKOUT_SITE_TYPES

NM = OutcomeState.NOT_MEASURED
CTX = MeasureCtx(site_category="commerce", defaulted=frozenset())
# A usable profile, read by the real parser from the vendored documentation example.
VALID = check_ucp_profile((Path(__file__).parent / "fixtures/ucp/current_rest.json").read_text(), 200)
NO_PAYMENTS = {"any_non_ucp": False, "protocols": {"l402": {}, "x402": {}}, "fetch_status": "ok"}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_the_ucp_site_types_are_the_published_ucp_profile():
    ucp_profile, = (set(p) for c, p in PUBLIC_POLICY.category_profiles.items() if c.value == "ucp")
    assert ucp_profile == UCP_APPLICABLE_SITE_TYPES
    assert UCP_CHECKOUT_SITE_TYPES < UCP_APPLICABLE_SITE_TYPES
    assert "saas" not in UCP_CHECKOUT_SITE_TYPES


# Per-rule behaviour on the UCP v2026-08-25 reading: tests/test_ucp_rules_v2026.py.


def test_a_payment_probe_that_never_got_an_answer_is_not_measured():
    """Core's own scan records no `defaulted` list: `fetch_status` says absence
    was not established."""
    failed = {**NO_PAYMENTS, "fetch_status": "error", "error": "ConnectError"}
    rule = _rule("AGENT_PAYMENTS_ABSENT")
    assert rule.measure({}, {"ucp": VALID, "agent_payments": failed}, MeasureCtx("commerce", None)) is NM

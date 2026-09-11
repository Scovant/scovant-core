from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/policy_pages/security_txt/...
from scovant_core.checks.trust._policy import policy_verdict
from scovant_core.checks.trust.core_trust_002 import ShippingPolicyDiscoverability
from scovant_core.checks.trust.core_trust_003 import ReturnsPolicyDiscoverability
from scovant_core.checks.trust.core_trust_004 import PrivacyPolicyDiscoverability
from scovant_core.checks.trust.core_trust_005 import TermsDiscoverability
from scovant_core.checks.trust.core_trust_006 import SecurityTxtDiscoverability
from scovant_core.checks.trust.core_trust_007 import PricingDiscoverability
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus, Confidence
from scovant_core.profiles import apply_profile

from .conftest import make_client


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


_MIN_INDEX = (
    "<!doctype html><html><head><title>Test</title></head><body>"
    "<h1>Test</h1><p>Minimal page with enough visible text for the parser "
    "to treat this as real content rather than an empty shell.</p></body></html>"
)


# ---------------------------------------------------------------------------
# _policy.policy_verdict shared helper
# ---------------------------------------------------------------------------

def test_policy_verdict_missing_page_returns_missing_status_warn():
    status, summary, ev, confidence = policy_verdict(None, missing_status=CheckStatus.WARN, label="shipping policy page")
    assert status == CheckStatus.WARN
    assert "no shipping policy page" in summary.lower()
    assert ev == {}


def test_policy_verdict_missing_page_can_be_fail():
    status, summary, ev, confidence = policy_verdict(None, missing_status=CheckStatus.FAIL, label="privacy policy page")
    assert status == CheckStatus.FAIL
    assert ev == {}


def test_policy_verdict_error_on_unread_page():
    page = {
        "url": "https://example.com/shipping", "status": None, "text_chars": 0,
        "served_as_html": False, "has_price_text": False, "has_structured_price": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="shipping policy page")
    assert status == CheckStatus.ERROR
    assert "could not be read" in summary.lower()
    assert ev["status"] is None


def test_policy_verdict_warn_on_broken_status():
    page = {
        "url": "u", "status": 404, "text_chars": 0, "served_as_html": False,
        "has_price_text": False, "has_structured_price": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.WARN
    assert "broken" in summary.lower()


def test_policy_verdict_broken_status_wins_even_when_served_as_html_true():
    """Controller ruling: `served_as_html` on a policy page is purely
    informational — a policy page genuinely IS an HTML document (unlike
    robots.txt/a sitemap/llms.txt, there is no soft-404 rule for it). Only
    `status >= 400` decides "broken", regardless of `served_as_html`."""
    page = {
        "url": "u", "status": 404, "text_chars": 5000, "served_as_html": True,
        "has_price_text": False, "has_structured_price": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.WARN
    assert "broken" in summary.lower()


def test_policy_verdict_pass_ignores_served_as_html_true_on_a_real_200():
    page = {
        "url": "u", "status": 200, "text_chars": 500, "served_as_html": True,
        "has_price_text": False, "has_structured_price": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.PASS


def test_policy_verdict_warn_on_thin_text():
    page = {
        "url": "u", "status": 200, "text_chars": 50, "served_as_html": False,
        "has_price_text": False, "has_structured_price": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.WARN
    assert "too little text" in summary.lower()


def test_policy_verdict_pass_on_substantive_page():
    page = {
        "url": "u", "status": 200, "text_chars": 500, "served_as_html": False,
        "has_price_text": False, "has_structured_price": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.PASS
    assert ev["text_chars"] == 500


def test_policy_verdict_pass_truncated_page_gets_note_and_medium_confidence():
    """A page cut off at the fetch cap must still say so — the truncation
    treatment threaded through `policy_verdict`. Neutralising the
    `record_truncation`/`truncated_confidence` calls in `_policy.py` must
    make this fail: PASS alone is not enough evidence the treatment ran."""
    page = {
        "url": "u", "status": 200, "text_chars": 500, "served_as_html": False,
        "has_price_text": False, "has_structured_price": False, "truncated": True,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.PASS
    assert confidence == Confidence.MEDIUM
    assert ev["truncated"] is True
    assert "read only in part" in summary.lower()


def test_policy_verdict_untruncated_page_writes_no_flag_and_stays_high_confidence():
    page = {
        "url": "u", "status": 200, "text_chars": 500, "served_as_html": False,
        "has_price_text": False, "has_structured_price": False, "truncated": False,
    }
    status, summary, ev, confidence = policy_verdict(page, missing_status=CheckStatus.WARN, label="terms/conditions page")
    assert status == CheckStatus.PASS
    assert confidence == Confidence.HIGH
    assert "truncated" not in ev
    assert "read only in part" not in summary.lower()


# ---------------------------------------------------------------------------
# TRUST-002 shipping policy discoverability
# ---------------------------------------------------------------------------

def test_trust_002_pass_on_commerce_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ShippingPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_trust_002_warn_on_commerce_bad_no_link(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = ShippingPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence == {}


def test_trust_002_na_when_profile_not_commerce(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    result = ShippingPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_trust_002_error_when_entry_page_unparsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(500, text="server error")), options=ScanOptions(profile="commerce"))
    result = ShippingPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# TRUST-003 returns/refund policy discoverability
# ---------------------------------------------------------------------------

def test_trust_003_pass_on_commerce_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ReturnsPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_trust_003_warn_on_commerce_bad_no_link(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = ReturnsPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# TRUST-004 privacy policy discoverability (missing -> FAIL, severity HIGH)
# ---------------------------------------------------------------------------

def test_trust_004_pass_on_commerce_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = PrivacyPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_trust_004_fail_on_commerce_bad_no_privacy_link(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = PrivacyPolicyDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.severity.name == "HIGH"


def test_trust_004_applies_to_every_profile(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    result = PrivacyPolicyDiscoverability().run(store, ctx)
    # api-good links a real privacy page, but it is thin (<200 chars).
    assert result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# TRUST-005 terms/conditions discoverability
# ---------------------------------------------------------------------------

def test_trust_005_pass_on_commerce_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = TermsDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_trust_005_warn_on_api_good_no_terms_link(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    result = TermsDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence == {}


# ---------------------------------------------------------------------------
# TRUST-006 security.txt discoverability
# ---------------------------------------------------------------------------

_SECURITY_TXT_VALID = "Contact: mailto:security@example.com\nExpires: 2099-12-31T00:00:00.000Z\n"
_SECURITY_TXT_NO_CONTACT = "Expires: 2099-12-31T00:00:00.000Z\n"
_SECURITY_TXT_EXPIRED = "Contact: mailto:security@example.com\nExpires: 2000-01-01T00:00:00.000Z\n"


def _security_txt_client(body: str | None, *, fetch_error: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_MIN_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path in ("/.well-known/security.txt", "/security.txt"):
            if fetch_error:
                raise httpx.ConnectError("simulated network failure", request=request)
            if body is not None:
                return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    return make_client(handler)


def test_trust_006_na_when_absent():
    # commerce-good now publishes a valid security.txt (CORE-TRUST-006 PASS
    # on that fixture, see fixtures/PROVENANCE.md) — the N/A "absent" path is
    # exercised here against an isolated client that 404s both conventional
    # paths instead.
    store, ctx = _scan(_security_txt_client(None), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_trust_006_error_when_fetch_fails():
    store, ctx = _scan(_security_txt_client(None, fetch_error=True), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_trust_006_error_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_MIN_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(500, text="server error")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["status"] == 500


def test_trust_006_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_MIN_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(403, text="forbidden")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["status"] == 403


def test_trust_006_pass_with_contact_and_future_expiry():
    store, ctx = _scan(_security_txt_client(_SECURITY_TXT_VALID), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_trust_006_warn_no_contact():
    store, ctx = _scan(_security_txt_client(_SECURITY_TXT_NO_CONTACT), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "contact" in result.summary.lower()


def test_trust_006_warn_expired():
    store, ctx = _scan(_security_txt_client(_SECURITY_TXT_EXPIRED), options=ScanOptions(profile="commerce"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "expires" in result.summary.lower()


def test_trust_006_na_when_profile_not_applicable(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="content"))
    result = SecurityTxtDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "not applicable" in result.summary.lower()


# ---------------------------------------------------------------------------
# TRUST-007 pricing discoverability
# ---------------------------------------------------------------------------

_PRICING_PAGE_WITH_PRICE = (
    "<!doctype html><html><head><title>Pricing</title></head><body>"
    "<h1>Pricing</h1><p>Our plan costs $9.99 per month, billed monthly with no "
    "long-term contract required and cancellation available at any time.</p></body></html>"
)
_PRICING_PAGE_NO_PRICE = (
    "<!doctype html><html><head><title>Pricing</title></head><body>"
    "<h1>Pricing</h1><p>Contact sales for a custom quote tailored to your team's "
    "specific usage needs, seat count, and support requirements.</p></body></html>"
)
_ENTRY_WITH_PRICING_LINK = (
    "<!doctype html><html><head><title>t</title></head><body>"
    "<h1>t</h1><p>enough visible text content for the parser to treat this as real content on the page.</p>"
    '<a href="/pricing">Pricing</a></body></html>'
)


def _pricing_client(pricing_body: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_WITH_PRICING_LINK.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/pricing":
            return httpx.Response(200, content=pricing_body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    return make_client(handler)


def test_trust_007_pass_pricing_page_with_visible_price():
    store, ctx = _scan(_pricing_client(_PRICING_PAGE_WITH_PRICE), options=ScanOptions(profile="saas"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["has_price_text"] is True


def test_trust_007_warn_pricing_page_without_readable_price():
    store, ctx = _scan(_pricing_client(_PRICING_PAGE_NO_PRICE), options=ScanOptions(profile="saas"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["has_price_text"] is False
    assert result.evidence["has_structured_price"] is False


def test_trust_007_pass_on_commerce_good_via_structured_product_price(fixture_site):
    """commerce-good has no discovered `pricing` policy page, but its product
    page carries a structured schema.org Offer price — the fallback signal."""
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert "structured_price" in result.evidence


def test_trust_007_na_when_no_pricing_signal(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_trust_007_na_when_profile_not_applicable(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "not applicable" in result.summary.lower()


def test_trust_007_error_when_pricing_page_fetch_fails():
    """A pricing page WAS discovered (linked from the entry page) but our own
    fetch of it failed — unmeasured (ERROR), never scored as though the page
    had a readable price or didn't."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_WITH_PRICING_LINK.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/pricing":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["status"] is None


def test_trust_007_pass_via_structured_price_fallback_survives_unparsed_entry():
    """The structured-price fallback reads `store.get("pages")` directly, not
    `policy_pages`'s own entry-parse gate — so an unparsed entry page never
    hides a real structured price sitting on a different sampled page."""
    from scovant_core.evidence import GATHERERS

    def fake_pages(client, ctx, store):
        return {
            "pages": [
                {"url": "https://example.com/", "parsed": None},
                {
                    "url": "https://example.com/products/widget",
                    "parsed": {"product_data": {"price": 19.99}},
                },
            ]
        }

    GATHERERS["pages"] = fake_pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404, text="not found")), options=ScanOptions(profile="commerce"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["structured_price"] == 19.99


def test_trust_007_error_when_entry_unparsed_and_no_fallback_signal():
    """Entry unparsed, no pricing page, no commerce structured-price fallback
    to fall back on either — genuinely unmeasured, so ERROR, not N/A."""
    from scovant_core.evidence import GATHERERS

    def fake_pages(client, ctx, store):
        return {"pages": [{"url": "https://example.com/", "parsed": None}]}

    GATHERERS["pages"] = fake_pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404, text="not found")), options=ScanOptions(profile="saas"))
    result = PricingDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR

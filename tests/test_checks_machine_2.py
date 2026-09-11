from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/http/robots/... gatherers
from scovant_core.checks.machine.core_machine_002 import OrganizationEntity
from scovant_core.checks.machine.core_machine_003 import WebSiteOrPageEntity
from scovant_core.checks.machine.core_machine_006 import ProductIdentifierCount
from scovant_core.checks.machine.core_machine_007 import Breadcrumbs
from scovant_core.checks.machine.core_machine_010 import LanguageDeclaration
from scovant_core.checks.machine.core_machine_011 import ImageAltCoverage
from scovant_core.checks.machine.core_machine_012 import VisibleVsStructuredPrice
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import GATHERERS, EvidenceStore
from scovant_core.models import CheckStatus
from scovant_core.profiles import apply_profile

from .conftest import make_client


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


def _html_only(request: httpx.Request, body: bytes) -> httpx.Response:
    if request.url.path == "/":
        return httpx.Response(200, content=body, headers={"content-type": "text/html"})
    return httpx.Response(404, text="not found")


# ---------------------------------------------------------------------------
# 002 Organization entity
# ---------------------------------------------------------------------------

def test_002_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = OrganizationEntity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["name"] == "Example Shop"
    assert result.evidence["url"] == "https://example.com/"


def test_002_warn_when_no_organization_node(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = OrganizationEntity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found"] is False


def test_002_warn_when_organization_missing_url():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Acme"}</script>'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = OrganizationEntity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["missing"] == ["url"]


def test_002_pass_with_organization_inside_graph():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@graph":['
        b'{"@type":"Organization","name":"Acme","url":"https://acme.example/","sameAs":["https://x.example/acme"]}'
        b']}</script>'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = OrganizationEntity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["has_sameAs"] is True


def test_002_error_when_no_page_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = OrganizationEntity().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 003 WebSite/WebPage entity
# ---------------------------------------------------------------------------

def test_003_pass_on_commerce_good_website_node(fixture_site):
    # commerce-good declares a WebSite node on the entry page (Fix round 1).
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = WebSiteOrPageEntity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["found"] is True


def test_003_warn_when_no_website_or_page_node():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Acme","url":"https://acme.example/"}</script>'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = WebSiteOrPageEntity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found"] is False


def test_003_pass_when_website_node_present():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"Acme","url":"https://acme.example/"}</script>'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = WebSiteOrPageEntity().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_003_error_when_no_page_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = WebSiteOrPageEntity().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 006 Product identifier count
# ---------------------------------------------------------------------------

def test_006_pass_with_two_identifiers(fixture_site):
    # commerce-good's Product node carries sku + brand.
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ProductIdentifierCount().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["count"] >= 2


def test_006_warn_with_one_identifier():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Thing","sku":"X1"}</script>'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = ProductIdentifierCount().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["count"] == 1


def test_006_warn_with_zero_identifiers(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = ProductIdentifierCount().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["count"] == 0


def test_006_na_without_a_product_node():
    body = b'<!doctype html><html><head><title>t</title></head><body><h1>t</h1><p>enough text to be real content here.</p></body></html>'
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = ProductIdentifierCount().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_006_na_on_content_profile(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="content"))
    result = ProductIdentifierCount().run(store, ctx)
    assert result.status == CheckStatus.NA


# ---------------------------------------------------------------------------
# 007 Breadcrumbs
# ---------------------------------------------------------------------------

def test_007_na_when_only_entry_page_sampled():
    def _pages(client, ctx, store):
        return {
            "pages": [{"url": ctx.final_url, "status": 200, "html": "", "bot_protection": None,
                       "parsed": {"breadcrumb": False}, "error": None}],
            "selection": [{"url": ctx.final_url, "reason": "entry"}],
        }

    GATHERERS["pages"] = _pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_007_warn_when_non_entry_pages_have_no_breadcrumb():
    def _pages(client, ctx, store):
        return {
            "pages": [
                {"url": "https://example.com/", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": False}, "error": None},
                {"url": "https://example.com/other", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": False}, "error": None},
            ],
            "selection": [{"url": "https://example.com/", "reason": "entry"},
                          {"url": "https://example.com/other", "reason": "sitemap"}],
        }

    GATHERERS["pages"] = _pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["has_breadcrumb"] is False


def test_007_error_when_no_non_entry_page_could_be_read():
    # Entry parsed fine; the one non-entry page we sampled has `parsed: None`
    # (a fetch error / 5xx) — this must never read as "no breadcrumb found".
    def _pages(client, ctx, store):
        return {
            "pages": [
                {"url": "https://example.com/", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": False}, "error": None},
                {"url": "https://example.com/other", "status": 500, "html": "", "bot_protection": None,
                 "parsed": None, "error": None},
            ],
            "selection": [{"url": "https://example.com/", "reason": "entry"},
                          {"url": "https://example.com/other", "reason": "sitemap"}],
        }

    GATHERERS["pages"] = _pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence == {"non_entry_sampled": 1, "non_entry_parsed": 0, "unread": 1}


def test_007_warn_includes_unread_count_when_some_non_entry_pages_unread():
    def _pages(client, ctx, store):
        return {
            "pages": [
                {"url": "https://example.com/", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": False}, "error": None},
                {"url": "https://example.com/other", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": False}, "error": None},
                {"url": "https://example.com/broken", "status": 500, "html": "", "bot_protection": None,
                 "parsed": None, "error": None},
            ],
            "selection": [{"url": "https://example.com/", "reason": "entry"},
                          {"url": "https://example.com/other", "reason": "sitemap"},
                          {"url": "https://example.com/broken", "reason": "sitemap"}],
        }

    GATHERERS["pages"] = _pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["unread"] == 1
    assert result.evidence["has_breadcrumb"] is False


def test_007_pass_when_a_non_entry_page_has_a_breadcrumb():
    def _pages(client, ctx, store):
        return {
            "pages": [
                {"url": "https://example.com/", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": False}, "error": None},
                {"url": "https://example.com/other", "status": 200, "html": "", "bot_protection": None,
                 "parsed": {"breadcrumb": True}, "error": None},
            ],
            "selection": [{"url": "https://example.com/", "reason": "entry"},
                          {"url": "https://example.com/other", "reason": "sitemap"}],
        }

    GATHERERS["pages"] = _pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_007_error_when_no_page_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_007_na_on_saas_content_commerce_only_profile_gate():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="api"))
    result = Breadcrumbs().run(store, ctx)
    assert result.status == CheckStatus.NA


# ---------------------------------------------------------------------------
# 010 Language declaration
# ---------------------------------------------------------------------------

def test_010_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = LanguageDeclaration().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["html_lang"] == "en"


def test_010_warn_when_lang_missing():
    body = b'<!doctype html><html><head><title>t</title></head><body><h1>t</h1><p>enough text to be real content here.</p></body></html>'
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = LanguageDeclaration().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["html_lang"] is None


def test_010_warn_when_lang_invalid():
    body = (
        b'<!doctype html><html lang="english!!"><head><title>t</title></head>'
        b'<body><h1>t</h1><p>enough text to be real content here.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = LanguageDeclaration().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["html_lang"] == "english!!"


def test_010_pass_when_lang_has_region_subtag():
    body = (
        b'<!doctype html><html lang="en-US"><head><title>t</title></head>'
        b'<body><h1>t</h1><p>enough text to be real content here.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)))
    result = LanguageDeclaration().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_010_error_when_entry_page_could_not_be_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(500, text="server error")))
    result = LanguageDeclaration().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 011 Image alt coverage
# ---------------------------------------------------------------------------

def test_011_na_when_no_images():
    # commerce-good now carries a fully-alt'd image (CORE-MACHINE-011 PASS on
    # that fixture, see fixtures/PROVENANCE.md) — the N/A "no images at all"
    # path is exercised here against an isolated image-free page instead.
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<main><p>No images on this page at all.</p></main></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = ImageAltCoverage().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_011_pass_with_high_alt_ratio():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<img src="a.png" alt="a description"><img src="b.png" alt=""><img src="c.png" alt="another">'
        b'<img src="d.png" alt="yet another"><img src="e.png" alt="fifth">'
        b'<img src="f.png" alt="sixth">'
        b'<img src="g.png" alt="seventh">'
        b'<img src="h.png" alt="eighth">'
        b'<img src="i.png" alt="ninth">'
        b'<img src="j.png">'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="content"))
    result = ImageAltCoverage().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["total"] == 10
    assert result.evidence["ratio"] == 0.9


def test_011_warn_with_low_alt_ratio():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<img src="a.png"><img src="b.png"><img src="c.png" alt="described">'
        b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="content"))
    result = ImageAltCoverage().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["total"] == 3
    assert result.evidence["covered"] == 1


def test_011_error_when_no_page_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="content"))
    result = ImageAltCoverage().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_011_na_on_api_profile(fixture_site):
    store, ctx = _scan(fixture_site("api-good"), options=ScanOptions(profile="api"))
    result = ImageAltCoverage().run(store, ctx)
    assert result.status == CheckStatus.NA


# ---------------------------------------------------------------------------
# 012 Visible vs structured price (experimental)
# ---------------------------------------------------------------------------

def test_012_pass_when_structured_price_matches_visible(fixture_site):
    # commerce-good/products/widget.html: structured 19.99, visible "$19.99".
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.experimental is True


def test_012_na_when_no_page_has_a_structured_price():
    body = b'<!doctype html><html><head><title>t</title></head><body><h1>t</h1><p>enough text to be real content here.</p></body></html>'
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_012_na_when_no_visible_prices():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Thing",'
        b'"offers":{"@type":"Offer","price":19.99,"priceCurrency":"USD"}}</script>'
        b'<h1>t</h1><p>enough text to be real content here for the parser, with no price shown to a visitor.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_012_fail_on_clear_mismatch():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Thing",'
        b'"offers":{"@type":"Offer","price":19.99,"priceCurrency":"USD"}}</script>'
        b'<h1>t</h1><p>Now just $29.99, a limited time offer for testing.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.FAIL


def test_012_fail_when_structured_price_unparseable():
    # A truthy but non-numeric structured price (e.g. "call for price") must
    # be distinguished from a real mismatch, not silently read as one.
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Thing",'
        b'"offers":{"@type":"Offer","price":"call for price","priceCurrency":"USD"}}</script>'
        b'<h1>t</h1><p>Now just $29.99, a limited time offer for testing.</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["structured_value"] is None
    assert "could not be parsed" in result.summary.lower()


def test_012_warn_when_ambiguous_many_distinct_visible_prices():
    body = (
        b'<!doctype html><html><head><title>t</title></head><body>'
        b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Thing",'
        b'"offers":{"@type":"Offer","price":19.99,"priceCurrency":"USD"}}</script>'
        b'<h1>t</h1><p>Was $39.99 then $34.99 then $29.99 now just $19.99 compare at $24.99 today</p></body></html>'
    )
    store, ctx = _scan(make_client(lambda r: _html_only(r, body)), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["distinct_visible_values"] > 3


def test_012_error_when_no_page_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="commerce"))
    result = VisibleVsStructuredPrice().run(store, ctx)
    assert result.status == CheckStatus.ERROR

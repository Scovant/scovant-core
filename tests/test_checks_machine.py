from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/http/robots/... gatherers
from scovant_core.checks.machine.core_machine_001 import JsonLdParseability
from scovant_core.checks.machine.core_machine_004 import ProductStructuredData
from scovant_core.checks.machine.core_machine_005 import OfferCompleteness
from scovant_core.checks.machine.core_machine_008 import MetadataQuality
from scovant_core.checks.machine.core_machine_009 import HeadingStructure
from scovant_core.checks.registry import CHECKS
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


# ---------------------------------------------------------------------------
# 001 JSON-LD parseability
# ---------------------------------------------------------------------------

def test_001_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = JsonLdParseability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["raw_total"] == result.evidence["parsed_total"] > 0


def test_001_warn_on_bad_one_of_two_blocks_invalid(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = JsonLdParseability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["raw_total"] == 2
    assert result.evidence["parsed_total"] == 1


def test_001_error_when_no_page_parsed():
    def _all_404(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_all_404))
    result = JsonLdParseability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    # This check's own phrasing ("could be parsed") never says "could not
    # be" — it names the branch by its distinctive actual text instead.
    assert "could be parsed" in result.summary.lower()


def test_001_error_when_pages_gatherer_raises():
    def _boom(client, ctx, store):
        raise RuntimeError("boom")

    GATHERERS["pages"] = _boom
    client = make_client(lambda r: httpx.Response(404))
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    result = JsonLdParseability().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 004 Product structured data
# ---------------------------------------------------------------------------

def test_004_pass_on_good_product_has_identifiers(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["has_identifiers"] is True


def test_004_na_on_content_profile(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="content"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_004_warn_on_bad_product_without_identifiers(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["has_identifiers"] is False


def test_004_fail_when_no_page_exposes_a_product_entity():
    def _no_product(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=b"<html><head><title>t</title></head>"
                                                  b"<body><h1>t</h1><p>enough text to be real content here.</p></body></html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_no_product), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.FAIL


def test_004_warn_when_product_has_no_identifiers():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = (
                b'<!doctype html><html><head><title>t</title></head><body>'
                b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product",'
                b'"name":"Thing"}</script>'
                b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
            )
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["has_identifiers"] is False


def test_004_warn_when_identifier_key_present_but_empty():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = (
                b'<!doctype html><html><head><title>t</title></head><body>'
                b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product",'
                b'"name":"Thing","sku":""}</script>'
                b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
            )
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["has_identifiers"] is False


# ---------------------------------------------------------------------------
# 005 Offer price/currency/availability
# ---------------------------------------------------------------------------

def test_005_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = OfferCompleteness().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["missing"] == []


def test_005_fail_on_bad_product_without_offer(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = OfferCompleteness().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert set(result.evidence["missing"]) == {"price", "priceCurrency", "availability"}


def test_005_pass_when_price_is_zero():
    # Injected directly at the "pages" evidence layer (bypassing HTML
    # parsing) because `extract_product_data`'s own `or`-chaining collapses
    # an explicit Offer price of 0 to the (absent) Product-level price —
    # a separate, out-of-scope upstream quirk in parsers/html.py (shared
    # with Cloud). This isolates CORE-MACHINE-005's own "0 is present"
    # handling from that upstream behavior.
    def _pages(client, ctx, store):
        return {"pages": [{
            "url": "https://example.com/", "status": 200,
            "parsed": {"product_data": {"product_name": "Free Thing", "price": 0,
                                         "currency": "USD", "availability": "https://schema.org/InStock"}},
            "error": None,
        }], "selection": []}

    GATHERERS["pages"] = _pages
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)), options=ScanOptions(profile="commerce"))
    result = OfferCompleteness().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["missing"] == []
    assert result.evidence["price"] == 0


def test_005_na_when_no_product_data_anywhere():
    def _no_product(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=b"<html><head><title>t</title></head>"
                                                  b"<body><h1>t</h1><p>enough text to be real content here.</p></body></html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_no_product), options=ScanOptions(profile="commerce"))
    result = OfferCompleteness().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_005_warn_on_partial_offer():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = (
                b'<!doctype html><html><head><title>t</title></head><body>'
                b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product",'
                b'"name":"Thing","offers":{"@type":"Offer","price":9.99}}</script>'
                b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
            )
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler), options=ScanOptions(profile="commerce"))
    result = OfferCompleteness().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert set(result.evidence["missing"]) == {"priceCurrency", "availability"}


# ---------------------------------------------------------------------------
# 008 metadata quality
# ---------------------------------------------------------------------------

def test_008_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = MetadataQuality().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["missing"] == []


def test_008_warn_on_bad_missing_og_tags(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = MetadataQuality().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "og:title" in result.evidence["missing"]
    assert "og:description" in result.evidence["missing"]


def test_008_warn_when_title_equals_description():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = (
                b'<!doctype html><html><head><title>Same Text</title>'
                b'<meta name="description" content="Same Text">'
                b'<meta property="og:title" content="Same Text">'
                b'<meta property="og:description" content="Same Text">'
                b'</head><body><h1>t</h1><p>enough text to be real content here.</p></body></html>'
            )
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler))
    result = MetadataQuality().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "title equals description" in result.evidence["issues"]


def test_008_error_when_entry_page_could_not_be_parsed():
    def _all_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    store, ctx = _scan(make_client(_all_500))
    result = MetadataQuality().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# ---------------------------------------------------------------------------
# 009 heading structure
# ---------------------------------------------------------------------------

def test_009_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = HeadingStructure().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["issues"] == []


def test_009_warn_on_bad_two_h1s(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = HeadingStructure().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "multiple H1" in result.evidence["issues"]


def test_009_warn_on_no_h1():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = b"<html><head><title>t</title></head><body><h2>only h2</h2><p>enough text to be real content.</p></body></html>"
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler))
    result = HeadingStructure().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "no H1" in result.evidence["issues"]


def test_009_warn_on_skipped_level():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = b"<html><head><title>t</title></head><body><h1>ok</h1><h3>skipped</h3><p>enough text here.</p></body></html>"
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler))
    result = HeadingStructure().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "skipped heading level" in result.evidence["issues"]


def test_009_error_when_entry_page_could_not_be_parsed():
    def _all_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    store, ctx = _scan(make_client(_all_500))
    result = HeadingStructure().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

def test_registry_has_the_machine_five():
    ids = {c.id for c in CHECKS}
    assert {"CORE-MACHINE-001", "CORE-MACHINE-004", "CORE-MACHINE-005", "CORE-MACHINE-008",
            "CORE-MACHINE-009"} <= ids
    # The overall registry total (20, the Phase 1 target) is pinned by
    # tests/test_registry.py::test_registry_has_the_phase_1_twenty.

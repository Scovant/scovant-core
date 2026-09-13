from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/mcp_discovery/... gatherers
from scovant_core.checks.interfaces.core_interface_001 import McpDiscoveryPresence
from scovant_core.checks.interfaces.core_interface_003 import WebMcpStaticPresence
from scovant_core.checks.interfaces.core_interface_005 import OpenApiDiscovery
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers.openapi import _CANDIDATE_PATHS
from scovant_core.models import CheckStatus, Confidence
from scovant_core.profiles import apply_profile

from .conftest import make_client


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


def _raise_connect_error(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("simulated network failure", request=request)


_DEFAULT_INDEX = (
    "<!doctype html><html><head><title>Test</title></head><body>"
    "<h1>Test</h1><p>Minimal page with enough visible text for the parser "
    "to treat this as real content rather than an empty shell.</p></body></html>"
)


# ---------------------------------------------------------------------------
# 001 MCP discovery presence
# ---------------------------------------------------------------------------

def test_001_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["endpoints"] == ["https://example.com/mcp"]
    assert result.evidence["declared_name"] == "example-shop"


def test_001_na_not_published_on_real_404():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "is published" in result.summary
    assert result.evidence["http_status"] == 404


def test_001_error_could_not_be_read_on_fetch_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be read" in result.summary
    assert result.evidence["http_status"] is None


def test_001_error_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(500, text="server error")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 500


def test_001_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(403, text="forbidden")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 403


def test_001_warn_on_malformed_discovery_file():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(200, text="{not valid json", headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["exists"] is True
    assert result.evidence["valid"] is False


def test_001_pass_medium_confidence_on_server_card_only():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp/server-card.json":
            return httpx.Response(200, json={"name": "s"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.confidence == Confidence.MEDIUM
    assert result.evidence["exists"] is False
    assert result.evidence["server_card"] is True


def test_001_error_on_truncated_server_card_probe():
    """CARRY-FORWARD fix: `server_card=None` (the probe's own read
    was cut off before it could tell whether a card exists —
    `gatherers/mcp_metadata.probe_mcp_server_card`) must not fall into "No
    MCP discovery file is published" — that asserts an absence never
    actually confirmed. See the twin below (`server_card=False`, no
    truncation) for the genuinely-absent case, which must still land on
    N/A — that twin is what stops this test from passing vacuously (e.g.
    if the new branch fired on every falsy `server_card`, not only
    `None`)."""
    big_padding = "A" * (600 * 1024)  # past the probe's own 512 KiB read cap

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp/server-card.json":
            # Cut mid-string by the probe's own cap, so it never parses as
            # JSON — the probe reports `exists=None`, never a claimed `False`.
            return httpx.Response(200, content=('{"padding": "' + big_padding).encode(),
                                  headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "server card" in result.summary.lower()
    assert result.evidence["server_card"] is None
    assert result.evidence["exists"] is False


def test_001_na_twin_when_server_card_is_confirmed_absent_not_truncated():
    """The twin of the truncated-probe test above: every path answers with
    a normal, small 404 — `server_card=False` (confirmed absent, NOT
    truncated) — and must still land on N/A, not ERROR."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["server_card"] is False
    assert result.evidence["exists"] is False


def test_001_error_when_gatherer_raises():
    from scovant_core.evidence import GATHERERS

    def _boom(client, ctx, store):
        raise RuntimeError("boom")

    GATHERERS["mcp_discovery"] = _boom
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 003 WebMCP static presence
# ---------------------------------------------------------------------------

def test_003_na_on_good_and_bad(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = WebMcpStaticPresence().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.confidence == Confidence.LOW


def test_003_pass_when_inline_script_registers_modelcontext():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        "<script>if (navigator.modelContext) { navigator.modelContext.registerTool({}); }</script>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpStaticPresence().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.confidence == Confidence.LOW
    assert result.evidence["pages_with_marker"] == ["https://example.com/"]


def test_003_pass_when_link_rel_modelcontext_present():
    body = (
        '<!doctype html><html><head><title>t</title><link rel="modelcontext" href="/tools.json"></head><body>'
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpStaticPresence().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_003_na_when_marker_only_in_visible_prose():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>We wrote a blog post about navigator.modelContext and WebMCP, "
        "but this page has no actual registration script — just prose mentioning it.</p>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpStaticPresence().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_003_error_when_no_page_has_html():
    def _raise(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure", request=request)

    store, ctx = _scan(make_client(_raise))
    result = WebMcpStaticPresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence == {}


# ---------------------------------------------------------------------------
# 005 OpenAPI discovery
# ---------------------------------------------------------------------------

def test_005_na_on_non_applicable_profile(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "commerce" in result.summary


def test_005_pass_on_api_good(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    assert ctx.profile == "api"
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["found_url"] == "https://example.com/openapi.json"
    assert result.evidence["openapi_version"] == "3.1.0"


def test_005_warn_not_found_on_api_profile():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found_url"] is None


def test_005_error_on_5xx_across_every_candidate():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(500, text="server error")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["found_url"] is None


def test_005_error_on_403_across_every_candidate():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(403, text="forbidden")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["found_url"] is None


# --- order-independence: the gatherer aggregates across every candidate
# rather than keying the verdict on whichever candidate answered last, so
# these four pin the same verdict regardless of iteration order.

def test_005_warn_absent_when_404s_precede_a_connect_error():
    """4x404 then a network error on the last candidate: a real 404/410 was
    seen, so the verdict is confirmed absence (WARN on the api profile),
    never ERROR just because the LAST candidate happened to fail our fetch."""
    *rest, last = _CANDIDATE_PATHS

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == last:
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found_url"] is None
    assert "No OpenAPI document discovered" in result.summary


def test_005_error_when_500_precedes_404s():
    """A real 500 on the first candidate, 404 on the rest: a genuine read
    failure was seen, so the verdict is ERROR, regardless of how many other
    candidates cleanly 404'd."""
    first, *rest = _CANDIDATE_PATHS

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == first:
            return httpx.Response(500, text="server error")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["found_url"] is None


def test_005_error_when_every_candidate_is_a_connect_error():
    def _raise(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        raise httpx.ConnectError("simulated network failure", request=request)

    store, ctx = _scan(make_client(_raise), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["found_url"] is None


def test_005_warn_absent_when_connect_error_precedes_404s():
    """Same as test_005_warn_absent_when_404s_precede_a_connect_error but
    with the network error FIRST and the real 404s afterward — the reverse
    iteration order must give the same verdict."""
    first, *rest = _CANDIDATE_PATHS

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == first:
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found_url"] is None
    assert "No OpenAPI document discovered" in result.summary


def test_005_error_when_500_follows_404s():
    """Same as test_005_error_when_500_precedes_404s but with the 500 LAST
    instead of first — the reverse iteration order must give the same
    ERROR verdict, not WARN just because the earlier candidates 404'd."""
    *rest, last = _CANDIDATE_PATHS

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == last:
            return httpx.Response(500, text="server error")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["found_url"] is None


def test_005_na_not_found_on_saas_profile():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_005_absence_is_warn_for_api_and_na_for_saas():
    """0.2.0 pin (audit §1): absence of an OpenAPI document is a defect ONLY
    for the `api` profile; for `saas` it is N/A — optional, never penalised.
    No dedicated fixtures for this exist, so the store is built inline the
    same way the neighbouring -005 tests above do (a same-origin 404 for
    every candidate path)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store_api, ctx_api = _scan(make_client(handler), options=ScanOptions(profile="api"))
    warn = OpenApiDiscovery().run(store_api, ctx_api)

    store_saas, ctx_saas = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    na = OpenApiDiscovery().run(store_saas, ctx_saas)

    assert warn.status is CheckStatus.WARN and na.status is CheckStatus.NA


def test_005_warn_found_but_not_parseable():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, text="not a spec at all", headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found_url"] is not None
    assert result.evidence["parseable"] is False


def test_005_catch_all_html_openapi_is_not_found_and_probing_continues():
    """A catch-all router answers 200 + HTML on /openapi.json. That candidate
    published no spec, so probing continues to the later candidates — and the
    real spec at /swagger.json is the one that is found."""
    spec = '{"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {}}'
    catch_all = (
        "<!doctype html><html><head><title>Not found</title></head><body>"
        "<h1>Page not found</h1><p>soft 404</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/swagger.json":
            return httpx.Response(200, text=spec, headers={"content-type": "application/json"})
        return httpx.Response(200, content=catch_all.encode(), headers={"content-type": "text/html"})

    store, ctx = _scan(make_client(handler), ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["found_url"] == "https://example.com/swagger.json"
    assert store.get("openapi")["served_as_html"] is True


def test_005_openapi_absent_behind_a_catch_all_reads_as_not_found():
    catch_all = (
        "<!doctype html><html><head><title>Not found</title></head><body>"
        "<h1>Page not found</h1><p>soft 404</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(200, content=catch_all.encode(), headers={"content-type": "text/html"})

    store, ctx = _scan(make_client(handler), ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["found_url"] is None
    assert "No OpenAPI document discovered" in result.summary


def test_005_json_openapi_spec_mislabeled_as_text_html_is_still_found():
    """A JSON body is a JSON body: an OpenAPI document served with
    `Content-Type: text/html` must be found and parsed, not skipped as a
    catch-all page."""
    spec = '{"openapi": "3.1.0", "info": {"title": "T", "version": "1"}, "paths": {}}'

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/openapi.json":
            return httpx.Response(200, text=spec, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["found_url"] == "https://example.com/openapi.json"
    assert result.evidence["parseable"] is True


def test_005_yaml_openapi_spec_mislabeled_as_text_html_is_still_found():
    spec = "openapi: 3.1.0\ninfo:\n  title: T\n  version: '1'\npaths: {}\n"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/openapi.yaml":
            return httpx.Response(200, text=spec, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), ScanOptions(profile="api"))
    result = OpenApiDiscovery().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["found_url"] == "https://example.com/openapi.yaml"

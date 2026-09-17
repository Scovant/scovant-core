from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/mcp_discovery/oauth_metadata/ucp/... gatherers
from scovant_core.checks.interfaces.core_interface_002 import McpServerDeclarationQuality
from scovant_core.checks.interfaces.core_interface_004 import WebMcpToolQuality
from scovant_core.checks.interfaces.core_interface_006 import OAuthAuthorizationServerMetadata
from scovant_core.checks.interfaces.core_interface_007 import OAuthProtectedResourceMetadata
from scovant_core.checks.interfaces.core_interface_008 import UcpProfilePresence
from scovant_core.checks.interfaces.core_interface_009 import AgentDiscoverySurfacePresence
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus
from scovant_core.profiles import apply_profile

from .conftest import make_client


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


_DEFAULT_INDEX = (
    "<!doctype html><html><head><title>Test</title></head><body>"
    "<h1>Test</h1><p>Minimal page with enough visible text for the parser "
    "to treat this as real content rather than an empty shell.</p></body></html>"
)


def _index_only_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/":
        return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
    return httpx.Response(404, text="not found")


def _connect_error_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("simulated network failure", request=request)


# ---------------------------------------------------------------------------
# 002 MCP server declaration quality
# ---------------------------------------------------------------------------

def test_002_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = McpServerDeclarationQuality().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["servers_count"] == 1


def test_002_na_when_no_servers_declared():
    store, ctx = _scan(make_client(_index_only_handler))
    result = McpServerDeclarationQuality().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_002_error_when_discovery_file_could_not_be_read():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpServerDeclarationQuality().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_002_warn_missing_fields():
    body = '{"mcpServers": {"svc": {"url": "https://example.com/mcp"}}}'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(200, text=body, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpServerDeclarationQuality().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["incomplete_servers"][0]["missing"] == ["transport"]


def test_002_warn_generic_description():
    body = (
        '{"mcpServers": {"svc": {"url": "https://example.com/mcp", "transport": "streamable-http", '
        '"description": "tools"}}}'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(200, text=body, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = McpServerDeclarationQuality().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "generic" in result.summary
    assert "incomplete_servers" not in result.evidence


# ---------------------------------------------------------------------------
# 004 WebMCP tool declaration quality (EXPERIMENTAL)
# ---------------------------------------------------------------------------

def test_004_na_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.experimental is True


def test_004_warn_parse_errors_only():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        "<script>navigator.modelContext.registerTool({name: 'x', unterminated: [1, 2 );</script>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["parse_errors"] >= 1
    assert result.evidence["tool_count"] == 0


def test_004_fail_when_tool_has_no_schema():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        "<script>navigator.modelContext.registerTool({"
        "name: 'search', description: 'Search the product catalog by keyword or category.'"
        "});</script>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["missing_schema"] == ["search"]


def test_004_warn_short_description():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        "<script>navigator.modelContext.registerTool({"
        "name: 'search', description: 'search', "
        "inputSchema: {type: 'object', properties: {q: {type: 'string'}}}"
        "});</script>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["short_description"] == ["search"]


def test_004_pass_when_tool_has_schema_and_description():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        "<script>navigator.modelContext.registerTool({"
        "name: 'search', description: 'Search the product catalog by keyword or category.', "
        "inputSchema: {type: 'object', properties: {q: {type: 'string'}}}"
        "});</script>"
        "</body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_004_error_when_no_page_could_be_parsed():
    store, ctx = _scan(make_client(_connect_error_handler))
    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_004_na_with_one_unread_page_records_pages_unread():
    """One parsed page (no tools) plus one page whose fetch resolved to a
    non-2xx status (so `parsed is None`) — `pages_unread`/`pages_total` must
    only appear in evidence when there IS an unread page, so the common
    all-readable-pages fixtures stay byte-identical (goldens)."""
    sitemap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.com/other</loc></url>"
        "</urlset>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/sitemap.xml":
            return httpx.Response(200, content=sitemap.encode(), headers={"content-type": "application/xml"})
        if path == "/other":
            return httpx.Response(500, text="server error")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    pages = store.get("pages")["pages"]
    assert len(pages) == 2
    assert any(p["parsed"] is None for p in pages)

    result = WebMcpToolQuality().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["pages_total"] == 2
    assert result.evidence["pages_unread"] == 1


# ---------------------------------------------------------------------------
# 006 OAuth authorization-server metadata
# ---------------------------------------------------------------------------

def test_006_na_on_absent():
    # api-good now publishes complete OAuth authorization-server metadata
    # (CORE-INTERFACE-006 PASS on that fixture, see fixtures/PROVENANCE.md) —
    # the N/A "absent (404)" path is exercised here against an isolated
    # index-only client instead.
    store, ctx = _scan(make_client(_index_only_handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["http_status"] == 404


def test_006_na_not_applicable_on_commerce_profile(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_006_pass_when_complete():
    metadata = (
        '{"issuer": "https://example.com", "authorization_endpoint": "https://example.com/authorize", '
        '"token_endpoint": "https://example.com/token"}'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, text=metadata, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["issuer"] == "https://example.com"


def test_006_warn_when_200_but_incomplete():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, text='{"issuer": "https://example.com"}', headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.WARN


def test_006_error_when_could_not_be_read():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_006_na_when_served_as_html_catch_all():
    """A 200 + HTML catch-all body is an ABSENT document (`_soft_200`'s
    contract), never 'found but incomplete' — must be N/A, not WARN."""
    catch_all = (
        "<!doctype html><html><head><title>Not found</title></head><body>"
        "<h1>Page not found</h1><p>soft 404</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, content=catch_all.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["served_as_html"] is True


def test_006_error_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(500, text="server error")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 500


def test_006_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(403, text="forbidden")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = OAuthAuthorizationServerMetadata().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 403


# ---------------------------------------------------------------------------
# 007 OAuth protected-resource metadata
# ---------------------------------------------------------------------------

def test_007_na_on_absent():
    # api-good now publishes complete OAuth protected-resource metadata
    # (CORE-INTERFACE-007 PASS on that fixture, see fixtures/PROVENANCE.md) —
    # the N/A "absent (404)" path is exercised here against an isolated
    # index-only client instead.
    store, ctx = _scan(make_client(_index_only_handler), options=ScanOptions(profile="api"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["http_status"] == 404


def test_007_pass_when_complete():
    metadata = (
        '{"resource": "https://example.com", "authorization_servers": ["https://example.com"],'
        ' "jwks_uri": "https://example.com/jwks.json", "scopes_supported": ["read"],'
        ' "dpop_bound_access_tokens_required": true}'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, text=metadata, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["resource_value"] == "https://example.com"
    # The five consistency/shape fields the gatherer computes must actually
    # reach a report — they were dead data before.
    for key in ("resource_matches_origin", "matches_issuer", "jwks_uri",
                "scopes_supported", "dpop_bound_access_tokens_required"):
        assert key in result.evidence, key
    assert result.evidence["resource_matches_origin"] is True
    assert result.evidence["jwks_uri"] == "https://example.com/jwks.json"
    assert result.evidence["scopes_supported"] == ["read"]
    assert result.evidence["dpop_bound_access_tokens_required"] is True
    # No authorization-server metadata document was served by this handler,
    # so its issuer consistency is unmeasured — never guessed as False.
    assert result.evidence["matches_issuer"] is None


def test_007_warn_when_200_but_incomplete():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, text='{"resource": "https://example.com"}', headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.WARN


def test_007_error_when_could_not_be_read():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_007_na_when_served_as_html_catch_all():
    catch_all = (
        "<!doctype html><html><head><title>Not found</title></head><body>"
        "<h1>Page not found</h1><p>soft 404</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, content=catch_all.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["served_as_html"] is True


def test_007_error_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(503, text="unavailable")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 503


def test_007_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(403, text="forbidden")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = OAuthProtectedResourceMetadata().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 403


# ---------------------------------------------------------------------------
# 008 UCP profile validity (EXPERIMENTAL)
# ---------------------------------------------------------------------------

def test_008_na_on_absent():
    # commerce-good now publishes a valid UCP profile (CORE-INTERFACE-008
    # PASS on that fixture, see fixtures/PROVENANCE.md) — the N/A "absent"
    # path is exercised here against an isolated index-only client instead.
    store, ctx = _scan(make_client(_index_only_handler), options=ScanOptions(profile="commerce"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.experimental is True


def test_008_na_not_applicable_on_api_profile(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.NA


_VALID_UCP_PROFILE = {
    "ucp": {
        "version": "1.0",
        "services": {
            "checkout": [
                {"version": "1.0", "spec": "https://example.com/ucp/checkout.json", "transport": "A2A"},
            ],
        },
        "capabilities": {
            "dev.ucp.commerce.checkout": [
                {
                    "version": "1.0",
                    "spec": "https://example.com/ucp/checkout-cap.json",
                    "schema": "https://example.com/ucp/checkout-cap.schema.json",
                },
            ],
        },
    },
    "signing_keys": [],
}


def test_008_pass_when_valid():
    profile = json.dumps(_VALID_UCP_PROFILE)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/ucp":
            return httpx.Response(200, text=profile, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_008_warn_when_exists_but_invalid():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/ucp":
            return httpx.Response(200, text='{"nope": true}', headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["validation_errors"]


def test_008_error_when_could_not_be_read():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/ucp":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_008_error_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/ucp":
            return httpx.Response(500, text="server error")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 500


def test_008_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/ucp":
            return httpx.Response(403, text="forbidden")
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = UcpProfilePresence().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["http_status"] == 403


# ---------------------------------------------------------------------------
# 009 Agent discovery surface presence (EXPERIMENTAL)
# ---------------------------------------------------------------------------

def test_009_na_when_none_found():
    # api-good now publishes an agent-card.json (CORE-INTERFACE-009 PASS on
    # that fixture, see fixtures/PROVENANCE.md) — the N/A "none found" path
    # is exercised here against an isolated index-only client instead.
    store, ctx = _scan(make_client(_index_only_handler), options=ScanOptions(profile="api"))
    result = AgentDiscoverySurfacePresence().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.experimental is True


def test_009_na_not_applicable_on_commerce_profile(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = AgentDiscoverySurfacePresence().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_009_pass_listing_surfaces_found():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/agent-card.json":
            return httpx.Response(200, json={"name": "example"})
        if request.url.path == "/.well-known/ai-plugin.json":
            return httpx.Response(200, json={"schema_version": "v1"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="saas"))
    result = AgentDiscoverySurfacePresence().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["found"] == ["a2a_card", "ai_plugin"]


def test_009_text_only_surface_recorded_but_not_scored():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/agents.txt":
            return httpx.Response(200, text="We welcome agents.", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="api"))
    result = AgentDiscoverySurfacePresence().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["agents_txt_present"] is True
    assert result.evidence["found"] == []

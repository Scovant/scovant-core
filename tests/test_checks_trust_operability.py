from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/contact/machine_links/... gatherers
from scovant_core.checks.operability.core_operability_004 import BrokenMachineEndpoints
from scovant_core.checks.trust.core_trust_001 import ContactDiscoverability
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


# ---------------------------------------------------------------------------
# TRUST-001 contact/support discoverability
# ---------------------------------------------------------------------------

def test_trust_001_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ContactDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["kind"] == "page"


def test_trust_001_warn_on_bad_no_contact_link(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = ContactDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["kind"] is None


def test_trust_001_pass_on_mailto():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        '<a href="mailto:hello@example.com">Email us</a></body></html>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = ContactDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["kind"] == "mailto"


def test_trust_001_warn_on_social_only():
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat this as real.</p>"
        '<a href="https://twitter.com/example">Follow us</a></body></html>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = ContactDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["kind"] == "social"


def test_trust_001_error_when_entry_page_could_not_be_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(500, text="server error")))
    result = ContactDiscoverability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# ---------------------------------------------------------------------------
# OPERABILITY-004 broken machine endpoints
# ---------------------------------------------------------------------------

def test_operability_004_declared_mcp_endpoint_is_inconclusive_not_broken(fixture_site):
    """The commerce-good fixture declares an MCP endpoint that answers 404 to
    a plain GET. An MCP endpoint speaks JSON-RPC over POST and Core never
    performs the handshake, so that 404 is evidence of nothing — it is
    recorded as `inconclusive` and must never fail the check."""
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["broken_count"] == 0
    inconclusive = {i["url"]: i for i in result.evidence["inconclusive"]}
    assert inconclusive["https://example.com/mcp"]["source"] == "mcp_endpoint"
    assert inconclusive["https://example.com/mcp"]["status"] == 404


def test_operability_004_fail_on_commerce_bad_canonical_and_llms(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    broken_urls = {b["url"] for b in result.evidence["broken"]}
    assert "https://example.org/elsewhere" in broken_urls
    assert "https://example.com/does-not-exist" in broken_urls


def test_operability_004_pass_on_api_good(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    assert ctx.profile == "api"
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["broken_count"] == 0
    assert result.evidence["refs_checked"] > 0


def test_operability_004_na_when_no_refs():
    store, ctx = _scan(make_client(lambda r: httpx.Response(404, text="not found")))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_operability_004_unresolved_transient_error_on_incidental_link_does_not_fail():
    """A connect error on a *policy* link (not a declared sitemap/llms/openapi/
    mcp_endpoint reference) is reported as `unresolved`, not `broken` — it
    must not fail the check on its own."""
    body = (
        "<!doctype html><html><head><title>t</title>"
        '<link rel="canonical" href="https://example.com/">'
        "</head><body><h1>t</h1><p>enough visible text content for the parser to treat as real.</p>"
        '<a href="/privacy">Privacy policy</a></body></html>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/privacy":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["broken_count"] == 0
    unresolved_urls = [u["url"] for u in result.evidence["unresolved"]]
    assert "https://example.com/privacy" in unresolved_urls


def test_operability_004_fetch_error_on_a_declared_ref_is_never_broken():
    """A ConnectTimeout on a DECLARED reference (the MCP endpoint the
    discovery file itself names) is OUR failure to read it, not the site's
    dead link — `unresolved`/`inconclusive`, never `broken`, whatever the
    source. Here it is the only reference, so nothing could be evaluated at
    all and the check degrades to ERROR rather than passing on nothing."""
    mcp_json = '{"mcpServers": {"s": {"url": "https://example.com/mcp"}}}'
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat as real.</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        if request.url.path == "/mcp":
            raise httpx.ConnectTimeout("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["broken"] == []
    assert result.evidence["broken_count"] == 0


def test_operability_004_unresolved_declared_ref_alongside_a_live_one_passes():
    """The same ConnectTimeout on a declared llms.txt reference, this time
    with other references that DID resolve: the check passes and records the
    unreadable one as `unresolved` — a document we could not read is never a
    finding."""
    llms = (
        "# Site\n\n> summary\n\n## Docs\n"
        "- [Up](https://example.com/ok)\n- [Down](https://example.com/timeout)\n"
    )
    body = (
        "<!doctype html><html><head><title>t</title></head><body>"
        "<h1>t</h1><p>enough visible text content for the parser to treat as real.</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms, headers={"content-type": "text/plain"})
        if path == "/timeout":
            raise httpx.ConnectTimeout("simulated network failure", request=request)
        if path == "/ok":
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["broken_count"] == 0
    assert [u["url"] for u in result.evidence["unresolved"]] == ["https://example.com/timeout"]


def test_operability_004_only_inconclusive_refs_is_na_not_error():
    """Every reference answered with a REAL status, but the only one there is
    is an MCP endpoint Core does not probe. Nothing failed to be read — there
    is genuinely nothing to evaluate, so N/A (not ERROR)."""
    mcp_json = '{"mcpServers": {"s": {"url": "https://example.com/mcp"}}}'

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["refs_resolved"] == 0
    assert result.evidence["unresolved"] == []
    assert [i["source"] for i in result.evidence["inconclusive"]] == ["mcp_endpoint"]


def test_operability_004_inconclusive_plus_unresolved_is_an_error():
    """Same shape, except one reference also failed OUR fetch. Nothing was
    judged AND some evidence is missing — that is unmeasured (ERROR, which
    lowers coverage), not "nothing to evaluate"."""
    mcp_json = '{"mcpServers": {"s": {"url": "https://example.com/mcp"}}}'
    llms = "# Site\n\n> summary\n\n## Docs\n- [Down](https://example.com/timeout)\n"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms, headers={"content-type": "text/plain"})
        if path == "/timeout":
            raise httpx.ConnectTimeout("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["refs_resolved"] == 0
    assert [u["url"] for u in result.evidence["unresolved"]] == ["https://example.com/timeout"]
    assert [i["source"] for i in result.evidence["inconclusive"]] == ["mcp_endpoint"]


def test_operability_004_fail_summary_counts_against_resolved_refs_only():
    """The denominator is what we actually read: "1 of 1", never "1 of 2"
    with an unread reference padding the total."""
    llms = (
        "# Site\n\n> summary\n\n## Docs\n"
        "- [Dead](https://example.com/dead)\n- [Down](https://example.com/timeout)\n"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms, headers={"content-type": "text/plain"})
        if path == "/timeout":
            raise httpx.ConnectTimeout("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = BrokenMachineEndpoints().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["refs_resolved"] == 1
    assert result.summary == "1 of 1 machine-consumable reference(s) do not resolve."

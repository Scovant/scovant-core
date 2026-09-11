"""Gatherer tests: llms, mcp_discovery, openapi, machine_links, contact."""
from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from tests.conftest import make_client

DOMAIN = "https://example.com"


def _store(fixture_site, name="commerce-good"):
    client = fixture_site(name)
    ctx = ScanContext("https://example.com/", ScanOptions())
    return EvidenceStore(client, ctx), ctx


def _store_for(handler):
    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions())
    return EvidenceStore(client, ctx), ctx


# ── llms ─────────────────────────────────────────────────────────────────


def test_llms_gatherer_parses_and_resolves_references(fixture_site):
    store, _ = _store(fixture_site)
    r = store.get("llms")
    assert r["status"] == 200
    assert r["parsed"]["valid"] is True
    assert len(r["references"]) == 2
    assert all(ref["status"] == 200 for ref in r["references"])
    urls = {ref["url"] for ref in r["references"]}
    assert urls == {"https://example.com/shipping", "https://example.com/returns"}
    assert r["full_exists"] is False


def test_llms_gatherer_absent():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("llms")
    assert r["status"] == 404
    assert r["parsed"]["exists"] is False
    assert r["references"] == []
    assert r["full_exists"] is False


def test_llms_gatherer_caps_references_at_20():
    links = "\n".join(f"- [Doc {i}](https://example.com/doc{i})" for i in range(25))
    content = f"# Site\n\n> desc\n\n## Docs\n{links}\n"

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text=content, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    store, _ = _store_for(handler)
    r = store.get("llms")
    assert len(r["parsed"]["urls"]) == 25
    assert len(r["references"]) == 20


# ── mcp_discovery ────────────────────────────────────────────────────────


def test_mcp_discovery_gatherer_finds_declared_endpoint(fixture_site):
    store, _ = _store(fixture_site)
    r = store.get("mcp_discovery")
    d = r["discovery"]
    assert d["exists"] is True and d["valid"] is True
    assert d["endpoints"] == ["https://example.com/mcp"]
    assert r["status"] == 200


def test_mcp_discovery_gatherer_absent():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("mcp_discovery")
    assert r["discovery"]["exists"] is False
    assert r["server_card"] is False
    assert r["status"] == 404


def test_mcp_discovery_gatherer_probes_server_card_when_declared():
    mcp_json = '{"mcpServers": {"s": {"url": "https://example.com/mcp"}}}'

    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        if path == "/.well-known/mcp/server-card.json":
            return httpx.Response(200, json={"name": "s"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("mcp_discovery")
    assert r["server_card"] is True
    assert r["discovery"]["server_card"] is True


# ── openapi ──────────────────────────────────────────────────────────────


def test_openapi_gatherer_none_found(fixture_site):
    store, _ = _store(fixture_site)
    r = store.get("openapi")
    assert r["found_url"] is None
    assert r["parseable"] is False
    assert r["openapi_version"] is None


def test_openapi_gatherer_found_and_parseable_json():
    spec = '{"openapi": "3.0.0", "info": {"title": "t"}}'

    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/openapi.json":
            return httpx.Response(200, text=spec, headers={"content-type": "application/json"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("openapi")
    assert r["found_url"] == "https://example.com/openapi.json"
    assert r["parseable"] is True
    assert r["openapi_version"] == "3.0.0"


def test_openapi_gatherer_found_but_not_parseable():
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/openapi.json":
            return httpx.Response(200, text="not a spec at all", headers={"content-type": "text/plain"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("openapi")
    assert r["found_url"] == "https://example.com/openapi.json"
    assert r["parseable"] is False
    assert r["openapi_version"] is None


def test_openapi_gatherer_finds_entry_page_link():
    spec = '{"swagger": "2.0"}'

    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(
                200,
                text='<html><body><a href="/api/swagger-spec.json">API spec</a></body></html>',
                headers={"content-type": "text/html"},
            )
        if path == "/api/swagger-spec.json":
            return httpx.Response(200, text=spec, headers={"content-type": "application/json"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("openapi")
    assert r["found_url"] == "https://example.com/api/swagger-spec.json"
    assert r["parseable"] is True
    assert r["openapi_version"] == "2.0"
    assert "https://example.com/api/swagger-spec.json" in r["candidates"]


# ── contact ──────────────────────────────────────────────────────────────


def test_contact_gatherer_finds_page_link(fixture_site):
    store, _ = _store(fixture_site)
    r = store.get("contact")
    assert r == {"contact_url": "https://example.com/contact", "kind": "page"}


def test_contact_gatherer_finds_mailto():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<html><body><a href="mailto:hi@example.com">Email us</a></body></html>',
                headers={"content-type": "text/html"},
            )
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("contact")
    assert r == {"contact_url": "mailto:hi@example.com", "kind": "mailto"}


def test_contact_gatherer_falls_back_to_social():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<html><body><a href="https://www.facebook.com/example">Follow us</a></body></html>',
                headers={"content-type": "text/html"},
            )
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("contact")
    assert r == {"contact_url": "https://www.facebook.com/example", "kind": "social"}


def test_contact_gatherer_none_found():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<html><body><a href=\"/about\">About</a></body></html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("contact")
    assert r == {"contact_url": None, "kind": None}


# ── machine_links ────────────────────────────────────────────────────────


def test_machine_links_gatherer_fixture_site(fixture_site):
    store, _ = _store(fixture_site)
    r = store.get("machine_links")
    refs_by_url = {ref["url"]: ref for ref in r["refs"]}
    assert refs_by_url["https://example.com/sitemap.xml"]["ok"] is True
    assert refs_by_url["https://example.com/sitemap.xml"]["source"] == "sitemap"
    mcp_ref = refs_by_url["https://example.com/mcp"]
    assert mcp_ref["source"] == "mcp_endpoint"
    assert mcp_ref["status"] == 404
    # recorded, never judged: Core does not speak MCP to the endpoint
    assert mcp_ref["ok"] is None
    assert mcp_ref["note"]
    assert len(r["refs"]) <= 30


def test_machine_links_gatherer_skips_canonical_refetch_when_equal_to_final_url(fixture_site):
    store, ctx = _store(fixture_site)
    r = store.get("machine_links")
    canonical_ref = next(ref for ref in r["refs"] if ref["source"] == "canonical")
    assert canonical_ref["url"] == ctx.final_url
    assert canonical_ref["ok"] is True
    assert canonical_ref["status"] == store.get("http")["status"]


def test_machine_links_reuses_llms_reference_statuses_without_refetching():
    """Every llms.txt reference was already resolved by the llms gatherer;
    machine_links must reuse those statuses rather than issuing a second GET
    for each one."""
    llms_content = "# Site\n\n> desc\n\n## Docs\n- [Doc](https://example.com/doc)\n"
    hits: list[str] = []

    def handler(request):
        path = request.url.path
        hits.append(path)
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms_content, headers={"content-type": "text/plain"})
        if path == "/doc":
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    store.get("llms")
    before = hits.count("/doc")
    r = store.get("machine_links")
    assert hits.count("/doc") == before  # no second fetch
    assert next(ref for ref in r["refs"] if ref["url"] == "https://example.com/doc")["status"] == 200


def test_machine_links_cap_never_drops_the_canonical_or_policy_refs():
    """With far more llms.txt references than the cap, the bounded sources
    (canonical, policy links) must still be in the inventory — CORE-ACCESS-007
    reads the canonical ref's status from here."""
    links = "\n".join(f"- [Doc {i}](https://example.com/doc{i})" for i in range(40))
    llms_content = f"# Site\n\n> desc\n\n## Docs\n{links}\n"
    body = (
        "<!doctype html><html><head><title>t</title>"
        '<link rel="canonical" href="https://example.com/canonical">'
        "</head><body><h1>t</h1><p>enough visible text content for the parser to treat as real.</p>"
        '<a href="/privacy">Privacy policy</a></body></html>'
    )

    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms_content, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    store, _ = _store_for(handler)
    r = store.get("machine_links")
    assert len(r["refs"]) == 30
    sources = {ref["source"] for ref in r["refs"]}
    assert {"canonical", "policy_link"} <= sources
    assert r["refs"][0]["source"] == "canonical"


def test_machine_links_gatherer_caps_at_30():
    links = "\n".join(f"- [Doc {i}](https://example.com/doc{i})" for i in range(40))
    llms_content = f"# Site\n\n> desc\n\n## Docs\n{links}\n"

    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms_content, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    store, _ = _store_for(handler)
    r = store.get("machine_links")
    assert len(r["refs"]) == 30

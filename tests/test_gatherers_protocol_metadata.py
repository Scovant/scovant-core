"""Gatherer tests: `policy_pages`, `security_txt`, `oauth_metadata`, `ucp`,
`agent_discovery_surface`, `mcp_discovery.servers`, `reference_integrity`."""
from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from tests.conftest import FixtureTransport, make_client

DOMAIN = "https://example.com"


def _store_for(handler):
    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions())
    return EvidenceStore(client, ctx), ctx


def _base_paths(extra: dict[str, httpx.Response], index_html: str) -> callable:
    """Handler serving `/` = index_html, `/robots.txt` and `/sitemap.xml` = 404
    (so the `pages`/`sitemap_urls` dependency chain resolves cleanly), plus
    whatever `extra` maps path -> Response."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text=index_html, headers={"content-type": "text/html"})
        if path in extra:
            return extra[path]
        return httpx.Response(404, text="not found")

    return handler


# ── policy_pages ─────────────────────────────────────────────────────────


def test_policy_pages_discovers_via_policy_links():
    index = (
        '<html><body><nav><a href="/shipping">Shipping</a> <a href="/returns">Returns</a></nav>'
        '<footer><a href="/privacy">Privacy</a> <a href="/terms">Terms</a></footer></body></html>'
    )
    extra = {
        "/shipping": httpx.Response(200, text="<html><body><p>We ship within two business days of order.</p></body></html>",
                                     headers={"content-type": "text/html"}),
        "/returns": httpx.Response(200, text="<html><body><p>Returns accepted within thirty days of purchase.</p></body></html>",
                                    headers={"content-type": "text/html"}),
        "/privacy": httpx.Response(200, text="<html><body><p>We only collect data needed to ship an order.</p></body></html>",
                                    headers={"content-type": "text/html"}),
        "/terms": httpx.Response(200, text="<html><body><p>By ordering you agree to these terms of service.</p></body></html>",
                                  headers={"content-type": "text/html"}),
    }
    store, _ = _store_for(_base_paths(extra, index))
    r = store.get("policy_pages")
    pages = r["pages"]
    assert pages["shipping"]["url"] == f"{DOMAIN}/shipping"
    assert pages["shipping"]["status"] == 200
    assert pages["shipping"]["text_chars"] > 0
    assert pages["shipping"]["served_as_html"] is True
    assert pages["shipping"]["has_price_text"] is False
    assert pages["shipping"]["has_structured_price"] is False
    assert pages["returns"]["url"] == f"{DOMAIN}/returns"
    assert pages["privacy"]["url"] == f"{DOMAIN}/privacy"
    assert pages["terms"]["url"] == f"{DOMAIN}/terms"
    assert pages["pricing"] is None
    assert "entry_unparsed" not in r


def test_policy_pages_anchor_discovery_for_pricing():
    """Pricing has no `policy_links` slot — this exercises the entry-page
    anchor fallback in isolation."""
    index = '<html><body><nav><a href="/pricing">Pricing &amp; Plans</a></nav></body></html>'
    extra = {
        "/pricing": httpx.Response(
            200, text="<html><body><p>Starter plan is $9/month, billed annually.</p></body></html>",
            headers={"content-type": "text/html"},
        ),
    }
    store, _ = _store_for(_base_paths(extra, index))
    r = store.get("policy_pages")
    pages = r["pages"]
    assert pages["pricing"]["url"] == f"{DOMAIN}/pricing"
    assert pages["pricing"]["has_price_text"] is True
    assert pages["shipping"] is None
    assert pages["returns"] is None
    assert pages["privacy"] is None
    assert pages["terms"] is None


def test_policy_pages_anchor_discovery_prefers_nav_footer_over_body_prose():
    """Both candidates below deliberately avoid `extract_policy_links`'s own
    ("terms"/"tos") patterns (its href/text checks would otherwise resolve
    `terms_url` directly via `policy_links`, before our own anchor fallback —
    which only runs on kinds `policy_links` left unresolved — ever gets a
    chance to choose between them). Using "legal" instead exercises our own
    fallback's DOM-order-vs-nav/footer tie-break in isolation: an earlier
    body-prose anchor must still lose to a later footer link."""
    index = (
        "<html><body>"
        '<a href="/blog/legal-musings">Legal thoughts on our policies</a>'
        "<footer><a href=\"/legal\">Legal</a></footer>"
        "</body></html>"
    )
    extra = {
        "/legal": httpx.Response(200, text="<html><body><p>Our terms of service.</p></body></html>",
                                  headers={"content-type": "text/html"}),
        "/blog/legal-musings": httpx.Response(
            200, text="<html><body><p>A long blog post, not a policy page.</p></body></html>",
            headers={"content-type": "text/html"},
        ),
    }
    store, _ = _store_for(_base_paths(extra, index))
    r = store.get("policy_pages")
    assert r["pages"]["terms"]["url"] == f"{DOMAIN}/legal"


def test_policy_pages_404_policy():
    index = '<html><body><a href="/shipping">Shipping</a></body></html>'
    extra = {"/shipping": httpx.Response(404, text="gone")}
    store, _ = _store_for(_base_paths(extra, index))
    r = store.get("policy_pages")
    shipping = r["pages"]["shipping"]
    assert shipping["url"] == f"{DOMAIN}/shipping"
    assert shipping["status"] == 404
    assert shipping["text_chars"] == 0
    assert shipping["has_price_text"] is False
    assert shipping["has_structured_price"] is False


def test_policy_pages_structured_price_jsonld():
    index = '<html><body><a href="/pricing">Pricing</a></body></html>'
    jsonld = json.dumps({"@context": "https://schema.org", "@type": "Offer", "price": "9.00", "priceCurrency": "USD"})
    extra = {
        "/pricing": httpx.Response(
            200,
            text=f'<html><body><script type="application/ld+json">{jsonld}</script>'
                 "<p>See our plans below.</p></body></html>",
            headers={"content-type": "text/html"},
        ),
    }
    store, _ = _store_for(_base_paths(extra, index))
    r = store.get("policy_pages")
    assert r["pages"]["pricing"]["has_structured_price"] is True


def test_policy_pages_fetches_at_most_five():
    # `/our-pricing-page` (not `/pricing`) deliberately dodges `pages.py`'s
    # `_PRODUCTISH` path pattern, which would otherwise fetch it a second
    # time as a "product_or_pricing" page pick and inflate the hit count
    # this test is asserting — this test is only about `policy_pages`' own
    # ≤5-fetch discipline.
    index = (
        '<html><body><nav><a href="/shipping">Shipping</a> <a href="/returns">Returns</a> '
        '<a href="/our-pricing-page">Pricing</a></nav>'
        '<footer><a href="/privacy">Privacy</a> <a href="/terms">Terms</a></footer></body></html>'
    )
    hits: dict[str, int] = {}
    policy_paths = {"/shipping", "/returns", "/privacy", "/terms", "/our-pricing-page"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text=index, headers={"content-type": "text/html"})
        if path in policy_paths:
            hits[path] = hits.get(path, 0) + 1
            return httpx.Response(200, text=f"<html><body><p>Content for {path}.</p></body></html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("policy_pages")
    assert all(r["pages"][kind] is not None for kind in ("shipping", "returns", "privacy", "terms", "pricing"))
    assert sum(hits.values()) == 5
    assert all(count == 1 for count in hits.values())


def test_policy_pages_entry_unparsed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    store, _ = _store_for(handler)
    r = store.get("policy_pages")
    assert r["entry_unparsed"] is True
    assert all(v is None for v in r["pages"].values())


# ── security_txt ─────────────────────────────────────────────────────────


def _sec_handler(well_known: httpx.Response | None, plain: httpx.Response | None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/security.txt":
            return well_known if well_known is not None else httpx.Response(404, text="not found")
        if path == "/security.txt":
            return plain if plain is not None else httpx.Response(404, text="not found")
        return httpx.Response(404, text="not found")

    return handler


def test_security_txt_well_known_valid():
    body = "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"
    wk = httpx.Response(200, text=body, headers={"content-type": "text/plain"})
    store, _ = _store_for(_sec_handler(wk, None))
    r = store.get("security_txt")
    assert r["found_url"] == f"{DOMAIN}/.well-known/security.txt"
    assert r["status"] == 200
    assert r["contact"] is True
    assert r["expires"] == "2030-01-01T00:00:00Z"
    assert r["expires_valid"] is True
    assert r["served_as_html"] is False


def test_security_txt_expired():
    body = "Contact: mailto:security@example.com\nExpires: 2020-01-01\n"
    wk = httpx.Response(200, text=body, headers={"content-type": "text/plain"})
    store, _ = _store_for(_sec_handler(wk, None))
    r = store.get("security_txt")
    assert r["expires_valid"] is False


def test_security_txt_no_expires():
    body = "Contact: mailto:security@example.com\n"
    wk = httpx.Response(200, text=body, headers={"content-type": "text/plain"})
    store, _ = _store_for(_sec_handler(wk, None))
    r = store.get("security_txt")
    assert r["expires"] is None
    assert r["expires_valid"] is None


def test_security_txt_only_plain_path():
    body = "Contact: mailto:security@example.com\n"
    plain = httpx.Response(200, text=body, headers={"content-type": "text/plain"})
    store, _ = _store_for(_sec_handler(None, plain))
    r = store.get("security_txt")
    assert r["found_url"] == f"{DOMAIN}/security.txt"
    assert r["status"] == 200
    assert r["contact"] is True


def test_security_txt_missing():
    store, _ = _store_for(_sec_handler(None, None))
    r = store.get("security_txt")
    assert r["found_url"] is None
    assert r["status"] == 404
    assert r["contact"] is False
    assert r["expires"] is None
    assert r["expires_valid"] is None


def test_security_txt_definitive_answer_survives_later_fetch_error():
    """A 404 on the first path followed by a network error on the second
    must still report the definitive 404, not None — only when EVERY path
    errors is the status unmeasured."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/security.txt":
            return httpx.Response(404, text="not found")
        if path == "/security.txt":
            raise httpx.ConnectError("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("security_txt")
    assert r["found_url"] is None
    assert r["status"] == 404


def test_security_txt_fetch_error_then_definitive_answer():
    """The reverse order — a network error on the first path, a real 404 on
    the second — must also report the definitive 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/security.txt":
            raise httpx.ConnectError("simulated network failure", request=request)
        if path == "/security.txt":
            return httpx.Response(404, text="not found")
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("security_txt")
    assert r["found_url"] is None
    assert r["status"] == 404


def test_security_txt_served_as_html():
    soft = httpx.Response(200, text="<html><body>Not found</body></html>", headers={"content-type": "text/html"})
    store, _ = _store_for(_sec_handler(soft, soft))
    r = store.get("security_txt")
    assert r["found_url"] is None
    assert r["served_as_html"] is True


# ── conftest: FixtureTransport `.headers` sidecar ───────────────────────


def test_fixture_transport_headers_sidecar(tmp_path):
    (tmp_path / "foo.txt").write_text("hello")
    (tmp_path / "foo.txt.headers").write_text(json.dumps({"x-test-header": "sidecar-value"}))
    client = make_client(FixtureTransport(tmp_path))
    res = client.fetch(f"{DOMAIN}/foo.txt", kind="text")
    assert res.status == 200
    assert res.headers.get("x-test-header") == "sidecar-value"


# ── oauth_metadata ───────────────────────────────────────────────────────


def _oauth_handler(as_resp: httpx.Response | None, pr_resp: httpx.Response | None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/oauth-authorization-server":
            return as_resp if as_resp is not None else httpx.Response(404, text="not found")
        if path == "/.well-known/oauth-protected-resource":
            return pr_resp if pr_resp is not None else httpx.Response(404, text="not found")
        return httpx.Response(404, text="not found")

    return handler


def test_oauth_metadata_authorization_server_valid():
    body = json.dumps({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
    })
    as_resp = httpx.Response(200, text=body, headers={"content-type": "application/json"})
    store, _ = _store_for(_oauth_handler(as_resp, None))
    r = store.get("oauth_metadata")
    asrv = r["authorization_server"]
    assert asrv["status"] == 200
    assert asrv["parseable"] is True
    assert asrv["issuer"] == "https://auth.example.com"
    assert asrv["has_endpoints"] is True
    assert asrv["served_as_html"] is False


def test_oauth_metadata_protected_resource_valid():
    body = json.dumps({
        "resource": "https://api.example.com",
        "authorization_servers": ["https://auth.example.com"],
    })
    pr_resp = httpx.Response(200, text=body, headers={"content-type": "application/json"})
    store, _ = _store_for(_oauth_handler(None, pr_resp))
    r = store.get("oauth_metadata")
    pr = r["protected_resource"]
    assert pr["status"] == 200
    assert pr["parseable"] is True
    assert pr["resource"] == "https://api.example.com"
    assert pr["authorization_servers"] == ["https://auth.example.com"]
    assert pr["served_as_html"] is False


def test_oauth_metadata_both_absent():
    store, _ = _store_for(_oauth_handler(None, None))
    r = store.get("oauth_metadata")
    assert r["authorization_server"]["status"] == 404
    assert r["authorization_server"]["parseable"] is False
    assert r["authorization_server"]["issuer"] is None
    assert r["authorization_server"]["has_endpoints"] is False
    assert r["protected_resource"]["status"] == 404
    assert r["protected_resource"]["parseable"] is False
    assert r["protected_resource"]["resource"] is None
    assert r["protected_resource"]["authorization_servers"] == []


def test_oauth_metadata_served_as_html_treated_as_absent():
    soft = httpx.Response(200, text="<html><body>Not found</body></html>", headers={"content-type": "text/html"})
    store, _ = _store_for(_oauth_handler(soft, None))
    r = store.get("oauth_metadata")
    asrv = r["authorization_server"]
    assert asrv["status"] == 200
    assert asrv["served_as_html"] is True
    assert asrv["parseable"] is False
    assert asrv["issuer"] is None
    assert asrv["has_endpoints"] is False


# ── ucp ──────────────────────────────────────────────────────────────────


def _ucp_handler(resp: httpx.Response | None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/ucp":
            return resp if resp is not None else httpx.Response(404, text="not found")
        return httpx.Response(404, text="not found")

    return handler


def test_ucp_gatherer_valid_profile():
    profile = json.dumps({
        "ucp": {
            "version": "1.0",
            "services": {},
            "capabilities": {},
        },
        "signing_keys": [],
    })
    resp = httpx.Response(200, text=profile, headers={"content-type": "application/json"})
    store, _ = _store_for(_ucp_handler(resp))
    r = store.get("ucp")
    assert r["exists"] is True
    assert r["status"] == 200
    assert r["served_as_html"] is False
    assert r["version"] == "1.0"


def test_ucp_gatherer_invalid_json():
    resp = httpx.Response(200, text="not json at all", headers={"content-type": "application/json"})
    store, _ = _store_for(_ucp_handler(resp))
    r = store.get("ucp")
    assert r["exists"] is True
    assert r["valid"] is False
    assert r["status"] == 200


def test_ucp_gatherer_absent():
    store, _ = _store_for(_ucp_handler(None))
    r = store.get("ucp")
    assert r["exists"] is False
    assert r["status"] == 404
    assert r["served_as_html"] is False


# ── agent_discovery_surface ──────────────────────────────────────────────


def test_agent_discovery_surface_finds_a2a_card():
    card = json.dumps({"name": "Example Agent"})

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/agent-card.json":
            return httpx.Response(200, text=card, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("agent_discovery_surface")
    assert r["any_found"] is True
    assert r["surfaces"]["a2a_card"]["exists"] is True
    assert r["surfaces"]["a2a_card_legacy"]["exists"] is False


def test_agent_discovery_surface_none_found():
    store, _ = _store_for(_base_paths({}, "<html><body></body></html>"))
    r = store.get("agent_discovery_surface")
    assert r["any_found"] is False


# ── mcp_discovery.servers ────────────────────────────────────────────────


def test_mcp_discovery_servers_from_dict_form():
    mcp_json = json.dumps({
        "mcpServers": {
            "shop": {
                "url": "https://example.com/mcp",
                "transport": "streamable-http",
                "description": "Catalog tools",
                "auth": "oauth2",
            }
        }
    })

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("mcp_discovery")
    servers = r["discovery"]["servers"]
    assert servers == [{
        "name": "shop", "url": "https://example.com/mcp", "transport": "streamable-http",
        "description": "Catalog tools", "auth": "oauth2",
    }]


def test_mcp_discovery_servers_from_list_form():
    mcp_json = json.dumps({
        "mcpServers": [
            {"name": "shop", "url": "https://example.com/mcp", "transport": "streamable-http",
             "authentication": "bearer"},
        ]
    })

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("mcp_discovery")
    servers = r["discovery"]["servers"]
    assert servers[0]["name"] == "shop"
    assert servers[0]["auth"] == "bearer"


def test_mcp_discovery_servers_auth_key_variants_and_none():
    mcp_json = json.dumps({
        "mcpServers": {
            "a": {"url": "u1", "authorization": "token-x"},
            "b": {"url": "u2"},
        }
    })

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    store, _ = _store_for(handler)
    r = store.get("mcp_discovery")
    by_name = {s["name"]: s for s in r["discovery"]["servers"]}
    assert by_name["a"]["auth"] == "token-x"
    assert by_name["b"]["auth"] is None


# ── reference_integrity ──────────────────────────────────────────────────


def test_reference_integrity_off_by_default_no_network():
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions(experimental=False))
    store = EvidenceStore(client, ctx)
    r = store.get("reference_integrity")
    assert r == {"attempted": False, "reason": "experimental_off", "truncated": False}
    # no oauth/ucp/agent-discovery/mcp/llms probing happened either.
    assert "/llms.txt" not in calls
    assert "/.well-known/mcp.json" not in calls


def test_reference_integrity_on_composes_text_and_omits_user_agent_kwarg(monkeypatch):
    """The gatherer does NOT pass `user_agent=` to `check_instruction_integrity`
    — it passes `fetch=`, which replaces that function's own internal
    `httpx.Client` entirely (the only place `user_agent` would apply), and
    the passed-in `fetch` is built over `SecureClient`, which already sets
    `CORE_USER_AGENT` on every request it makes."""
    import scovant_core.gatherers.reference_integrity as ri_module

    captured = {}

    def fake_check_instruction_integrity(text, *, self_domain=None, user_agent=None, **kwargs):
        captured["text"] = text
        captured["self_domain"] = self_domain
        captured["user_agent"] = user_agent
        return {"attempted": True, "checked": 0, "references": [], "remote_exec": [],
                "budget_exhausted": False}

    monkeypatch.setattr(ri_module, "check_instruction_integrity", fake_check_instruction_integrity)

    llms_content = "# Site\n\n> A description.\n"
    mcp_json = json.dumps({
        "mcpServers": {"shop": {"url": "https://example.com/mcp", "description": "Catalog tools"}}
    })

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms_content, headers={"content-type": "text/plain"})
        if path == "/.well-known/mcp.json":
            return httpx.Response(200, text=mcp_json, headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions(experimental=True))
    store = EvidenceStore(client, ctx)
    r = store.get("reference_integrity")

    assert r["attempted"] is True
    assert llms_content in captured["text"]
    assert "Catalog tools" in captured["text"]
    assert captured["self_domain"] == "example.com"
    assert captured["user_agent"] is None  # not passed — the fake's own default


def test_reference_integrity_does_not_clobber_probes_own_attempted_false(monkeypatch):
    """The probe can signal its OWN internal failure via `attempted: False`
    (an extraction exception) — the gatherer must never overwrite that back
    to True; it only fills the key in when the probe's result is silent
    about it."""
    import scovant_core.gatherers.reference_integrity as ri_module

    def fake_check_instruction_integrity(text, *, self_domain=None, user_agent=None, **kwargs):
        return {"attempted": False, "error": "extract_failed"}

    monkeypatch.setattr(ri_module, "check_instruction_integrity", fake_check_instruction_integrity)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions(experimental=True))
    store = EvidenceStore(client, ctx)
    r = store.get("reference_integrity")

    assert r["attempted"] is False
    assert r["error"] == "extract_failed"

from __future__ import annotations

import datetime
import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers import security_txt as sec_mod

from .conftest import make_client

_HTML = "<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>" + "text " * 40 + "</p></body></html>"


def _store(handler, url="https://example.com/"):
    client = make_client(handler)
    ctx = ScanContext(url, ScanOptions())
    return EvidenceStore(client, ctx), client


def _site(extra_headers=None, http_handler=None):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http":
            return http_handler(req) if http_handler else httpx.Response(301, headers={"location": "https://example.com/"})
        if req.url.path == "/":
            h = [("content-type", "text/html")] + list(extra_headers or [])
            return httpx.Response(200, headers=h, text=_HTML)
        return httpx.Response(404, text="nf")
    return handler


def test_http_records_cookie_attributes_without_values():
    store, client = _store(_site([
        ("set-cookie", "sessionid=SECRETVALUE123; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ("set-cookie", "_ga=GA1.2.3; Max-Age=63072000"),
    ]))
    http = store.get("http")
    assert http["set_cookie"] == [
        {"name": "sessionid", "secure": True, "httponly": True, "samesite": "lax", "path": "/", "domain": None, "max_age_present": False},
        {"name": "_ga", "secure": False, "httponly": False, "samesite": None, "path": None, "domain": None, "max_age_present": True},
    ]
    assert "SECRETVALUE123" not in json.dumps(http["set_cookie"])


def test_http_security_headers_subset_lowercased():
    store, _ = _store(_site([("Strict-Transport-Security", "max-age=63072000"), ("X-Content-Type-Options", "nosniff"), ("X-Powered-By", "x")]))
    sh = store.get("http")["security_headers"]
    assert sh == {"strict-transport-security": "max-age=63072000", "x-content-type-options": "nosniff"}


def test_http_downgrade_probe_records_redirect_to_https():
    store, client = _store(_site())
    d = store.get("http")["downgrade"]
    assert d == {"attempted": True, "status": 301, "final_scheme": "https", "redirected_to_https": True, "error": None}
    assert [r["url"] for r in client.requests].count("http://example.com/") == 1


def test_http_downgrade_probe_plain_200_over_http():
    store, _ = _store(_site(http_handler=lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=_HTML)))
    d = store.get("http")["downgrade"]
    assert d["attempted"] and d["status"] == 200 and d["final_scheme"] == "http" and d["redirected_to_https"] is False


def test_http_downgrade_probe_skipped_when_entry_is_http():
    store, client = _store(_site(http_handler=lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=_HTML)), url="http://example.com/")
    assert store.get("http")["downgrade"] == {"attempted": False, "status": None, "final_scheme": None, "redirected_to_https": None, "error": None}


def test_security_txt_canonical_fields(monkeypatch):
    monkeypatch.setattr(sec_mod, "today", lambda: datetime.date(2026, 9, 16))
    body = "Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://example.com/.well-known/security.txt\n"
    def handler(req):
        if req.url.path == "/.well-known/security.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=body)
        return _site()(req)
    store, _ = _store(handler)
    s = store.get("security_txt")
    assert s["canonical_location"] is True
    assert s["canonical_uris"] == ["https://example.com/.well-known/security.txt"]
    assert s["expires_parsed"] == "2027-01-01" and s["expired"] is False


def test_security_txt_legacy_location_and_expired(monkeypatch):
    monkeypatch.setattr(sec_mod, "today", lambda: datetime.date(2026, 9, 16))
    def handler(req):
        if req.url.path == "/security.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text="Contact: mailto:a@example.com\nExpires: 2025-01-01T00:00:00Z\n")
        return _site()(req)
    store, _ = _store(handler)
    s = store.get("security_txt")
    assert s["canonical_location"] is False and s["expired"] is True and s["canonical_uris"] == []


def test_oauth_metadata_consistency_fields():
    pr = {"resource": "https://example.com", "authorization_servers": ["https://auth.example.com"],
          "scopes_supported": ["read", "write"], "jwks_uri": "https://example.com/jwks", "dpop_bound_access_tokens_required": True}
    def handler(req):
        if req.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, headers={"content-type": "application/json"}, text=json.dumps(pr))
        if req.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, headers={"content-type": "application/json"},
                                  text=json.dumps({"issuer": "https://example.com", "authorization_endpoint": "https://example.com/a", "token_endpoint": "https://example.com/t"}))
        return _site()(req)
    store, _ = _store(handler)
    o = store.get("oauth_metadata")
    assert o["protected_resource"]["scopes_supported"] == ["read", "write"]
    assert o["protected_resource"]["jwks_uri"] == "https://example.com/jwks"
    assert o["protected_resource"]["resource_matches_origin"] is True
    assert o["protected_resource"]["dpop_bound_access_tokens_required"] is True
    assert o["authorization_server"]["matches_issuer"] is True

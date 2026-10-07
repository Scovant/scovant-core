"""CORE-SECURITY-017/018 — which origin the published metadata is compared
against. The documents are judged against the origin that actually SERVED
them (after redirects), a default port is the same origin, and a sibling host
on the same registrable domain is a medium WARN, never a high FAIL."""
from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.checks.security.oauth import (
    AuthorizationServerConsistency,
    ProtectedResourceConsistency,
)
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus, Severity
from scovant_core.profiles import apply_profile

from .conftest import make_client

_INDEX = "<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>" + "words " * 40 + "</p></body></html>"
_AS = "/.well-known/oauth-authorization-server"
_PR = "/.well-known/oauth-protected-resource"

_GOOD_AS = {"authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True}


def _scan(routes: dict, start: str = "https://example.com/"):
    """routes: (host, path) -> (status, body, headers)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text=_INDEX, headers={"content-type": "text/html"})
        hit = routes.get((request.url.host, request.url.path))
        if hit is None:
            return httpx.Response(404, text="not found")
        status, body, headers = hit
        return httpx.Response(status, text=body, headers=headers)

    # The SSRF guard resolves every hop's host; the sibling hosts used here
    # have no DNS records, so they are named as test-only private hosts.
    hosts = frozenset(h for h, _ in routes) | {"example.com", "www.example.com"}
    ctx = ScanContext(start, ScanOptions())
    store = EvidenceStore(make_client(handler, allow_private_networks=True, private_hosts=hosts), ctx)
    apply_profile(ctx, store)
    return store, ctx


def _json(doc):
    return (200, json.dumps(doc), {"content-type": "application/json"})


def _redirect(to):
    return (302, "", {"location": to})


def test_018_issuer_judged_against_where_the_redirected_document_was_served():
    store, ctx = _scan({
        ("example.com", _AS): _redirect(f"https://auth.example.com{_AS}"),
        ("auth.example.com", _AS): _json({**_GOOD_AS, "issuer": "https://auth.example.com"}),
    })
    rec = store.get("oauth_metadata")["authorization_server"]
    assert rec["served_url"] == f"https://auth.example.com{_AS}"
    r = AuthorizationServerConsistency().run(store, ctx)
    assert "issuer_mismatch" not in r.evidence["problems"], r.summary
    assert r.status == CheckStatus.PASS


def test_017_resource_judged_against_where_the_redirected_document_was_served():
    store, ctx = _scan({
        ("www.example.com", _PR): _redirect(f"https://example.com{_PR}"),
        ("example.com", _PR): _json({"resource": "https://example.com",
                                     "authorization_servers": ["https://example.com"]}),
    }, start="https://www.example.com/")
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.PASS, r.summary


def test_017_sibling_host_resource_is_a_medium_warn_not_a_high_fail():
    store, ctx = _scan({
        ("www.example.com", _PR): _json({"resource": "https://example.com",
                                         "authorization_servers": ["https://example.com"]}),
    }, start="https://www.example.com/")
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.WARN and r.severity == Severity.MEDIUM, r.summary
    assert "resource_sibling_host" in r.evidence["problems"]
    assert "resource_other_origin" not in r.evidence["problems"]


def test_018_sibling_host_issuer_is_a_medium_warn_not_a_high_fail():
    store, ctx = _scan({
        ("www.example.com", _AS): _json({**_GOOD_AS, "issuer": "https://example.com"}),
    }, start="https://www.example.com/")
    r = AuthorizationServerConsistency().run(store, ctx)
    assert r.status == CheckStatus.WARN and r.severity == Severity.MEDIUM, r.summary
    assert "issuer_sibling_host" in r.evidence["problems"]
    assert "issuer_mismatch" not in r.evidence["problems"]


def test_other_registrable_domain_still_fails_high():
    store, ctx = _scan({
        ("example.com", _AS): _json({**_GOOD_AS, "issuer": "https://login.other.test"}),
        ("example.com", _PR): _json({"resource": "https://api.other.test",
                                     "authorization_servers": ["https://login.other.test"]}),
    })
    assert AuthorizationServerConsistency().run(store, ctx).status == CheckStatus.FAIL
    assert ProtectedResourceConsistency().run(store, ctx).status == CheckStatus.FAIL


def test_same_host_issuer_with_a_path_still_fails():
    store, ctx = _scan({("example.com", _AS): _json({**_GOOD_AS, "issuer": "https://example.com/tenant"})})
    r = AuthorizationServerConsistency().run(store, ctx)
    assert r.status == CheckStatus.FAIL and "issuer_mismatch" in r.evidence["problems"]


def test_default_https_port_is_the_same_origin():
    store, ctx = _scan({
        ("example.com", _AS): _json({**_GOOD_AS, "issuer": "https://example.com:443"}),
        ("example.com", _PR): _json({"resource": "https://example.com:443/",
                                     "authorization_servers": ["https://example.com"]}),
    })
    a = AuthorizationServerConsistency().run(store, ctx)
    p = ProtectedResourceConsistency().run(store, ctx)
    assert "issuer_mismatch" not in a.evidence["problems"], a.summary
    assert "issuer_not_in_protected_resource" not in a.evidence["problems"], a.summary
    assert p.status == CheckStatus.PASS, p.summary


def test_issuer_listing_compares_the_path_case_sensitively():
    store, ctx = _scan({
        ("example.com", _AS): _json({**_GOOD_AS, "issuer": "https://example.com/Tenant"}),
        ("example.com", _PR): _json({"resource": "https://example.com",
                                     "authorization_servers": ["https://example.com/tenant"]}),
    })
    r = AuthorizationServerConsistency().run(store, ctx)
    assert "issuer_not_in_protected_resource" in r.evidence["problems"]
    # Host case and a trailing slash still compare equal.
    store, ctx = _scan({
        ("example.com", _AS): _json({**_GOOD_AS, "issuer": "https://example.com/Tenant"}),
        ("example.com", _PR): _json({"resource": "https://example.com",
                                     "authorization_servers": ["https://EXAMPLE.com/Tenant/"]}),
    })
    r = AuthorizationServerConsistency().run(store, ctx)
    assert "issuer_not_in_protected_resource" not in r.evidence["problems"]

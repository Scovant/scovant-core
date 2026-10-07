"""CORE-SECURITY-017/018 — a field published with the wrong JSON type is
reported as such, not as "not declared" / "not advertised" (0.15.1)."""
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
_GOOD_AS = {"issuer": "https://example.com", "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token", "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True}


def _scan(as_doc=None, pr_doc=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text=_INDEX, headers={"content-type": "text/html"})
        doc = {_AS: as_doc, _PR: pr_doc}.get(request.url.path)
        if doc is None:
            return httpx.Response(404, text="not found")
        return httpx.Response(200, text=json.dumps(doc), headers={"content-type": "application/json"})

    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    return store, ctx


def test_017_resource_of_the_wrong_type_is_named_as_such():
    store, ctx = _scan(pr_doc={"resource": 42, "authorization_servers": ["https://example.com"]})
    r = ProtectedResourceConsistency().run(store, ctx)
    assert "resource_not_a_string" in r.evidence["problems"]
    assert "resource_missing" not in r.evidence["problems"]
    assert r.status == CheckStatus.WARN and r.severity == Severity.MEDIUM
    assert "not as a string" in r.summary


def test_018_issuer_of_the_wrong_type_is_named_as_such_and_still_fails():
    store, ctx = _scan(as_doc={**_GOOD_AS, "issuer": {"url": "https://example.com"}})
    r = AuthorizationServerConsistency().run(store, ctx)
    assert "issuer_not_a_string" in r.evidence["problems"]
    assert "issuer_missing" not in r.evidence["problems"]
    assert r.status == CheckStatus.FAIL
    assert "not as a string" in r.summary


def test_018_iss_flag_published_as_a_string_is_named_as_such():
    store, ctx = _scan(as_doc={**_GOOD_AS, "authorization_response_iss_parameter_supported": "true"})
    r = AuthorizationServerConsistency().run(store, ctx)
    assert "iss_parameter_not_boolean" in r.evidence["problems"]
    assert "iss_parameter_not_advertised" not in r.evidence["problems"]
    assert r.status == CheckStatus.WARN and r.severity == Severity.LOW
    assert "boolean" in r.summary
    assert r.evidence["iss_parameter_published"] == "true"


def test_absent_fields_keep_their_existing_findings():
    store, ctx = _scan(as_doc={k: v for k, v in _GOOD_AS.items()
                               if k not in ("issuer", "authorization_response_iss_parameter_supported")},
                       pr_doc={"authorization_servers": ["https://example.com"]})
    a = AuthorizationServerConsistency().run(store, ctx)
    p = ProtectedResourceConsistency().run(store, ctx)
    assert "issuer_missing" in a.evidence["problems"] and "iss_parameter_not_advertised" in a.evidence["problems"]
    assert "resource_missing" in p.evidence["problems"]

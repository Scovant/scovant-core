"""Additive fields the OAuth security checks read (spec §3). `None` means the
field was not published — never False."""
from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.profiles import apply_profile

from .conftest import make_client

_INDEX = "<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>" + "words " * 40 + "</p></body></html>"


def _record(as_doc=None, pr_doc=None, host="example.com"):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text=_INDEX, headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server" and as_doc is not None:
            return httpx.Response(200, text=json.dumps(as_doc), headers={"content-type": "application/json"})
        if request.url.path == "/.well-known/oauth-protected-resource" and pr_doc is not None:
            return httpx.Response(200, text=json.dumps(pr_doc), headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    ctx = ScanContext(f"https://{host}/", ScanOptions())
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    return store.get("oauth_metadata")


FULL_AS = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "code_challenge_methods_supported": ["S256"],
    "authorization_response_iss_parameter_supported": True,
    "registration_endpoint": "https://example.com/register",
    "client_id_metadata_document_supported": True,
}


def test_gatherer_reads_every_new_authorization_server_field():
    a = _record(as_doc=FULL_AS)["authorization_server"]
    assert a["issuer_exact"] is True
    assert a["authorization_endpoint"] == "https://example.com/authorize"
    assert a["token_endpoint"] == "https://example.com/token"
    assert a["code_challenge_methods_supported"] == ["S256"]
    assert a["iss_parameter_supported"] is True
    assert a["registration_endpoint"] == "https://example.com/register"
    assert a["client_id_metadata_document_supported"] is True


def test_gatherer_unpublished_fields_are_none_not_false():
    a = _record(as_doc={"issuer": "https://example.com"})["authorization_server"]
    for key in ("authorization_endpoint", "token_endpoint", "code_challenge_methods_supported",
                "iss_parameter_supported", "registration_endpoint", "client_id_metadata_document_supported"):
        assert a[key] is None, key


def test_gatherer_wrong_typed_fields_are_none():
    a = _record(as_doc={"issuer": "https://example.com", "code_challenge_methods_supported": "S256",
                        "authorization_response_iss_parameter_supported": "yes",
                        "token_endpoint": 7})["authorization_server"]
    assert a["code_challenge_methods_supported"] is None
    assert a["iss_parameter_supported"] is None
    assert a["token_endpoint"] is None


def test_gatherer_issuer_exact_tolerates_case_and_one_trailing_slash():
    assert _record(as_doc={"issuer": "https://Example.com/"})["authorization_server"]["issuer_exact"] is True


def test_gatherer_issuer_exact_false_for_other_host_or_a_path():
    assert _record(as_doc={"issuer": "https://auth.example.com"})["authorization_server"]["issuer_exact"] is False
    assert _record(as_doc={"issuer": "https://example.com/tenant"})["authorization_server"]["issuer_exact"] is False


def test_gatherer_issuer_exact_none_without_an_issuer():
    assert _record(as_doc={"token_endpoint": "https://example.com/t"})["authorization_server"]["issuer_exact"] is None


def test_gatherer_authorization_servers_valid_three_ways():
    pr = lambda doc: _record(pr_doc=doc)["protected_resource"]["authorization_servers_valid"]  # noqa: E731
    assert pr({"resource": "https://example.com"}) is None
    assert pr({"resource": "https://example.com", "authorization_servers": []}) is False
    assert pr({"resource": "https://example.com", "authorization_servers": ["https://auth.example.com", 5]}) is False
    assert pr({"resource": "https://example.com", "authorization_servers": "https://auth.example.com"}) is False
    assert pr({"resource": "https://example.com", "authorization_servers": ["https://auth.example.com"]}) is True


def test_gatherer_no_documents_leaves_new_fields_none():
    rec = _record()
    assert rec["authorization_server"]["issuer_exact"] is None
    assert rec["protected_resource"]["authorization_servers_valid"] is None

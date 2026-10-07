"""CORE-SECURITY-017/018 — passive OAuth metadata consistency (gap-audit D slice 1)."""
from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.checks.security.oauth import ProtectedResourceConsistency
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus, Confidence, Severity
from scovant_core.profiles import apply_profile

from .conftest import make_client

_INDEX = "<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>" + "words " * 40 + "</p></body></html>"
_AS = "/.well-known/oauth-authorization-server"
_PR = "/.well-known/oauth-protected-resource"


def _scan(routes: dict, **policy):
    """routes: path -> (status, body_text) or an Exception to raise."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text=_INDEX, headers={"content-type": "text/html"})
        hit = routes.get(request.url.path)
        if isinstance(hit, Exception):
            raise hit
        if hit is None:
            return httpx.Response(404, text="not found")
        status, body = hit
        return httpx.Response(status, text=body, headers={"content-type": "application/json"})

    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(make_client(handler, **policy), ctx)
    apply_profile(ctx, store)
    return store, ctx


def _pr(doc):
    return {_PR: (200, json.dumps(doc))}


GOOD_PR = {"resource": "https://example.com", "authorization_servers": ["https://example.com"],
           "jwks_uri": "https://example.com/jwks.json"}


def test_017_declares_the_contract():
    c = ProtectedResourceConsistency
    assert (c.id, c.family_id, c.security_domain, c.fix_owner) == ("CORE-SECURITY-017", "MCP-AUTH-011", "auth", "identity")
    assert c.experimental and c.promotion_criteria and c.verification_mode == "PASSIVE_OBSERVED"
    assert c.profiles is None
    assert "OWASP Agentic Top 10 2026: ASI03 (partial)" in c.standards


def test_017_pass_on_consistent_https_metadata():
    store, ctx = _scan(_pr(GOOD_PR))
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.PASS and r.confidence == Confidence.HIGH


def test_017_fail_when_resource_names_another_origin():
    store, ctx = _scan(_pr({**GOOD_PR, "resource": "https://api.other.test"}))
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.FAIL and r.severity == Severity.HIGH
    assert "resource_other_origin" in r.evidence["problems"] and r.remediation


def test_017_warn_when_resource_missing():
    store, ctx = _scan(_pr({"authorization_servers": ["https://example.com"]}))
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.WARN and r.severity == Severity.MEDIUM
    assert "resource_missing" in r.evidence["problems"]


def test_017_warn_on_malformed_authorization_servers():
    for bad in ([], "https://example.com", ["https://example.com", 3]):
        store, ctx = _scan(_pr({"resource": "https://example.com", "authorization_servers": bad}))
        r = ProtectedResourceConsistency().run(store, ctx)
        assert r.status == CheckStatus.WARN and "authorization_servers_invalid" in r.evidence["problems"], bad


def test_017_warn_on_plain_http_urls():
    store, ctx = _scan(_pr({**GOOD_PR, "authorization_servers": ["http://example.com"],
                            "jwks_uri": "http://example.com/jwks.json"}))
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.WARN
    assert set(r.evidence["problems"]) >= {"authorization_server_not_https", "jwks_uri_not_https"}


def test_017_fail_wins_and_every_problem_is_listed():
    store, ctx = _scan(_pr({"resource": "https://other.test", "authorization_servers": ["http://x.test"]}))
    r = ProtectedResourceConsistency().run(store, ctx)
    assert r.status == CheckStatus.FAIL
    assert set(r.evidence["problems"]) == {"resource_other_origin", "authorization_server_not_https"}


def test_017_na_when_not_published():
    store, ctx = _scan({})
    assert ProtectedResourceConsistency().run(store, ctx).status == CheckStatus.NA


def test_017_non_json_200_is_na():
    store, ctx = _scan({_PR: (200, "<p>oops</p>")})
    assert ProtectedResourceConsistency().run(store, ctx).status == CheckStatus.NA


def test_017_error_on_our_fetch_failure_and_on_a_5xx():
    store, ctx = _scan({_PR: httpx.ConnectTimeout("t")})
    assert ProtectedResourceConsistency().run(store, ctx).status == CheckStatus.ERROR
    store, ctx = _scan({_PR: (503, "busy")})
    assert ProtectedResourceConsistency().run(store, ctx).status == CheckStatus.ERROR


def test_017_truncated_read_never_reports_missing_fields():
    padded = {"jwks_uri": "https://example.com/jwks.json", "pad": "x" * 5000,
              "resource": "https://example.com", "authorization_servers": ["https://example.com"]}
    store, ctx = _scan(_pr(padded), size_limits={"json": 200})
    r = ProtectedResourceConsistency().run(store, ctx)
    # A truncated JSON body does not parse: the record is unreadable, never "missing fields".
    assert r.status in (CheckStatus.ERROR, CheckStatus.NA)
    assert "resource_missing" not in (r.evidence.get("problems") or [])


from scovant_core.checks.security.oauth import AuthorizationServerConsistency  # noqa: E402

GOOD_AS = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "code_challenge_methods_supported": ["S256"],
    "authorization_response_iss_parameter_supported": True,
}


def _as(doc, pr=None):
    routes = {_AS: (200, json.dumps(doc))}
    if pr is not None:
        routes[_PR] = (200, json.dumps(pr))
    return routes


def _run18(routes):
    store, ctx = _scan(routes)
    return AuthorizationServerConsistency().run(store, ctx)


def test_018_declares_the_contract():
    c = AuthorizationServerConsistency
    assert (c.id, c.family_id, c.security_domain, c.fix_owner) == ("CORE-SECURITY-018", "MCP-AUTH-012", "auth", "identity")
    assert {"RFC 8414", "RFC 9207", "OWASP Agentic Top 10 2026: ASI03 (partial)"} <= set(c.standards)


def test_018_pass_on_complete_consistent_metadata():
    r = _run18(_as(GOOD_AS, pr=GOOD_PR))
    assert r.status == CheckStatus.PASS


def test_018_records_registration_approach_without_judging_it():
    r = _run18(_as({**GOOD_AS, "registration_endpoint": "https://example.com/register",
                    "client_id_metadata_document_supported": True}))
    assert r.status == CheckStatus.PASS
    assert r.evidence["registration"] == {"dynamic_registration": True, "client_id_metadata_document": True}


def test_018_fail_when_issuer_missing():
    r = _run18(_as({k: v for k, v in GOOD_AS.items() if k != "issuer"}))
    assert r.status == CheckStatus.FAIL and r.severity == Severity.HIGH
    assert "issuer_missing" in r.evidence["problems"]


def test_018_fail_when_issuer_is_another_host():
    r = _run18(_as({**GOOD_AS, "issuer": "https://login.other.test"}))
    assert r.status == CheckStatus.FAIL and "issuer_mismatch" in r.evidence["problems"]


def test_018_issuer_with_path_served_at_root_fails():
    r = _run18(_as({**GOOD_AS, "issuer": "https://example.com/tenant"}))
    assert r.status == CheckStatus.FAIL and "issuer_mismatch" in r.evidence["problems"]


def test_018_issuer_case_and_trailing_slash_pass():
    assert _run18(_as({**GOOD_AS, "issuer": "https://EXAMPLE.com/"})).status == CheckStatus.PASS


def test_018_medium_warn_on_missing_or_plain_http_endpoints():
    r = _run18(_as({**GOOD_AS, "token_endpoint": "http://example.com/token"}))
    assert r.status == CheckStatus.WARN and r.severity == Severity.MEDIUM
    assert "token_endpoint_not_https" in r.evidence["problems"]
    r = _run18(_as({k: v for k, v in GOOD_AS.items() if k != "authorization_endpoint"}))
    assert "authorization_endpoint_missing" in r.evidence["problems"]


def test_018_low_warn_when_pkce_s256_not_advertised():
    for methods in (None, ["plain"]):
        doc = {**GOOD_AS}
        if methods is None:
            doc.pop("code_challenge_methods_supported")
        else:
            doc["code_challenge_methods_supported"] = methods
        r = _run18(_as(doc))
        assert r.status == CheckStatus.WARN and r.severity == Severity.LOW
        assert "pkce_s256_not_advertised" in r.evidence["problems"]
        assert "may still enforce" in r.summary


def test_018_low_warn_when_iss_parameter_not_advertised():
    doc = {k: v for k, v in GOOD_AS.items() if k != "authorization_response_iss_parameter_supported"}
    r = _run18(_as(doc))
    assert r.status == CheckStatus.WARN and r.severity == Severity.LOW
    assert "iss_parameter_not_advertised" in r.evidence["problems"]


def test_018_low_warn_when_protected_resource_does_not_list_this_issuer():
    r = _run18(_as(GOOD_AS, pr={**GOOD_PR, "authorization_servers": ["https://login.other.test"]}))
    assert r.status == CheckStatus.WARN and "issuer_not_in_protected_resource" in r.evidence["problems"]


def test_018_cross_document_check_skipped_without_a_valid_protected_resource():
    r = _run18(_as(GOOD_AS, pr={"resource": "https://example.com"}))
    assert "issuer_not_in_protected_resource" not in r.evidence["problems"]


def test_018_fail_outranks_warnings_and_lists_all():
    r = _run18(_as({"issuer": "https://other.test", "token_endpoint": "http://example.com/t"}))
    assert r.status == CheckStatus.FAIL
    assert {"issuer_mismatch", "token_endpoint_not_https", "authorization_endpoint_missing"} <= set(r.evidence["problems"])


def test_018_na_and_error_branches():
    assert _run18({}).status == CheckStatus.NA
    assert _run18({_AS: (200, "<p>oops</p>")}).status == CheckStatus.NA
    assert _run18({_AS: httpx.ConnectTimeout("t")}).status == CheckStatus.ERROR
    assert _run18({_AS: (500, "x")}).status == CheckStatus.ERROR


def test_018_non_json_200_is_na():
    assert _run18({_AS: (200, "not json")}).status == CheckStatus.NA


def test_every_oauth_finding_carries_a_remediation():
    for r in (_run18(_as({"issuer": "https://other.test"})),
              _run18(_as({**GOOD_AS, "code_challenge_methods_supported": ["plain"]}))):
        assert r.remediation

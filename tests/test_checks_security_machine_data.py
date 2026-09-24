"""CORE-SECURITY-007..010 — public machine-facing data exposure (MACHINE-DATA-*)."""
from __future__ import annotations

import hashlib
import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.checks.security.machine_data import (
    CredentialExposed,
    InternalReference,
    PrivilegedEndpoint,
    SensitiveSchemaField,
)
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus, Confidence, Severity
from scovant_core.profiles import apply_profile

from .conftest import FIXTURES, FixtureTransport, make_client

_MIN = "<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>" + "words " * 40 + "</p></body></html>"


def _fixture(name):
    client = make_client(FixtureTransport(FIXTURES / "security" / name))
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


def _with_llms(text):
    def handler(req):
        if req.url.path == "/llms.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=text)
        if req.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN)
        return httpx.Response(404, text="nf")
    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    store.get("llms")
    return store, ctx


def test_ids():
    assert (CredentialExposed.id, CredentialExposed.family_id) == ("CORE-SECURITY-007", "MACHINE-DATA-001")
    assert (InternalReference.id, InternalReference.family_id) == ("CORE-SECURITY-008", "MACHINE-DATA-002")
    assert (PrivilegedEndpoint.id, PrivilegedEndpoint.family_id, PrivilegedEndpoint.experimental) == (
        "CORE-SECURITY-009", "MACHINE-DATA-003", True)
    assert (SensitiveSchemaField.id, SensitiveSchemaField.family_id, SensitiveSchemaField.experimental) == (
        "CORE-SECURITY-010", "MACHINE-DATA-004", True)


def test_credential_exposed_fail_on_generic_assignment_fixture_and_redacts():
    store, ctx = _fixture("machine-secret-exposed")
    store.get("llms")
    r = CredentialExposed().run(store, ctx)
    assert r.status == CheckStatus.WARN and r.severity == Severity.MEDIUM  # generic family = medium confidence → WARN
    hit = r.evidence["hits"][0]
    assert hit["kind"] == "generic_assignment" and set(hit) >= {"redacted", "sha256_prefix", "length", "source", "surface_kind"}
    assert "f3a9c1e7b2d4" not in json.dumps(r.evidence)


def test_credential_exposed_fail_high_on_vendor_shape_assembled_at_runtime():
    store, ctx = _with_llms("# Site\nkey: " + "AKIA" + "J" * 16 + "\n")
    r = CredentialExposed().run(store, ctx)
    assert r.status == CheckStatus.FAIL and r.severity == Severity.HIGH and r.confidence == Confidence.HIGH
    assert "AKIAJ" not in json.dumps(r.evidence)


def test_credential_exposed_pass_on_placeholder_fixture_and_na_without_surfaces():
    store, ctx = _fixture("machine-secret-placeholder")
    store.get("llms")
    assert CredentialExposed().run(store, ctx).status == CheckStatus.PASS
    client = make_client(lambda req: httpx.Response(404, text="nf"))
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    store.try_get("http")
    assert CredentialExposed().run(store, ctx).status == CheckStatus.ERROR  # entry unreadable → ERROR, not N/A


def test_internal_reference_warn_and_excludes_self_and_placeholders():
    store, ctx = _fixture("internal-refs")
    store.get("llms")
    r = InternalReference().run(store, ctx)
    assert r.status == CheckStatus.WARN and r.severity == Severity.LOW
    assert {h["host"] for h in r.evidence["hits"]} == {"10.0.0.5", "169.254.169.254", "db.internal"}
    store, ctx = _with_llms("see https://example.com/x and https://example.invalid/ and http://localhost.example.test/")
    assert InternalReference().run(store, ctx).status == CheckStatus.PASS


def test_privileged_endpoint_warn_from_mcp_server_names_and_openapi_paths():
    store, ctx = _fixture("privileged-endpoints")
    store.get("mcp_discovery")
    store.get("openapi")
    r = PrivilegedEndpoint().run(store, ctx)
    assert r.status == CheckStatus.WARN and sorted(h["name"] for h in r.evidence["hits"]) == ["/admin/users", "delete_all_orders"]


def test_sensitive_schema_field_classification():
    store, ctx = _fixture("sensitive-schema")
    store.get("openapi")
    r = SensitiveSchemaField().run(store, ctx)
    assert r.status == CheckStatus.WARN
    kinds = {h["field"]: h["classification"] for h in r.evidence["hits"]}
    assert kinds == {"password": "field_name_only", "api_secret": "sample_value"}


# --- fix round 1 -------------------------------------------------------------

def test_credential_exposed_warn_confidence_is_medium_not_high():
    """The generic-assignment family is a heuristic match, not a proof — the
    WARN verdict it drives must publish at MEDIUM confidence even when the
    surface that produced it was read in full (the FAIL/PASS branches keep
    HIGH by default; only WARN is capped independently of truncation)."""
    store, ctx = _fixture("machine-secret-exposed")
    store.get("llms")
    r = CredentialExposed().run(store, ctx)
    assert r.status == CheckStatus.WARN and r.confidence == Confidence.MEDIUM


def _openapi_truncated_store():
    """A real spec, oversized enough that a small `json` size cap cuts it off
    mid-document — it fails to parse, so `paths`/`schemas` degrade to `[]`/`{}`
    exactly as a genuine absence would, but `openapi["truncated"]` stays True."""
    body = json.dumps({"openapi": "3.1.0", "paths": {"/x": {"get": {}}},
                        "components": {"schemas": {"S": {"properties": {"password": {"type": "string"}}}}}})
    body += "x" * 5000

    def handler(req):
        if req.url.path == "/openapi.json":
            return httpx.Response(200, headers={"content-type": "application/json"}, text=body)
        if req.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN)
        return httpx.Response(404, text="nf")

    client = make_client(handler, size_limits={"json": 100})
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    store.get("openapi")
    return store, ctx


def test_privileged_endpoint_na_discloses_a_truncated_openapi_read():
    store, ctx = _openapi_truncated_store()
    r = PrivilegedEndpoint().run(store, ctx)
    assert r.status == CheckStatus.NA
    assert r.evidence.get("truncated") is True
    assert r.confidence == Confidence.MEDIUM


def test_sensitive_schema_field_na_discloses_a_truncated_openapi_read():
    store, ctx = _openapi_truncated_store()
    r = SensitiveSchemaField().run(store, ctx)
    assert r.status == CheckStatus.NA
    assert r.evidence.get("truncated") is True
    assert r.confidence == Confidence.MEDIUM


def test_sensitive_schema_field_fail_flags_real_value_like_and_redacts():
    # Assembled at runtime (never a contiguous vendor-shaped literal in
    # source — D7): the "sk_live_" prefix and the hex suffix never appear
    # concatenated in the raw source text.
    live_looking = "sk_live_" + hashlib.sha256(b"machine-data-010-fix-round-1").hexdigest()[:24]
    spec = {
        "openapi": "3.1.0",
        "paths": {},
        "components": {"schemas": {"Client": {"properties": {
            "api_secret": {"type": "string", "example": live_looking},
        }}}},
    }

    def handler(req):
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json=spec, headers={"content-type": "application/json"})
        if req.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN)
        return httpx.Response(404, text="nf")

    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    store.get("openapi")
    r = SensitiveSchemaField().run(store, ctx)
    assert r.status == CheckStatus.FAIL and r.severity == Severity.HIGH
    hit = next(h for h in r.evidence["hits"] if h["field"] == "api_secret")
    assert hit["classification"] == "real_value_like"
    assert {"redacted", "sha256_prefix", "length"} <= set(hit)
    assert live_looking not in json.dumps(r.evidence)


def test_unreadable_entry_error_names_the_shape_and_carries_evidence():
    """A bot wall's 403 is a fetch that happened and was refused — the ERROR
    must say so (status in the summary, `http_status` in evidence) so a
    reader can tell it from a transport failure, and so Cloud can compare it
    with its own honest fetch of the same page."""
    client = make_client(lambda req: httpx.Response(403, text="blocked"))
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    store.try_get("http")
    r = CredentialExposed().run(store, ctx)
    assert r.status == CheckStatus.ERROR
    assert "HTTP 403" in r.summary and r.evidence == {"http_status": 403}

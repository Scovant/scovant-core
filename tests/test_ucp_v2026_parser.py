"""The `v2026` block of `check_ucp_profile`: a business profile read against
the vendored UCP v2026-08-25 schemas, in shadow — every legacy key stays
exactly what the parser produced before the block existed.

Fixtures and their origin: `tests/fixtures/ucp/PROVENANCE.md`.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scovant_core.parsers.ucp import (
    LEGACY_KEYS,
    UCP_MAX_BODY_BYTES,
    UCP_SCHEMA_RELEASE,
    check_ucp_profile,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ucp"


def _text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _doc(name: str):
    return json.loads(_text(f"{name}.json"))


def _v(name: str, content_type: str | None = "application/json") -> dict:
    return check_ucp_profile(_text(f"{name}.json"), 200, content_type)["v2026"]


def _parse(doc, content_type: str | None = "application/json") -> dict:
    return check_ucp_profile(json.dumps(doc), 200, content_type)["v2026"]


# ── the positive fixtures, one per binding / capability ────────────────────

def test_current_rest():
    v = _v("current_rest")
    assert v["valid"] is True and v["version_state"] == "CURRENT"
    assert v["profile_version"] == "2026-08-25"
    assert v["transports"] == ["rest"] and v["transports_raw"] == ["rest"]
    assert v["capabilities_standard"] == ["dev.ucp.shopping.checkout"]
    assert v["capabilities_custom"] == []
    assert (v["has_checkout"], v["has_cart"], v["has_permalink"]) == (True, False, False)
    assert v["keys_state"] == "MISSING"
    assert v["media_type_ok"] is True
    assert v["validation_errors"] == [] and v["validation_warnings"] == []
    assert v["schema_release"] == UCP_SCHEMA_RELEASE == "v2026-08-25"
    assert len(v["schema_digest"]) == 12 and int(v["schema_digest"], 16) >= 0


def test_current_mcp():
    v = _v("current_mcp")
    assert v["valid"] is True and v["version_state"] == "CURRENT"
    assert v["transports"] == ["mcp"]
    assert v["has_checkout"] is True
    assert "dev.ucp.shopping.fulfillment" in v["capabilities_standard"]


def test_current_a2a():
    v = _v("current_a2a")
    assert v["valid"] is True and v["transports"] == ["a2a"]
    assert v["has_checkout"] is False and v["capabilities_standard"] == []


def test_current_embedded_needs_no_endpoint():
    v = _v("current_embedded")
    assert v["valid"] is True and v["transports"] == ["embedded"]


def test_checkout_and_cart():
    v = _v("checkout_and_cart")
    assert v["valid"] is True
    assert (v["has_checkout"], v["has_cart"], v["has_permalink"]) == (True, True, False)


def test_permalink():
    v = _v("permalink")
    assert v["valid"] is True
    assert (v["has_checkout"], v["has_cart"], v["has_permalink"]) == (False, False, True)


def test_overview_business_profile_with_keys():
    v = _v("overview_business")
    assert v["valid"] is True and v["keys_state"] == "VALID"
    assert v["transports"] == ["a2a", "embedded", "mcp", "rest"]
    assert v["capabilities_custom"] == []


def test_supported_legacy_version_is_checked_against_this_release_and_says_so():
    v = _v("protocol_version_2026_01_23")
    assert v["version_state"] == "SUPPORTED_LEGACY" and v["valid"] is True
    assert "validated_against_v2026-08-25" in v["validation_warnings"]


# ── the negative / variant fixtures ────────────────────────────────────────

def test_uppercase_rest_is_invalid_and_warned():
    v = _v("uppercase_rest")
    assert v["valid"] is False
    assert v["transports"] == ["rest"] and v["transports_raw"] == ["REST"]
    assert "noncanonical_transport:REST" in v["validation_warnings"]


def test_legacy_commerce_checkout_is_custom_not_checkout():
    v = _v("legacy_commerce_checkout")
    assert v["valid"] is True and v["has_checkout"] is False
    assert v["capabilities_custom"] == ["dev.ucp.commerce.checkout"]
    assert v["capabilities_standard"] == []
    assert "legacy_capability:dev.ucp.commerce.checkout" in v["validation_warnings"]


def test_version_0_1_is_invalid():
    v = _v("version_0_1")
    assert v["valid"] is False and v["version_state"] == "INVALID"
    assert v["profile_version"] == "0.1"


def test_missing_endpoint_is_invalid():
    v = _v("missing_endpoint")
    assert v["valid"] is False
    assert any("endpoint" in e for e in v["validation_errors"])


def test_missing_capability_schema_is_invalid():
    v = _v("missing_schema")
    assert v["valid"] is False
    assert any("schema" in e for e in v["validation_errors"])


def test_future_version():
    v = _v("future_version")
    assert v["version_state"] == "FUTURE_UNSUPPORTED" and v["valid"] is True
    assert "validated_against_v2026-08-25" in v["validation_warnings"]


def test_custom_capability_is_never_standard():
    v = _v("custom_capability")
    assert v["valid"] is True
    assert v["capabilities_custom"] == ["com.example.loyalty"]
    assert v["capabilities_standard"] == ["dev.ucp.shopping.checkout"]


def test_html_catchall_is_invalid_and_never_raises():
    v = check_ucp_profile(_text("html_catchall.html"), 200, "text/html")["v2026"]
    assert v["valid"] is False and v["validation_errors"] == ["html_body"]
    v = check_ucp_profile(_text("html_catchall.html"), 200, None)["v2026"]
    assert v["valid"] is False and v["validation_errors"] == ["html_body"]


def test_json_array_root_is_invalid():
    v = _v("json_array_root")
    assert v["valid"] is False and v["validation_errors"] == ["root_not_object"]


def test_oversized_body_is_invalid():
    doc = _doc("current_rest")
    doc["padding"] = "a" * UCP_MAX_BODY_BYTES
    v = _parse(doc)
    assert v["valid"] is False and v["validation_errors"] == ["body_too_large"]
    assert UCP_MAX_BODY_BYTES == 128 * 1024


def test_a_body_at_the_cap_is_read():
    doc = _doc("current_rest")
    doc["padding"] = ""
    pad = UCP_MAX_BODY_BYTES - len(json.dumps(doc).encode("utf-8"))
    doc["padding"] = "a" * pad
    assert len(json.dumps(doc).encode("utf-8")) == UCP_MAX_BODY_BYTES
    assert _parse(doc)["valid"] is True


def test_schema_url_is_never_fetched():
    """The offline guard (conftest) refuses every socket; a parser that
    dereferenced the private-IP schema URL would raise here."""
    v = _v("private_ip_schema_url")
    assert v["valid"] is True


def test_private_jwk_is_invalid_and_never_echoed():
    result = check_ucp_profile(_text("private_jwk.json"), 200, "application/json")
    v = result["v2026"]
    assert v["valid"] is False and v["keys_state"] == "INVALID"
    blob = json.dumps(result)
    for key in _doc("private_jwk")["keys"]:
        for member, value in key.items():
            if member not in ("kid", "kty", "crv", "alg", "use"):
                assert value not in blob, member


def test_no_key_material_in_errors_for_any_malformed_key():
    material = {"x": "xmaterialvalue1", "y": "ymaterialvalue2", "d": "dmaterialvalue3",
                "n": "nmaterialvalue4", "e": "ematerialvalue5", "k": "kmaterialvalue6",
                "p": "pmaterialvalue7", "q": "qmaterialvalue8"}
    for kty in ("EC", "OKP", "RSA", "oct", 7, None):
        doc = _doc("current_rest")
        doc["keys"] = [{"kty": kty, "crv": "P-256", "alg": "EdDSA", **material}]
        blob = json.dumps(check_ucp_profile(json.dumps(doc), 200, None))
        for value in material.values():
            assert value not in blob, (kty, value)


def test_legacy_signing_keys():
    v = _v("legacy_signing_keys")
    assert v["valid"] is True and v["keys_state"] == "LEGACY_FIELD"
    assert "legacy_field:signing_keys" in v["validation_warnings"]


def test_keys_states():
    doc = _doc("current_rest")
    assert _parse(doc)["keys_state"] == "MISSING"
    doc["keys"] = []
    assert _parse(doc)["keys_state"] == "MISSING"
    doc["keys"] = [{"kid": "a", "kty": "RSA", "n": "nn", "e": "AQAB"}]  # an unrecognised kty is fine
    assert _parse(doc)["keys_state"] == "VALID" and _parse(doc)["valid"] is True
    doc["keys"] = [{"kid": "a", "kty": "EC", "crv": "P-256", "x": "xx"}]  # EC needs y
    assert _parse(doc)["keys_state"] == "INVALID" and _parse(doc)["valid"] is False
    doc["keys"] = "not-a-list"
    assert _parse(doc)["keys_state"] == "INVALID"


def test_wrong_content_type_is_a_warning_not_invalid():
    v = _v("current_rest", content_type="text/plain; charset=utf-8")
    assert v["valid"] is True and v["media_type_ok"] is False
    assert "content_type_not_json:text/plain" in v["validation_warnings"]
    assert _v("current_rest", content_type=None)["media_type_ok"] is None
    assert _v("current_rest", content_type="application/ucp+json")["media_type_ok"] is True
    v = _v("current_rest", content_type="text/html")
    assert v["valid"] is True and v["media_type_ok"] is False


def test_versions():
    states = {}
    for version in ("2026-08-25", "2026-04-08", "2026-01-23", "2026-01-11", "2026-03-01",
                    "2025-11-01", "2027-01-01", "2026-13-45", "0.1", "", " 2026-08-25"):
        doc = _doc("current_rest")
        doc["ucp"]["version"] = version
        states[version] = _parse(doc)["version_state"]
    assert states == {
        "2026-08-25": "CURRENT", "2026-04-08": "SUPPORTED_LEGACY", "2026-01-23": "SUPPORTED_LEGACY",
        "2026-01-11": "SUPPORTED_LEGACY", "2026-03-01": "INVALID", "2025-11-01": "INVALID",
        "2027-01-01": "FUTURE_UNSUPPORTED", "2026-13-45": "INVALID", "0.1": "INVALID", "": "INVALID",
        " 2026-08-25": "INVALID",
    }
    for value in (None, 20260825, ["2026-08-25"]):
        doc = _doc("current_rest")
        doc["ucp"]["version"] = value
        v = _parse(doc)
        assert v["version_state"] == "INVALID" and v["profile_version"] is None and v["valid"] is False
    doc = _doc("current_rest")
    del doc["ucp"]["version"]
    assert _parse(doc)["version_state"] == "INVALID"


def test_not_found_has_no_block():
    assert check_ucp_profile(None, 404)["v2026"] is None
    assert check_ucp_profile(None, 0)["v2026"] is None


@pytest.mark.parametrize("body", ["", "not json {", "null", "1", '"s"', "{}", '{"ucp": 1}',
                                  '{"ucp": {"services": [], "capabilities": {"A": 1}}}',
                                  "﻿{}", "[]", "NaN", '{"ucp": {"version": "2026-08-25", '
                                  '"services": {"x": [null, 1, {"transport": {}}]}, '
                                  '"payment_handlers": {"a.b": [{"available_instruments": [{}]}]}}}',
                                  "[" * 100000, '{"a":' * 100000])
def test_never_raises(body):
    v = check_ucp_profile(body, 200, "application/json")["v2026"]
    assert v["valid"] is False
    assert all(isinstance(e, str) for e in v["validation_errors"] + v["validation_warnings"])


# ── legacy keys stay byte-identical ────────────────────────────────────────

def test_legacy_keys_unchanged_for_every_fixture():
    expected = json.loads(_text("legacy_expected.json"))
    names = sorted(p.name for p in FIXTURES.iterdir()
                   if p.suffix in (".json", ".html") and p.name != "legacy_expected.json")
    assert sorted(expected) == names
    for name in names:
        for ct in (None, "application/json", "text/html"):
            result = check_ucp_profile(_text(name), 200, ct)
            legacy = {k: v for k, v in result.items() if k != "v2026"}
            assert json.dumps(legacy) == json.dumps(expected[name]), (name, ct)
            assert set(result) == set(LEGACY_KEYS) | {"v2026"}


def test_legacy_keys_unchanged_for_absent_profiles():
    for status in (0, 404, 500):
        result = check_ucp_profile(None, status)
        assert {k: v for k, v in result.items() if k != "v2026"} == {
            "exists": False, "valid": False, "validation_errors": [], "version": None,
            "services": [], "capabilities": [], "has_checkout": False, "transports": [],
            "signing_keys_valid": False,
        }


def test_the_block_never_shares_state_with_its_input():
    doc = _doc("overview_business")
    before = copy.deepcopy(doc)
    _parse(doc)
    assert doc == before


def test_a_pathological_body_reads_like_invalid_json_in_the_legacy_keys():
    deep = check_ucp_profile("[" * 100000, 200)
    flat = check_ucp_profile("not json {", 200)
    assert {k: deep[k] for k in LEGACY_KEYS} == {k: flat[k] for k in LEGACY_KEYS}
    assert deep["v2026"]["valid"] is False


def _provenance_states() -> dict[str, str]:
    """`file -> v2026 state` from PROVENANCE.md's table (generated rows say `—`)."""
    states = {}
    for line in (FIXTURES / "PROVENANCE.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0].endswith((".json", ".html")) and cells[2] != "—":
            states[cells[0]] = cells[2]
    return states


def test_provenance_states_match_the_parser():
    """The `v2026 state` column is the stated verdict for every fixture, and
    downstream checks read it: it must equal what the parser says, and every
    fixture in the directory must have one."""
    from scovant_core.parsers.ucp import ucp_profile_state

    states = _provenance_states()
    files = sorted(p.name for p in FIXTURES.iterdir()
                   if p.suffix in (".json", ".html") and p.name != "legacy_expected.json")
    assert sorted(states) == files
    for name, stated in states.items():
        ctype = "text/html" if name.endswith(".html") else "application/json"
        got = ucp_profile_state(check_ucp_profile(_text(name), 200, ctype))[0]
        assert got == stated, (name, got, stated)
    assert {"usable", "unusable", "future", "html"} <= set(states.values())


@pytest.mark.parametrize("body", ["[" * 100000, '{"a":' * 100000])
def test_the_legacy_reader_itself_never_raises_on_a_deep_body(body):
    """The legacy reading catches the RecursionError itself (one message constant),
    so no caller of it can see one."""
    from scovant_core.parsers.ucp import _LEGACY_INVALID_JSON, _legacy_profile
    out = _legacy_profile(body, 200)
    assert out["exists"] is True and out["validation_errors"] == [_LEGACY_INVALID_JSON]
    assert _legacy_profile("not json {", 200)["validation_errors"] == [_LEGACY_INVALID_JSON]

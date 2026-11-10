"""Universal Commerce Protocol (UCP) profile parsing and validation.

Two readings of the ``/.well-known/ucp`` document live side by side:

* the legacy keys (``exists``, ``valid``, ``validation_errors``, ``version``,
  ``services``, ``capabilities``, ``has_checkout``, ``transports``,
  ``signing_keys_valid``) — an older model of the protocol, kept exactly as they
  were; no verdict reads them except ``exists`` (``ucp_profile_state``) and the
  ``services``/``capabilities`` name lists CORE-INTERFACE-008 shows as evidence;
* ``v2026`` — the profile read as a business profile against the vendored
  UCP v2026-08-25 schemas (``ucp_schemas/v2026-08-25``; facts and their
  sources in that directory's ``FACTS.md``). ``ucp_profile_state`` turns it
  into the one UCP verdict the rules, the capability flag and CORE-INTERFACE-008
  read (Core 0.25.0).

The v2026 validator is hand-written and dependency-free. It implements exactly
the constraints the vendored schemas state for
``profile.json#/$defs/business_schema`` (``format`` is an annotation, as for a
default JSON Schema 2020-12 validator) and never dereferences a URL: a
``$ref``, ``schema`` or ``spec`` value is only ever a string here. Its verdict
is pinned to a real JSON Schema validator over a local registry of the
vendored files by ``tests/test_ucp_schema_conformance.py``.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

# The legacy reading's one message for a body json.loads cannot read
# (including one nested too deeply for it — RecursionError).
_LEGACY_INVALID_JSON = "invalid JSON"


def _legacy_profile(json_content: str | None, http_status: int) -> dict[str, Any]:
    """The pre-v2026 reading, kept byte-for-byte (verdicts read only ``exists``).

    Returns:
        {
            "exists": bool,
            "valid": bool,
            "validation_errors": list[str],
            "version": str | None,
            "services": list[str],
            "capabilities": list[str],
            "has_checkout": bool,
            "transports": list[str],
            "signing_keys_valid": bool,
        }
    """
    result: dict[str, Any] = {
        "exists": False,
        "valid": False,
        "validation_errors": [],
        "version": None,
        "services": [],
        "capabilities": [],
        "has_checkout": False,
        "transports": [],
        "signing_keys_valid": False,
    }

    if http_status != 200 or json_content is None:
        return result

    result["exists"] = True

    try:
        data = json.loads(json_content)
    except (ValueError, RecursionError):  # e.g. "[" * 100000 recurses before it fails
        result["validation_errors"].append(_LEGACY_INVALID_JSON)
        return result

    if not isinstance(data, dict):
        result["validation_errors"].append("root must be a JSON object")
        return result

    ucp = data.get("ucp")
    if not isinstance(ucp, dict):
        result["validation_errors"].append("missing or invalid 'ucp' root key")
        return result

    errors: list[str] = []

    version = ucp.get("version")
    if not isinstance(version, str):
        errors.append("ucp.version is missing or not a string")
    else:
        result["version"] = version

    services_raw = ucp.get("services")
    if not isinstance(services_raw, dict):
        errors.append("ucp.services is missing or not an object")
        services_raw = {}
    result["services"] = list(services_raw.keys())

    capabilities_raw = ucp.get("capabilities")
    if not isinstance(capabilities_raw, dict):
        errors.append("ucp.capabilities is missing or not an object")
        capabilities_raw = {}
    result["capabilities"] = list(capabilities_raw.keys())
    result["has_checkout"] = any(
        cap.startswith("dev.ucp.commerce.checkout") for cap in result["capabilities"]
    )

    signing_keys = data.get("signing_keys")
    if not isinstance(signing_keys, list):
        errors.append("signing_keys is missing or not a list")

    transports: set[str] = set()
    for svc_name, svc_list in services_raw.items():
        if not isinstance(svc_list, list):
            errors.append(f"services.{svc_name} must be a list")
            continue
        for svc in svc_list:
            if not isinstance(svc, dict):
                continue
            for required in ("version", "spec", "transport"):
                if not isinstance(svc.get(required), str):
                    errors.append(f"services.{svc_name} entry missing '{required}'")
            transport = svc.get("transport")
            if isinstance(transport, str):
                transports.add(transport)
                if transport != "A2A" and not isinstance(svc.get("endpoint"), str):
                    errors.append(
                        f"services.{svc_name} entry with transport={transport} missing 'endpoint'"
                    )
                if transport in {"REST", "MCP", "embedded"} and not isinstance(svc.get("schema"), str):
                    errors.append(
                        f"services.{svc_name} entry with transport={transport} missing 'schema'"
                    )

    for cap_name, cap_list in capabilities_raw.items():
        if not isinstance(cap_list, list):
            errors.append(f"capabilities.{cap_name} must be a list")
            continue
        for cap in cap_list:
            if not isinstance(cap, dict):
                continue
            for required in ("version", "spec", "schema"):
                if not isinstance(cap.get(required), str):
                    errors.append(f"capabilities.{cap_name} entry missing '{required}'")

    result["transports"] = sorted(transports)
    result["validation_errors"] = errors[:10]  # cap to 10 to keep the result readable
    # Strict signing_keys check: must be a non-empty list whose every entry
    # has kid/kty/use=sig. `valid` is the looser invariant (signing_keys is a
    # list); this stricter check is exposed separately as `signing_keys_valid`.
    if isinstance(signing_keys, list) and len(signing_keys) > 0 and all(
        isinstance(k, dict)
        and isinstance(k.get("kid"), str) and k["kid"]
        and isinstance(k.get("kty"), str) and k["kty"]
        and k.get("use") == "sig"
        for k in signing_keys
    ):
        result["signing_keys_valid"] = True
    result["valid"] = not errors
    return result


# ─── v2026-08-25 business-profile reading ──────────────────────────────────

LEGACY_KEYS: tuple[str, ...] = (
    "exists", "valid", "validation_errors", "version", "services", "capabilities",
    "has_checkout", "transports", "signing_keys_valid",
)

UCP_SCHEMA_RELEASE = "v2026-08-25"
UCP_CURRENT_VERSION = "2026-08-25"
# FACTS.md (a): the earlier protocol releases the documentation announces.
UCP_SUPPORTED_LEGACY_VERSIONS: frozenset[str] = frozenset({"2026-04-08", "2026-01-23", "2026-01-11"})
# FACTS.md (f): the documentation asks verifiers to read at least 128 KiB.
UCP_MAX_BODY_BYTES = 128 * 1024

TRANSPORTS: tuple[str, ...] = ("rest", "mcp", "a2a", "embedded")
CAPABILITY_CHECKOUT = "dev.ucp.shopping.checkout"
CAPABILITY_CART = "dev.ucp.shopping.cart"
CAPABILITY_PERMALINK = "dev.ucp.shopping.permalink"
# Every `name` an upstream capability schema declares at v2026-08-25
# (`source/schemas/**/*.json`, commit in SOURCE.md). Anything else — a
# business's own reverse-DNS capability, or the pre-release
# `dev.ucp.commerce.*` names — is custom, never standard.
STANDARD_CAPABILITIES: frozenset[str] = frozenset({
    "dev.ucp.common.identity_linking", "dev.ucp.common.location.lookup",
    "dev.ucp.common.location.search", "dev.ucp.common.loyalty",
    "dev.ucp.common.payment.ap2_mandate", "dev.ucp.common.payment.authentication",
    "dev.ucp.common.payment.split_payments", "dev.ucp.common.payment.terms",
    "dev.ucp.shopping.buyer_consent", CAPABILITY_CART, "dev.ucp.shopping.catalog.lookup",
    "dev.ucp.shopping.catalog.search", CAPABILITY_CHECKOUT, "dev.ucp.shopping.discount",
    "dev.ucp.shopping.fulfillment", "dev.ucp.shopping.order", CAPABILITY_PERMALINK,
})
_LEGACY_CAPABILITY_PREFIX = "dev.ucp.commerce."

_SCHEMA_DIR = Path(__file__).resolve().parent / "ucp_schemas" / UCP_SCHEMA_RELEASE
# The schemas' own patterns, used with `re.search` exactly as a JSON Schema
# validator applies `pattern` (ucp.json#/$defs/version,
# common/types/reverse_domain_name.json).
_VERSION_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RDN_PATTERN = re.compile(r"^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9_])?)+$")
_CALENDAR_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}")
# profile.json#/$defs/jwk_public_key/not/anyOf — private JWK members.
_JWK_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
_JWK_STRING_MEMBERS = ("kid", "kty", "crv", "x", "y", "alg", "use")
_JWK_CURVE_ALG = {"P-256": "ES256", "P-384": "ES384", "Ed25519": "EdDSA"}
_MAX_MESSAGES = 20
_MAX_RAW = 32


@lru_cache(maxsize=1)
def ucp_schema_digest() -> str:
    """sha256 over the vendored schema files (path and bytes, sorted), first 12 hex."""
    h = hashlib.sha256()
    for path in sorted(_SCHEMA_DIR.rglob("*.json")):
        h.update(path.relative_to(_SCHEMA_DIR).as_posix().encode("utf-8") + b"\0")
        h.update(path.read_bytes() + b"\0")
    return h.hexdigest()[:12]


def _name(value: object) -> str:
    """A registry key safe to repeat in a message: only a well-formed name is echoed."""
    if isinstance(value, str) and len(value) <= 128 and _RDN_PATTERN.search(value):
        return value
    return "<name>"


def _is_version(value: object) -> bool:
    return isinstance(value, str) and _VERSION_PATTERN.search(value) is not None


def _json_identity(value: object) -> tuple:
    """JSON equality for `uniqueItems`: 1 == 1.0, but true is not 1."""
    if isinstance(value, bool):
        return ("b", value)
    if isinstance(value, (int, float)):
        return ("n", value)
    if isinstance(value, str):
        return ("s", value)
    if value is None:
        return ("z",)
    if isinstance(value, list):
        return ("l", tuple(_json_identity(v) for v in value))
    if isinstance(value, dict):
        return ("d", frozenset((k, _json_identity(v)) for k, v in value.items()))
    return ("?", id(value))


def _unique(items: list) -> bool:
    try:
        seen = [_json_identity(v) for v in items]
        return len(set(seen)) == len(seen)
    except TypeError:  # unhashable after all: fall back to pairwise
        return all(items[i] != items[j] for i in range(len(items)) for j in range(i))


class _Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, path: str, problem: str) -> None:
        self.errors.append(f"{path}: {problem}" if path else problem)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


def _check_string(rep: _Report, obj: dict, key: str, path: str) -> None:
    if key in obj and not isinstance(obj[key], str):
        rep.error(f"{path}.{key}", "must be a string")


def _check_entity(rep: _Report, entry: object, path: str) -> bool:
    """ucp.json#/$defs/entity: an object with a version; spec/schema/id strings; config an object."""
    if not isinstance(entry, dict):
        rep.error(path, "must be an object")
        return False
    if "version" not in entry:
        rep.error(path, "version is required")
    elif not _is_version(entry["version"]):
        rep.error(f"{path}.version", "must be YYYY-MM-DD")
    for key in ("spec", "schema", "id"):
        _check_string(rep, entry, key, path)
    if "config" in entry and not isinstance(entry["config"], dict):
        rep.error(f"{path}.config", "must be an object")
    return True


def _check_registry(rep: _Report, ucp: dict, key: str, entry_check, required: bool) -> None:
    """A reverse-domain-name keyed map whose values are arrays of entries."""
    if key not in ucp:
        if required:
            rep.error(f"ucp.{key}", "required (may be empty)")
        return
    registry = ucp[key]
    if not isinstance(registry, dict):
        rep.error(f"ucp.{key}", "must be an object keyed by reverse-domain name")
        return
    for name, entries in registry.items():
        path = f"ucp.{key}.{_name(name)}"
        if not _RDN_PATTERN.search(name):
            rep.error(f"ucp.{key}", "key is not a reverse-domain name")
        if not isinstance(entries, list):
            rep.error(path, "must be an array")
            continue
        for i, entry in enumerate(entries):
            entry_check(rep, entry, f"{path}[{i}]")


# service.json#/$defs/business_schema: one function per transport binding.

def _binding_rest(rep: _Report, entry: dict, path: str) -> None:
    if "endpoint" not in entry:
        rep.error(path, "transport rest requires endpoint")


def _binding_mcp(rep: _Report, entry: dict, path: str) -> None:
    if "endpoint" not in entry:
        rep.error(path, "transport mcp requires endpoint")


def _binding_a2a(rep: _Report, entry: dict, path: str) -> None:
    # docs § "Endpoint Resolution": for A2A the endpoint is the Agent Card URL.
    if "endpoint" not in entry:
        rep.error(path, "transport a2a requires endpoint (the Agent Card URL)")


def _binding_embedded(rep: _Report, entry: dict, path: str) -> None:
    """No endpoint; `config`, when present, matches transports/embedded_config.json."""
    if "config" not in entry or not isinstance(entry["config"], dict):
        return  # absent: nothing required; not an object: already an entity error
    config = entry["config"]
    if "delegate" in config:
        delegate = config["delegate"]
        if not isinstance(delegate, list) or not all(isinstance(d, str) for d in delegate):
            rep.error(f"{path}.config.delegate", "must be an array of strings")
    if "color_scheme" in config:
        scheme = config["color_scheme"]
        if not isinstance(scheme, list) or not all(isinstance(c, str) and c in ("light", "dark")
                                                   for c in scheme):
            rep.error(f"{path}.config.color_scheme", "must be an array of light/dark")


_BINDINGS = {"rest": _binding_rest, "mcp": _binding_mcp, "a2a": _binding_a2a,
             "embedded": _binding_embedded}


def _check_service(rep: _Report, entry: object, path: str) -> None:
    if not _check_entity(rep, entry, path):
        return
    assert isinstance(entry, dict)
    _check_string(rep, entry, "endpoint", path)
    if "transport" not in entry:
        rep.error(path, "transport is required")
        return
    transport = entry["transport"]
    if not isinstance(transport, str) or transport not in _BINDINGS:
        rep.error(f"{path}.transport", "must be one of rest, mcp, a2a, embedded (lowercase)")
        return
    _BINDINGS[transport](rep, entry, path)


def _check_capability(rep: _Report, entry: object, path: str) -> None:
    if not _check_entity(rep, entry, path):
        return
    assert isinstance(entry, dict)
    if "schema" not in entry:
        rep.error(path, "schema is required")
    if "extends" in entry:
        extends = entry["extends"]
        if isinstance(extends, str):
            ok = _RDN_PATTERN.search(extends) is not None
        elif isinstance(extends, list):
            ok = len(extends) >= 1 and all(isinstance(e, str) and _RDN_PATTERN.search(e)
                                           for e in extends)
        else:
            ok = False
        if not ok:
            rep.error(f"{path}.extends", "must be a reverse-domain name or a non-empty array of them")


def _value_constraint_ok(value: object) -> bool:
    """constraint_expression.json#/$defs/value_constraint."""
    if not isinstance(value, dict):
        return False
    if set(value) - {"enum", "const"} or not ({"enum", "const"} & set(value)):
        return False
    if "enum" in value:
        enum = value["enum"]
        if not isinstance(enum, list) or len(enum) < 1 or not _unique(enum):
            return False
    return True


def _string_set_ok(value: object) -> bool:
    return (isinstance(value, list) and len(value) >= 1 and _unique(value)
            and all(isinstance(v, str) for v in value))


def _constraint_expression_ok(value: object, depth: int = 0) -> bool:
    """common/types/constraint_expression.json (recursive)."""
    if depth > 200 or not isinstance(value, dict):  # far beyond any real profile
        return False
    if set(value) - {"required", "properties", "anyOf"}:
        return False
    if "required" in value and not _string_set_ok(value["required"]):
        return False
    if "properties" in value:
        props = value["properties"]
        if not isinstance(props, dict) or len(props) < 1:
            return False
        for item in props.values():  # oneOf: exactly one of the two shapes
            if _constraint_expression_ok(item, depth + 1) == _value_constraint_ok(item):
                return False
    if "anyOf" in value:
        branches = value["anyOf"]
        if not isinstance(branches, list) or len(branches) < 1:
            return False
        for branch in branches:
            if not (_constraint_expression_ok(branch, depth + 1) and len(branch) >= 1):
                return False
    return True


def _check_payment_handler(rep: _Report, entry: object, path: str) -> None:
    if not _check_entity(rep, entry, path):
        return
    assert isinstance(entry, dict)
    if "id" not in entry:
        rep.error(path, "id is required")
    if "available_instruments" not in entry:
        return
    instruments = entry["available_instruments"]
    ipath = f"{path}.available_instruments"
    if not isinstance(instruments, list) or len(instruments) < 1:
        rep.error(ipath, "must be a non-empty array")
        return
    for i, instrument in enumerate(instruments):
        if not isinstance(instrument, dict):
            rep.error(f"{ipath}[{i}]", "must be an object")
            continue
        if "type" not in instrument:
            rep.error(f"{ipath}[{i}]", "type is required")
        _check_string(rep, instrument, "type", f"{ipath}[{i}]")
        if "constraints" in instrument and not _constraint_expression_ok(instrument["constraints"]):
            rep.error(f"{ipath}[{i}].constraints", "not a valid constraint expression")


def _check_ucp(rep: _Report, ucp: object) -> None:
    """ucp.json#/$defs/business_schema."""
    if not isinstance(ucp, dict):
        rep.error("ucp", "must be an object")
        return
    if "version" not in ucp:
        rep.error("ucp.version", "required")
    elif not _is_version(ucp["version"]):
        rep.error("ucp.version", "must be YYYY-MM-DD")
    if "status" in ucp and not (isinstance(ucp["status"], str) and ucp["status"] in ("success", "error")):
        rep.error("ucp.status", "must be success or error")
    if "map_order" in ucp:
        order = ucp["map_order"]
        if not isinstance(order, dict) or not all(
                isinstance(v, list) and all(isinstance(s, str) for s in v) for v in order.values()):
            rep.error("ucp.map_order", "must map names to arrays of strings")
    if "supported_versions" in ucp:
        supported = ucp["supported_versions"]
        if not isinstance(supported, dict) or not all(
                _is_version(k) and isinstance(v, str) for k, v in supported.items()):
            rep.error("ucp.supported_versions", "must map YYYY-MM-DD versions to URIs")
    _check_registry(rep, ucp, "services", _check_service, required=True)
    _check_registry(rep, ucp, "capabilities", _check_capability, required=False)
    _check_registry(rep, ucp, "payment_handlers", _check_payment_handler, required=True)


def _jwk_problems(key: object) -> list[str]:
    """profile.json#/$defs/jwk_public_key. Messages name members, never values."""
    if not isinstance(key, dict):
        return ["must be an object"]
    problems = [f"{m} is required" for m in ("kid", "kty") if m not in key]
    problems += [f"{m} must be a string" for m in _JWK_STRING_MEMBERS
                 if m in key and not isinstance(key[m], str)]
    kty = key.get("kty")
    if kty == "EC" and isinstance(kty, str):
        problems += [f"EC key requires {m}" for m in ("crv", "x", "y") if m not in key]
    if kty == "OKP" and isinstance(kty, str):
        problems += [f"OKP key requires {m}" for m in ("crv", "x") if m not in key]
    crv = key.get("crv")
    if isinstance(crv, str) and crv in _JWK_CURVE_ALG and "alg" in key \
            and not (isinstance(key["alg"], str) and key["alg"] == _JWK_CURVE_ALG[crv]):
        problems.append(f"alg must be {_JWK_CURVE_ALG[crv]} for this curve")
    if any(m in key for m in _JWK_PRIVATE_MEMBERS):
        problems.append("private key member present")
    return problems


def _keys_state(rep: _Report, doc: dict) -> str:
    """profile.json#/$defs/base/properties/keys — optional, a JWK Set of public keys."""
    if "signing_keys" in doc:
        rep.warn("legacy_field:signing_keys")
    if "keys" not in doc:
        return "LEGACY_FIELD" if "signing_keys" in doc else "MISSING"
    keys = doc["keys"]
    if not isinstance(keys, list):
        rep.error("keys", "must be an array")
        return "INVALID"
    state = "VALID" if keys else "MISSING"
    for i, key in enumerate(keys):
        for problem in _jwk_problems(key):
            rep.error(f"keys[{i}]", problem)
            state = "INVALID"
    return state


def _version_state(version: object) -> str:
    if not isinstance(version, str) or not _CALENDAR_DATE.fullmatch(version):
        return "INVALID"
    try:
        datetime.date.fromisoformat(version)
    except ValueError:
        return "INVALID"
    if version == UCP_CURRENT_VERSION:
        return "CURRENT"
    if version in UCP_SUPPORTED_LEGACY_VERSIONS:
        return "SUPPORTED_LEGACY"
    if version > UCP_CURRENT_VERSION:
        return "FUTURE_UNSUPPORTED"
    return "INVALID"


def _media_type(content_type: str | None) -> tuple[str | None, bool | None]:
    if content_type is None:
        return None, None
    media = content_type.split(";", 1)[0].strip().lower()
    ok = media == "application/json" or (media.startswith("application/") and media.endswith("+json"))
    return media, ok


def _looks_like_html(text: str) -> bool:
    return text.lstrip("﻿ \t\r\n").startswith("<")


def _empty_block(media_ok: bool | None) -> dict[str, Any]:
    return {
        "valid": False, "profile_version": None, "version_state": "INVALID",
        "transports": [], "transports_raw": [],
        "capabilities_standard": [], "capabilities_custom": [],
        "has_checkout": False, "has_cart": False, "has_permalink": False,
        "keys_state": "MISSING", "media_type_ok": media_ok,
        "validation_errors": [], "validation_warnings": [],
        "schema_release": UCP_SCHEMA_RELEASE, "schema_digest": ucp_schema_digest(),
    }


def _declared(doc: dict) -> tuple[dict, dict]:
    ucp = doc.get("ucp")
    if not isinstance(ucp, dict):
        return {}, {}
    services = ucp.get("services")
    capabilities = ucp.get("capabilities")
    return (services if isinstance(services, dict) else {},
            capabilities if isinstance(capabilities, dict) else {})


def _summarise(rep: _Report, block: dict[str, Any], doc: dict) -> None:
    """Transports, capabilities and docs-only advice (warnings, never validity)."""
    services, capabilities = _declared(doc)
    profile_version = doc["ucp"].get("version") if isinstance(doc.get("ucp"), dict) else None
    raw: set[str] = set()
    canonical: set[str] = set()
    for name, entries in services.items():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            transport = entry.get("transport")
            if isinstance(transport, str):
                raw.add(transport[:_MAX_RAW])
                lowered = transport.lower()
                if lowered in TRANSPORTS:
                    canonical.add(lowered)
                    if lowered != transport:
                        rep.warn(f"noncanonical_transport:{transport}")
            endpoint = entry.get("endpoint")
            if isinstance(endpoint, str) and not endpoint.lower().startswith("https://"):
                rep.warn(f"endpoint_not_https:{_name(name)}")
            if (isinstance(name, str) and name.startswith("dev.ucp.") and isinstance(profile_version, str)
                    and entry.get("version") != profile_version):
                rep.warn(f"entry_version_mismatch:{_name(name)}")  # docs § Component Versioning
    block["transports_raw"] = sorted(raw)
    block["transports"] = sorted(canonical)

    standard: list[str] = []
    custom: list[str] = []
    for name, entries in capabilities.items():
        if not _RDN_PATTERN.search(name):
            continue
        (standard if name in STANDARD_CAPABILITIES else custom).append(name)
        if name.startswith(_LEGACY_CAPABILITY_PREFIX):
            rep.warn(f"legacy_capability:{name}")
        for entry in entries if isinstance(entries, list) else []:
            if (isinstance(entry, dict) and name.startswith("dev.ucp.") and isinstance(profile_version, str)
                    and entry.get("version") != profile_version):
                rep.warn(f"entry_version_mismatch:{name}")
    block["capabilities_standard"] = sorted(standard)
    block["capabilities_custom"] = sorted(custom)

    def declared(capability: str) -> bool:
        entries = capabilities.get(capability)
        return isinstance(entries, list) and any(isinstance(e, dict) for e in entries)

    block["has_checkout"] = declared(CAPABILITY_CHECKOUT)
    block["has_cart"] = declared(CAPABILITY_CART)
    block["has_permalink"] = declared(CAPABILITY_PERMALINK)


def read_ucp_v2026(json_content: str, content_type: str | None = None) -> dict[str, Any]:
    """The ``v2026`` block for a fetched profile body. Never raises."""
    media, media_ok = _media_type(content_type)
    block = _empty_block(media_ok)
    rep = _Report()
    if media_ok is False:
        rep.warn(f"content_type_not_json:{media}" if media and _MEDIA_TYPE.fullmatch(media)
                 else "content_type_not_json")
    try:
        _read_body(rep, block, json_content, media)
    except Exception:  # noqa: BLE001 — a reading must never fail the scan
        rep.errors.append("parser_error")
    block["valid"] = not rep.errors
    block["validation_errors"] = rep.errors[:_MAX_MESSAGES]
    block["validation_warnings"] = rep.warnings[:_MAX_MESSAGES]
    return block


def _read_body(rep: _Report, block: dict[str, Any], text: str, media: str | None) -> None:
    if not isinstance(text, str):
        rep.errors.append("invalid_json")
        return
    if len(text.encode("utf-8", "surrogatepass")) > UCP_MAX_BODY_BYTES:
        rep.errors.append("body_too_large")
        return
    if _looks_like_html(text):
        rep.errors.append("html_body")
        return
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        rep.errors.append("html_body" if media in ("text/html", "application/xhtml+xml") else "invalid_json")
        return
    if not isinstance(doc, dict):
        rep.errors.append("root_not_object")
        return

    ucp = doc.get("ucp")
    version = ucp.get("version") if isinstance(ucp, dict) else None
    block["profile_version"] = version[:64] if isinstance(version, str) else None
    block["version_state"] = _version_state(version)
    if block["version_state"] in ("SUPPORTED_LEGACY", "FUTURE_UNSUPPORTED"):
        rep.warn(f"validated_against_{UCP_SCHEMA_RELEASE}")

    if "ucp" not in doc:
        rep.error("ucp", "required")
    else:
        _check_ucp(rep, ucp)
    block["keys_state"] = _keys_state(rep, doc)
    _summarise(rep, block, doc)


def check_ucp_profile(json_content: str | None, http_status: int,
                      content_type: str | None = None) -> dict[str, Any]:
    """Parse and validate a ``/.well-known/ucp`` Universal Commerce Protocol profile.

    Returns the legacy keys (see ``LEGACY_KEYS``; unchanged) plus ``v2026``:
    ``None`` when no profile was fetched (``exists`` is False), else the
    profile read as a UCP v2026-08-25 business profile (``UcpV2026`` in
    ``scovant_core.rules.evidence``). ``content_type`` is the response's
    ``Content-Type``; a non-JSON media type is a warning, never invalidity.
    """
    result = _legacy_profile(json_content, http_status)
    result["v2026"] = (read_ucp_v2026(json_content, content_type)
                       if result["exists"] and json_content is not None else None)
    return result


# ─── one verdict over the v2026 reading, shared by every consumer ───────────

UCP_USABLE_VERSION_STATES: frozenset[str] = frozenset({"CURRENT", "SUPPORTED_LEGACY"})


def ucp_profile_state(ucp: object) -> tuple[str, dict]:
    """What a ``check_ucp_profile`` result says was served at /.well-known/ucp.

    One of ``absent`` (nothing published), ``html`` (an HTML page — no
    profile), ``unread`` (a profile was served but the evidence predates the
    ``v2026`` reading, so its content is unknown), ``oversized`` (the body
    exceeded our read bound ``UCP_MAX_BODY_BYTES`` — a deployment guard, FACTS
    (f), not a site defect: never judged), ``future`` (it declares a
    later release than the vendored schemas: never judged), ``usable``
    (schema-valid AND a current or earlier announced release) or ``unusable``
    (anything else that was served). Returns the state and the v2026 block
    (empty unless one exists). The UCP rules, the transactional-checkout
    capability flag and CORE-INTERFACE-008 all read this one verdict."""
    u = ucp if isinstance(ucp, dict) else {}
    if not u.get("exists"):
        return "absent", {}
    v = u.get("v2026")
    if not isinstance(v, dict):
        return "unread", {}
    errors = v.get("validation_errors") or []
    if "html_body" in errors:
        return "html", v
    if "body_too_large" in errors:
        return "oversized", v
    state = v.get("version_state")
    if state == "FUTURE_UNSUPPORTED":
        return "future", v
    if v.get("valid") is True and state in UCP_USABLE_VERSION_STATES:
        return "usable", v
    return "unusable", v


def ucp_declares_checkout(ucp: object) -> bool:
    """A usable profile that declares ``dev.ucp.shopping.checkout``."""
    state, v = ucp_profile_state(ucp)
    return state == "usable" and v.get("has_checkout") is True

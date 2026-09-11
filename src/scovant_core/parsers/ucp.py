"""Universal Commerce Protocol (UCP) profile parsing and validation.

Validates the ``/.well-known/ucp`` document against the shape described by
the UCP specification: a versioned root, a services map (transport-bearing
entries), a capabilities map (each capability describing its own schema),
and an optional signing-key set.
"""
from __future__ import annotations

import json
from typing import Any


def check_ucp_profile(json_content: str | None, http_status: int) -> dict[str, Any]:
    """Parse and validate a ``/.well-known/ucp`` Universal Commerce Protocol profile.

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
    except (json.JSONDecodeError, ValueError):
        result["validation_errors"].append("invalid JSON")
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

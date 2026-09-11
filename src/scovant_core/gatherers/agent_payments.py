"""Agent-payment-protocol discovery probe (beyond UCP)."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_TIMEOUT, _capped_body, _probe_json
from .probe_tables import PAYMENT_PROBES

if TYPE_CHECKING:
    import httpx


def check_agent_payments(client: httpx.Client, domain: str) -> dict[str, Any]:
    """Probe agent payment protocols beyond UCP.

    Generic over the probe kinds in PAYMENT_PROBES ("well_known_json",
    "challenge_header", "json_text_marker", "x402") — driven entirely by the
    table; a future entry using an existing kind plugs in without code
    changes here.

    Returns:
        {"any_non_ucp": bool, "truncated": bool,
         "protocols": {key: {"detected": bool | None, "evidence": str | None}}}

    `truncated` is True when ANY body this probe actually read was cut off
    at `_PROBE_BODY_CAP`. Per-protocol, `detected` is `None` (never a
    claimed `False`) whenever a truncated read left that protocol's
    presence undetermined and no OTHER read for the same protocol
    confirmed it — `well_known_json` and the x402 catalog probe read
    through the shared `_probe_json` helper, whose `(parsed, truncated)`
    return makes that distinction explicit; `json_text_marker` and the
    x402 status-path loop read directly via `_capped_body`.
    """
    protocols: dict[str, Any] = {}
    truncated_flags: list[bool] = []
    for key, probe in PAYMENT_PROBES.items():
        detected: bool | None = False
        evidence: str | None = None
        if probe["kind"] == "well_known_json":
            data, was_truncated = _probe_json(client, f"{domain}{probe['path']}")
            truncated_flags.append(was_truncated)
            marker = probe.get("json_marker")
            if isinstance(data, dict) and (marker is None or marker in data):
                detected, evidence = True, probe["path"]
            elif was_truncated:
                detected = None  # cut off before we could tell — not a claimed absence
        elif probe["kind"] == "challenge_header":
            try:
                resp = client.get(f"{domain}/", timeout=_PROBE_TIMEOUT)
                header_val = resp.headers.get(probe["header"], "")
                if probe["marker"] in header_val.lower():
                    detected, evidence = True, f"{probe['header']}: {header_val[:100]}"
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                pass
        elif probe["kind"] == "json_text_marker":
            # 200 + parseable JSON + marker substring anywhere in the document
            # (per-operation OpenAPI extensions sit at arbitrary nesting).
            try:
                resp = client.get(f"{domain}{probe['path']}", timeout=_PROBE_TIMEOUT)
                if resp.status_code == 200:
                    text, was_truncated = _capped_body(resp.text)
                    truncated_flags.append(was_truncated and text != "")
                else:
                    text = None
                if text is not None:
                    json.loads(text)
                    if probe["marker"] in text:
                        detected, evidence = True, f"{probe['path']} ({probe['marker']})"
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                pass
        elif probe["kind"] == "x402":
            # Catalog descriptor first, then 402-status probing. The 402
            # body must carry the spec-required json_marker key — a bare
            # 402 (e.g. an L402 challenge, or a plain paywall) is not x402
            # evidence.
            data, catalog_truncated = _probe_json(client, f"{domain}{probe['catalog_path']}")
            truncated_flags.append(catalog_truncated)
            if isinstance(data, dict):
                detected, evidence = True, probe["catalog_path"]
            else:
                any_status_path_truncated = False
                for path in probe["status_paths"]:
                    try:
                        resp = client.get(f"{domain}{path}", timeout=_PROBE_TIMEOUT)
                        if resp.status_code != 402:
                            continue
                        capped, was_truncated = _capped_body(resp.text)
                        was_truncated = was_truncated and capped != ""
                        any_status_path_truncated = any_status_path_truncated or was_truncated
                        truncated_flags.append(was_truncated)
                        body = json.loads(capped)
                    except SoftTimeLimitExceeded:
                        raise
                    except Exception:
                        continue
                    if isinstance(body, dict) and probe["json_marker"] in body:
                        detected = True
                        evidence = f"HTTP 402 with {probe['json_marker']} at {path}"
                        break
                # Neither the catalog nor any status path confirmed x402 —
                # if either read was truncated, that is "could not tell",
                # never a claimed absence.
                if not detected and (catalog_truncated or any_status_path_truncated):
                    detected = None
        protocols[key] = {"detected": detected, "evidence": evidence}
    return {
        "any_non_ucp": any(p["detected"] for p in protocols.values()),
        "truncated": any(truncated_flags),
        "protocols": protocols,
    }

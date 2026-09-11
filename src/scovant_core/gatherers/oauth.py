"""RFC 9728 OAuth protected-resource discovery probe for an MCP endpoint
that signaled it requires auth."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_TIMEOUT, _capped_body, _probe_json

if TYPE_CHECKING:
    import httpx

_MCP_OAUTH_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"
_MCP_OAUTH_AS_METADATA_PATH = "/.well-known/oauth-authorization-server"


def probe_mcp_oauth_discovery(client: httpx.Client, endpoint_url: str) -> dict[str, Any]:
    """UNAUTHENTICATED read of the RFC 9728 OAuth protected-resource
    metadata for an MCP endpoint that signaled it requires auth. This
    issues ONLY GET requests against public ``.well-known`` discovery
    documents — NO auth flow, NO credentials, NO token exchange.

    GETs ``{endpoint-origin}/.well-known/oauth-protected-resource``. On a
    200 response with valid JSON carrying a non-empty ``authorization_servers``
    list, ``discovered`` is True and the parsed body is stored as
    ``resource_metadata``. As an optional second read, the first entry of
    ``authorization_servers`` (treated as the issuer per RFC 8414 /
    OpenID Connect Discovery) is GETted at its own
    ``/.well-known/oauth-authorization-server`` suffix; ``auth_server_metadata_ok``
    records only whether THAT response parsed as a JSON object — a shallow
    "does this look like a real document" check, not spec-conformance
    validation, and its failure never affects ``discovered``.

    Never raises (SoftTimeLimitExceeded excepted, per package convention) —
    every failure (network, non-200, malformed JSON, missing/malformed
    authorization_servers, an unparsable endpoint URL) degrades to the inert
    ``{attempted: False, discovered: False, resource_metadata: None,
    auth_server_metadata_ok: False, error: None}`` default, EXCEPT that
    ``attempted`` is set True as soon as the discovery GET is actually
    issued.
    """
    result: dict[str, Any] = {
        "attempted": False, "discovered": False,
        "resource_metadata": None, "auth_server_metadata_ok": False,
        "error": None, "truncated": False,
    }
    parsed = urlsplit(endpoint_url)
    if not parsed.scheme or not parsed.netloc:
        result["error"] = "invalid endpoint URL"
        return result
    origin = f"{parsed.scheme}://{parsed.netloc}"
    discovery_url = f"{origin}{_MCP_OAUTH_RESOURCE_METADATA_PATH}"

    result["attempted"] = True
    try:
        resp = client.get(discovery_url, timeout=_PROBE_TIMEOUT)
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return result

    if resp.status_code != 200:
        result["error"] = f"HTTP {resp.status_code}"
        return result

    body, was_truncated = _capped_body(resp.text)
    result["truncated"] = was_truncated and body != ""
    try:
        metadata = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        # A parse failure caused by OUR OWN read cap is a different fact
        # from "the server published invalid JSON" — the latter is a real
        # finding about the site, the former is a statement about us, and
        # conflating them would report a possibly-valid, possibly-large
        # metadata document as malformed.
        result["error"] = (
            "response was truncated at the fetch cap before it could be parsed"
            if result["truncated"] else "response is not valid JSON"
        )
        return result

    if not isinstance(metadata, dict):
        result["error"] = "response is not a JSON object"
        return result

    auth_servers = metadata.get("authorization_servers")
    if not isinstance(auth_servers, list) or not auth_servers:
        result["error"] = "no authorization_servers in resource metadata"
        return result

    result["discovered"] = True
    result["resource_metadata"] = metadata

    first_server = auth_servers[0]
    if isinstance(first_server, str) and first_server:
        as_metadata_url = first_server.rstrip("/") + _MCP_OAUTH_AS_METADATA_PATH
        as_metadata, as_truncated = _probe_json(client, as_metadata_url)
        result["auth_server_metadata_ok"] = isinstance(as_metadata, dict)
        # This shallow secondary check (see the docstring: "never affects
        # discovered") stays a plain bool even when inconclusive — but a
        # truncated read here still contributed a body to this scan, so it
        # counts toward the record's own `truncated` flag.
        result["truncated"] = result["truncated"] or as_truncated

    return result

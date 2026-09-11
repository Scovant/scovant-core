"""OAuth discovery-document gatherer: RFC 8414 authorization-server metadata
and RFC 9728 protected-resource metadata, both read UNAUTHENTICATED at the
scan target's own origin (not an MCP endpoint's origin — see `gatherers.oauth`
for that, unrelated, probe). Two GETs, no auth flow, no credentials.
"""
from __future__ import annotations

import json
from typing import Any

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

_AS_PATH = "/.well-known/oauth-authorization-server"
_PR_PATH = "/.well-known/oauth-protected-resource"


def _fetch_json_object(
    client: SecureClient, url: str,
) -> tuple[int | None, bool, dict[str, Any] | None, bool]:
    """GET `url`; return `(status, served_as_html, parsed, truncated)`.
    `parsed` is the body as a JSON object only when the response is a real
    (not soft-200-HTML) 200 whose body actually parses as a JSON `dict` —
    anything else stays `None`, never guessed. `truncated` reflects THIS
    fetch alone; the caller combines the two documents' flags."""
    res = client.try_fetch(url, kind="json")
    if isinstance(res, FetchError):
        return None, False, None, False

    status = res.status
    truncated = bool(res.truncated) and res.text != ""
    served_as_html = is_soft_200_html(status, res.content_type, res.text, document="openapi")
    if status != 200 or served_as_html:
        return status, served_as_html, None, truncated

    try:
        data = json.loads(res.text)
    except (json.JSONDecodeError, ValueError):
        return status, served_as_html, None, truncated
    return status, served_as_html, data if isinstance(data, dict) else None, truncated


@register_gatherer("oauth_metadata")
def gather_oauth_metadata(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""

    as_status, as_html, as_data, as_truncated = _fetch_json_object(client, f"{origin}{_AS_PATH}")
    issuer = as_data.get("issuer") if as_data else None
    authorization_server = {
        "status": as_status,
        "parseable": as_data is not None,
        "issuer": issuer if isinstance(issuer, str) else None,
        "has_endpoints": bool(
            as_data is not None
            and isinstance(as_data.get("authorization_endpoint"), str)
            and isinstance(as_data.get("token_endpoint"), str)
        ),
        "served_as_html": as_html,
        "truncated": as_truncated,
    }

    pr_status, pr_html, pr_data, pr_truncated = _fetch_json_object(client, f"{origin}{_PR_PATH}")
    resource = pr_data.get("resource") if pr_data else None
    auth_servers = pr_data.get("authorization_servers") if pr_data else None
    protected_resource = {
        "status": pr_status,
        "parseable": pr_data is not None,
        "resource": resource if isinstance(resource, str) else None,
        "authorization_servers": auth_servers if isinstance(auth_servers, list) else [],
        "served_as_html": pr_html,
        "truncated": pr_truncated,
    }

    # Two independent documents (authorization-server metadata and
    # protected-resource metadata) contribute to this record; the top-level
    # flag is true when EITHER was cut off at the fetch cap.
    return {"authorization_server": authorization_server, "protected_resource": protected_resource,
            "truncated": as_truncated or pr_truncated}

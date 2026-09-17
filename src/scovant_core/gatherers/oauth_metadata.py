"""OAuth discovery-document gatherer: RFC 8414 authorization-server metadata
and RFC 9728 protected-resource metadata, both read UNAUTHENTICATED at the
scan target's own origin (not an MCP endpoint's origin — see `gatherers.oauth`
for that, unrelated, probe). Two GETs, no auth flow, no credentials.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

_AS_PATH = "/.well-known/oauth-authorization-server"
_PR_PATH = "/.well-known/oauth-protected-resource"


def _origin(u: str) -> str:
    """Scheme + authority, fully lower-cased — the ONE normalisation both
    consistency comparisons below use. `ctx.origin` is built from the final
    URL verbatim (`context.set_final_url`) and so preserves whatever case
    the target was given in; comparing it raw against a normalised value
    reported a spurious mismatch for `https://Example.com/`."""
    p = urlsplit(u)
    return f"{p.scheme}://{p.netloc}".lower()


def _fetch_json_object(
    client: SecureClient, url: str,
) -> tuple[int | None, bool, dict[str, Any] | None, bool, str | None]:
    """GET `url`; return `(status, served_as_html, parsed, truncated, retry_after)`.
    `parsed` is the body as a JSON object only when the response is a real
    (not soft-200-HTML) 200 whose body actually parses as a JSON `dict` —
    anything else stays `None`, never guessed. `truncated` reflects THIS
    fetch alone; the caller combines the two documents' flags. `retry_after`
    is the Retry-After header, only ever populated when `status == 429`."""
    res = client.try_fetch(url, kind="json")
    if isinstance(res, FetchError):
        return None, False, None, False, None

    status = res.status
    truncated = bool(res.truncated) and res.text != ""
    retry_after = res.headers.get("retry-after") if status == 429 else None
    served_as_html = is_soft_200_html(status, res.content_type, res.text, document="openapi")
    if status != 200 or served_as_html:
        return status, served_as_html, None, truncated, retry_after

    try:
        data = json.loads(res.text)
    except (json.JSONDecodeError, ValueError):
        return status, served_as_html, None, truncated, retry_after
    return status, served_as_html, data if isinstance(data, dict) else None, truncated, retry_after


@register_gatherer("oauth_metadata")
def gather_oauth_metadata(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""
    # The scanned site's own origin, normalised the same way `_origin`
    # normalises a document-declared URL (see `_origin`'s docstring).
    _base = ctx.final_url or ctx.input_url

    as_url = f"{origin}{_AS_PATH}"
    as_status, as_html, as_data, as_truncated, as_retry_after = _fetch_json_object(client, as_url)
    issuer = as_data.get("issuer") if as_data else None
    authorization_server = {
        "url": as_url,
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
        "matches_issuer": (_origin(issuer) == _origin(as_url)) if isinstance(issuer, str) else None,
    }
    if as_status == 429:
        authorization_server["retry_after"] = as_retry_after

    pr_url = f"{origin}{_PR_PATH}"
    pr_status, pr_html, pr_data, pr_truncated, pr_retry_after = _fetch_json_object(client, pr_url)
    resource = pr_data.get("resource") if pr_data else None
    auth_servers = pr_data.get("authorization_servers") if pr_data else None
    protected_resource = {
        "url": pr_url,
        "status": pr_status,
        "parseable": pr_data is not None,
        "resource": resource if isinstance(resource, str) else None,
        "authorization_servers": auth_servers if isinstance(auth_servers, list) else [],
        "served_as_html": pr_html,
        "truncated": pr_truncated,
        "scopes_supported": [s for s in (pr_data or {}).get("scopes_supported", []) if isinstance(s, str)] if pr_data else [],
        "jwks_uri": (pr_data or {}).get("jwks_uri") if isinstance((pr_data or {}).get("jwks_uri"), str) else None,
        "resource_matches_origin": (
            (_origin(resource) == _origin(_base)) if isinstance(resource, str) and _base else None
        ),
        "dpop_bound_access_tokens_required": bool((pr_data or {}).get("dpop_bound_access_tokens_required", False)),
    }
    if pr_status == 429:
        protected_resource["retry_after"] = pr_retry_after

    # Two independent documents (authorization-server metadata and
    # protected-resource metadata) contribute to this record; the top-level
    # flag is true when EITHER was cut off at the fetch cap.
    return {"authorization_server": authorization_server, "protected_resource": protected_resource,
            "truncated": as_truncated or pr_truncated}

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
from scovant_core.parsers.html import _registrable_domain
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

_AS_PATH = "/.well-known/oauth-authorization-server"
_PR_PATH = "/.well-known/oauth-protected-resource"


_DEFAULT_PORTS = {"https": 443, "http": 80}


def _origin(u: str) -> str:
    """Scheme + host (+ a non-default port), lower-cased — the ONE
    normalisation every consistency comparison below uses. `ctx.origin` is
    built from the final URL verbatim (`context.set_final_url`) and so
    preserves whatever case the target was given in; comparing it raw
    against a normalised value reported a spurious mismatch for
    `https://Example.com/`. A default port is the same origin
    (`https://example.com:443` == `https://example.com`)."""
    p = urlsplit(u)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def normalize_issuer(url: str) -> str:
    """An issuer/authorization-server URL for comparison: origin normalised
    as `_origin` does, the path kept case-sensitive (RFC 3986 case normalisation) with
    one trailing slash dropped."""
    return _origin(url) + urlsplit(url).path.rstrip("/")


def _same_site(a: str, b: str) -> bool | None:
    """Whether two URLs' hosts share a registrable domain (eTLD+1) — a
    sibling host such as the apex and `www.`, or `auth.` under the same site.
    None when either has no host."""
    ha, hb = urlsplit(a).hostname, urlsplit(b).hostname
    if not ha or not hb:
        return None
    return _registrable_domain(a) == _registrable_domain(b)


def _fetch_json_object(
    client: SecureClient, url: str,
) -> tuple[int | None, bool, dict[str, Any] | None, bool, str | None, str]:
    """GET `url`; return `(status, served_as_html, parsed, truncated, retry_after, served_url)`.
    `parsed` is the body as a JSON object only when the response is a real
    (not soft-200-HTML) 200 whose body actually parses as a JSON `dict` —
    anything else stays `None`, never guessed. `truncated` reflects THIS
    fetch alone; the caller combines the two documents' flags. `retry_after`
    is the Retry-After header, only ever populated when `status == 429`.
    `served_url` is where the body actually came from after redirects (the
    requested URL when nothing was served) — RFC 8414/9728 consistency is
    judged against it, not against the URL we asked for."""
    res = client.try_fetch(url, kind="json")
    if isinstance(res, FetchError):
        return None, False, None, False, None, url
    served = res.final_url or url

    status = res.status
    truncated = bool(res.truncated) and res.text != ""
    retry_after = res.headers.get("retry-after") if status == 429 else None
    served_as_html = is_soft_200_html(status, res.content_type, res.text, document="openapi")
    if status != 200 or served_as_html:
        return status, served_as_html, None, truncated, retry_after, served

    try:
        data = json.loads(res.text)
    except (json.JSONDecodeError, ValueError):
        return status, served_as_html, None, truncated, retry_after, served
    return status, served_as_html, data if isinstance(data, dict) else None, truncated, retry_after, served


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _non_bool_raw(doc: dict[str, Any] | None, key: str) -> str | None:
    """A short repr of `doc[key]` when it is present but not a JSON boolean."""
    if not doc or key not in doc or isinstance(doc[key], bool):
        return None
    return str(doc[key])[:40]


def _str_list_or_none(value: Any) -> list[str] | None:
    """A published list of strings, or None when the key is absent or is not
    a list. Non-string entries are dropped; an empty list stays empty."""
    if not isinstance(value, list):
        return None
    return [v for v in value if isinstance(v, str)]


def _issuer_exact(issuer: Any, origin: str) -> bool | None:
    """RFC 8414 §3.3 for metadata served at the ROOT well-known path: the
    issuer must be exactly the origin that served it — scheme and host
    compared case-insensitively, a default port ignored, no path beyond one
    trailing slash, no query or fragment. None when no string issuer was
    published."""
    if not isinstance(issuer, str) or not issuer:
        return None
    p = urlsplit(issuer)
    if not p.scheme or not p.netloc:
        return False
    return (_origin(issuer) == _origin(origin)
            and p.path in ("", "/") and not p.query and not p.fragment)


def _authorization_servers_valid(pr_data: dict[str, Any] | None) -> bool | None:
    if pr_data is None or "authorization_servers" not in pr_data:
        return None
    value = pr_data["authorization_servers"]
    return bool(isinstance(value, list) and value
                and all(isinstance(v, str) and v for v in value))


@register_gatherer("oauth_metadata")
def gather_oauth_metadata(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""

    as_url = f"{origin}{_AS_PATH}"
    as_status, as_html, as_data, as_truncated, as_retry_after, as_served = _fetch_json_object(client, as_url)
    issuer = as_data.get("issuer") if as_data else None
    authorization_server = {
        "url": as_url,
        "served_url": as_served,
        "status": as_status,
        "parseable": as_data is not None,
        "issuer": issuer if isinstance(issuer, str) else None,
        # Published, but not as a JSON string — told apart from "absent".
        "issuer_wrong_type": bool(as_data is not None and "issuer" in as_data and not isinstance(issuer, str)),
        "has_endpoints": bool(
            as_data is not None
            and isinstance(as_data.get("authorization_endpoint"), str)
            and isinstance(as_data.get("token_endpoint"), str)
        ),
        "served_as_html": as_html,
        "truncated": as_truncated,
        "matches_issuer": (_origin(issuer) == _origin(as_url)) if isinstance(issuer, str) else None,
        "issuer_exact": _issuer_exact(issuer, as_served) if as_data is not None else None,
        "issuer_same_site": (_same_site(issuer, as_served)
                             if as_data is not None and isinstance(issuer, str) and issuer else None),
        "authorization_endpoint": _str_or_none((as_data or {}).get("authorization_endpoint")),
        "token_endpoint": _str_or_none((as_data or {}).get("token_endpoint")),
        "code_challenge_methods_supported": _str_list_or_none((as_data or {}).get("code_challenge_methods_supported")),
        "iss_parameter_supported": _bool_or_none((as_data or {}).get("authorization_response_iss_parameter_supported")),
        # The raw value when the flag was published but is not a JSON boolean
        # (e.g. the string "true"); None when absent or a real boolean.
        "iss_parameter_raw": _non_bool_raw(as_data, "authorization_response_iss_parameter_supported"),
        "registration_endpoint": _str_or_none((as_data or {}).get("registration_endpoint")),
        "client_id_metadata_document_supported": _bool_or_none((as_data or {}).get("client_id_metadata_document_supported")),
    }
    if as_status == 429:
        authorization_server["retry_after"] = as_retry_after

    pr_url = f"{origin}{_PR_PATH}"
    pr_status, pr_html, pr_data, pr_truncated, pr_retry_after, pr_served = _fetch_json_object(client, pr_url)
    resource = pr_data.get("resource") if pr_data else None
    auth_servers = pr_data.get("authorization_servers") if pr_data else None
    protected_resource = {
        "url": pr_url,
        "served_url": pr_served,
        "status": pr_status,
        "parseable": pr_data is not None,
        "resource": resource if isinstance(resource, str) else None,
        "resource_wrong_type": bool(pr_data is not None and "resource" in pr_data and not isinstance(resource, str)),
        "authorization_servers": auth_servers if isinstance(auth_servers, list) else [],
        "served_as_html": pr_html,
        "truncated": pr_truncated,
        "scopes_supported": [s for s in (pr_data or {}).get("scopes_supported", []) if isinstance(s, str)] if pr_data else [],
        "jwks_uri": (pr_data or {}).get("jwks_uri") if isinstance((pr_data or {}).get("jwks_uri"), str) else None,
        "resource_matches_origin": (
            (_origin(resource) == _origin(pr_served)) if isinstance(resource, str) else None
        ),
        "resource_same_site": (
            _same_site(resource, pr_served) if isinstance(resource, str) else None
        ),
        "dpop_bound_access_tokens_required": bool((pr_data or {}).get("dpop_bound_access_tokens_required", False)),
        "authorization_servers_valid": _authorization_servers_valid(pr_data),
    }
    if pr_status == 429:
        protected_resource["retry_after"] = pr_retry_after

    # Two independent documents (authorization-server metadata and
    # protected-resource metadata) contribute to this record; the top-level
    # flag is true when EITHER was cut off at the fetch cap.
    return {"authorization_server": authorization_server, "protected_resource": protected_resource,
            "truncated": as_truncated or pr_truncated}

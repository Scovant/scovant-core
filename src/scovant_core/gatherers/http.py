from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.bot_protection import detect_bot_protection
from scovant_core.security.client import FetchError, SecureClient

_SECURITY_HEADER_NAMES = (
    "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "referrer-policy", "x-content-type-options", "permissions-policy",
)

_INERT_DOWNGRADE = {"attempted": False, "status": None, "final_scheme": None, "redirected_to_https": None, "error": None}


def _cookie_records(raw_headers: list[tuple[str, str]]) -> list[dict]:
    out: list[dict] = []
    for name, value in raw_headers:
        if name.lower() != "set-cookie":
            continue
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(value)
        except Exception:  # noqa: BLE001 — a malformed cookie header is evidence, not a crash
            continue
        for key, morsel in jar.items():
            out.append({
                "name": key,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": (morsel["samesite"].lower() or None) if morsel["samesite"] else None,
                "path": morsel["path"] or None,
                "domain": morsel["domain"] or None,
                "max_age_present": bool(morsel["max-age"]) or bool(morsel["expires"]),
            })
    return out


def _downgrade_probe(client: SecureClient, ctx: ScanContext) -> dict:
    """Probe the plain-http origin to see whether it still serves content or
    redirects to https. `status` is the FIRST hop's status (was the http://
    request itself answered directly, or did it redirect?) — not the status
    of whatever the client's normal redirect-following ultimately landed on
    — while `final_scheme`/`redirected_to_https` describe where that
    following actually ended up. Both come from the same single fetch: the
    first entry `_log`ged during this call is the first hop, `res.final_url`
    is where the client's own (SSRF-guarded, capped) redirect loop stopped.
    """
    parts = urlsplit(ctx.input_url)
    if parts.scheme != "https":
        return dict(_INERT_DOWNGRADE)
    logged_before = len(client.requests)
    res = client.try_fetch(f"http://{parts.netloc}/", kind="text")
    if isinstance(res, FetchError):
        return {**_INERT_DOWNGRADE, "attempted": True, "error": res.kind}
    first_hop = client.requests[logged_before] if len(client.requests) > logged_before else None
    first_status = first_hop["status"] if first_hop else res.status
    final_scheme = urlsplit(res.final_url).scheme
    return {"attempted": True, "status": first_status, "final_scheme": final_scheme,
            "redirected_to_https": final_scheme == "https", "error": None}


@register_gatherer("http")
def gather_http(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    res = client.try_fetch(ctx.input_url, kind="html")
    if isinstance(res, FetchError):
        ctx.set_final_url(ctx.input_url)
        return {"input_url": ctx.input_url, "final_url": None, "status": None, "headers": {},
                "redirect_chain": [], "html": "", "bytes": 0, "truncated": False,
                "bot_protection": None, "error": {"kind": res.kind, "message": res.message},
                "set_cookie": [], "security_headers": {}, "downgrade": dict(_INERT_DOWNGRADE)}
    ctx.set_final_url(res.final_url)
    out = {"input_url": ctx.input_url, "final_url": res.final_url, "status": res.status,
           "headers": res.headers, "redirect_chain": res.redirect_chain, "html": res.text,
           "bytes": res.bytes_len, "truncated": res.truncated,
           "bot_protection": detect_bot_protection(res.status, res.headers, res.text, "browser"),
           "error": None}
    if res.status == 429:
        out["retry_after"] = res.headers.get("retry-after")
    out["set_cookie"] = _cookie_records(res.raw_headers)
    out["security_headers"] = {k: v for k, v in res.headers.items() if k.lower() in _SECURITY_HEADER_NAMES}
    out["downgrade"] = _downgrade_probe(client, ctx)
    return out
